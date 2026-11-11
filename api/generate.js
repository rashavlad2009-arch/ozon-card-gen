import crypto from 'crypto';

const FALLBACK_SUPABASE_URL = 'https://irxszktfwtravyeqnueh.supabase.co';
global.usersVault = global.usersVault || {};

function findEnvVar(suffixes) {
  for (const s of suffixes) {
    if (process.env[s]) return process.env[s].trim();
  }
  const allKeys = Object.keys(process.env);
  for (const s of suffixes) {
    const match = allKeys.find(k => k.endsWith(s) && process.env[k]);
    if (match) return process.env[match].trim();
  }
  return '';
}

function getEnvConfig() {
  const apiKey = findEnvVar(['GROQ_API_KEY']);
  const sbUrl = (findEnvVar(['SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL']) || FALLBACK_SUPABASE_URL).replace(/\/$/, '');
  const sbServiceKey = findEnvVar(['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SECRET_KEY']);
  const secretSalt = sbServiceKey || apiKey || 'kardpro_master_secret_2026';
  return { apiKey, sbUrl, sbServiceKey, secretSalt };
}

function createSessionToken(userObj, salt) {
  const payload = Buffer.from(JSON.stringify({
    id: userObj.id,
    email: userObj.email,
    name: userObj.name,
    provider: userObj.provider || 'yandex',
    credits: typeof userObj.credits === 'number' ? userObj.credits : 0,
    ts: Date.now()
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  return `kp.${payload}.${sig}`;
}

function verifySessionToken(token, salt) {
  if (!token || !token.startsWith('kp.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payload, sig] = parts;
  const expected = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  if (sig !== expected) return null;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
  } catch (e) {
    return null;
  }
}

function readCookieVault(req, salt) {
  try {
    const cookieHeader = req.headers.cookie || '';
    const match = cookieHeader.split(';').map(c => c.trim()).find(c => c.startsWith('kp_vault='));
    if (!match) return {};
    const raw = decodeURIComponent(match.split('=')[1]);
    const [b64, sig] = raw.split('.');
    if (!b64 || !sig) return {};
    const expected = crypto.createHmac('sha256', salt).update(b64).digest('base64url');
    if (sig !== expected) return {};
    return JSON.parse(Buffer.from(b64, 'base64url').toString('utf-8')) || {};
  } catch (e) {
    return {};
  }
}

function writeCookieVault(res, vaultObj, salt) {
  try {
    const b64 = Buffer.from(JSON.stringify(vaultObj)).toString('base64url');
    const sig = crypto.createHmac('sha256', salt).update(b64).digest('base64url');
    const val = encodeURIComponent(`${b64}.${sig}`);
    res.setHeader('Set-Cookie', `kp_vault=${val}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax`);
  } catch (e) {}
}

async function getCloudUserByEmail(sbUrl, sbServiceKey, email) {
  if (!sbUrl || !sbServiceKey || !email) return null;
  try {
    const linkRes = await fetch(`${sbUrl}/auth/v1/admin/generate_link`, {
      method: 'POST',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ type: 'magiclink', email })
    });
    if (!linkRes.ok) return null;
    const data = await linkRes.json();
    return data?.user || (data?.id ? data : null);
  } catch (e) {
    return null;
  }
}

async function saveCloudUserCredits(sbUrl, sbServiceKey, sbUserId, email, oldMeta, nextCredits) {
  if (!sbUrl || !sbServiceKey || !sbUserId) return;
  try {
    await fetch(`${sbUrl}/auth/v1/admin/users/${sbUserId}`, {
      method: 'PUT',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        user_metadata: {
          ...oldMeta,
          kp_initialized: true,
          has_spent: true,
          bonus_blocked: false,
          credits: nextCredits
        }
      })
    });
  } catch (e) {}

  try {
    await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(sbUserId)}`, {
      method: 'PATCH',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ credits: nextCredits })
    });
  } catch (e) {}
}

// Этап 1: Точное распознавание товара по фотографии (Groq Vision + динамический список моделей + резервный Vision-шлюз)
async function recognizeProductFromImage(apiKey, imageBase64, userHint = '') {
  const visionPrompt = userHint
    ? `Посмотри на фото товара (подсказка пользователя: "${userHint}"). Напиши на русском языке в 1-2 предложениях точное название этого товара, его тип, цвет, материал, видимые детали и назначение для продажи на маркетплейсе.`
    : `Внимательно посмотри на фотографию товара. Определи, что именно изображено на фото: напиши на русском языке точное название товара, его категорию, цвет, материал, форму и ключевые видимые особенности в 1-2 предложениях.`;

  // Приоритетный список актуальных мультимодальных моделей Groq 2026
  let visionModels = [
    'qwen/qwen3.8-27b',
    'qwen/qwen3.6-27b',
    'meta-llama/llama-4-scout-17b-16e-instruct',
    'meta-llama/llama-4-maverick-17b-128e-instruct',
    'llama-3.2-90b-vision-preview',
    'llama-3.2-11b-vision-preview'
  ];

  // Динамически подтягиваем все активные модели из каталога Groq, чтобы не зависеть от переименований
  try {
    const mRes = await fetch('https://api.groq.com/openai/v1/models', {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    });
    if (mRes.ok) {
      const mData = await mRes.json();
      const dynamicVision = (mData.data || [])
        .map(m => m.id)
        .filter(id => {
          const low = id.toLowerCase();
          return low.includes('vision') || low.includes('vl') || low.includes('scout') || low.includes('maverick') || low.includes('qwen3');
        });
      visionModels = [...new Set([...visionModels, ...dynamicVision])];
    }
  } catch (e) {}

  // Важно: для Vision-моделей передаем строго одно сообщение role: "user" без role: "system" и без json_object
  for (const vModel of visionModels) {
    try {
      const vRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: vModel,
          messages: [
            {
              role: 'user',
              content: [
                { type: 'text', text: visionPrompt },
                { type: 'image_url', image_url: { url: imageBase64 } }
              ]
            }
          ],
          temperature: 0.3,
          max_completion_tokens: 300
        })
      });

      if (vRes.ok) {
        const vData = await vRes.json();
        const text = vData.choices?.[0]?.message?.content?.trim();
        if (text && text.length > 5) {
          return text.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
        }
      }
    } catch (e) {}
  }

  // Резервный бесплатный мультимодальный шлюз OpenAI Vision (на случай если в Groq временно недоступны Vision-модели)
  try {
    const backupRes = await fetch('https://text.pollinations.ai/openai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'openai',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: visionPrompt },
              { type: 'image_url', image_url: { url: imageBase64 } }
            ]
          }
        ]
      })
    });
    if (backupRes.ok) {
      const bData = await backupRes.json();
      const bText = bData.choices?.[0]?.message?.content?.trim();
      if (bText && bText.length > 5) return bText;
    }
  } catch (e) {}

  return null;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    let product = (body?.product || '').trim();
    const tone = body?.tone || 'hit';
    const imageBase64 = body?.imageBase64 || null;

    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '').trim();

    const { apiKey, sbUrl, sbServiceKey, secretSalt } = getEnvConfig();

    if (!apiKey) {
      return res.status(500).json({ error: 'Не задан GROQ_API_KEY в настройках Vercel -> Environment Variables' });
    }

    if (!token) {
      return res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Войдите через Яндекс ID, чтобы получить 5 бесплатных генераций!'
      });
    }

    const userObj = verifySessionToken(token, secretSalt);
    if (!userObj || !userObj.email) {
      return res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Сессия устарела, пожалуйста, войдите в аккаунт снова'
      });
    }

    const cookieVault = readCookieVault(req, secretSalt);
    const memRecord = global.usersVault[userObj.id] || cookieVault[userObj.id] || null;

    const sbUser = await getCloudUserByEmail(sbUrl, sbServiceKey, userObj.email);
    const cloudMeta = sbUser?.user_metadata || {};

    let currentCredits = 5;
    if (typeof cloudMeta.credits === 'number') {
      currentCredits = cloudMeta.credits;
    } else if (memRecord && typeof memRecord.credits === 'number') {
      currentCredits = memRecord.credits;
    } else if (typeof userObj.credits === 'number') {
      currentCredits = userObj.credits;
    } else if (userObj.provider === 'email') {
      currentCredits = 0;
    }

    if (currentCredits <= 0) {
      return res.status(402).json({
        error: 'NO_CREDITS',
        message: 'Бесплатные генерации закончились. Пополните баланс от 50 ₽!'
      });
    }

    // Если передано фото товара — запускаем Этап 1 (AI Vision распознавание)
    let recognizedProduct = null;
    if (imageBase64 && imageBase64.startsWith('data:image/')) {
      recognizedProduct = await recognizeProductFromImage(apiKey, imageBase64, product);
      if (recognizedProduct) {
        product = product ? `${product} (${recognizedProduct})` : recognizedProduct;
      } else if (!product) {
        return res.status(422).json({
          error: 'Не удалось разглядеть товар на фото. Попробуйте загрузить более четкое фото или кратко подпишите название товара в поле 1.'
        });
      }
    }

    if (!product) {
      return res.status(400).json({ error: 'Опишите ваш товар или загрузите его фотографию!' });
    }

    const toneInstructions = {
      hit: 'Сделай упор на максимальный CTR, яркую выгоду и бестселлер.',
      luxury: 'Сделай упор на премиальность, статус, долговечность и дорогие материалы.',
      trust: 'Сделай упор на надежность, проверку качества, безопасность и гарантию.',
      gift: 'Сделай упор на готовую идею для подарка, эмоции и богатую комплектацию.'
    };

    const systemPrompt = `Ты топ-маркетолог и арт-директор маркетплейсов Ozon, Wildberries, Яндекс Маркет и Авито.
Задача: ${toneInstructions[tone] || toneInstructions.hit}
Создай продающую воронку из 3 слайдов карточки товара и верни строго валидный JSON без markdown-обертки:
{
  "title_variants": [
    "Главный заголовок Вариант 1 (2-3 слова КАПСОМ)",
    "Альтернативный заголовок Вариант 2 (2-3 слова КАПСОМ)",
    "Выгодный заголовок Вариант 3 (2-3 слова КАПСОМ)"
  ],
  "ai_colors": {
    "bg1": "#HEX_верх_фона_под_товар",
    "bg2": "#HEX_темный_низ_фона",
    "accent": "#HEX_яркий_акцент",
    "badge": "#HEX_цвет_бейджа"
  },
  "slides": [
    {
      "title": "Главный заголовок 2-3 слова КАПСОМ",
      "subtitle": "Главное УТП до 5 слов",
      "badge": "ХИТ ПРОДАЖ",
      "sticker": "ГАРАНТИЯ 1 ГОД",
      "bullets": ["Выгода 1 (2-4 слова)", "Выгода 2 (2-4 слова)", "Выгода 3 (2-4 слова)"]
    },
    {
      "title": "ХАРАКТЕРИСТИКИ",
      "subtitle": "Надежные материалы и точность",
      "badge": "ПАРАМЕТРЫ",
      "sticker": "ПРЕМИУМ КАЧЕСТВО",
      "bullets": ["Материал: ...", "Мощность / Емкость: ...", "Особенность: ...", "Вес / Ресурс: ..."]
    },
    {
      "title": "КОМПЛЕКТАЦИЯ",
      "subtitle": "Полный набор в фирменной упаковке",
      "badge": "ЧТО В КОРОБКЕ",
      "sticker": "ПОДАРОК ВНУТРИ",
      "bullets": ["1. Основной товар", "2. Кабель / Аксессуар", "3. Инструкция на русском", "4. Коробка для подарка"]
    }
  ],
  "dimensions": {
    "width": "18 см",
    "height": "24 см"
  },
  "bg_prompt": "Detailed English prompt for commercial product studio background with empty center podium, soft cinematic lighting, 8k photorealistic",
  "seo": "Продающее SEO-описание для карточки товара на 500-700 символов с ключевыми запросами и характеристиками."
}`;

    // Этап 2: Генерация структурированной воронки из 3 слайдов по распознанному товару
    let candidateModels = ['openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'llama-3.3-70b-versatile'];
    try {
      const mRes = await fetch('https://api.groq.com/openai/v1/models', {
        headers: { 'Authorization': `Bearer ${apiKey}` }
      });
      if (mRes.ok) {
        const mData = await mRes.json();
        const ids = (mData.data || [])
          .map(m => m.id)
          .filter(id => !id.includes('whisper') && !id.includes('guard') && !id.includes('tts') && !id.includes('orpheus'));
        candidateModels = [...new Set([...candidateModels, ...ids])];
      }
    } catch (e) {}

    let rawContent = null;
    let lastError = 'Ошибка обращения к модели ИИ';

    for (const modelId of candidateModels) {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: modelId,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: `Товар: ${product}. Сформируй JSON:` }
          ],
          temperature: 0.7
        })
      });
      const result = await response.json();
      if (response.ok && result.choices?.[0]?.message?.content) {
        rawContent = result.choices[0].message.content;
        break;
      } else {
        lastError = result.error?.message || `Ошибка модели ${modelId}`;
      }
    }

    if (!rawContent) return res.status(500).json({ error: lastError });

    const cleanedJson = rawContent.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
    const content = JSON.parse(cleanedJson);

    const nextCredits = Math.max(0, currentCredits - 1);
    const updatedRecord = {
      ...(memRecord || {}),
      id: sbUser?.id || userObj.id,
      email: userObj.email,
      name: userObj.name,
      provider: userObj.provider || 'yandex',
      credits: nextCredits,
      hasSpent: true,
      bonusBlocked: false,
      usedLabels: Array.isArray(memRecord?.usedLabels) ? memRecord.usedLabels : []
    };

    global.usersVault[updatedRecord.id] = updatedRecord;
    cookieVault[updatedRecord.id] = updatedRecord;
    writeCookieVault(res, cookieVault, secretSalt);

    if (sbUser?.id) {
      await saveCloudUserCredits(sbUrl, sbServiceKey, sbUser.id, userObj.email, cloudMeta, nextCredits);
    }

    if (recognizedProduct) {
      content.recognized_product = recognizedProduct;
    }
    content.remaining_credits = nextCredits;
    content.session_token = createSessionToken(updatedRecord, secretSalt);
    return res.status(200).json(content);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
