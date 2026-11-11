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
  const sbAnonKey = findEnvVar([
    'SUPABASE_ANON_KEY',
    'NEXT_PUBLIC_SUPABASE_ANON_KEY',
    'SUPABASE_PUBLISHABLE_KEY',
    'NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY'
  ]);
  const sbServiceKey = findEnvVar(['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SECRET_KEY']);
  const secretSalt = sbServiceKey || apiKey || 'kardpro_master_secret_2026';
  return { apiKey, sbUrl, sbAnonKey, sbServiceKey, secretSalt };
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
    const match = cookieHeader.split(';').map(c => c.trim()).find(c => c.startsWith('kp_vault_v3='));
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
    res.setHeader('Set-Cookie', `kp_vault_v3=${val}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax`);
  } catch (e) {}
}

async function fetchCloudUserState(sbUrl, sbAnonKey, sbServiceKey, secretSalt, email) {
  if (!sbUrl) return null;

  if (sbServiceKey) {
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
      if (linkRes.ok) {
        const linkData = await linkRes.json();
        const u = linkData?.user || linkData;
        if (u?.id) {
          const meta = u.user_metadata || {};
          return {
            supabaseUid: u.id,
            credits: typeof meta.credits === 'number' ? meta.credits : null,
            genCount: meta.gen_count || 0,
            usedLabels: Array.isArray(meta.used_labels) ? meta.used_labels : [],
            passHash: meta.pass_hash || null,
            mode: 'admin'
          };
        }
      }
    } catch (e) {}
  }

  const activeKey = sbAnonKey || sbServiceKey;
  if (activeKey) {
    try {
      const autoPassword = 'Kp!' + crypto.createHmac('sha256', secretSalt).update(`cloud_sync_${email}`).digest('hex').substring(0, 20);
      const tokenRes = await fetch(`${sbUrl}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers: { 'apikey': activeKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: autoPassword })
      });
      if (tokenRes.ok) {
        const tokenData = await tokenRes.json();
        const u = tokenData?.user;
        const userJwt = tokenData?.access_token;
        if (u?.id && userJwt) {
          const meta = u.user_metadata || {};
          return {
            supabaseUid: u.id,
            userJwt,
            credits: typeof meta.credits === 'number' ? meta.credits : null,
            genCount: meta.gen_count || 0,
            usedLabels: Array.isArray(meta.used_labels) ? meta.used_labels : [],
            passHash: meta.pass_hash || null,
            mode: 'user_jwt'
          };
        }
      }
    } catch (e) {}
  }

  return null;
}

async function saveCloudUserState(sbUrl, sbAnonKey, sbServiceKey, cloudState, email, nextCredits, nextGenCount) {
  if (!sbUrl || !cloudState) return;

  const metaPayload = {
    kp_init: true,
    credits: nextCredits,
    gen_count: nextGenCount,
    used_labels: cloudState.usedLabels || [],
    pass_hash: cloudState.passHash || null
  };

  if (cloudState.mode === 'admin' && sbServiceKey && cloudState.supabaseUid) {
    try {
      await fetch(`${sbUrl}/auth/v1/admin/users/${cloudState.supabaseUid}`, {
        method: 'PUT',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ user_metadata: metaPayload })
      });
    } catch (e) {}

    try {
      await fetch(`${sbUrl}/rest/v1/profiles`, {
        method: 'POST',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates'
        },
        body: JSON.stringify({
          id: cloudState.supabaseUid,
          email,
          credits: nextCredits
        })
      });
    } catch (e) {}
  } else if (cloudState.mode === 'user_jwt' && cloudState.userJwt) {
    const activeKey = sbAnonKey || sbServiceKey;
    try {
      await fetch(`${sbUrl}/auth/v1/user`, {
        method: 'PUT',
        headers: {
          'apikey': activeKey,
          'Authorization': `Bearer ${cloudState.userJwt}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ data: metaPayload })
      });
    } catch (e) {}
  }
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const product = (body?.product || '').trim();
    const tone = body?.tone || 'hit';
    const imageBase64 = body?.imageBase64 || null;

    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '').trim();

    const { apiKey, sbUrl, sbAnonKey, sbServiceKey, secretSalt } = getEnvConfig();

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
    const memRecord = global.usersVault[userObj.email] || cookieVault[userObj.email] || null;
    const cloudState = await fetchCloudUserState(sbUrl, sbAnonKey, sbServiceKey, secretSalt, userObj.email);

    let currentCredits = (cloudState && typeof cloudState.credits === 'number')
      ? cloudState.credits
      : (memRecord && typeof memRecord.credits === 'number' ? memRecord.credits : (userObj.provider === 'yandex' ? 5 : 0));

    if (currentCredits <= 0) {
      return res.status(402).json({
        error: 'NO_CREDITS',
        message: 'Бесплатные генерации закончились. Пополните баланс от 50 ₽!'
      });
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

    let rawContent = null;
    let lastError = 'Ошибка обращения к модели ИИ';

    if (imageBase64 && imageBase64.startsWith('data:image/')) {
      const visionModels = [
        'meta-llama/llama-4-scout-17b-16e-instruct',
        'meta-llama/llama-4-maverick-17b-128e-instruct'
      ];
      for (const vModel of visionModels) {
        try {
          const vRes = await fetch('https://api.groq.com/openai/v1/chat/completions', {
            method: 'POST',
            headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
            body: JSON.stringify({
              model: vModel,
              response_format: { type: 'json_object' },
              messages: [
                { role: 'system', content: systemPrompt },
                {
                  role: 'user',
                  content: [
                    { type: 'text', text: product ? `Товар на фото (${product}). Создай воронку:` : 'Определи товар на фото и создай для него продающую воронку из 3 слайдов:' },
                    { type: 'image_url', image_url: { url: imageBase64 } }
                  ]
                }
              ],
              temperature: 0.65
            })
          });
          const vData = await vRes.json();
          if (vRes.ok && vData.choices?.[0]?.message?.content) {
            rawContent = vData.choices[0].message.content;
            break;
          }
        } catch (e) {}
      }
    }

    if (!rawContent) {
      let candidateModels = ['openai/gpt-oss-120b', 'openai/gpt-oss-20b'];
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

      for (const modelId of candidateModels) {
        const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST',
          headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({
            model: modelId,
            response_format: { type: 'json_object' },
            messages: [
              { role: 'system', content: systemPrompt },
              { role: 'user', content: `Товар: ${product || 'Популярный товар для маркетплейса'}` }
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
    }

    if (!rawContent) return res.status(500).json({ error: lastError });

    const cleanedJson = rawContent.replace(/^```json\s*/i, '').replace(/```\s*$/i, '').trim();
    const content = JSON.parse(cleanedJson);

    const nextCredits = Math.max(0, currentCredits - 1);
    const nextGenCount = (cloudState?.genCount || memRecord?.genCount || 0) + 1;

    const updatedRecord = {
      ...(memRecord || {}),
      id: userObj.id,
      email: userObj.email,
      name: userObj.name,
      provider: userObj.provider || 'yandex',
      isInitialized: true,
      credits: nextCredits,
      genCount: nextGenCount
    };

    global.usersVault[userObj.email] = updatedRecord;
    cookieVault[userObj.email] = updatedRecord;
    writeCookieVault(res, cookieVault, secretSalt);

    await saveCloudUserState(sbUrl, sbAnonKey, sbServiceKey, cloudState, userObj.email, nextCredits, nextGenCount);

    content.remaining_credits = nextCredits;
    return res.status(200).json(content);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
