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

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const product = body?.product;
    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '').trim();

    const { apiKey, sbUrl, sbServiceKey, secretSalt } = getEnvConfig();

    if (!apiKey) {
      return res.status(500).json({ error: 'Не задан GROQ_API_KEY в настройках Vercel -> Environment Variables' });
    }

    if (!token) {
      return res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Войдите через Яндекс, Google или Почту, чтобы получить 5 бесплатных генераций!'
      });
    }

    let userObj = verifySessionToken(token, secretSalt);

    if (!userObj && sbUrl && sbServiceKey) {
      try {
        const userRes = await fetch(`${sbUrl}/auth/v1/user`, {
          headers: { 'Authorization': `Bearer ${token}`, 'apikey': sbServiceKey }
        });
        if (userRes.ok) {
          const u = await userRes.json();
          if (u?.id) userObj = { id: u.id, email: u.email || '', name: (u.email || 'Профиль').split('@')[0] };
        }
      } catch (e) {}
    }

    if (!userObj) {
      return res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Сессия устарела, пожалуйста, войдите в аккаунт снова'
      });
    }

    // Проверяем баланс пользователя (в Cookie-сейфе, памяти и БД Supabase)
    const cookieVault = readCookieVault(req, secretSalt);
    const memRecord = global.usersVault[userObj.id] || cookieVault[userObj.id] || null;
    let currentCredits = memRecord && typeof memRecord.credits === 'number' ? memRecord.credits : 5;

    if (sbUrl && sbServiceKey) {
      try {
        const profRes = await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(userObj.id)}&select=credits`, {
          headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
        });
        if (profRes.ok) {
          const profList = await profRes.json();
          if (Array.isArray(profList) && profList.length > 0 && typeof profList[0].credits === 'number') {
            currentCredits = profList[0].credits;
          }
        }
      } catch (e) {}
    }

    if (currentCredits <= 0) {
      return res.status(402).json({
        error: 'NO_CREDITS',
        message: 'Бесплатные генерации закончились. Пополните баланс!'
      });
    }

    const systemPrompt = `Ты топ-маркетолог и арт-директор маркетплейсов Ozon, Wildberries, Яндекс Маркет и Авито.
Создай продающую воронку из 3 слайдов карточки товара и верни строго валидный JSON без markdown-обертки:
{
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
  "seo": "Продающее SEO-описание для карточки товара на 500-700 символов с ключевыми запросами."
}`;

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
            { role: 'user', content: `Товар: ${product}` }
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

    // Списываем 1 генерацию и сохраняем в защищенную куку и БД
    const nextCredits = Math.max(0, currentCredits - 1);
    const updatedRecord = {
      ...(memRecord || {}),
      id: userObj.id,
      email: userObj.email,
      name: userObj.name,
      credits: nextCredits,
      usedLabels: Array.isArray(memRecord?.usedLabels) ? memRecord.usedLabels : []
    };

    global.usersVault[userObj.id] = updatedRecord;
    cookieVault[userObj.id] = updatedRecord;
    writeCookieVault(res, cookieVault, secretSalt);

    if (sbUrl && sbServiceKey) {
      try {
        await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(userObj.id)}`, {
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

    content.remaining_credits = nextCredits;
    return res.status(200).json(content);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
