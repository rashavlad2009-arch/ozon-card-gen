import crypto from 'crypto';

function getEnvConfig() {
  const apiKey = (process.env.GROQ_API_KEY || '').trim();
  const sbUrl = (process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim().replace(/\/$/, '');
  const sbServiceKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || '').trim();
  const secretSalt = sbServiceKey || apiKey || 'kardpro_salt_2026';
  return { apiKey, sbUrl, sbServiceKey, secretSalt };
}

function verifyYandexSession(token, salt) {
  if (!token || !token.startsWith('ya_')) return null;
  const parts = token.split('_');
  if (parts.length !== 3) return null;
  const [, userId, sig] = parts;
  const expected = crypto.createHmac('sha256', salt).update(String(userId)).digest('hex').substring(0, 24);
  return sig === expected ? userId : null;
}

async function getUserCredits(sbUrl, sbServiceKey, userId, email = '') {
  let metaCredits = null;
  try {
    const adminUserRes = await fetch(`${sbUrl}/auth/v1/admin/users/${userId}`, {
      headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
    });
    if (adminUserRes.ok) {
      const adminUser = await adminUserRes.json();
      if (typeof adminUser?.user_metadata?.credits === 'number') {
        metaCredits = adminUser.user_metadata.credits;
      }
    }
  } catch (e) {}

  try {
    const profRes = await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${userId}&select=credits`, {
      headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
    });
    if (profRes.ok) {
      const profList = await profRes.json();
      if (Array.isArray(profList) && profList.length > 0 && typeof profList[0].credits === 'number') {
        return profList[0].credits;
      }
      const initial = metaCredits !== null ? metaCredits : 5;
      await fetch(`${sbUrl}/rest/v1/profiles`, {
        method: 'POST',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ id: userId, email, credits: initial })
      });
      return initial;
    }
  } catch (e) {}

  if (metaCredits !== null) return metaCredits;
  await setUserCredits(sbUrl, sbServiceKey, userId, 5);
  return 5;
}

async function setUserCredits(sbUrl, sbServiceKey, userId, newCredits) {
  try {
    await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${userId}`, {
      method: 'PATCH',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ credits: newCredits })
    });
  } catch (e) {}

  try {
    await fetch(`${sbUrl}/auth/v1/admin/users/${userId}`, {
      method: 'PUT',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ user_metadata: { credits: newCredits } })
    });
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

    // 1. Строгая проверка авторизации (никаких гостевых генераций без входа)
    if (!token) {
      return res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Войдите через Яндекс, Google или Почту, чтобы получить 5 бесплатных генераций!'
      });
    }

    let userId = null;
    let userEmail = '';

    const yaVerifiedId = verifyYandexSession(token, secretSalt);
    if (yaVerifiedId) {
      userId = yaVerifiedId;
    } else if (sbUrl && sbServiceKey) {
      const userRes = await fetch(`${sbUrl}/auth/v1/user`, {
        headers: { 'Authorization': `Bearer ${token}`, 'apikey': sbServiceKey }
      });
      if (!userRes.ok) {
        return res.status(401).json({
          error: 'AUTH_REQUIRED',
          message: 'Сессия истекла, пожалуйста, войдите в аккаунт снова'
        });
      }
      const userData = await userRes.json();
      userId = userData.id;
      userEmail = userData.email || '';
    } else {
      return res.status(500).json({ error: 'Не настроены ключи SUPABASE_URL и SUPABASE_SERVICE_ROLE_KEY в Vercel' });
    }

    // 2. Проверяем баланс в базе Supabase
    const currentCredits = await getUserCredits(sbUrl, sbServiceKey, userId, userEmail);
    if (currentCredits <= 0) {
      return res.status(402).json({
        error: 'NO_CREDITS',
        message: 'Бесплатные генерации закончились. Пополните баланс!'
      });
    }

    // 3. Запрос к ИИ Groq (с авто-подбором доступной модели)
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

    // 4. Списываем 1 генерацию в базе данных
    const nextCredits = Math.max(0, currentCredits - 1);
    await setUserCredits(sbUrl, sbServiceKey, userId, nextCredits);

    content.remaining_credits = nextCredits;
    return res.status(200).json(content);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
