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

    const apiKey = (process.env.GROQ_API_KEY || '').trim();
    const sbUrl = (process.env.SUPABASE_URL || '').trim().replace(/\/$/, '');
    const sbServiceKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();

    if (!apiKey) {
      return res.status(500).json({ error: 'Не задан GROQ_API_KEY в настройках Vercel -> Environment Variables' });
    }

    let userId = null;
    let currentCredits = null;

    // Если Supabase настроен на сервере — проверяем авторизацию и баланс по БД
    // Если пользователь вошел через прямой Яндекс-токен (ya_...), пропускаем его к генерации без ошибки!
    if (sbUrl && sbServiceKey && !token.startsWith('ya_')) {
      if (!token) {
        return res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Войдите в аккаунт (Google, Яндекс или Почта), чтобы использовать 5 бесплатных генераций!' });
      }

      const userRes = await fetch(`${sbUrl}/auth/v1/user`, {
        headers: { 'Authorization': `Bearer ${token}`, 'apikey': sbServiceKey }
      });
      if (!userRes.ok) {
        return res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Сессия истекла, пожалуйста, войдите снова' });
      }
      const userData = await userRes.json();
      userId = userData.id;

      const profRes = await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${userId}&select=credits`, {
        headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
      });
      const profList = await profRes.json();

      if (!Array.isArray(profList) || profList.length === 0) {
        currentCredits = 5;
        await fetch(`${sbUrl}/rest/v1/profiles`, {
          method: 'POST',
          headers: {
            'apikey': sbServiceKey,
            'Authorization': `Bearer ${sbServiceKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ id: userId, email: userData.email || '', credits: 5 })
        });
      } else {
        currentCredits = profList[0].credits;
      }

      if (currentCredits <= 0) {
        return res.status(402).json({ error: 'NO_CREDITS', message: 'Бесплатные генерации закончились. Пополните баланс!' });
      }
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

    if (sbUrl && sbServiceKey && userId !== null && currentCredits !== null) {
      const nextCredits = Math.max(0, currentCredits - 1);
      await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${userId}`, {
        method: 'PATCH',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ credits: nextCredits })
      });
      content.remaining_credits = nextCredits;
    }

    return res.status(200).json(content);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
