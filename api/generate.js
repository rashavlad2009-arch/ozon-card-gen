export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const product = body?.product;
    const apiKey = (process.env.GROQ_API_KEY || '').trim();

    if (!apiKey) {
      return res.status(500).json({ error: 'Не задан GROQ_API_KEY в настройках Vercel -> Environment Variables' });
    }

    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: 'llama-3.3-70b-versatile',
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content: 'Ты топ-маркетолог и арт-директор маркетплейсов Ozon и Wildberries. Верни строго JSON: "title" (цепляющий заголовок 2-3 слова КАПСОМ), "subtitle" (выгода или УТП до 5 слов), "badge" (короткий триггер 1-2 слова КАПСОМ, напр. ХИТ ПРОДАЖ), "bullets" (массив ровно из 3-4 ключевых преимуществ товара, каждое по 2-4 слова без маркеров в начале), "sticker" (короткий текст для круглого стикера 2 слова, напр. "ГАРАНТИЯ 1 ГОД" или "100% ОРИГИНАЛ"), "bg_prompt" (детальный промпт на АНГЛИЙСКОМ языке для нейросети Flux/SDXL, описывающий красивый коммерческий студийный фон и подиум для этого товара без самого товара в кадре, напр. "luxury minimalist podium in modern studio, soft cinematic lighting, depth of field, 8k photorealistic"), "seo" (богатое ключевыми словами продающее SEO-описание для карточки Ozon на 500-700 символов с абзацами).'
          },
          { role: 'user', content: `Товар: ${product}` }
        ],
        temperature: 0.7
      })
    });

    const result = await response.json();
    if (!response.ok) {
      return res.status(500).json({ error: result.error?.message || 'Ошибка ответа Groq API' });
    }

    const content = JSON.parse(result.choices[0].message.content);
    return res.status(200).json(content);
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
