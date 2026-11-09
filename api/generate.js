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
            content: `Ты топ-маркетолог и арт-директор маркетплейсов Ozon, Wildberries, Яндекс Маркет и Авито. 
Создай воронку из 3 слайдов карточки товара и верни строго JSON следующей структуры:
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
      "subtitle": "Продуманная конструкция и материалы",
      "badge": "ПАРАМЕТРЫ",
      "sticker": "ПРЕМИУМ КАЧЕСТВО",
      "bullets": ["Материал: ...", "Размеры / Вес: ...", "Особенность: ...", "Ресурс / Мощность: ..."]
    },
    {
      "title": "КОМПЛЕКТАЦИЯ",
      "subtitle": "Всё необходимое уже в наборе",
      "badge": "ЧТО В КОРОБКЕ",
      "sticker": "ГОТОВО К ДАРЕНИЮ",
      "bullets": ["1. Основной товар", "2. Кабель / Аксессуар", "3. Инструкция на русском", "4. Надежная упаковка"]
    }
  ],
  "bg_prompt": "Детальный промпт на АНГЛИЙСКОМ для генерации студийного фона и подиума под этот товар без самого товара в кадре, 8k photorealistic",
  "seo": "Продающее SEO-описание для карточки товара на 500-700 символов с ключевыми запросами."
}`
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
