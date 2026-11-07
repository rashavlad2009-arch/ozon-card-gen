export default async function handler(req, res) {
  // Жестко фиксируем, что сервер всегда отвечает в формате JSON
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  try {
    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    const product = body?.product;
    
    // Ключ берется из скрытой памяти Vercel (Environment Variables), его нет в коде!
    const apiKey = (process.env.GROQ_API_KEY || '').trim();

    if (!apiKey) {
      return res.status(500).json({ error: 'Системная ошибка: не задан API-ключ на сервере.' });
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
            content: 'Ты арт-директор и эксперт по карточкам Ozon. Верни строго JSON: "title" (заголовок 2-3 слова КАПСОМ), "subtitle" (подзаголовок до 5 слов), "badge" (триггер 1-2 слова, напр. ХИТ ПРОДАЖ), "bullets" (массив из 3-4 преимуществ до 4 слов без галочек), "bg_prompt" (детальный промпт на АНГЛИЙСКОМ для генерации красивого фона студии без товара, напр. "minimalist product podium with soft neon studio lighting, 8k").'
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
    return.status(200).json(content); // Возвращаем готовый JSON клиенту
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
