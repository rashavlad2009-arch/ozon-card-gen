export default async function handler(req, res) {
  if (req.method !== 'POST') {
    return res.status(405).json({ error: 'Method not allowed' });
  }

  const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
  const product = body?.product;
  const apiKey = (process.env.GROQ_API_KEY || '').trim();

  if (!apiKey) {
    return res.status(500).json({ error: 'Не задан GROQ_API_KEY в настройках Vercel' });
  }

  try {
    // 1. Автоматически узнаем список доступных текстовых моделей на вашем ключе Groq
    let selectedModel = 'llama-3.1-8b-instant';
    const modelsRes = await fetch('https://api.groq.com/openai/v1/models', {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    });
    
    if (modelsRes.ok) {
      const modelsData = await modelsRes.json();
      const available = (modelsData.data || [])
        .map(m => m.id)
        .filter(id => !id.includes('whisper') && !id.includes('guard') && !id.includes('tts') && !id.includes('vision'));

      const preferred = [
        'llama-3.3-70b-versatile',
        'llama-3.1-8b-instant',
        'qwen-qwq-32b',
        'deepseek-r1-distill-llama-70b',
        'gemma2-9b-it'
      ];
      selectedModel = preferred.find(p => available.includes(p)) || available[0] || selectedModel;
    }

    // 2. Генерируем тексты карточки и SEO
    const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
      method: 'POST',
      headers: {
        'Authorization': `Bearer ${apiKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        model: selectedModel,
        response_format: { type: 'json_object' },
        messages: [
          {
            role: 'system',
            content: 'Ты эксперт по инфографике и SEO для маркетплейса Ozon. Верни строго JSON на русском языке со следующими полями: "title" (короткий мощный заголовок товара для обложки, 2-3 слова, КАПСОМ), "subtitle" (подзаголовок до 4-5 слов), "badge" (короткий триггер 1-2 слова, например ХИТ ПРОДАЖ или ПРЕМИУМ), "bullets" (массив ровно из 3 коротких главных преимуществ для плашек, каждое не длиннее 4 слов, без галочек в начале), "seo" (продающее SEO-описание товара для карточки Ozon на 400-600 символов с ключевыми словами).'
          },
          {
            role: 'user',
            content: `Товар: ${product}`
          }
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
