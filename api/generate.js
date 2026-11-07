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
    // 1. Получаем список только текстовых чат-моделей Groq (исключая аудио/голос/модерацию)
    const modelsRes = await fetch('https://api.groq.com/openai/v1/models', {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    });
    
    let candidates = ['openai/gpt-oss-120b', 'openai/gpt-oss-20b', 'llama-3.1-8b-instant', 'gemma2-9b-it'];

    if (modelsRes.ok) {
      const modelsData = await modelsRes.json();
      const chatModels = (modelsData.data || [])
        .map(m => m.id)
        .filter(id => {
          const s = id.toLowerCase();
          return !s.includes('whisper') &&
                 !s.includes('guard') &&
                 !s.includes('tts') &&
                 !s.includes('orpheus') &&
                 !s.includes('playai') &&
                 !s.includes('vision') &&
                 !s.includes('allam') &&
                 !s.includes('safeguard') &&
                 !s.includes('prompt-guard');
        });

      // Ставим проверенные модели Llama / Qwen / GPT-OSS / DeepSeek в приоритет
      const sorted = chatModels.sort((a, b) => {
        const score = (name) => {
          if (name.includes('gpt-oss')) return 10;
          if (name.includes('llama') && name.includes('70b')) return 9;
          if (name.includes('qwen')) return 8;
          if (name.includes('llama')) return 7;
          if (name.includes('gemma')) return 6;
          return 1;
        };
        return score(b) - score(a);
      });

      if (sorted.length > 0) candidates = sorted;
    }

    // 2. Пробуем модели по очереди, пока одна из них не ответит без ошибок доступа
    let lastError = 'Не удалось получить ответ от моделей Groq';
    for (const modelId of candidates.slice(0, 4)) {
      const response = await fetch('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: modelId,
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
      if (response.ok && result.choices?.[0]?.message?.content) {
        const content = JSON.parse(result.choices[0].message.content);
        return res.status(200).json(content);
      } else {
        lastError = result.error?.message || lastError;
      }
    }

    return res.status(500).json({ error: lastError });
  } catch (err) {
    return res.status(500).json({ error: err.message });
  }
}
