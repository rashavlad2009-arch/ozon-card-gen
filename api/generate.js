import crypto from 'crypto';

const FALLBACK_SUPABASE_URL = 'https://irxszktfravyeqnueh.supabase.co';

const LIMITS = {
  MAX_PRODUCT_LEN: 2000,
  MAX_RECOGNIZED_LEN: 300,
  MAX_IMAGE_BYTES: 3 * 1024 * 1024,
  MAX_IMAGE_B64_LEN: Math.ceil(3 * 1024 * 1024 * 4 / 3) + 100,
  MAX_BODY_BYTES: 4 * 1024 * 1024,
  SESSION_TTL_MS: 30 * 24 * 60 * 60 * 1000,
  FETCH_TIMEOUT_MS: 25000,
  RATE_WINDOW_MS: 60 * 1000,
  RATE_MAX_HITS: 20
};

const ALLOWED_IMAGE_MIMES = new Set(['image/jpeg', 'image/png', 'image/webp']);

global.usersVault = global.usersVault || {};
global.rateBuckets = global.rateBuckets || new Map();

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
  const secretSalt = findEnvVar(['KARDPRO_SESSION_SALT', 'SESSION_SECRET']) || sbServiceKey;
  const allowedOrigins = (findEnvVar(['ALLOWED_ORIGINS']) || '').split(',').map(s => s.trim()).filter(Boolean);
  return { apiKey, sbUrl, sbServiceKey, secretSalt, allowedOrigins };
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  try { return crypto.timingSafeEqual(bufA, bufB); } catch { return false; }
}

function verifySessionToken(token, salt) {
  if (!token || typeof token !== 'string' || !token.startsWith('kp.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payload, sig] = parts;
  const expected = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  if (!safeEqual(sig, expected)) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
    if (typeof decoded.ts !== 'number') return null;
    if (Date.now() - decoded.ts > LIMITS.SESSION_TTL_MS) return null;
    if (decoded.ts - Date.now() > 5 * 60 * 1000) return null;
    if (!decoded.id || !decoded.email) return null;
    return decoded;
  } catch { return null; }
}

function createSessionToken(userObj, salt) {
  if (!salt) throw new Error('secretSalt не задан');
  const payload = Buffer.from(JSON.stringify({
    id: userObj.id, email: userObj.email, name: userObj.name,
    provider: userObj.provider || 'yandex',
    credits: typeof userObj.credits === 'number' ? userObj.credits : 0,
    ts: Date.now()
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  return `kp.${payload}.${sig}`;
}

function readCookieVault(req, salt) {
  try {
    const cookieHeader = req.headers.cookie || '';
    const match = cookieHeader.split(';').map(c => c.trim()).find(c => c.startsWith('kp_vault='));
    if (!match) return {};
    const raw = decodeURIComponent(match.substring('kp_vault='.length));
    const [b64, sig] = raw.split('.');
    if (!b64 || !sig) return {};
    const expected = crypto.createHmac('sha256', salt).update(b64).digest('base64url');
    if (!safeEqual(sig, expected)) return {};
    return JSON.parse(Buffer.from(b64, 'base64url').toString('utf-8')) || {};
  } catch { return {}; }
}

async function fetchWithTimeout(url, opts = {}, timeoutMs = LIMITS.FETCH_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
}

function checkRateLimit(key) {
  const now = Date.now();
  const bucket = global.rateBuckets.get(key);
  if (!bucket || now - bucket.start > LIMITS.RATE_WINDOW_MS) {
    global.rateBuckets.set(key, { start: now, hits: 1 });
    if (global.rateBuckets.size > 5000) {
      for (const [k, v] of global.rateBuckets) {
        if (now - v.start > LIMITS.RATE_WINDOW_MS) global.rateBuckets.delete(k);
      }
    }
    return { allowed: true };
  }
  if (bucket.hits >= LIMITS.RATE_MAX_HITS) {
    return { allowed: false, retryAfter: Math.ceil((bucket.start + LIMITS.RATE_WINDOW_MS - now) / 1000) };
  }
  bucket.hits++;
  return { allowed: true };
}

async function getSupabaseUserByEmail(sbUrl, sbServiceKey, email) {
  if (!sbUrl || !sbServiceKey || !email) return null;
  try {
    const res = await fetchWithTimeout(
      `${sbUrl}/auth/v1/admin/users?email=eq.${encodeURIComponent(email)}&per_page=1`,
      { headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}` } }, 8000
    );
    if (!res.ok) return null;
    const data = await res.json();
    const users = data.users || data || [];
    return Array.isArray(users) ? users.find(u => (u.email || '').toLowerCase() === email.toLowerCase()) || null : null;
  } catch { return null; }
}

async function getProfileCredits(sbUrl, sbServiceKey, userId) {
  if (!sbUrl || !sbServiceKey || !userId) return null;
  try {
    const res = await fetchWithTimeout(
      `${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=credits`,
      { headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}` } }, 8000
    );
    if (!res.ok) return null;
    const list = await res.json();
    return (Array.isArray(list) && list.length > 0 && typeof list[0].credits === 'number') ? list[0].credits : null;
  } catch { return null; }
}

async function saveSupabaseCredits(sbUrl, sbServiceKey, sbUserId, nextCredits, patch) {
  if (!sbUrl || !sbServiceKey || !sbUserId) return;
  try {
    await fetchWithTimeout(`${sbUrl}/auth/v1/admin/users/${sbUserId}`, {
      method: 'PUT',
      headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        app_metadata: {
          kp_initialized: true, kp_credits: nextCredits, kp_has_spent: true,
          kp_bonus_blocked: !!patch.bonusBlocked,
          kp_pass_hash: patch.passHash || null,
          kp_used_labels: Array.isArray(patch.usedLabels) ? patch.usedLabels.slice(-100) : []
        }
      })
    }, 8000);
  } catch (e) { console.error('[generate] saveSupabaseCredits auth:', e.message); }
  try {
    await fetchWithTimeout(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(sbUserId)}`, {
      method: 'PATCH',
      headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
      body: JSON.stringify({ credits: nextCredits })
    }, 8000);
  } catch (e) { console.error('[generate] saveSupabaseCredits profiles:', e.message); }
}

function validateImageDataUrl(imageBase64) {
  if (!imageBase64 || typeof imageBase64 !== 'string') return { ok: false, reason: 'not_a_string' };
  if (imageBase64.length > LIMITS.MAX_IMAGE_B64_LEN) return { ok: false, reason: 'too_large' };
  const match = imageBase64.match(/^data:(image\/[a-z+]+);base64,/i);
  if (!match) return { ok: false, reason: 'bad_format' };
  const mime = match[1].toLowerCase();
  if (!ALLOWED_IMAGE_MIMES.has(mime)) return { ok: false, reason: 'bad_mime' };
  const b64 = imageBase64.split(',')[1] || '';
  const estimatedBytes = Math.floor(b64.length * 0.75);
  if (estimatedBytes > LIMITS.MAX_IMAGE_BYTES) return { ok: false, reason: 'too_large' };
  return { ok: true };
}

function clampString(s, max) {
  if (typeof s !== 'string') return '';
  const t = s.trim();
  return t.length > max ? t.slice(0, max) : t;
}

// ================== ВАЛИДАТОР КАРТОЧКИ (МП) ==================
function validateCardContent(content) {
  const issues = [];
  const warnings = [];

  if (!content || !Array.isArray(content.slides)) {
    return { ok: false, issues: [{ field: 'структура', label: 'Отсутствует массив slides', snippet: '' }], warnings: [], checkedCount: 0 };
  }

  const FORBIDDEN_PATTERNS = [
    { re: /\b(?:8[\s\-]?\(?9\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})\b/i, label: 'номер телефона', severity: 'error' },
    { re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, label: 'email', severity: 'error' },
    { re: /\b(?:vk\.com|instagram|t\.me|wa\.me|whatsapp|telegram)\b/i, label: 'ссылка на соцсеть', severity: 'error' },
    { re: /\b(?:qr[\s\-]?код|qr[\s\-]?code)\b/i, label: 'упоминание QR-кода', severity: 'warning' },
    { re: /(?:скидк[аи]|акция|распродажа|только сегодня|черная пятница|black friday)/i, label: 'акция/скидка (запрещена на инфографике)', severity: 'warning' },
    { re: /\b(?:самый лучший|лучший в мире|№\s*1|номер\s*1|лидер рынка|100%\s*качество)\b/i, label: 'недоказуемое превосходство', severity: 'warning' },
    { re: /\b(?:гарантия\s+пожизненн|пожизненная гарантия)\b/i, label: 'пожизненная гарантия (недоказуемо)', severity: 'warning' },
    { re: /(?:лечит|исцеляет|избавляет от болезней|медицинск)/i, label: 'медицинские утверждения', severity: 'error' }
  ];

  const textToCheck = [];
  content.slides.forEach((slide, idx) => {
    if (slide.title) textToCheck.push({ text: String(slide.title), slide: idx + 1, field: `Слайд ${idx + 1}: Заголовок` });
    if (slide.subtitle) textToCheck.push({ text: String(slide.subtitle), slide: idx + 1, field: `Слайд ${idx + 1}: Подзаголовок` });
    if (slide.badge) textToCheck.push({ text: String(slide.badge), slide: idx + 1, field: `Слайд ${idx + 1}: Бейдж` });
    if (slide.sticker) textToCheck.push({ text: String(slide.sticker), slide: idx + 1, field: `Слайд ${idx + 1}: Стикер` });
    if (Array.isArray(slide.bullets)) {
      slide.bullets.forEach((b, bIdx) => textToCheck.push({ text: String(b), slide: idx + 1, field: `Слайд ${idx + 1}: Пункт ${bIdx + 1}` }));
    }
  });
  if (content.seo) textToCheck.push({ text: String(content.seo), slide: 0, field: 'SEO' });

  textToCheck.forEach(({ text, field }) => {
    FORBIDDEN_PATTERNS.forEach(({ re, label, severity }) => {
      if (re.test(text)) {
        const entry = { field, label, snippet: text.substring(0, 60) + (text.length > 60 ? '...' : '') };
        if (severity === 'error') issues.push(entry);
        else warnings.push(entry);
      }
    });
  });

  // Проверки длины
  content.slides.forEach((slide, idx) => {
    if (slide.title && String(slide.title).length > 55) {
      warnings.push({ field: `Слайд ${idx + 1}: Заголовок`, label: 'Длинный заголовок (>55 символов) — может не влезть', snippet: String(slide.title).substring(0, 50) + '...' });
    }
  });

  return { ok: issues.length === 0, issues, warnings, checkedCount: textToCheck.length };
}

// ================== VISION ==================
async function recognizeProductFromImage(apiKey, imageBase64, userHint = '') {
  const visionPrompt = userHint
    ? `Посмотри на фото товара (подсказка: "${userHint.slice(0, 200)}"). Напиши на русском в 1-2 предложениях точное название товара, тип, цвет, материал, видимые детали и назначение для маркетплейса.`
    : `Внимательно посмотри на фото товара. Определи что изображено: напиши на русском точное название, категорию, цвет, материал, форму и ключевые особенности в 1-2 предложениях.`;

  const baseVisionModels = [
    'meta-llama/llama-4-scout-17b-16e-instruct',
    'meta-llama/llama-4-maverick-17b-128e-instruct',
    'llama-3.2-90b-vision-preview',
    'llama-3.2-11b-vision-preview'
  ];

  let visionModels = [...baseVisionModels];
  try {
    const mRes = await fetchWithTimeout('https://api.groq.com/openai/v1/models', { headers: { Authorization: `Bearer ${apiKey}` } }, 8000);
    if (mRes.ok) {
      const mData = await mRes.json();
      const dyn = (mData.data || []).map(m => m.id).filter(id => {
        const low = id.toLowerCase();
        return low.includes('vision') || low.includes('scout') || low.includes('maverick');
      });
      visionModels = [...new Set([...visionModels, ...dyn])];
    }
  } catch {}

  for (const vModel of visionModels) {
    try {
      const vRes = await fetchWithTimeout('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: vModel,
          messages: [{ role: 'user', content: [{ type: 'text', text: visionPrompt }, { type: 'image_url', image_url: { url: imageBase64 } }] }],
          temperature: 0.3,
          max_tokens: 300
        })
      }, 25000);
      if (vRes.ok) {
        const vData = await vRes.json();
        const text = vData.choices?.[0]?.message?.content?.trim();
        if (text && text.length > 5) return text.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
      }
    } catch {}
  }

  try {
    const backupRes = await fetchWithTimeout('https://text.pollinations.ai/openai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'openai',
        messages: [{ role: 'user', content: [{ type: 'text', text: visionPrompt }, { type: 'image_url', image_url: { url: imageBase64 } }] }]
      })
    }, 20000);
    if (backupRes.ok) {
      const bData = await backupRes.json();
      const bText = bData.choices?.[0]?.message?.content?.trim();
      if (bText && bText.length > 5) return bText;
    }
  } catch {}

  return null;
}

async function generateFunnelJSON(apiKey, systemPrompt, product) {
  const priorityModels = ['llama-3.3-70b-versatile', 'openai/gpt-oss-20b', 'openai/gpt-oss-120b'];
  let candidateModels = [...priorityModels];
  try {
    const mRes = await fetchWithTimeout('https://api.groq.com/openai/v1/models', { headers: { Authorization: `Bearer ${apiKey}` } }, 8000);
    if (mRes.ok) {
      const mData = await mRes.json();
      const dyn = (mData.data || []).map(m => m.id).filter(id =>
        !id.includes('whisper') && !id.includes('guard') && !id.includes('tts') &&
        !id.includes('orpheus') && !id.toLowerCase().includes('vision')
      );
      candidateModels = [...new Set([...candidateModels, ...dyn])];
    }
  } catch {}

  let lastError = 'Ошибка ИИ';
  let rawContent = null;

  for (const modelId of candidateModels) {
    try {
      const response = await fetchWithTimeout('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { Authorization: `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: modelId,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: `Товар: ${product}. Сформируй JSON:` }
          ],
          temperature: 0.3,
          max_tokens: 2000
        })
      }, 40000);
      if (!response.ok) {
        const errBody = await response.text().catch(() => '');
        lastError = `Модель ${modelId}: ${response.status} ${errBody.slice(0, 200)}`;
        continue;
      }
      const result = await response.json();
      const content = result.choices?.[0]?.message?.content;
      if (content) { rawContent = content; break; }
    } catch (e) { lastError = `Модель ${modelId}: ${e.message}`; }
  }

  if (!rawContent) throw new Error(lastError);

  const cleaned = rawContent.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```\s*$/i, '').trim();
  try { return JSON.parse(cleaned); }
  catch (e) { throw new Error(`Невалидный JSON от модели: ${e.message}`); }
}

export default async function handler(req, res) {
  const { apiKey, sbUrl, sbServiceKey, secretSalt, allowedOrigins } = getEnvConfig();
  const origin = req.headers.origin || '';

  if (allowedOrigins.length > 0) {
    if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (process.env.NODE_ENV === 'production') console.warn('[generate] ALLOWED_ORIGINS не задан!');
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > LIMITS.MAX_BODY_BYTES) {
      return res.status(413).json({ error: 'Слишком большое тело запроса' });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    let product = clampString(body?.product || '', LIMITS.MAX_PRODUCT_LEN);
    const tone = body?.tone || 'hit';
    const rawImageBase64 = body?.imageBase64 || null;

    let imageBase64 = null;
    if (rawImageBase64) {
      const v = validateImageDataUrl(rawImageBase64);
      if (!v.ok) return res.status(400).json({ error: `Недопустимое изображение: ${v.reason}` });
      imageBase64 = rawImageBase64;
    }

    if (!secretSalt) { console.error('[generate] secretSalt не задан!'); return res.status(500).json({ error: 'Server misconfiguration' }); }
    if (!apiKey) return res.status(500).json({ error: 'GROQ_API_KEY не задан' });

    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Войдите через Яндекс ID!' });

    const userObj = verifySessionToken(token, secretSalt);
    if (!userObj || !userObj.email) return res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Сессия устарела' });

    const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
    const rate = checkRateLimit(`${clientIp}:${userObj.id}`);
    if (!rate.allowed) {
      res.setHeader('Retry-After', String(rate.retryAfter));
      return res.status(429).json({ error: 'RATE_LIMIT', message: `Подождите ${rate.retryAfter}с.` });
    }

    const cookieVault = readCookieVault(req, secretSalt);
    const memRecord = global.usersVault[userObj.id] || cookieVault[userObj.id] || null;
    const sbUser = await getSupabaseUserByEmail(sbUrl, sbServiceKey, userObj.email);
    const appMeta = sbUser?.app_metadata || {};

    let currentCredits = 0, initialized = false;
    if (typeof appMeta.kp_credits === 'number') { currentCredits = appMeta.kp_credits; initialized = true; }
    else if (sbUser?.id) {
      const pc = await getProfileCredits(sbUrl, sbServiceKey, sbUser.id);
      if (pc !== null) { currentCredits = pc; initialized = true; }
    }
    if (!initialized && memRecord && typeof memRecord.credits === 'number') currentCredits = memRecord.credits;

    const bonusBlocked = !!(appMeta.kp_bonus_blocked || memRecord?.bonusBlocked);
    if (!initialized && !bonusBlocked && currentCredits === 0 && userObj.provider !== 'email') currentCredits = 5;

    if (currentCredits <= 0) {
      return res.status(402).json({ error: 'NO_CREDITS', message: 'Генерации закончились. Пополните баланс от 50 ₽!', creditsNotCharged: true });
    }

    let recognizedProduct = null;
    if (imageBase64) {
      recognizedProduct = await recognizeProductFromImage(apiKey, imageBase64, product);
      if (recognizedProduct) {
        recognizedProduct = clampString(recognizedProduct, LIMITS.MAX_RECOGNIZED_LEN);
        product = clampString(product ? `${product} (${recognizedProduct})` : recognizedProduct, LIMITS.MAX_PRODUCT_LEN);
      } else if (!product) {
        return res.status(422).json({ error: 'Не удалось разглядеть товар. Загрузите более чёткое фото.', creditsNotCharged: true });
      }
    }

    if (!product) return res.status(400).json({ error: 'Опишите товар или загрузите фото!', creditsNotCharged: true });

    const toneInstructions = {
      hit: 'Упор на максимальный CTR, яркую выгоду и бестселлер.',
      luxury: 'Упор на премиальность, статус, долговечность.',
      trust: 'Упор на надежность, качество, безопасность и гарантию.',
      gift: 'Упор на идею для подарка, эмоции и богатую комплектацию.'
    };

    const systemPrompt = `Ты топ-маркетолог и арт-директор маркетплейсов Ozon, Wildberries, Яндекс Маркет и Авито.
Задача: ${toneInstructions[tone] || toneInstructions.hit}
КРИТИЧНО: не используй в текстах номера телефонов, email, ссылки на соцсети, слова "скидка/акция/распродажа", "лучший/№1/лидер", медицинские утверждения. Ozon/WB блокируют такие карточки.
Создай продающую воронку из 3 слайдов и верни строго валидный JSON без markdown-обертки:
{
  "title_variants": ["Заголовок 1 (2-3 слова КАПСОМ)", "Заголовок 2", "Заголовок 3"],
  "ai_colors": { "bg1": "#HEX", "bg2": "#HEX", "accent": "#HEX", "badge": "#HEX" },
  "slides": [
    { "title": "ЗАГОЛОВОК", "subtitle": "УТП до 5 слов", "badge": "ХИТ ПРОДАЖ", "sticker": "ГАРАНТИЯ 1 ГОД", "bullets": ["Выгода 1", "Выгода 2", "Выгода 3"] },
    { "title": "ХАРАКТЕРИСТИКИ", "subtitle": "Надежные материалы", "badge": "ПАРАМЕТРЫ", "sticker": "ПРЕМИУМ", "bullets": ["Материал: ...", "Мощность: ...", "Особенность: ...", "Вес: ..."] },
    { "title": "КОМПЛЕКТАЦИЯ", "subtitle": "Полный набор", "badge": "ЧТО В КОРОБКЕ", "sticker": "ПОДАРОК", "bullets": ["1. Товар", "2. Кабель", "3. Инструкция", "4. Коробка"] }
  ],
  "dimensions": { "width": "18 см", "height": "24 см" },
  "bg_prompt": "English prompt for studio background, empty center podium, 8k",
  "seo": "SEO-описание на 500-700 символов с ключевыми запросами."
}`;

    let content;
    try { content = await generateFunnelJSON(apiKey, systemPrompt, product); }
    catch (e) { return res.status(500).json({ error: e.message, creditsNotCharged: true }); }

    // 🔴 ВАЛИДАЦИЯ — до списания кредита
    const validation = validateCardContent(content);

    // Кредит списывается ТОЛЬКО после успешной валидации структуры
    const nextCredits = Math.max(0, currentCredits - 1);
    const updatedRecord = {
      ...(memRecord || {}),
      id: sbUser?.id || userObj.id, email: userObj.email, name: userObj.name,
      provider: userObj.provider || 'yandex', credits: nextCredits, hasSpent: true, bonusBlocked,
      usedLabels: Array.isArray(memRecord?.usedLabels) ? memRecord.usedLabels : []
    };
    global.usersVault[updatedRecord.id] = updatedRecord;

    if (sbUser?.id) {
      await saveSupabaseCredits(sbUrl, sbServiceKey, sbUser.id, nextCredits, {
        bonusBlocked, passHash: appMeta.kp_pass_hash || null,
        usedLabels: Array.isArray(appMeta.kp_used_labels) ? appMeta.kp_used_labels : []
      });
    }

    if (recognizedProduct) content.recognized_product = recognizedProduct;
    content.remaining_credits = nextCredits;
    content.session_token = createSessionToken(updatedRecord, secretSalt);
    content.validation = validation;

    console.log(`[generate] OK ${userObj.email} ${currentCredits}->${nextCredits} issues=${validation.issues.length} warnings=${validation.warnings.length}`);
    return res.status(200).json(content);
  } catch (err) {
    console.error('[generate] error:', err.message);
    return res.status(500).json({ error: err.message || 'Внутренняя ошибка', creditsNotCharged: true });
  }
}
