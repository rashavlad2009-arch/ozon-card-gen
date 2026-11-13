import crypto from 'crypto';

const FALLBACK_SUPABASE_URL = 'https://irxszktfwtravyeqnueh.supabase.co';

const LIMITS = {
  MAX_PRODUCT_LEN: 2000,
  MAX_RECOGNIZED_LEN: 300,
  MAX_IMAGE_BYTES: 3 * 1024 * 1024,
  MAX_IMAGE_B64_LEN: Math.ceil(3 * 1024 * 1024 * 4 / 3) + 100,
  MAX_BODY_BYTES: 4 * 1024 * 1024,
  SESSION_TTL_MS: 30 * 24 * 60 * 60 * 1000,
  FETCH_TIMEOUT_MS: 25000,
  RATE_WINDOW_MS: 60 * 1000,
  RATE_MAX_HITS: 20,
  DB_TIMEOUT_MS: 20000,
  DB_RETRIES: 3
};
const ALLOWED_IMAGE_MIMES = new Set(['image/jpeg', 'image/png', 'image/webp']);
const BONUS_CREDITS = 5;

global.usersVault = global.usersVault || {};
global.rateBuckets = global.rateBuckets || new Map();

function findEnvVar(suffixes) {
  for (const s of suffixes) if (process.env[s]) return process.env[s].trim();
  const allKeys = Object.keys(process.env);
  for (const s of suffixes) {
    const m = allKeys.find(k => k.endsWith(s) && process.env[k]);
    if (m) return process.env[m].trim();
  }
  return '';
}

function normalizeSupabaseUrl(raw) {
  let url = String(raw || '').trim().replace(/\/$/, '');
  if (!url) return '';
  if (!url.startsWith('http://') && !url.startsWith('https://')) {
    if (/^[a-z0-9]{15,40}$/i.test(url)) return `https://${url}.supabase.co`;
    return url;
  }
  return url.replace(/^http:\/\//, 'https://');
}

function getEnvConfig() {
  const groqKey = findEnvVar(['GROQ_API_KEY']);
  const openRouterKey = findEnvVar(['OPENROUTER_API_KEY']);
  const sbUrl = normalizeSupabaseUrl(findEnvVar(['SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL']) || FALLBACK_SUPABASE_URL);
  const sbServiceKey = (findEnvVar(['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SECRET_KEY']) || '').trim();
  const secretSalt = (findEnvVar(['KARDPRO_SESSION_SALT', 'SESSION_SECRET']) || sbServiceKey).trim();
  const allowedOrigins = (findEnvVar(['ALLOWED_ORIGINS']) || '').split(',').map(s => s.trim()).filter(Boolean);
  return { groqKey, openRouterKey, sbUrl, sbServiceKey, secretSalt, allowedOrigins };
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bA = Buffer.from(a, 'utf8'), bB = Buffer.from(b, 'utf8');
  if (bA.length !== bB.length) return false;
  try { return crypto.timingSafeEqual(bA, bB); } catch { return false; }
}

function verifySessionToken(token, salt) {
  if (!token || typeof token !== 'string' || !token.startsWith('kp.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payload, sig] = parts;
  const expected = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  if (!safeEqual(sig, expected)) return null;
  try {
    const d = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
    if (typeof d.ts !== 'number') return null;
    if (Date.now() - d.ts > LIMITS.SESSION_TTL_MS) return null;
    if (!d.id || !d.email) return null;
    return d;
  } catch { return null; }
}

function createSessionToken(u, salt) {
  if (!salt) throw new Error('secretSalt не задан');
  const payload = Buffer.from(JSON.stringify({ id: u.id, email: u.email, name: u.name, provider: u.provider || 'yandex', credits: typeof u.credits === 'number' ? u.credits : 0, ts: Date.now() })).toString('base64url');
  const sig = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  return `kp.${payload}.${sig}`;
}

function readCookieVault(req, salt) {
  try {
    const ch = req.headers.cookie || '';
    const match = ch.split(';').map(c => c.trim()).find(c => c.startsWith('kp_vault='));
    if (!match) return {};
    const raw = decodeURIComponent(match.substring('kp_vault='.length));
    const [b64, sig] = raw.split('.');
    if (!b64 || !sig) return {};
    const expected = crypto.createHmac('sha256', salt).update(b64).digest('base64url');
    if (!safeEqual(sig, expected)) return {};
    return JSON.parse(Buffer.from(b64, 'base64url').toString('utf-8')) || {};
  } catch { return {}; }
}

async function fetchWithRetry(url, opts = {}, timeoutMs = LIMITS.DB_TIMEOUT_MS, retries = LIMITS.DB_RETRIES) {
  for (let i = 0; i < retries; i++) {
    try {
      const ctrl = new AbortController();
      const timer = setTimeout(() => ctrl.abort(), timeoutMs);
      const res = await fetch(url, { ...opts, signal: ctrl.signal });
      clearTimeout(timer);
      return res;
    } catch (err) {
      if (i === retries - 1) throw err;
      await new Promise(r => setTimeout(r, 1000 * (i + 1)));
    }
  }
}

async function fetchWithTimeout(url, opts = {}, timeoutMs = LIMITS.FETCH_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
}

function checkRateLimit(key) {
  const now = Date.now();
  const b = global.rateBuckets.get(key);
  if (!b || now - b.start > LIMITS.RATE_WINDOW_MS) {
    global.rateBuckets.set(key, { start: now, hits: 1 });
    if (global.rateBuckets.size > 5000) {
      for (const [k, v] of global.rateBuckets) if (now - v.start > LIMITS.RATE_WINDOW_MS) global.rateBuckets.delete(k);
    }
    return { allowed: true };
  }
  if (b.hits >= LIMITS.RATE_MAX_HITS) return { allowed: false, retryAfter: Math.ceil((b.start + LIMITS.RATE_WINDOW_MS - now) / 1000) };
  b.hits++;
  return { allowed: true };
}

function emailToDeterministicUUID(email) {
  const hex = crypto.createHash('sha256').update(`user_${String(email).toLowerCase()}`).digest('hex').substring(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

async function getSupabaseUserByEmail(sbUrl, sbServiceKey, email) {
  if (!sbUrl || !sbServiceKey || !email) return null;
  try {
    const res = await fetchWithRetry(`${sbUrl}/auth/v1/admin/users?email=eq.${encodeURIComponent(email)}&per_page=1`, { headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}` } });
    if (!res.ok) return null;
    const data = await res.json();
    const users = data.users || data || [];
    return Array.isArray(users) ? users.find(u => (u.email || '').toLowerCase() === email.toLowerCase()) || null : null;
  } catch { return null; }
}

async function readProfile(sbUrl, sbServiceKey, userId) {
  if (!sbUrl || !sbServiceKey || !userId) return null;
  try {
    const res = await fetchWithRetry(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=credits,bonus_granted`, { headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}` } });
    if (!res.ok) return null;
    const list = await res.json();
    if (Array.isArray(list) && list.length > 0) return { credits: typeof list[0].credits === 'number' ? list[0].credits : 0, bonusGranted: !!list[0].bonus_granted };
    return null;
  } catch { return null; }
}

async function upsertProfile(sbUrl, sbServiceKey, userId, email, credits, bonusGranted) {
  if (!sbUrl || !sbServiceKey || !userId) return { ok: false };
  try {
    const res = await fetchWithRetry(`${sbUrl}/rest/v1/profiles`, {
      method: 'POST', headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}`, 'Content-Type': 'application/json', 'Prefer': 'resolution=merge-duplicates,return=minimal' },
      body: JSON.stringify({ id: userId, email, credits, bonus_granted: !!bonusGranted })
    });
    return { ok: res.ok };
  } catch (e) { return { ok: false, error: e.message }; }
}

async function patchProfileCredits(sbUrl, sbServiceKey, userId, newCredits) {
  if (!sbUrl || !sbServiceKey || !userId) return { ok: false };
  try {
    const res = await fetchWithRetry(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}`, {
      method: 'PATCH', headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}`, 'Content-Type': 'application/json', 'Prefer': 'return=minimal' },
      body: JSON.stringify({ credits: newCredits })
    });
    return { ok: res.ok };
  } catch (e) { return { ok: false, error: e.message }; }
}

async function updateAppMetadata(sbUrl, sbServiceKey, sbUserId, patch) {
  if (!sbUrl || !sbServiceKey || !sbUserId) return;
  try {
    await fetchWithRetry(`${sbUrl}/auth/v1/admin/users/${sbUserId}`, { method: 'PUT', headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}`, 'Content-Type': 'application/json' }, body: JSON.stringify({ app_metadata: patch }) });
  } catch (e) { /* ignore */ }
}

function validateImageDataUrl(imageBase64) {
  if (!imageBase64 || typeof imageBase64 !== 'string') return { ok: false, reason: 'not_a_string' };
  if (imageBase64.length > LIMITS.MAX_IMAGE_B64_LEN) return { ok: false, reason: 'too_large' };
  const match = imageBase64.match(/^data:(image\/[a-z+]+);base64,/i);
  if (!match) return { ok: false, reason: 'bad_format' };
  if (!ALLOWED_IMAGE_MIMES.has(match[1].toLowerCase())) return { ok: false, reason: 'bad_mime' };
  if (Math.floor((imageBase64.split(',')[1] || '').length * 0.75) > LIMITS.MAX_IMAGE_BYTES) return { ok: false, reason: 'too_large' };
  return { ok: true };
}

function clampString(s, max) { return typeof s !== 'string' ? '' : s.trim().length > max ? s.trim().slice(0, max) : s.trim(); }

function validateCardContent(content) {
  const issues = [], warnings = [];
  if (!content || !Array.isArray(content.slides)) return { ok: false, issues: [{ field: 'структура', label: 'Отсутствует slides', snippet: '' }], warnings: [], checkedCount: 0 };
  const FORBIDDEN = [
    { re: /\b(?:8[\s\-]?\(?9\d{2}\)?[\s\-]?\d{3}[\s\-]?\d{2}[\s\-]?\d{2})\b/i, label: 'номер телефона', severity: 'error' },
    { re: /\b[A-Z0-9._%+-]+@[A-Z0-9.-]+\.[A-Z]{2,}\b/i, label: 'email', severity: 'error' },
    { re: /\b(?:vk\.com|instagram|t\.me|wa\.me|whatsapp|telegram)\b/i, label: 'ссылка на соцсеть', severity: 'error' },
    { re: /\b(?:qr[\s\-]?код|qr[\s\-]?code)\b/i, label: 'QR-код', severity: 'warning' },
    { re: /(?:скидк[аи]|акция|распродажа|только сегодня|черная пятница|black friday)/i, label: 'акция/скидка', severity: 'warning' },
    { re: /\b(?:самый лучший|лучший в мире|№\s*1|номер\s*1|лидер рынка|100%\s*качество)\b/i, label: 'недоказуемое превосходство', severity: 'warning' },
    { re: /(?:лечит|исцеляет|избавляет от болезней|медицинск)/i, label: 'медицинские утверждения', severity: 'error' }
  ];
  const texts = [];
  content.slides.forEach((sl, idx) => {
    if (sl.title) texts.push({ text: String(sl.title), field: `Слайд ${idx + 1}: Заголовок` });
    if (sl.subtitle) texts.push({ text: String(sl.subtitle), field: `Слайд ${idx + 1}: Подзаголовок` });
    if (sl.badge) texts.push({ text: String(sl.badge), field: `Слайд ${idx + 1}: Бейдж` });
    if (sl.sticker) texts.push({ text: String(sl.sticker), field: `Слайд ${idx + 1}: Стикер` });
    if (Array.isArray(sl.bullets)) sl.bullets.forEach((b, i) => texts.push({ text: String(b), field: `Слайд ${idx + 1}: Пункт ${i + 1}` }));
  });
  if (content.seo) texts.push({ text: String(content.seo), field: 'SEO' });
  texts.forEach(({ text, field }) => {
    FORBIDDEN.forEach(({ re, label, severity }) => {
      if (re.test(text)) {
        const e = { field, label, snippet: text.substring(0, 60) + (text.length > 60 ? '...' : '') };
        if (severity === 'error') issues.push(e); else warnings.push(e);
      }
    });
  });
  content.slides.forEach((sl, idx) => {
    if (sl.title && String(sl.title).length > 55) warnings.push({ field: `Слайд ${idx + 1}: Заголовок`, label: 'Длинный заголовок (>55)', snippet: String(sl.title).substring(0, 50) + '...' });
  });
  return { ok: issues.length === 0, issues, warnings, checkedCount: texts.length };
}

async function recognizeProductFromImage(groqKey, openRouterKey, imageBase64, userHint = '') {
  const visionPrompt = userHint ? `Посмотри на фото (подсказка: "${userHint.slice(0, 200)}"). Напиши на русском в 1-2 предложениях точное название, тип, цвет, материал, детали и назначение.` : `Внимательно посмотри на фото. Напиши на русском точное название, категорию, цвет, материал, форму и особенности в 1-2 предложениях.`;

  if (groqKey) {
    const groqModels = ['meta-llama/llama-4-scout-17b-16e-instruct', 'llama-3.2-90b-vision-preview', 'llama-3.2-11b-vision-preview'];
    for (const vModel of groqModels) {
      try {
        const vRes = await fetchWithTimeout('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST', headers: { Authorization: `Bearer ${groqKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model: vModel, messages: [{ role: 'user', content: [{ type: 'text', text: visionPrompt }, { type: 'image_url', image_url: { url: imageBase64 } }] }], temperature: 0.3, max_tokens: 300 })
        }, 25000);
        if (vRes.ok) {
          const d = await vRes.json();
          const t = d.choices?.[0]?.message?.content?.trim();
          if (t && t.length > 5) return t.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
        }
      } catch {}
    }
  }

  if (openRouterKey) {
    const orModels = ['google/gemini-2.0-flash-exp:free', 'qwen/qwen-2-vl-72b-instruct'];
    for (const model of orModels) {
      try {
        const vRes = await fetchWithTimeout('https://openrouter.ai/api/v1/chat/completions', {
          method: 'POST', headers: { 'Authorization': `Bearer ${openRouterKey}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://kard-pro.ru', 'X-Title': 'KARD-PRO' },
          body: JSON.stringify({ model, messages: [{ role: 'user', content: [{ type: 'text', text: visionPrompt }, { type: 'image_url', image_url: { url: imageBase64 } }] }], temperature: 0.3, max_tokens: 300 })
        }, 25000);
        if (vRes.ok) {
          const d = await vRes.json();
          const t = d.choices?.[0]?.message?.content?.trim();
          if (t && t.length > 5) return t.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
        }
      } catch {}
    }
  }

  try {
    const b = await fetchWithTimeout('https://text.pollinations.ai/openai', {
      method: 'POST', headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ model: 'openai', messages: [{ role: 'user', content: [{ type: 'text', text: visionPrompt }, { type: 'image_url', image_url: { url: imageBase64 } }] }] })
    }, 20000);
    if (b.ok) {
      const d = await b.json();
      const t = d.choices?.[0]?.message?.content?.trim();
      if (t && t.length > 5) return t;
    }
  } catch {}
  return null;
}

async function generateFunnelJSON(groqKey, openRouterKey, systemPrompt, product) {
  const groqModels = ['llama-3.3-70b-versatile', 'openai/gpt-oss-20b', 'openai/gpt-oss-120b'];
  const openRouterModels = ['meta-llama/llama-3.3-70b-instruct:free', 'google/gemini-2.0-flash-exp:free', 'deepseek/deepseek-r1:free'];
  let lastError = 'Все провайдеры недоступны', rawContent = null;

  if (groqKey) {
    for (const model of groqModels) {
      try {
        const res = await fetchWithTimeout('https://api.groq.com/openai/v1/chat/completions', {
          method: 'POST', headers: { Authorization: `Bearer ${groqKey}`, 'Content-Type': 'application/json' },
          body: JSON.stringify({ model, response_format: { type: 'json_object' }, messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: `Товар: ${product}. Сформируй JSON:` }], temperature: 0.3, max_tokens: 2000 })
        }, 40000);
        if (res.ok) {
          const d = await res.json();
          rawContent = d.choices?.[0]?.message?.content;
          if (rawContent) break;
        }
      } catch (e) { lastError = `Groq ${model}: ${e.message}`; }
    }
  }

  if (!rawContent && openRouterKey) {
    for (const model of openRouterModels) {
      try {
        const res = await fetchWithTimeout('https://openrouter.ai/api/v1/chat/completions', {
          method: 'POST', headers: { 'Authorization': `Bearer ${openRouterKey}`, 'Content-Type': 'application/json', 'HTTP-Referer': 'https://kard-pro.ru', 'X-Title': 'KARD-PRO' },
          body: JSON.stringify({ model, response_format: { type: 'json_object' }, messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: `Товар: ${product}. Сформируй JSON:` }], temperature: 0.3, max_tokens: 2000 })
        }, 40000);
        if (res.ok) {
          const d = await res.json();
          rawContent = d.choices?.[0]?.message?.content;
          if (rawContent) break;
        }
      } catch (e) { lastError = `OpenRouter ${model}: ${e.message}`; }
    }
  }

  if (!rawContent) {
    try {
      const res = await fetchWithTimeout('https://text.pollinations.ai/openai', {
        method: 'POST', headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ model: 'openai', response_format: { type: 'json_object' }, messages: [{ role: 'system', content: systemPrompt }, { role: 'user', content: `Товар: ${product}. Сформируй JSON:` }], temperature: 0.3, max_tokens: 2000 })
      }, 40000);
      if (res.ok) { const d = await res.json(); rawContent = d.choices?.[0]?.message?.content; }
    } catch (e) { lastError = `Pollinations: ${e.message}`; }
  }

  if (!rawContent) throw new Error(lastError);
  const cleaned = rawContent.replace(/^```json\s*/i, '').replace(/^```\s*/i, '').replace(/```\s*$/i, '').trim();
  try { return JSON.parse(cleaned); } catch (e) { throw new Error(`Невалидный JSON: ${e.message}`); }
}

export default async function handler(req, res) {
  const { groqKey, openRouterKey, sbUrl, sbServiceKey, secretSalt, allowedOrigins } = getEnvConfig();
  const origin = req.headers.origin || '';
  
  if (allowedOrigins.length > 0) {
    if (allowedOrigins.includes(origin)) { res.setHeader('Access-Control-Allow-Origin', origin); res.setHeader('Vary', 'Origin'); }
  } else { res.setHeader('Access-Control-Allow-Origin', '*'); }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    if (parseInt(req.headers['content-length'] || '0', 10) > LIMITS.MAX_BODY_BYTES) return res.status(413).json({ error: 'Слишком большое тело' });
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

    if (!secretSalt) return res.status(500).json({ error: 'KARDPRO_SESSION_SALT не задан' });
    if (!groqKey && !openRouterKey) return res.status(500).json({ error: 'Нужен хотя бы один ключ ИИ' });
    if (!sbUrl || !sbServiceKey) return res.status(500).json({ error: 'Supabase не настроен' });

    const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
    if (!token) return res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Войдите через Яндекс ID!' });

    const userObj = verifySessionToken(token, secretSalt);
    if (!userObj || !userObj.email) return res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Сессия устарела' });

    const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
    const rate = checkRateLimit(`${clientIp}:${userObj.id}`);
    if (!rate.allowed) { res.setHeader('Retry-After', String(rate.retryAfter)); return res.status(429).json({ error: 'RATE_LIMIT', message: `Подождите ${rate.retryAfter}с.` }); }

    const sbUser = await getSupabaseUserByEmail(sbUrl, sbServiceKey, userObj.email);
    const appMeta = sbUser?.app_metadata || {};
    const userId = emailToDeterministicUUID(userObj.email);

    const profile = await readProfile(sbUrl, sbServiceKey, userId);
    let currentCredits = 0, bonusGranted = false;

    if (profile === null) {
      const isOAuth = userObj.provider !== 'email';
      if (isOAuth && !appMeta.kp_has_spent) { currentCredits = BONUS_CREDITS; bonusGranted = true; }
      else { currentCredits = 0; bonusGranted = isOAuth; }
      const created = await upsertProfile(sbUrl, sbServiceKey, userId, userObj.email, currentCredits, bonusGranted);
      if (!created.ok) return res.status(500).json({ error: 'Ошибка создания профиля', creditsNotCharged: true });
    } else {
      currentCredits = profile.credits;
      bonusGranted = profile.bonusGranted;
    }

    if (currentCredits <= 0) return res.status(402).json({ error: 'NO_CREDITS', message: 'Пополните баланс от 50 ₽!', creditsNotCharged: true });

    let recognizedProduct = null;
    if (imageBase64) {
      recognizedProduct = await recognizeProductFromImage(groqKey, openRouterKey, imageBase64, product);
      if (recognizedProduct) {
        recognizedProduct = clampString(recognizedProduct, LIMITS.MAX_RECOGNIZED_LEN);
        product = clampString(product ? `${product} (${recognizedProduct})` : recognizedProduct, LIMITS.MAX_PRODUCT_LEN);
      } else if (!product) {
        return res.status(422).json({ error: 'ИИ не смог распознать товар. Напишите пару слов в поле "Опишите товар" или загрузите фото на белом фоне.', creditsNotCharged: true });
      }
    }

    if (!product) return res.status(400).json({ error: 'Опишите товар или загрузите фото!', creditsNotCharged: true });

    const systemPrompt = `Ты топ-маркетолог. Задача: ${tone === 'luxury' ? 'Премиум' : tone === 'trust' ? 'Надежность' : tone === 'gift' ? 'Подарок' : 'Хит продаж'}. КРИТИЧНО: без телефонов, email, ссылок, слов "скидка", "акция", "лучший", "№1". Верни СТРОГО валидный JSON без markdown: {"title_variants":["Заголовок 1","Заголовок 2","Заголовок 3"],"ai_colors":{"bg1":"#HEX","bg2":"#HEX","accent":"#HEX","badge":"#HEX"},"slides":[{"title":"ЗАГОЛОВОК","subtitle":"УТП","badge":"ХИТ ПРОДАЖ","sticker":"ГАРАНТИЯ 1 ГОД","bullets":["Выгода 1","Выгода 2","Выгода 3"]},{"title":"ХАРАКТЕРИСТИКИ","subtitle":"Надежные материалы","badge":"ПАРАМЕТРЫ","sticker":"ПРЕМИУМ","bullets":["Материал: ...","Мощность: ...","Особенность: ...","Вес: ..."]},{"title":"КОМПЛЕКТАЦИЯ","subtitle":"Полный набор","badge":"ЧТО В КОРОБКЕ","sticker":"ПОДАРОК","bullets":["1. Товар","2. Кабель","3. Инструкция","4. Коробка"]}],"dimensions":{"width":"18 см","height":"24 см"},"bg_prompt":"English studio prompt, empty center podium, 8k","seo":"SEO-описание 500-700 символов."}`;

    let content;
    try { content = await generateFunnelJSON(groqKey, openRouterKey, systemPrompt, product); }
    catch (e) { return res.status(500).json({ error: e.message, creditsNotCharged: true }); }

    const validation = validateCardContent(content);
    const nextCredits = Math.max(0, currentCredits - 1);
    const saved = await patchProfileCredits(sbUrl, sbServiceKey, userId, nextCredits);
    if (!saved.ok) return res.status(500).json({ error: 'Ошибка сохранения в БД', creditsNotCharged: true });

    if (sbUser?.id) updateAppMetadata(sbUrl, sbServiceKey, sbUser.id, { ...appMeta, kp_initialized: true, kp_has_spent: true }).catch(() => {});

    const updatedRecord = { id: userId, email: userObj.email, name: userObj.name, provider: userObj.provider || 'yandex', credits: nextCredits, hasSpent: true, bonusGranted };
    global.usersVault[userId] = updatedRecord;

    if (recognizedProduct) content.recognized_product = recognizedProduct;
    content.remaining_credits = nextCredits;
    content.session_token = createSessionToken(updatedRecord, secretSalt);
    content.validation = validation;

    return res.status(200).json(content);
  } catch (err) { return res.status(500).json({ error: err.message || 'Внутренняя ошибка', creditsNotCharged: true }); }
}
