import crypto from 'crypto';

// =========================================================================
// КОНСТАНТЫ И КОНФИГ
// =========================================================================
const FALLBACK_SUPABASE_URL = 'https://irxszktfwtravyeqnueh.supabase.co';

const LIMITS = {
  MAX_PRODUCT_LEN: 2000,
  MAX_RECOGNIZED_LEN: 300,
  MAX_IMAGE_BYTES: 3 * 1024 * 1024,       // 3 MB — запас под 4.5MB Vercel limit
  MAX_IMAGE_B64_LEN: 4.2 * 1024 * 1024,    // ~3MB base64
  MAX_BODY_BYTES: 4 * 1024 * 1024,
  MAX_COOKIE_VAULT_BYTES: 3000,
  SESSION_TTL_MS: 30 * 24 * 60 * 60 * 1000, // 30 дней
  FETCH_TIMEOUT_MS: 25000,
  RATE_LIMIT_WINDOW_MS: 60 * 1000,
  RATE_LIMIT_MAX_HITS: 20,                 // 20 генераций/мин на IP (in-memory)
  FREE_CREDITS_ON_FIRST_LOGIN: 5
};

const ALLOWED_IMAGE_MIMES = new Set(['image/jpeg', 'image/png', 'image/webp']);

// Глобальный in-memory кэш (теряется при cold start — fallback на Supabase)
global.usersVault = global.usersVault || {};
// In-memory rate limit (только per-instance, для реальной защиты нужен Redis)
global.rateBuckets = global.rateBuckets || new Map();

// =========================================================================
// ENV
// =========================================================================
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
  // 🔴 КРИТИЧНО: без явной соли сессии нельзя подписывать — иначе дефолтный salt = публичный секрет
  const secretSalt = findEnvVar(['KARDPRO_SESSION_SALT', 'SESSION_SECRET']) || sbServiceKey || apiKey;
  const allowedOrigins = (findEnvVar(['ALLOWED_ORIGINS']) || '').split(',').map(s => s.trim()).filter(Boolean);
  return { apiKey, sbUrl, sbServiceKey, secretSalt, allowedOrigins };
}

// =========================================================================
// БЕЗОПАСНОЕ СРАВНЕНИЕ (защита от timing attack)
// =========================================================================
function safeEqualStr(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a);
  const bufB = Buffer.from(b);
  if (bufA.length !== bufB.length) return false;
  try {
    return crypto.timingSafeEqual(bufA, bufB);
  } catch {
    return false;
  }
}

// =========================================================================
// СЕССИОННЫЕ ТОКЕНЫ
// =========================================================================
function createSessionToken(userObj, salt) {
  if (!salt) throw new Error('secretSalt не задан');
  const payload = Buffer.from(JSON.stringify({
    id: userObj.id,
    email: userObj.email,
    name: userObj.name,
    provider: userObj.provider || 'yandex',
    credits: typeof userObj.credits === 'number' ? userObj.credits : 0,
    ts: Date.now()
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  return `kp.${payload}.${sig}`;
}

function verifySessionToken(token, salt) {
  if (!token || typeof token !== 'string' || !token.startsWith('kp.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payload, sig] = parts;
  const expected = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  // 🔴 КРИТИЧНО: timingSafeEqual вместо !==
  if (!safeEqualStr(sig, expected)) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
    // 🔴 Проверка срока жизни токена
    if (typeof decoded.ts !== 'number') return null;
    if (Date.now() - decoded.ts > LIMITS.SESSION_TTL_MS) return null;
    if (decoded.ts - Date.now() > 5 * 60 * 1000) return null; // токен из будущего (clock skew)
    return decoded;
  } catch {
    return null;
  }
}

// =========================================================================
// COOKIE VAULT
// =========================================================================
function readCookieVault(req, salt) {
  try {
    const cookieHeader = req.headers.cookie || '';
    const match = cookieHeader.split(';').map(c => c.trim()).find(c => c.startsWith('kp_vault='));
    if (!match) return {};
    const raw = decodeURIComponent(match.substring('kp_vault='.length));
    const [b64, sig] = raw.split('.');
    if (!b64 || !sig) return {};
    const expected = crypto.createHmac('sha256', salt).update(b64).digest('base64url');
    // 🔴 timingSafeEqual
    if (!safeEqualStr(sig, expected)) return {};
    return JSON.parse(Buffer.from(b64, 'base64url').toString('utf-8')) || {};
  } catch {
    return {};
  }
}

function writeCookieVault(res, vaultObj, salt) {
  try {
    // 🔴 Ограничение размера: cookie max 4KB. Храним только текущего пользователя,
    //    остальных в cookie не тащим — они и так в Supabase.
    let payloadToStore = vaultObj;
    let b64 = Buffer.from(JSON.stringify(payloadToStore)).toString('base64url');
    if (b64.length > LIMITS.MAX_COOKIE_VAULT_BYTES) {
      // fallback: храним только "последнего" юзера из vault
      const entries = Object.entries(vaultObj);
      if (entries.length > 0) {
        const [lastKey, lastVal] = entries[entries.length - 1];
        payloadToStore = { [lastKey]: lastVal };
        b64 = Buffer.from(JSON.stringify(payloadToStore)).toString('base64url');
      }
    }
    if (b64.length > LIMITS.MAX_COOKIE_VAULT_BYTES) return; // не влезает — не пишем

    const sig = crypto.createHmac('sha256', salt).update(b64).digest('base64url');
    const val = encodeURIComponent(`${b64}.${sig}`);
    // 🔴 Secure флаг при HTTPS
    const isHttps = (process.env.VERCEL || process.env.NODE_ENV === 'production');
    const secureFlag = isHttps ? ' Secure;' : '';
    res.setHeader('Set-Cookie', `kp_vault=${val}; Path=/; Max-Age=31536000; HttpOnly;${secureFlag} SameSite=Lax`);
  } catch {}
}

// =========================================================================
// SUPABASE ADMIN API
// =========================================================================
// 🔴 findEnvVar: generate_link — это workaround (создаёт user + возвращает объект).
//    Правильный способ — GET /auth/v1/admin/users?email=eq.X, но он работает не на всех версиях.
//    Оставляем generate_link как primary, но с ограничением: он тратит вызовы API.
async function getCloudUserByEmail(sbUrl, sbServiceKey, email) {
  if (!sbUrl || !sbServiceKey || !email) return null;

  // Попытка 1: список с фильтром по email (Supabase Admin API поддерживает filter)
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    const listRes = await fetch(
      `${sbUrl}/auth/v1/admin/users?email=eq.${encodeURIComponent(email)}&per_page=1`,
      {
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`
        },
        signal: ctrl.signal
      }
    );
    clearTimeout(t);
    if (listRes.ok) {
      const listData = await listRes.json();
      const users = listData.users || listData || [];
      if (Array.isArray(users) && users.length > 0) {
        // точное совпадение по email (на случай если фильтр проигнорирован)
        const exact = users.find(u => (u.email || '').toLowerCase() === email.toLowerCase());
        if (exact) return exact;
      }
    }
  } catch {}

  // Попытка 2 (fallback): generate_link — создаст/вернёт пользователя без отправки письма
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    const linkRes = await fetch(`${sbUrl}/auth/v1/admin/generate_link`, {
      method: 'POST',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ type: 'magiclink', email }),
      signal: ctrl.signal
    });
    clearTimeout(t);
    if (!linkRes.ok) return null;
    const data = await linkRes.json();
    return data?.user || (data?.id ? data : null);
  } catch {
    return null;
  }
}

async function saveCloudUserCredits(sbUrl, sbServiceKey, sbUserId, email, oldMeta, nextCredits, hasSpent, bonusBlocked) {
  if (!sbUrl || !sbServiceKey || !sbUserId) return;
  // 🔴 user_metadata — публичное поле (клиент может его читать/менять).
  //    Кредиты должны жить в app_metadata (только service_role) или в profiles.
  //    Здесь обновляем оба: app_metadata (безопасно) + profiles (для UI).
  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    await fetch(`${sbUrl}/auth/v1/admin/users/${sbUserId}`, {
      method: 'PUT',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({
        app_metadata: {
          ...((oldMeta && oldMeta.__app) || {}),
          kp_initialized: true,
          kp_credits: nextCredits,
          kp_has_spent: !!hasSpent,
          kp_bonus_blocked: !!bonusBlocked
        },
        user_metadata: {
          ...oldMeta,
          kp_initialized: true,
          credits: nextCredits,
          has_spent: !!hasSpent,
          bonus_blocked: !!bonusBlocked
        }
      }),
      signal: ctrl.signal
    });
    clearTimeout(t);
  } catch (e) {
    console.error('[generate] Supabase auth PUT failed:', e.message);
  }

  try {
    const ctrl = new AbortController();
    const t = setTimeout(() => ctrl.abort(), 8000);
    await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(sbUserId)}`, {
      method: 'PATCH',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json',
        'Prefer': 'return=minimal'
      },
      body: JSON.stringify({ credits: nextCredits }),
      signal: ctrl.signal
    });
    clearTimeout(t);
  } catch (e) {
    console.error('[generate] Supabase profiles PATCH failed:', e.message);
  }
}

// =========================================================================
// ВАЛИДАЦИЯ ВХОДНЫХ ДАННЫХ
// =========================================================================
function validateImageDataUrl(imageBase64) {
  if (!imageBase64 || typeof imageBase64 !== 'string') return { ok: false, reason: 'not_a_string' };
  if (imageBase64.length > LIMITS.MAX_IMAGE_B64_LEN) return { ok: false, reason: 'too_large' };
  const match = imageBase64.match(/^data:(image\/[a-z+]+);base64,/i);
  if (!match) return { ok: false, reason: 'bad_format' };
  const mime = match[1].toLowerCase();
  if (!ALLOWED_IMAGE_MIMES.has(mime)) return { ok: false, reason: 'bad_mime' };
  // Грубая оценка размера base64 → bytes
  const b64 = imageBase64.split(',')[1] || '';
  const estimatedBytes = Math.floor(b64.length * 0.75);
  if (estimatedBytes > LIMITS.MAX_IMAGE_BYTES) return { ok: false, reason: 'too_large' };
  return { ok: true };
}

function clampString(s, max) {
  if (typeof s !== 'string') return '';
  const trimmed = s.trim();
  return trimmed.length > max ? trimmed.slice(0, max) : trimmed;
}

// =========================================================================
// RATE LIMIT (in-memory per-instance; для multi-instance нужен Redis)
// =========================================================================
function checkRateLimit(key) {
  const now = Date.now();
  const bucket = global.rateBuckets.get(key);
  if (!bucket || now - bucket.start > LIMITS.RATE_LIMIT_WINDOW_MS) {
    global.rateBuckets.set(key, { start: now, hits: 1 });
    // lazy cleanup
    if (global.rateBuckets.size > 5000) {
      for (const [k, v] of global.rateBuckets) {
        if (now - v.start > LIMITS.RATE_LIMIT_WINDOW_MS) global.rateBuckets.delete(k);
      }
    }
    return { allowed: true };
  }
  if (bucket.hits >= LIMITS.RATE_LIMIT_MAX_HITS) {
    return { allowed: false, retryAfter: Math.ceil((bucket.start + LIMITS.RATE_LIMIT_WINDOW_MS - now) / 1000) };
  }
  bucket.hits++;
  return { allowed: true };
}

// =========================================================================
// FETCH С ТАЙМАУТОМ
// =========================================================================
async function fetchWithTimeout(url, opts = {}, timeoutMs = LIMITS.FETCH_TIMEOUT_MS) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try {
    return await fetch(url, { ...opts, signal: ctrl.signal });
  } finally {
    clearTimeout(timer);
  }
}

// =========================================================================
// ЭТАП 1: РАСПОЗНАВАНИЕ ТОВАРА ПО ФОТО
// =========================================================================
async function recognizeProductFromImage(apiKey, imageBase64, userHint = '') {
  const visionPrompt = userHint
    ? `Посмотри на фото товара (подсказка пользователя: "${userHint.slice(0, 200)}"). Напиши на русском языке в 1-2 предложениях точное название этого товара, его тип, цвет, материал, видимые детали и назначение для продажи на маркетплейсе.`
    : `Внимательно посмотри на фотографию товара. Определи, что именно изображено на фото: напиши на русском языке точное название товара, его категорию, цвет, материал, форму и ключевые видимые особенности в 1-2 предложениях.`;

  // 🔴 Убрал несуществующие модели (qwen/qwen3.8-27b, qwen/qwen3.6-27b — таких нет в Groq)
  const baseVisionModels = [
    'meta-llama/llama-4-scout-17b-16e-instruct',
    'meta-llama/llama-4-maverick-17b-128e-instruct',
    'llama-3.2-90b-vision-preview',
    'llama-3.2-11b-vision-preview'
  ];

  // Динамически подтягиваем активные vision-модели
  let visionModels = [...baseVisionModels];
  try {
    const mRes = await fetchWithTimeout('https://api.groq.com/openai/v1/models', {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    }, 8000);
    if (mRes.ok) {
      const mData = await mRes.json();
      const dynamicVision = (mData.data || [])
        .map(m => m.id)
        .filter(id => {
          const low = id.toLowerCase();
          return low.includes('vision') || low.includes('scout') || low.includes('maverick');
        });
      visionModels = [...new Set([...visionModels, ...dynamicVision])];
    }
  } catch {}

  for (const vModel of visionModels) {
    try {
      const vRes = await fetchWithTimeout('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: {
          'Authorization': `Bearer ${apiKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          model: vModel,
          messages: [
            {
              role: 'user',
              content: [
                { type: 'text', text: visionPrompt },
                { type: 'image_url', image_url: { url: imageBase64 } }
              ]
            }
          ],
          temperature: 0.3,
          // 🔴 max_completion_tokens → max_tokens (универсальный параметр для Groq chat)
          max_tokens: 300
        })
      }, 25000);

      if (vRes.ok) {
        const vData = await vRes.json();
        const text = vData.choices?.[0]?.message?.content?.trim();
        if (text && text.length > 5) {
          return text.replace(/<think>[\s\S]*?<\/think>/gi, '').trim();
        }
      } else {
        const errBody = await vRes.text().catch(() => '');
        console.warn(`[generate] Vision model ${vModel} failed: ${vRes.status} ${errBody.slice(0, 200)}`);
      }
    } catch (e) {
      console.warn(`[generate] Vision model ${vModel} error: ${e.message}`);
    }
  }

  // Резервный мультимодальный шлюз
  try {
    const backupRes = await fetchWithTimeout('https://text.pollinations.ai/openai', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({
        model: 'openai',
        messages: [
          {
            role: 'user',
            content: [
              { type: 'text', text: visionPrompt },
              { type: 'image_url', image_url: { url: imageBase64 } }
            ]
          }
        ]
      })
    }, 20000);
    if (backupRes.ok) {
      const bData = await backupRes.json();
      const bText = bData.choices?.[0]?.message?.content?.trim();
      if (bText && bText.length > 5) return bText;
    }
  } catch (e) {
    console.warn('[generate] Backup vision gateway error:', e.message);
  }

  return null;
}

// =========================================================================
// ЭТАП 2: ГЕНЕРАЦИЯ JSON-ВОРОНКИ
// =========================================================================
async function generateFunnelJSON(apiKey, systemPrompt, product) {
  // 🔴 Приоритет: быстрые/дешёвые модели. Огромные (120b) — fallback.
  const priorityModels = [
    'llama-3.3-70b-versatile',
    'openai/gpt-oss-20b',
    'openai/gpt-oss-120b'
  ];

  let candidateModels = [...priorityModels];
  try {
    const mRes = await fetchWithTimeout('https://api.groq.com/openai/v1/models', {
      headers: { 'Authorization': `Bearer ${apiKey}` }
    }, 8000);
    if (mRes.ok) {
      const mData = await mRes.json();
      const dynamicModels = (mData.data || [])
        .map(m => m.id)
        .filter(id =>
          !id.includes('whisper') &&
          !id.includes('guard') &&
          !id.includes('tts') &&
          !id.includes('orpheus') &&
          !id.toLowerCase().includes('vision')
        );
      candidateModels = [...new Set([...candidateModels, ...dynamicModels])];
    }
  } catch {}

  let lastError = 'Ошибка обращения к модели ИИ';
  let rawContent = null;

  for (const modelId of candidateModels) {
    try {
      const response = await fetchWithTimeout('https://api.groq.com/openai/v1/chat/completions', {
        method: 'POST',
        headers: { 'Authorization': `Bearer ${apiKey}`, 'Content-Type': 'application/json' },
        body: JSON.stringify({
          model: modelId,
          response_format: { type: 'json_object' },
          messages: [
            { role: 'system', content: systemPrompt },
            { role: 'user', content: `Товар: ${product}. Сформируй JSON:` }
          ],
          // 🔴 temperature 0.7 → 0.3: для JSON-вывода меньше галлюцинаций
          temperature: 0.3,
          max_tokens: 2000
        })
      }, 40000);

      if (!response.ok) {
        const errBody = await response.text().catch(() => '');
        lastError = `Модель ${modelId}: ${response.status} ${errBody.slice(0, 200)}`;
        console.warn(`[generate] ${lastError}`);
        continue;
      }

      const result = await response.json();
      const content = result.choices?.[0]?.message?.content;
      if (content) {
        rawContent = content;
        break;
      }
      lastError = `Модель ${modelId}: пустой ответ`;
    } catch (e) {
      lastError = `Модель ${modelId}: ${e.message}`;
      console.warn(`[generate] ${lastError}`);
    }
  }

  if (!rawContent) throw new Error(lastError);

  const cleaned = rawContent
    .replace(/^```json\s*/i, '')
    .replace(/^```\s*/i, '')
    .replace(/```\s*$/i, '')
    .trim();

  let parsed;
  try {
    parsed = JSON.parse(cleaned);
  } catch (e) {
    throw new Error(`Невалидный JSON от модели: ${e.message}`);
  }
  return parsed;
}

// =========================================================================
// HANDLER
// =========================================================================
export default async function handler(req, res) {
  const origin = req.headers.origin || '';
  const { apiKey, sbUrl, sbServiceKey, secretSalt, allowedOrigins } = getEnvConfig();

  // 🔴 CORS: whitelist вместо '*'
  if (allowedOrigins.length > 0) {
    if (allowedOrigins.includes(origin)) {
      res.setHeader('Access-Control-Allow-Origin', origin);
      res.setHeader('Vary', 'Origin');
    }
  } else {
    // dev / не настроено — открываем, но предупреждаем в лог
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (process.env.NODE_ENV === 'production') {
      console.warn('[generate] ALLOWED_ORIGINS не задан — CORS открыт для всех. Настройте ENV!');
    }
  }
  res.setHeader('Access-Control-Allow-Methods', 'POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (req.method !== 'POST') return res.status(405).json({ error: 'Method not allowed' });

  try {
    // 🔴 Проверка размера тела
    const contentLength = parseInt(req.headers['content-length'] || '0', 10);
    if (contentLength > LIMITS.MAX_BODY_BYTES) {
      return res.status(413).json({ error: 'Слишком большое тело запроса (макс. 4 MB)' });
    }

    const body = typeof req.body === 'string' ? JSON.parse(req.body) : req.body;
    let product = clampString(body?.product || '', LIMITS.MAX_PRODUCT_LEN);
    const tone = body?.tone || 'hit';
    const rawImageBase64 = body?.imageBase64 || null;

    // 🔴 Валидация изображения
    let imageBase64 = null;
    if (rawImageBase64) {
      const v = validateImageDataUrl(rawImageBase64);
      if (!v.ok) {
        return res.status(400).json({
          error: `Недопустимое изображение: ${v.reason}. Разрешены JPEG/PNG/WebP до 3 MB.`
        });
      }
      imageBase64 = rawImageBase64;
    }

    // 🔴 Обязательная соль — иначе токены подделываемы
    if (!secretSalt) {
      console.error('[generate] secretSalt не задан! Настройте KARDPRO_SESSION_SALT или SUPABASE_SERVICE_ROLE_KEY');
      return res.status(500).json({ error: 'Server misconfiguration: session secret not set' });
    }
    if (!apiKey) {
      return res.status(500).json({ error: 'Не задан GROQ_API_KEY в Environment Variables' });
    }

    const authHeader = req.headers.authorization || '';
    const token = authHeader.replace('Bearer ', '').trim();

    if (!token) {
      return res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Войдите через Яндекс ID, чтобы получить 5 бесплатных генераций!'
      });
    }

    const userObj = verifySessionToken(token, secretSalt);
    if (!userObj || !userObj.email) {
      return res.status(401).json({
        error: 'AUTH_REQUIRED',
        message: 'Сессия устарела, пожалуйста, войдите в аккаунт снова'
      });
    }

    // 🔴 Rate limit: на IP + на user
    const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';
    const rateKey = `${clientIp}:${userObj.id}`;
    const rate = checkRateLimit(rateKey);
    if (!rate.allowed) {
      res.setHeader('Retry-After', String(rate.retryAfter));
      return res.status(429).json({
        error: 'RATE_LIMIT',
        message: `Слишком много запросов. Подождите ${rate.retryAfter} секунд.`
      });
    }

    // Загружаем состояние
    const cookieVault = readCookieVault(req, secretSalt);
    const memRecord = global.usersVault[userObj.id] || cookieVault[userObj.id] || null;
    const sbUser = await getCloudUserByEmail(sbUrl, sbServiceKey, userObj.email);
    const cloudAppMeta = sbUser?.app_metadata || {};
    const cloudUserMeta = sbUser?.user_metadata || {};

    // 🔴 Проверка, получал ли пользователь уже бесплатные кредиты
    const hasSpentBefore = !!(cloudAppMeta.kp_has_spent || cloudUserMeta.has_spent || memRecord?.hasSpent);
    const bonusBlocked = !!(cloudAppMeta.kp_bonus_blocked || cloudUserMeta.bonus_blocked || memRecord?.bonusBlocked);
    const initialized = !!(cloudAppMeta.kp_initialized || cloudUserMeta.kp_initialized || memRecord?.hasSpent);

    // 🔴 Кредиты: app_metadata приоритетнее user_metadata (безопаснее)
    let currentCredits = 0;
    if (typeof cloudAppMeta.kp_credits === 'number') {
      currentCredits = cloudAppMeta.kp_credits;
    } else if (typeof cloudUserMeta.credits === 'number') {
      currentCredits = cloudUserMeta.credits;
    } else if (memRecord && typeof memRecord.credits === 'number') {
      currentCredits = memRecord.credits;
    } else if (typeof userObj.credits === 'number' && userObj.credits > 0) {
      currentCredits = userObj.credits;
    }

    // Бесплатные 5 кредитов — только если ещё не было иницициализации и не заблокировано
    if (!initialized && !bonusBlocked && currentCredits === 0 && userObj.provider !== 'email') {
      currentCredits = LIMITS.FREE_CREDITS_ON_FIRST_LOGIN;
    }

    if (currentCredits <= 0) {
      return res.status(402).json({
        error: 'NO_CREDITS',
        message: 'Бесплатные генерации закончились. Пополните баланс от 50 ₽!'
      });
    }

    // ЭТАП 1: Vision
    let recognizedProduct = null;
    if (imageBase64) {
      recognizedProduct = await recognizeProductFromImage(apiKey, imageBase64, product);
      if (recognizedProduct) {
        recognizedProduct = clampString(recognizedProduct, LIMITS.MAX_RECOGNIZED_LEN);
        product = product
          ? `${product} (${recognizedProduct})`
          : recognizedProduct;
        product = clampString(product, LIMITS.MAX_PRODUCT_LEN);
      } else if (!product) {
        return res.status(422).json({
          error: 'Не удалось разглядеть товар на фото. Загрузите более четкое фото или кратко опишите товар.'
        });
      }
    }

    if (!product) {
      return res.status(400).json({ error: 'Опишите ваш товар или загрузите его фотографию!' });
    }

    const toneInstructions = {
      hit: 'Сделай упор на максимальный CTR, яркую выгоду и бестселлер.',
      luxury: 'Сделай упор на премиальность, статус, долговечность и дорогие материалы.',
      trust: 'Сделай упор на надежность, проверку качества, безопасность и гарантию.',
      gift: 'Сделай упор на готовую идею для подарка, эмоции и богатую комплектацию.'
    };

    const systemPrompt = `Ты топ-маркетолог и арт-директор маркетплейсов Ozon, Wildberries, Яндекс Маркет и Авито.
Задача: ${toneInstructions[tone] || toneInstructions.hit}
Создай продающую воронку из 3 слайдов карточки товара и верни строго валидный JSON без markdown-обертки:
{
  "title_variants": [
    "Главный заголовок Вариант 1 (2-3 слова КАПСОМ)",
    "Альтернативный заголовок Вариант 2 (2-3 слова КАПСОМ)",
    "Выгодный заголовок Вариант 3 (2-3 слова КАПСОМ)"
  ],
  "ai_colors": {
    "bg1": "#HEX_верх_фона_под_товар",
    "bg2": "#HEX_темный_низ_фона",
    "accent": "#HEX_яркий_акцент",
    "badge": "#HEX_цвет_бейджа"
  },
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
  "seo": "Продающее SEO-описание для карточки товара на 500-700 символов с ключевыми запросами и характеристиками."
}`;

    // ЭТАП 2: Генерация JSON
    let content;
    try {
      content = await generateFunnelJSON(apiKey, systemPrompt, product);
    } catch (e) {
      return res.status(500).json({ error: e.message });
    }

    // Обновляем кредиты
    const nextCredits = Math.max(0, currentCredits - 1);
    const updatedRecord = {
      ...(memRecord || {}),
      id: sbUser?.id || userObj.id,
      email: userObj.email,
      name: userObj.name,
      provider: userObj.provider || 'yandex',
      credits: nextCredits,
      hasSpent: true,
      bonusBlocked: false,
      usedLabels: Array.isArray(memRecord?.usedLabels) ? memRecord.usedLabels : []
    };

    global.usersVault[updatedRecord.id] = updatedRecord;
    // 🔴 В cookie храним только этого пользователя, чтобы не раздувать 4KB
    writeCookieVault(res, { [updatedRecord.id]: updatedRecord }, secretSalt);

    if (sbUser?.id) {
      await saveCloudUserCredits(
        sbUrl, sbServiceKey, sbUser.id, userObj.email, cloudUserMeta,
        nextCredits, true, false
      );
    }

    if (recognizedProduct) content.recognized_product = recognizedProduct;
    content.remaining_credits = nextCredits;
    content.session_token = createSessionToken(updatedRecord, secretSalt);

    console.log(`[generate] OK user=${userObj.email} credits=${currentCredits}->${nextCredits} product_len=${product.length}`);

    return res.status(200).json(content);
  } catch (err) {
    console.error('[generate] handler error:', err.message, err.stack?.split('\n').slice(0, 3).join(' | '));
    return res.status(500).json({ error: err.message || 'Внутренняя ошибка сервера' });
  }
}
