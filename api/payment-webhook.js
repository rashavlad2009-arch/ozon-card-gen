const crypto = require('crypto');

const SUPABASE_URL = (process.env.SUPABASE_URL || '').replace(/\/$/, '');
const SUPABASE_SERVICE_KEY =
  process.env.SUPABASE_SERVICE_ROLE_KEY ||
  process.env.SUPABASE_KEY ||
  process.env.SUPABASE_ANON_KEY ||
  '';

const YANDEX_CLIENT_ID =
  process.env.YANDEX_CLIENT_ID || '5e55cf35d18a47eaa84b5e23f0d91427';

const YOOMONEY_SECRET = process.env.YOOMONEY_SECRET || '';
const SESSION_SECRET =
  process.env.SESSION_SECRET ||
  SUPABASE_SERVICE_KEY ||
  'kard_pro_fallback_secret_change_in_vercel';

// Промокоды (можно переопределить через переменную окружения PROMO_CODES_JSON='{"BONUS5":5}')
function getPromoCodes() {
  if (process.env.PROMO_CODES_JSON) {
    try {
      return JSON.parse(process.env.PROMO_CODES_JSON);
    } catch (e) {}
  }
  return {
    START5: 5,
    KARD10: 10
  };
}

// ================== РАБОТА С SUPABASE REST API ==================
async function supabaseRequest(path, { method = 'GET', body = null, prefer = '' } = {}) {
  if (!SUPABASE_URL || !SUPABASE_SERVICE_KEY) {
    throw new Error('Не заданы SUPABASE_URL и SUPABASE_SERVICE_ROLE_KEY в настройках Vercel.');
  }

  const headers = {
    apikey: SUPABASE_SERVICE_KEY,
    Authorization: `Bearer ${SUPABASE_SERVICE_KEY}`,
    'Content-Type': 'application/json'
  };
  if (prefer) headers['Prefer'] = prefer;

  const res = await fetch(`${SUPABASE_URL}/rest/v1/${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch (e) {
      data = text;
    }
  }

  if (!res.ok) {
    const msg = (data && (data.message || data.error_description || data.hint)) || `Supabase HTTP ${res.status}`;
    throw new Error(msg);
  }

  return data;
}

async function findUserByEmail(email) {
  const clean = encodeURIComponent(email.trim().toLowerCase());
  const rows = await supabaseRequest(`users?email=eq.${clean}&limit=1`);
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

async function findUserByYandexId(yandexId) {
  const clean = encodeURIComponent(String(yandexId));
  const rows = await supabaseRequest(`users?yandex_id=eq.${clean}&limit=1`);
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

async function findUserById(id) {
  const clean = encodeURIComponent(String(id));
  const rows = await supabaseRequest(`users?id=eq.${clean}&limit=1`);
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

async function findUserBySessionToken(token) {
  const clean = encodeURIComponent(String(token));
  const rows = await supabaseRequest(`users?session_token=eq.${clean}&limit=1`);
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

async function hasDeviceClaimedBonus(deviceFp) {
  if (!deviceFp || deviceFp === 'default_hw_fp') return false;
  const clean = encodeURIComponent(String(deviceFp));
  const rows = await supabaseRequest(
    `users?device_fp=eq.${clean}&yandex_bonus_claimed=eq.true&select=id&limit=1`
  );
  return Array.isArray(rows) && rows.length > 0;
}

async function updateUser(id, patch) {
  const clean = encodeURIComponent(String(id));
  const rows = await supabaseRequest(`users?id=eq.${clean}`, {
    method: 'PATCH',
    body: patch,
    prefer: 'return=representation'
  });
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

async function insertUser(payload) {
  const rows = await supabaseRequest('users', {
    method: 'POST',
    body: payload,
    prefer: 'return=representation'
  });
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

// ================== ТОКЕНЫ СЕССИИ И ПАРОЛИ ==================
function createSessionToken(userId, email) {
  const payloadObj = {
    uid: String(userId),
    email: String(email).toLowerCase(),
    iat: Date.now()
  };
  const payloadB64 = Buffer.from(JSON.stringify(payloadObj)).toString('base64url');
  const sig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payloadB64)
    .digest('base64url');
  return `${payloadB64}.${sig}`;
}

function verifySessionToken(token) {
  if (!token || typeof token !== 'string' || !token.includes('.')) return null;
  const [payloadB64, sig] = token.split('.');
  if (!payloadB64 || !sig) return null;

  const expectedSig = crypto
    .createHmac('sha256', SESSION_SECRET)
    .update(payloadB64)
    .digest('base64url');

  const sigBuf = Buffer.from(sig);
  const expBuf = Buffer.from(expectedSig);
  if (sigBuf.length !== expBuf.length || !crypto.timingSafeEqual(sigBuf, expBuf)) {
    return null;
  }

  try {
    return JSON.parse(Buffer.from(payloadB64, 'base64url').toString('utf8'));
  } catch (e) {
    return null;
  }
}

async function authenticateRequest(req) {
  const authHeader = req.headers.authorization || req.headers.Authorization || '';
  if (!authHeader.startsWith('Bearer ')) return null;
  const token = authHeader.slice(7).trim();
  if (!token) return null;

  const decoded = verifySessionToken(token);
  if (decoded && decoded.uid) {
    const user = await findUserById(decoded.uid);
    if (user) return user;
  }
  return await findUserBySessionToken(token);
}

function hashPassword(password) {
  const salt = crypto.randomBytes(16).toString('hex');
  const hash = crypto.scryptSync(password, salt, 64).toString('hex');
  return `${salt}:${hash}`;
}

function verifyPassword(password, storedHash) {
  if (!storedHash || !storedHash.includes(':')) return false;
  const [salt, keyHex] = storedHash.split(':');
  const derivedKey = crypto.scryptSync(password, salt, 64);
  const keyBuf = Buffer.from(keyHex, 'hex');
  if (derivedKey.length !== keyBuf.length) return false;
  return crypto.timingSafeEqual(derivedKey, keyBuf);
}

// ================== ПАРСИНГ ТЕЛА ЗАПРОСА ==================
function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) {
    return req.body;
  }
  const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : String(req.body);
  try {
    return JSON.parse(raw);
  } catch (e) {
    const params = new URLSearchParams(raw);
    const obj = {};
    for (const [k, v] of params.entries()) obj[k] = v;
    return obj;
  }
}

// ================== ОСНОВНОЙ ОБРАБОТЧИК ==================
module.exports = async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  try {
    // -------------------- GET ЗАПРОСЫ --------------------
    if (req.method === 'GET') {
      const action = String(req.query.action || '');

      if (action === 'config') {
        return res.status(200).json({ yandexClientId: YANDEX_CLIENT_ID });
      }

      if (action === 'profile') {
        const user = await authenticateRequest(req);
        if (!user) {
          return res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Сессия не найдена' });
        }
        return res.status(200).json({
          id: user.id,
          email: user.email,
          name: user.name || user.email.split('@')[0],
          credits: Number(user.credits || 0),
          session_token: user.session_token
        });
      }

      if (action === 'check_payment') {
        const user = await authenticateRequest(req);
        if (!user) {
          return res.status(401).json({ error: 'AUTH_REQUIRED' });
        }
        const label = String(req.query.label || '').trim();
        if (!label) {
          return res.status(400).json({ error: 'Не указан label платежа' });
        }

        const cleanLabel = encodeURIComponent(label);
        const rows = await supabaseRequest(
          `payments?label=eq.${cleanLabel}&status=eq.paid&limit=1`
        );
        const paid = Array.isArray(rows) && rows.length > 0;

        return res.status(200).json({
          paid,
          credits: Number(user.credits || 0)
        });
      }

      return res.status(400).json({ error: 'Неизвестное GET-действие' });
    }

    // -------------------- POST ЗАПРОСЫ --------------------
    if (req.method === 'POST') {
      const body = parseBody(req);
      const action = String(body.action || '');

      // 1. ВХОД ЧЕРЕЗ ЯНДЕКС ID
      if (action === 'social_auth') {
        const accessToken = String(body.accessToken || '').trim();
        const deviceFp = String(body.deviceFp || '').trim();

        if (!accessToken) {
          return res.status(400).json({ error: 'Отсутствует токен Яндекс ID' });
        }

        // Проверяем токен напрямую на сервере Яндекса (защита от подделки)
        const yaRes = await fetch('https://login.yandex.ru/info?format=json', {
          headers: { Authorization: `OAuth ${accessToken}` }
        });

        if (!yaRes.ok) {
          return res.status(401).json({ error: 'Не удалось подтвердить токен Яндекс ID' });
        }

        const yaInfo = await yaRes.json();
        if (!yaInfo || !yaInfo.id) {
          return res.status(401).json({ error: 'Яндекс не вернул данные профиля' });
        }

        const yandexId = String(yaInfo.id);
        const rawEmail =
          yaInfo.default_email ||
          (Array.isArray(yaInfo.emails) && yaInfo.emails[0]) ||
          `${yaInfo.login || yandexId}@yandex.ru`;
        const email = String(rawEmail).trim().toLowerCase();
        const displayName =
          yaInfo.display_name ||
          yaInfo.real_name ||
          yaInfo.login ||
          email.split('@')[0];

        // Ищем существующий аккаунт по yandex_id или по email (независимо от устройства!)
        let user = await findUserByYandexId(yandexId);
        if (!user) {
          user = await findUserByEmail(email);
        }

        if (user) {
          // Пользователь уже существует: сохраняем его текущий баланс!
          let updatedCredits = Number(user.credits || 0);
          let bonusClaimed = Boolean(user.yandex_bonus_claimed);

          // Если ранее аккаунт был создан по паролю (0 кредитов) и бонус Яндекса ещё не выдавался
          if (!bonusClaimed) {
            const deviceAlreadyUsed = await hasDeviceClaimedBonus(deviceFp);
            if (!deviceAlreadyUsed) {
              updatedCredits += 5;
            }
            bonusClaimed = true;
          }

          // Переиспользуем текущий session_token, чтобы не выкидывать пользователя на первом устройстве
          const sessionToken =
            user.session_token && verifySessionToken(user.session_token)
              ? user.session_token
              : createSessionToken(user.id, user.email);

          user = await updateUser(user.id, {
            yandex_id: yandexId,
            name: user.name || displayName,
            credits: updatedCredits,
            yandex_bonus_claimed: bonusClaimed,
            session_token: sessionToken,
            last_login_at: new Date().toISOString()
          });
        } else {
          // Новый пользователь: проверяем, не получало ли это устройство приветственные 5 генераций ранее
          const deviceAlreadyUsed = await hasDeviceClaimedBonus(deviceFp);
          const welcomeCredits = deviceAlreadyUsed ? 0 : 5;

          const created = await insertUser({
            email,
            name: displayName,
            yandex_id: yandexId,
            credits: welcomeCredits,
            yandex_bonus_claimed: true,
            device_fp: deviceFp || null,
            last_login_at: new Date().toISOString()
          });

          const sessionToken = createSessionToken(created.id, created.email);
          user = await updateUser(created.id, { session_token: sessionToken });
        }

        return res.status(200).json({
          id: user.id,
          email: user.email,
          name: user.name || displayName,
          credits: Number(user.credits || 0),
          session_token: user.session_token
        });
      }

      // 2. ВХОД И РЕГИСТРАЦИЯ ПО EMAIL И ПАРОЛЮ
      if (action === 'email_auth') {
        const mode = String(body.mode || 'login');
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');
        const deviceFp = String(body.deviceFp || '').trim();

        if (!email || !email.includes('@') || password.length < 6) {
          return res.status(400).json({ error: 'Введите корректный Email и пароль от 6 символов' });
        }

        let user = await findUserByEmail(email);

        if (mode === 'signup') {
          if (user) {
            return res.status(400).json({ error: 'Этот Email уже зарегистрирован. Нажмите «Войти».' });
          }

          const created = await insertUser({
            email,
            name: email.split('@')[0],
            password_hash: hashPassword(password),
            credits: 0,
            yandex_bonus_claimed: false,
            device_fp: deviceFp || null,
            last_login_at: new Date().toISOString()
          });

          const sessionToken = createSessionToken(created.id, created.email);
          user = await updateUser(created.id, { session_token: sessionToken });

          return res.status(200).json({
            id: user.id,
            email: user.email,
            name: user.name,
            credits: 0,
            session_token: user.session_token
          });
        }

        // Режим входа (login)
        if (!user) {
          return res.status(401).json({ error: 'Аккаунт не найден. Нажмите «Создать» или войдите через Яндекс.' });
        }

        if (!user.password_hash) {
          return res.status(401).json({ error: 'Аккаунт создан через Яндекс ID. Войдите через кнопку Яндекса.' });
        }

        if (!verifyPassword(password, user.password_hash)) {
          return res.status(401).json({ error: 'Неверный пароль' });
        }

        const sessionToken =
          user.session_token && verifySessionToken(user.session_token)
            ? user.session_token
            : createSessionToken(user.id, user.email);

        user = await updateUser(user.id, {
          session_token: sessionToken,
          last_login_at: new Date().toISOString()
        });

        return res.status(200).json({
          id: user.id,
          email: user.email,
          name: user.name || email.split('@')[0],
          credits: Number(user.credits || 0),
          session_token: user.session_token
        });
      }

      // 3. АКТИВАЦИЯ ПРОМОКОДА
      if (action === 'promo') {
        const user = await authenticateRequest(req);
        if (!user) {
          return res.status(401).json({ error: 'Войдите в аккаунт для активации промокода' });
        }

        const code = String(body.code || '').trim().toUpperCase();
        const promoMap = getPromoCodes();
        const bonus = Number(promoMap[code] || 0);

        if (!bonus) {
          return res.status(400).json({ error: 'Неверный или истёкший промокод' });
        }

        const usedList = Array.isArray(user.used_promos) ? user.used_promos : [];
        if (usedList.includes(code)) {
          return res.status(400).json({ error: 'Вы уже активировали этот промокод' });
        }

        const newCredits = Number(user.credits || 0) + bonus;
        const updated = await updateUser(user.id, {
          credits: newCredits,
          used_promos: [...usedList, code]
        });

        return res.status(200).json({
          added: bonus,
          credits: Number(updated.credits || newCredits),
          session_token: updated.session_token
        });
      }

      // 4. HTTP-УВЕДОМЛЕНИЕ ОБ ОПЛАТЕ ОТ ЮMONEY
      if (body.notification_type || body.label) {
        const {
          notification_type = '',
          operation_id = '',
          amount = '',
          currency = '',
          datetime = '',
          sender = '',
          codepro = '',
          label = '',
          sha1_hash = '',
          unaccepted = ''
        } = body;

        // Проверка подписи SHA-1 от ЮMoney
        if (YOOMONEY_SECRET) {
          const checkStr = [
            notification_type,
            operation_id,
            amount,
            currency,
            datetime,
            sender,
            codepro,
            YOOMONEY_SECRET,
            label
          ].join('&');

          const expectedHash = crypto
            .createHash('sha1')
            .update(checkStr)
            .digest('hex');

          if (expectedHash.toLowerCase() !== String(sha1_hash).toLowerCase()) {
            return res.status(403).send('Invalid sha1_hash');
          }
        }

        if (String(codepro) === 'true' || String(unaccepted) === 'true') {
          return res.status(200).send('Payment held');
        }

        // Формат label из index.html: kp_<credits>_<userId>_<rand>
        const match = /^kp_(\d+)_([^_]+)_[a-z0-9]+$/i.exec(String(label).trim());
        if (!match) {
          return res.status(200).send('Ignored label');
        }

        const creditsToAdd = parseInt(match[1], 10);
        const userId = match[2];

        // Защита от повторного начисления при дублировании вебхука ЮMoney
        const existingPay = await supabaseRequest(
          `payments?label=eq.${encodeURIComponent(label)}&limit=1`
        );
        if (Array.isArray(existingPay) && existingPay.length > 0) {
          return res.status(200).send('Already processed');
        }

        const user = await findUserById(userId);
        if (!user) {
          return res.status(404).send('User not found');
        }

        await supabaseRequest('payments', {
          method: 'POST',
          body: {
            label,
            operation_id: String(operation_id || label),
            user_id: user.id,
            credits: creditsToAdd,
            amount: parseFloat(amount) || 0,
            status: 'paid'
          }
        });

        await updateUser(user.id, {
          credits: Number(user.credits || 0) + creditsToAdd
        });

        return res.status(200).send('OK');
      }

      return res.status(400).json({ error: 'Неизвестное действие' });
    }

    return res.status(405).json({ error: 'Method Not Allowed' });
  } catch (err) {
    console.error('payment-webhook error:', err);
    return res.status(500).json({ error: err.message || 'Внутренняя ошибка сервера' });
  }
};
