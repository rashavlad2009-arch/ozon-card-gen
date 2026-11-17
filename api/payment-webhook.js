import crypto from 'crypto';

const DEFAULT_YANDEX_CLIENT_ID = '5e55cf35d18a47eaa84b5e23f0d91427';
const BONUS_CREDITS = 5;
const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;

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
  const sbUrl = normalizeSupabaseUrl(
    findEnvVar(['SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL'])
  );
  const sbServiceKey = (
    findEnvVar(['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SECRET_KEY']) || ''
  ).trim();
  const secretSalt = (
    findEnvVar(['KARDPRO_SESSION_SALT', 'SESSION_SECRET']) || sbServiceKey
  ).trim();
  const yandexClientId =
    findEnvVar(['YANDEX_CLIENT_ID']) || DEFAULT_YANDEX_CLIENT_ID;
  const yooMoneySecret = findEnvVar(['YOOMONEY_SECRET']);
  return { sbUrl, sbServiceKey, secretSalt, yandexClientId, yooMoneySecret };
}

function getPromoCodes() {
  const raw = findEnvVar(['PROMO_CODES_JSON']);
  if (raw) {
    try {
      return JSON.parse(raw);
    } catch {}
  }
  return { START5: 5, KARD10: 10 };
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bA = Buffer.from(a, 'utf8');
  const bB = Buffer.from(b, 'utf8');
  if (bA.length !== bB.length) return false;
  try {
    return crypto.timingSafeEqual(bA, bB);
  } catch {
    return false;
  }
}

function emailToDeterministicUUID(email) {
  const hex = crypto
    .createHash('sha256')
    .update(`user_${String(email).trim().toLowerCase()}`)
    .digest('hex')
    .substring(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
}

function createSessionToken(u, salt) {
  if (!salt) throw new Error('KARDPRO_SESSION_SALT / SUPABASE_SERVICE_ROLE_KEY не задан');
  const payload = Buffer.from(
    JSON.stringify({
      id: u.id,
      email: u.email,
      name: u.name,
      provider: u.provider || 'yandex',
      credits: typeof u.credits === 'number' ? u.credits : 0,
      ts: Date.now()
    })
  ).toString('base64url');
  const sig = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  return `kp.${payload}.${sig}`;
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
    if (Date.now() - d.ts > SESSION_TTL_MS) return null;
    if (!d.id || !d.email) return null;
    return d;
  } catch {
    return null;
  }
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

async function sbFetch(sbUrl, sbServiceKey, path, { method = 'GET', body = null, prefer = '' } = {}) {
  if (!sbUrl || !sbServiceKey) {
    throw new Error('Не заданы SUPABASE_URL и SUPABASE_SERVICE_ROLE_KEY в переменных окружения Vercel');
  }
  const headers = {
    apikey: sbServiceKey,
    Authorization: `Bearer ${sbServiceKey}`,
    'Content-Type': 'application/json'
  };
  if (prefer) headers['Prefer'] = prefer;

  const res = await fetch(`${sbUrl}/rest/v1/${path}`, {
    method,
    headers,
    body: body ? JSON.stringify(body) : undefined
  });

  const text = await res.text();
  let data = null;
  if (text) {
    try {
      data = JSON.parse(text);
    } catch {
      data = text;
    }
  }

  if (!res.ok) {
    const msg = (data && (data.message || data.hint || data.details)) || `Supabase HTTP ${res.status}`;
    throw new Error(msg);
  }
  return data;
}

const PROFILE_FIELDS = 'id,email,name,credits,bonus_granted,password_hash,used_promos';

async function getProfileById(sbUrl, sbServiceKey, userId) {
  const rows = await sbFetch(
    sbUrl,
    sbServiceKey,
    `profiles?id=eq.${encodeURIComponent(userId)}&select=${PROFILE_FIELDS}&limit=1`
  );
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

async function getProfileByYandexId(sbUrl, sbServiceKey, yandexId) {
  const rows = await sbFetch(
    sbUrl,
    sbServiceKey,
    `profiles?yandex_id=eq.${encodeURIComponent(yandexId)}&select=${PROFILE_FIELDS}&limit=1`
  );
  return Array.isArray(rows) && rows.length > 0 ? rows[0] : null;
}

async function hasDeviceClaimedBonus(sbUrl, sbServiceKey, deviceFp) {
  if (!deviceFp || deviceFp === 'default_hw_fp') return false;
  const rows = await sbFetch(
    sbUrl,
    sbServiceKey,
    `profiles?device_fp=eq.${encodeURIComponent(deviceFp)}&bonus_granted=eq.true&select=id&limit=1`
  );
  return Array.isArray(rows) && rows.length > 0;
}

function parseBody(req) {
  if (!req.body) return {};
  if (typeof req.body === 'object' && !Buffer.isBuffer(req.body)) return req.body;
  const raw = Buffer.isBuffer(req.body) ? req.body.toString('utf8') : String(req.body);
  try {
    return JSON.parse(raw);
  } catch {
    const params = new URLSearchParams(raw);
    const obj = {};
    for (const [k, v] of params.entries()) obj[k] = v;
    return obj;
  }
}

export default async function handler(req, res) {
  const { sbUrl, sbServiceKey, secretSalt, yandexClientId, yooMoneySecret } = getEnvConfig();

  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Content-Type', 'application/json; charset=utf-8');

  if (req.method === 'OPTIONS') return res.status(200).end();

  try {
    // -------------------- GET --------------------
    if (req.method === 'GET') {
      const action = String(req.query?.action || '');

      if (action === 'config') {
        return res.status(200).json({ yandexClientId });
      }

      if (action === 'profile') {
        const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
        const userObj = verifySessionToken(token, secretSalt);
        if (!userObj || !userObj.email) {
          return res.status(401).json({ error: 'AUTH_REQUIRED', message: 'Сессия устарела' });
        }

        const userId = userObj.id || emailToDeterministicUUID(userObj.email);
        const profile = await getProfileById(sbUrl, sbServiceKey, userId);
        const credits = profile ? Number(profile.credits || 0) : 0;
        const name = (profile && profile.name) || userObj.name || userObj.email.split('@')[0];

        const freshToken = createSessionToken(
          {
            id: userId,
            email: userObj.email,
            name,
            provider: userObj.provider || 'yandex',
            credits
          },
          secretSalt
        );

        return res.status(200).json({
          id: userId,
          email: userObj.email,
          name,
          credits,
          session_token: freshToken
        });
      }

      if (action === 'check_payment') {
        const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
        const userObj = verifySessionToken(token, secretSalt);
        if (!userObj || !userObj.email) {
          return res.status(401).json({ error: 'AUTH_REQUIRED' });
        }

        const label = String(req.query?.label || '').trim();
        if (!label) return res.status(400).json({ error: 'Не указан label платежа' });

        const rows = await sbFetch(
          sbUrl,
          sbServiceKey,
          `payments?label=eq.${encodeURIComponent(label)}&status=eq.paid&select=id&limit=1`
        );
        const paid = Array.isArray(rows) && rows.length > 0;

        const userId = userObj.id || emailToDeterministicUUID(userObj.email);
        const profile = await getProfileById(sbUrl, sbServiceKey, userId);

        return res.status(200).json({
          paid,
          credits: profile ? Number(profile.credits || 0) : 0
        });
      }

      return res.status(400).json({ error: 'Неизвестное GET-действие' });
    }

    // -------------------- POST --------------------
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

        // Ищем единый профиль по yandex_id или email (независимо от устройства)
        let profile = await getProfileByYandexId(sbUrl, sbServiceKey, yandexId);
        const userId = profile ? profile.id : emailToDeterministicUUID(email);
        if (!profile) {
          profile = await getProfileById(sbUrl, sbServiceKey, userId);
        }

        let credits = 0;

        if (profile) {
          credits = Number(profile.credits || 0);
          let bonusGranted = Boolean(profile.bonus_granted);

          if (!bonusGranted) {
            const deviceUsed = await hasDeviceClaimedBonus(sbUrl, sbServiceKey, deviceFp);
            if (!deviceUsed) {
              credits += BONUS_CREDITS;
            }
            bonusGranted = true;
          }

          await sbFetch(sbUrl, sbServiceKey, `profiles?id=eq.${encodeURIComponent(userId)}`, {
            method: 'PATCH',
            body: {
              name: profile.name || displayName,
              yandex_id: yandexId,
              credits,
              bonus_granted: bonusGranted,
              last_login_at: new Date().toISOString()
            },
            prefer: 'return=minimal'
          });
        } else {
          const deviceUsed = await hasDeviceClaimedBonus(sbUrl, sbServiceKey, deviceFp);
          credits = deviceUsed ? 0 : BONUS_CREDITS;

          await sbFetch(sbUrl, sbServiceKey, 'profiles', {
            method: 'POST',
            body: {
              id: userId,
              email,
              name: displayName,
              yandex_id: yandexId,
              credits,
              bonus_granted: true,
              device_fp: deviceFp || null,
              last_login_at: new Date().toISOString()
            },
            prefer: 'return=minimal'
          });
        }

        const finalEmail = (profile && profile.email) || email;
        const finalName = (profile && profile.name) || displayName;

        const sessionToken = createSessionToken(
          { id: userId, email: finalEmail, name: finalName, provider: 'yandex', credits },
          secretSalt
        );

        return res.status(200).json({
          id: userId,
          email: finalEmail,
          name: finalName,
          credits,
          session_token: sessionToken
        });
      }

      // 2. ВХОД / РЕГИСТРАЦИЯ ПО EMAIL
      if (action === 'email_auth') {
        const mode = String(body.mode || 'login');
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '');
        const deviceFp = String(body.deviceFp || '').trim();

        if (!email || !email.includes('@') || password.length < 6) {
          return res.status(400).json({ error: 'Введите корректный Email и пароль от 6 символов' });
        }

        const userId = emailToDeterministicUUID(email);
        const profile = await getProfileById(sbUrl, sbServiceKey, userId);

        if (mode === 'signup') {
          if (profile) {
            return res.status(400).json({ error: 'Этот Email уже зарегистрирован. Нажмите «Войти».' });
          }

          const name = email.split('@')[0];
          await sbFetch(sbUrl, sbServiceKey, 'profiles', {
            method: 'POST',
            body: {
              id: userId,
              email,
              name,
              password_hash: hashPassword(password),
              credits: 0,
              bonus_granted: false,
              device_fp: deviceFp || null,
              last_login_at: new Date().toISOString()
            },
            prefer: 'return=minimal'
          });

          const sessionToken = createSessionToken(
            { id: userId, email, name, provider: 'email', credits: 0 },
            secretSalt
          );

          return res.status(200).json({
            id: userId,
            email,
            name,
            credits: 0,
            session_token: sessionToken
          });
        }

        if (!profile) {
          return res.status(401).json({ error: 'Аккаунт не найден. Нажмите «Создать» или войдите через Яндекс.' });
        }

        if (!profile.password_hash) {
          return res.status(401).json({ error: 'Аккаунт создан через Яндекс ID. Войдите через кнопку Яндекса.' });
        }

        if (!verifyPassword(password, profile.password_hash)) {
          return res.status(401).json({ error: 'Неверный пароль' });
        }

        const credits = Number(profile.credits || 0);
        const name = profile.name || email.split('@')[0];

        await sbFetch(sbUrl, sbServiceKey, `profiles?id=eq.${encodeURIComponent(userId)}`, {
          method: 'PATCH',
          body: { last_login_at: new Date().toISOString() },
          prefer: 'return=minimal'
        });

        const sessionToken = createSessionToken(
          { id: userId, email, name, provider: 'email', credits },
          secretSalt
        );

        return res.status(200).json({
          id: userId,
          email,
          name,
          credits,
          session_token: sessionToken
        });
      }

      // 3. ПРОМОКОДЫ
      if (action === 'promo') {
        const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
        const userObj = verifySessionToken(token, secretSalt);
        if (!userObj || !userObj.email) {
          return res.status(401).json({ error: 'Войдите в аккаунт для активации промокода' });
        }

        const code = String(body.code || '').trim().toUpperCase();
        const promoMap = getPromoCodes();
        const bonus = Number(promoMap[code] || 0);
        if (!bonus) return res.status(400).json({ error: 'Неверный промокод' });

        const userId = userObj.id || emailToDeterministicUUID(userObj.email);
        const profile = await getProfileById(sbUrl, sbServiceKey, userId);
        if (!profile) return res.status(404).json({ error: 'Профиль не найден' });

        const usedList = Array.isArray(profile.used_promos) ? profile.used_promos : [];
        if (usedList.includes(code)) {
          return res.status(400).json({ error: 'Вы уже активировали этот промокод' });
        }

        const newCredits = Number(profile.credits || 0) + bonus;
        await sbFetch(sbUrl, sbServiceKey, `profiles?id=eq.${encodeURIComponent(userId)}`, {
          method: 'PATCH',
          body: {
            credits: newCredits,
            used_promos: [...usedList, code]
          },
          prefer: 'return=minimal'
        });

        const sessionToken = createSessionToken(
          {
            id: userId,
            email: userObj.email,
            name: profile.name || userObj.name,
            provider: userObj.provider || 'yandex',
            credits: newCredits
          },
          secretSalt
        );

        return res.status(200).json({
          added: bonus,
          credits: newCredits,
          session_token: sessionToken
        });
      }

      // 4. ВЕБХУК ОПЛАТЫ ЮMONEY
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

        if (yooMoneySecret) {
          const checkStr = [
            notification_type,
            operation_id,
            amount,
            currency,
            datetime,
            sender,
            codepro,
            yooMoneySecret,
            label
          ].join('&');

          const expectedHash = crypto.createHash('sha1').update(checkStr).digest('hex');
          if (!safeEqual(expectedHash.toLowerCase(), String(sha1_hash).toLowerCase())) {
            return res.status(403).send('Invalid sha1_hash');
          }
        }

        if (String(codepro) === 'true' || String(unaccepted) === 'true') {
          return res.status(200).send('Payment held');
        }

        const match = /^kp_(\d+)_([^_]+)_[a-z0-9]+$/i.exec(String(label).trim());
        if (!match) return res.status(200).send('Ignored label');

        const creditsToAdd = parseInt(match[1], 10);
        const userId = match[2];

        const existingPay = await sbFetch(
          sbUrl,
          sbServiceKey,
          `payments?label=eq.${encodeURIComponent(label)}&select=id&limit=1`
        );
        if (Array.isArray(existingPay) && existingPay.length > 0) {
          return res.status(200).send('Already processed');
        }

        const profile = await getProfileById(sbUrl, sbServiceKey, userId);
        if (!profile) return res.status(404).send('User not found');

        await sbFetch(sbUrl, sbServiceKey, 'payments', {
          method: 'POST',
          body: {
            label,
            operation_id: String(operation_id || label),
            user_id: userId,
            credits: creditsToAdd,
            amount: parseFloat(amount) || 0,
            status: 'paid'
          },
          prefer: 'return=minimal'
        });

        await sbFetch(sbUrl, sbServiceKey, `profiles?id=eq.${encodeURIComponent(userId)}`, {
          method: 'PATCH',
          body: { credits: Number(profile.credits || 0) + creditsToAdd },
          prefer: 'return=minimal'
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
}
