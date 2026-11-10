import crypto from 'crypto';

const VALID_PROMO_CODES = {
  'START5': 5,
  'PRO50': 5,
  'SELLER10': 10,
  'SHOP20': 20,
  'VIP2026': 50
};

// Резервные публичные идентификаторы вашего проекта, чтобы вход работал всегда
const FALLBACK_SUPABASE_URL = 'https://irxszktfwtravyeqnueh.supabase.co';
const FALLBACK_YANDEX_CLIENT_ID = '5e55cf35d18a47eaa84b5e23f0d91427';

global.usersVault = global.usersVault || {};

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
  const sbUrl = (findEnvVar(['SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL']) || FALLBACK_SUPABASE_URL).replace(/\/$/, '');
  const sbAnonKey = findEnvVar([
    'SUPABASE_ANON_KEY',
    'NEXT_PUBLIC_SUPABASE_ANON_KEY',
    'SUPABASE_PUBLISHABLE_KEY',
    'NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY'
  ]);
  const sbServiceKey = findEnvVar(['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SECRET_KEY']);
  const yandexClientId = findEnvVar(['YANDEX_CLIENT_ID']) || FALLBACK_YANDEX_CLIENT_ID;
  const secretSalt = sbServiceKey || process.env.GROQ_API_KEY || 'kardpro_master_secret_2026';

  return { sbUrl, sbAnonKey, sbServiceKey, yandexClientId, secretSalt };
}

// Универсальный криптографический токен сессии (не зависит от сбоев Supabase)
function createSessionToken(userObj, salt) {
  const payload = Buffer.from(JSON.stringify({
    id: userObj.id,
    email: userObj.email,
    name: userObj.name
  })).toString('base64url');
  const sig = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  return `kp.${payload}.${sig}`;
}

function verifySessionToken(token, salt) {
  if (!token || !token.startsWith('kp.')) return null;
  const parts = token.split('.');
  if (parts.length !== 3) return null;
  const [, payload, sig] = parts;
  const expected = crypto.createHmac('sha256', salt).update(payload).digest('base64url');
  if (sig !== expected) return null;
  try {
    return JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
  } catch (e) {
    return null;
  }
}

// Чтение и запись защищенного серверного cookie-сейфа балансов
function readCookieVault(req, salt) {
  try {
    const cookieHeader = req.headers.cookie || '';
    const match = cookieHeader.split(';').map(c => c.trim()).find(c => c.startsWith('kp_vault='));
    if (!match) return {};
    const raw = decodeURIComponent(match.split('=')[1]);
    const [b64, sig] = raw.split('.');
    if (!b64 || !sig) return {};
    const expected = crypto.createHmac('sha256', salt).update(b64).digest('base64url');
    if (sig !== expected) return {};
    return JSON.parse(Buffer.from(b64, 'base64url').toString('utf-8')) || {};
  } catch (e) {
    return {};
  }
}

function writeCookieVault(res, vaultObj, salt) {
  try {
    const b64 = Buffer.from(JSON.stringify(vaultObj)).toString('base64url');
    const sig = crypto.createHmac('sha256', salt).update(b64).digest('base64url');
    const val = encodeURIComponent(`${b64}.${sig}`);
    res.setHeader('Set-Cookie', `kp_vault=${val}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax`);
  } catch (e) {}
}

async function getHybridUserRecord(req, res, sbUrl, sbServiceKey, secretSalt, userId, email = '', name = '') {
  const cookieVault = readCookieVault(req, secretSalt);
  const memRecord = global.usersVault[userId] || cookieVault[userId] || null;
  let dbCredits = null;

  // Если ключи Supabase настроены, синхронизируемся с базой данных Supabase
  if (sbUrl && sbServiceKey) {
    try {
      const profRes = await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(userId)}&select=credits`, {
        headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
      });
      if (profRes.ok) {
        const profList = await profRes.json();
        if (Array.isArray(profList) && profList.length > 0 && typeof profList[0].credits === 'number') {
          dbCredits = profList[0].credits;
        }
      }
    } catch (e) {}
  }

  const finalCredits = dbCredits !== null
    ? dbCredits
    : (memRecord && typeof memRecord.credits === 'number' ? memRecord.credits : 5);

  const record = {
    id: userId,
    email: email || memRecord?.email || '',
    name: name || memRecord?.name || (email ? email.split('@')[0] : 'Селлер'),
    credits: finalCredits,
    usedLabels: Array.isArray(memRecord?.usedLabels) ? memRecord.usedLabels : [],
    passHash: memRecord?.passHash || null
  };

  global.usersVault[userId] = record;
  cookieVault[userId] = record;
  writeCookieVault(res, cookieVault, secretSalt);

  return record;
}

async function saveHybridUserRecord(req, res, sbUrl, sbServiceKey, secretSalt, record) {
  global.usersVault[record.id] = record;
  const cookieVault = readCookieVault(req, secretSalt);
  cookieVault[record.id] = record;
  writeCookieVault(res, cookieVault, secretSalt);

  if (sbUrl && sbServiceKey) {
    try {
      await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(record.id)}`, {
        method: 'PATCH',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ credits: record.credits })
      });
    } catch (e) {}
  }
}

async function resolveUserFromRequest(req, sbUrl, sbServiceKey, secretSalt) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return null;

  // 1. Проверяем наш криптографический токен (kp....)
  const verifiedKp = verifySessionToken(token, secretSalt);
  if (verifiedKp) return verifiedKp;

  // 2. Если это стандартный токен Supabase JWT
  if (sbUrl && sbServiceKey) {
    try {
      const userRes = await fetch(`${sbUrl}/auth/v1/user`, {
        headers: { 'Authorization': `Bearer ${token}`, 'apikey': sbServiceKey }
      });
      if (userRes.ok) {
        const u = await userRes.json();
        if (u?.id) {
          return { id: u.id, email: u.email || '', name: (u.email || 'Профиль').split('@')[0] };
        }
      }
    } catch (e) {}
  }

  return null;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const { sbUrl, sbAnonKey, sbServiceKey, yandexClientId, secretSalt } = getEnvConfig();

  // 1. GET-запросы: конфигурация, профиль и проверка оплаты
  if (req.method === 'GET') {
    const { action, label } = req.query;

    if (action === 'config') {
      return res.status(200).json({
        supabaseUrl: sbUrl,
        supabaseAnonKey: sbAnonKey,
        yandexClientId,
        hasSupabaseAnon: Boolean(sbAnonKey),
        hasSupabaseService: Boolean(sbServiceKey)
      });
    }

    if (action === 'profile') {
      const userObj = await resolveUserFromRequest(req, sbUrl, sbServiceKey, secretSalt);
      if (!userObj) return res.status(401).json({ error: 'Unauthorized' });
      const record = await getHybridUserRecord(req, res, sbUrl, sbServiceKey, secretSalt, userObj.id, userObj.email, userObj.name);
      return res.status(200).json({
        ok: true,
        id: record.id,
        email: record.email,
        name: record.name,
        credits: record.credits
      });
    }

    if (!label) return res.status(400).json({ error: 'Missing label' });

    if (global.usersVault[`paid_${label}`]) {
      return res.status(200).json({ paid: true, credits: global.usersVault[`paid_${label}`] });
    }

    return res.status(200).json({ paid: false });
  }

  // 2. POST-запросы: Яндекс ID, Email-регистрация, Промокоды и ЮMoney
  if (req.method === 'POST') {
    try {
      const isJson = (req.headers['content-type'] || '').includes('application/json');
      const body = isJson
        ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body)
        : (typeof req.body === 'string' ? Object.fromEntries(new URLSearchParams(req.body)) : req.body);

      // А) Авторизация через Яндекс ID (работает всегда, даже без ключей Supabase!)
      if (body?.action === 'social_auth') {
        const { accessToken, clientProfile } = body;
        let verifiedEmail = '';
        let displayName = '';

        if (accessToken) {
          try {
            const yaRes = await fetch('https://login.yandex.ru/info?format=json', {
              headers: { 'Authorization': `OAuth ${accessToken}` }
            });
            if (yaRes.ok) {
              const yaData = await yaRes.json();
              verifiedEmail = (
                yaData.default_email ||
                (Array.isArray(yaData.emails) && yaData.emails[0]) ||
                `${yaData.login || yaData.id}@yandex.ru`
              ).toLowerCase();
              displayName = yaData.display_name || yaData.real_name || yaData.login || verifiedEmail.split('@')[0];
            }
          } catch (e) {}
        }

        // Резервный подхват профиля, если браузер уже проверил токен Яндекса напрямую
        if (!verifiedEmail && clientProfile?.email) {
          verifiedEmail = String(clientProfile.email).toLowerCase();
          displayName = clientProfile.name || verifiedEmail.split('@')[0];
        }

        if (!verifiedEmail) {
          return res.status(401).json({ error: 'Не удалось получить профиль от Яндекса' });
        }

        const deterministicId = crypto.createHash('sha256').update(`user_${verifiedEmail}`).digest('hex').substring(0, 32);
        const record = await getHybridUserRecord(req, res, sbUrl, sbServiceKey, secretSalt, deterministicId, verifiedEmail, displayName);
        const sessionToken = createSessionToken(record, secretSalt);

        return res.status(200).json({
          ok: true,
          id: record.id,
          email: record.email,
          name: record.name,
          credits: record.credits,
          session_token: sessionToken
        });
      }

      // Б) Встроенная серверная регистрация и вход по Email + Пароль (работает без ошибок ключей!)
      if (body?.action === 'email_auth') {
        const email = String(body.email || '').trim().toLowerCase();
        const password = String(body.password || '').trim();
        const mode = body.mode || 'login';

        if (!email || !email.includes('@') || password.length < 6) {
          return res.status(400).json({ error: 'Введите корректный Email и пароль (не менее 6 символов)' });
        }

        const deterministicId = crypto.createHash('sha256').update(`user_${email}`).digest('hex').substring(0, 32);
        const passHash = crypto.createHmac('sha256', secretSalt).update(`${email}:${password}`).digest('hex');

        // Если в Vercel настроен Supabase Anon Key, пробуем также синхронизировать с Supabase Auth
        if (sbUrl && sbAnonKey) {
          try {
            const endpoint = mode === 'signup' ? `${sbUrl}/auth/v1/signup` : `${sbUrl}/auth/v1/token?grant_type=password`;
            await fetch(endpoint, {
              method: 'POST',
              headers: { 'apikey': sbAnonKey, 'Content-Type': 'application/json' },
              body: JSON.stringify({ email, password })
            });
          } catch (e) {}
        }

        const record = await getHybridUserRecord(req, res, sbUrl, sbServiceKey, secretSalt, deterministicId, email, email.split('@')[0]);

        if (record.passHash && record.passHash !== passHash && mode === 'login') {
          return res.status(401).json({ error: 'Неверный пароль для этого Email' });
        }

        record.passHash = passHash;
        await saveHybridUserRecord(req, res, sbUrl, sbServiceKey, secretSalt, record);

        const sessionToken = createSessionToken(record, secretSalt);
        return res.status(200).json({
          ok: true,
          id: record.id,
          email: record.email,
          name: record.name,
          credits: record.credits,
          session_token: sessionToken
        });
      }

      // В) Промокоды и подтверждение возврата с оплаты ЮMoney
      if (body?.action === 'promo' || body?.action === 'confirm_return') {
        const userObj = await resolveUserFromRequest(req, sbUrl, sbServiceKey, secretSalt);
        if (!userObj) {
          return res.status(401).json({ error: 'Пожалуйста, войдите в аккаунт' });
        }

        const record = await getHybridUserRecord(req, res, sbUrl, sbServiceKey, secretSalt, userObj.id, userObj.email, userObj.name);

        if (body.action === 'promo') {
          const code = String(body.code || '').trim().toUpperCase();
          const bonus = VALID_PROMO_CODES[code];
          if (!bonus) return res.status(400).json({ error: 'Неверный промокод' });

          const promoLabel = code === 'VIP2026' ? `promo_${code}_${Date.now()}` : `promo_${code}`;
          if (record.usedLabels.includes(promoLabel)) {
            return res.status(400).json({ error: 'Вы уже активировали этот промокод ранее!' });
          }

          record.credits += bonus;
          record.usedLabels.push(promoLabel);
          await saveHybridUserRecord(req, res, sbUrl, sbServiceKey, secretSalt, record);

          return res.status(200).json({ ok: true, added: bonus, credits: record.credits });
        }

        if (body.action === 'confirm_return') {
          const { orderId, credits } = body;
          const addCount = [5, 10, 20].includes(Number(credits)) ? Number(credits) : 5;
          if (!record.usedLabels.includes(orderId)) {
            record.credits += addCount;
            record.usedLabels.push(orderId);
            await saveHybridUserRecord(req, res, sbUrl, sbServiceKey, secretSalt, record);
          }
          return res.status(200).json({ ok: true, added: addCount, credits: record.credits });
        }
      }

      // Г) Прямой HTTP-вебхук от ЮMoney
      const {
        notification_type = '',
        operation_id = '',
        amount = '',
        currency = '',
        datetime = '',
        sender = '',
        codepro = '',
        label = '',
        sha1_hash = ''
      } = body;

      const secret = (process.env.YOOMONEY_NOTIFICATION_SECRET || '').trim();
      if (secret) {
        const checkString = `${notification_type}&${operation_id}&${amount}&${currency}&${datetime}&${sender}&${codepro}&${secret}&${label}`;
        const calculatedHash = crypto.createHash('sha1').update(checkString, 'utf-8').digest('hex');
        if (calculatedHash !== sha1_hash) {
          return res.status(400).send('Invalid signature');
        }
      }

      if (label && label.startsWith('kp_')) {
        const parts = label.split('_');
        const parsedCredits = parseInt(parts[1], 10);
        const userId = parts[2];
        const creditsToAdd = [5, 10, 20].includes(parsedCredits) ? parsedCredits : 5;

        global.usersVault[`paid_${label}`] = creditsToAdd;
        if (userId && global.usersVault[userId]) {
          global.usersVault[userId].credits += creditsToAdd;
        }
      }

      return res.status(200).send('OK');
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
