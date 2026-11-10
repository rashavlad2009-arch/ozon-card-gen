import crypto from 'crypto';

const VALID_PROMO_CODES = {
  'START5': 5,
  'PRO50': 5,
  'SELLER10': 10,
  'SHOP20': 20,
  'VIP2026': 50
};

const FALLBACK_SUPABASE_URL = 'https://irxszktfwtravyeqnueh.supabase.co';
const FALLBACK_YANDEX_CLIENT_ID = '5e55cf35d18a47eaa84b5e23f0d91427';

global.usersVault = global.usersVault || {};
global.claimedDevices = global.claimedDevices || {};
global.claimedIps = global.claimedIps || {};

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

function normalizeEmail(rawEmail) {
  const clean = String(rawEmail || '').trim().toLowerCase();
  if (!clean.includes('@')) return clean;
  let [local, domain] = clean.split('@');
  local = local.split('+')[0];

  const yandexDomains = ['ya.ru', 'yandex.com', 'yandex.by', 'yandex.kz', 'yandex.ua', 'narod.ru'];
  if (yandexDomains.includes(domain)) {
    domain = 'yandex.ru';
  }
  if (domain === 'gmail.com' || domain === 'yandex.ru') {
    local = local.replace(/\./g, '').replace(/-/g, '');
  }
  return `${local}@${domain}`;
}

function getClientIpHash(req, salt) {
  const forwarded = req.headers['x-forwarded-for'] || req.headers['x-real-ip'] || '';
  const ip = String(forwarded).split(',')[0].trim() || req.socket?.remoteAddress || 'unknown_ip';
  return crypto.createHmac('sha256', salt).update(`ip_${ip}`).digest('hex').substring(0, 24);
}

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

async function getOrInitUserWithAntiAbuse(req, res, sbUrl, sbServiceKey, secretSalt, userId, email, name, deviceFp, isVerifiedOAuth) {
  const cookieVault = readCookieVault(req, secretSalt);
  const ipHash = getClientIpHash(req, secretSalt);
  const hwHash = deviceFp ? crypto.createHmac('sha256', secretSalt).update(`hw_${deviceFp}`).digest('hex').substring(0, 24) : null;

  const existingRecord = global.usersVault[userId] || cookieVault[userId] || null;
  let dbCredits = null;

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

  if (existingRecord !== null || dbCredits !== null) {
    const currentCredits = dbCredits !== null
      ? dbCredits
      : (typeof existingRecord.credits === 'number' ? existingRecord.credits : 0);

    const record = {
      id: userId,
      email: email || existingRecord?.email || '',
      name: name || existingRecord?.name || (email ? email.split('@')[0] : 'Селлер'),
      credits: currentCredits,
      usedLabels: Array.isArray(existingRecord?.usedLabels) ? existingRecord.usedLabels : [],
      passHash: existingRecord?.passHash || null,
      bonusBlocked: false
    };

    if (currentCredits > 0 && isVerifiedOAuth) {
      cookieVault._bonus_owner_id = cookieVault._bonus_owner_id || userId;
      if (hwHash && !global.claimedDevices[hwHash]) global.claimedDevices[hwHash] = userId;
      if (ipHash && !global.claimedIps[ipHash]) global.claimedIps[ipHash] = userId;
    }

    global.usersVault[userId] = record;
    cookieVault[userId] = record;
    writeCookieVault(res, cookieVault, secretSalt);
    return record;
  }

  const cookieOwner = cookieVault._bonus_owner_id;
  const hwOwner = hwHash ? global.claimedDevices[hwHash] : null;
  const ipOwner = global.claimedIps[ipHash];

  let alreadyClaimedOnDevice = false;
  if (cookieOwner && cookieOwner !== userId) alreadyClaimedOnDevice = true;
  if (hwOwner && hwOwner !== userId) alreadyClaimedOnDevice = true;
  if (ipOwner && ipOwner !== userId) alreadyClaimedOnDevice = true;

  if (!alreadyClaimedOnDevice && sbUrl && sbServiceKey && (hwHash || ipHash)) {
    try {
      const devLabel = `trial_hw_${hwHash || ipHash}`;
      const checkRes = await fetch(`${sbUrl}/rest/v1/payments_log?label=eq.${encodeURIComponent(devLabel)}&select=user_id`, {
        headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
      });
      if (checkRes.ok) {
        const list = await checkRes.json();
        if (Array.isArray(list) && list.length > 0 && list[0].user_id !== userId) {
          alreadyClaimedOnDevice = true;
        }
      }
    } catch (e) {}
  }

  let starterCredits = 0;
  let bonusBlocked = false;

  if (!isVerifiedOAuth || alreadyClaimedOnDevice) {
    starterCredits = 0;
    bonusBlocked = true;
  } else {
    starterCredits = 5;
    cookieVault._bonus_owner_id = userId;
    if (hwHash) global.claimedDevices[hwHash] = userId;
    if (ipHash) global.claimedIps[ipHash] = userId;

    if (sbUrl && sbServiceKey) {
      try {
        const devLabel = `trial_hw_${hwHash || ipHash}`;
        await fetch(`${sbUrl}/rest/v1/payments_log`, {
          method: 'POST',
          headers: {
            'apikey': sbServiceKey,
            'Authorization': `Bearer ${sbServiceKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ label: devLabel, user_id: userId, credits: 5 })
        });
      } catch (e) {}
    }
  }

  const newRecord = {
    id: userId,
    email,
    name: name || (email ? email.split('@')[0] : 'Селлер'),
    credits: starterCredits,
    usedLabels: [],
    passHash: null,
    bonusBlocked
  };

  global.usersVault[userId] = newRecord;
  cookieVault[userId] = newRecord;
  writeCookieVault(res, cookieVault, secretSalt);

  if (sbUrl && sbServiceKey) {
    try {
      await fetch(`${sbUrl}/rest/v1/profiles`, {
        method: 'POST',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ id: userId, email, credits: starterCredits })
      });
    } catch (e) {}
  }

  return newRecord;
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
  return verifySessionToken(token, secretSalt);
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const { sbUrl, sbAnonKey, sbServiceKey, yandexClientId, secretSalt } = getEnvConfig();

  if (req.method === 'GET') {
    const { action, label, fp } = req.query;

    if (action === 'config') {
      return res.status(200).json({
        supabaseUrl: sbUrl,
        supabaseAnonKey: sbAnonKey,
        yandexClientId
      });
    }

    if (action === 'profile') {
      const userObj = await resolveUserFromRequest(req, sbUrl, sbServiceKey, secretSalt);
      if (!userObj) return res.status(401).json({ error: 'Unauthorized' });
      const record = await getOrInitUserWithAntiAbuse(req, res, sbUrl, sbServiceKey, secretSalt, userObj.id, userObj.email, userObj.name, fp || '', true);
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

  if (req.method === 'POST') {
    try {
      const isJson = (req.headers['content-type'] || '').includes('application/json');
      const body = isJson
        ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body)
        : (typeof req.body === 'string' ? Object.fromEntries(new URLSearchParams(req.body)) : req.body);

      if (body?.action === 'social_auth') {
        const { accessToken, clientProfile, deviceFp } = body;
        let rawEmail = '';
        let displayName = '';

        if (accessToken) {
          try {
            const yaRes = await fetch('https://login.yandex.ru/info?format=json', {
              headers: { 'Authorization': `OAuth ${accessToken}` }
            });
            if (yaRes.ok) {
              const yaData = await yaRes.json();
              rawEmail = yaData.default_email || (Array.isArray(yaData.emails) && yaData.emails[0]) || `${yaData.login || yaData.id}@yandex.ru`;
              displayName = yaData.display_name || yaData.real_name || yaData.login || rawEmail.split('@')[0];
            }
          } catch (e) {}
        }

        if (!rawEmail && clientProfile?.email) {
          rawEmail = String(clientProfile.email);
          displayName = clientProfile.name || rawEmail.split('@')[0];
        }

        if (!rawEmail) {
          return res.status(401).json({ error: 'Не удалось получить профиль от Яндекса' });
        }

        const verifiedEmail = normalizeEmail(rawEmail);
        const deterministicId = crypto.createHash('sha256').update(`user_${verifiedEmail}`).digest('hex').substring(0, 32);

        const record = await getOrInitUserWithAntiAbuse(
          req, res, sbUrl, sbServiceKey, secretSalt,
          deterministicId, verifiedEmail, displayName, deviceFp || '', true
        );
        const sessionToken = createSessionToken(record, secretSalt);

        return res.status(200).json({
          ok: true,
          id: record.id,
          email: record.email,
          name: record.name,
          credits: record.credits,
          bonus_blocked: record.bonusBlocked,
          session_token: sessionToken
        });
      }

      if (body?.action === 'email_auth') {
        const rawEmail = String(body.email || '').trim();
        const password = String(body.password || '').trim();
        const mode = body.mode || 'login';
        const deviceFp = body.deviceFp || '';

        if (!rawEmail || !rawEmail.includes('@') || password.length < 6) {
          return res.status(400).json({ error: 'Введите корректный Email и пароль (не менее 6 символов)' });
        }

        const email = normalizeEmail(rawEmail);
        const deterministicId = crypto.createHash('sha256').update(`user_${email}`).digest('hex').substring(0, 32);
        const passHash = crypto.createHmac('sha256', secretSalt).update(`${email}:${password}`).digest('hex');

        const record = await getOrInitUserWithAntiAbuse(
          req, res, sbUrl, sbServiceKey, secretSalt,
          deterministicId, email, email.split('@')[0], deviceFp, false
        );

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
          bonus_blocked: true,
          session_token: sessionToken
        });
      }

      if (body?.action === 'promo' || body?.action === 'confirm_return') {
        const userObj = await resolveUserFromRequest(req, sbUrl, sbServiceKey, secretSalt);
        if (!userObj) {
          return res.status(401).json({ error: 'Пожалуйста, войдите в аккаунт' });
        }

        const record = await getOrInitUserWithAntiAbuse(
          req, res, sbUrl, sbServiceKey, secretSalt,
          userObj.id, userObj.email, userObj.name, body.deviceFp || '', false
        );

        if (body.action === 'promo') {
          const code = String(body.code || '').trim().toUpperCase();
          const bonus = VALID_PROMO_CODES[code];
          if (!bonus) return res.status(400).json({ error: 'Неверный промокод' });

          const cookieVault = readCookieVault(req, secretSalt);
          const globalPromoKey = `promo_used_${code}`;

          if (code !== 'VIP2026' && (record.usedLabels.includes(globalPromoKey) || cookieVault[globalPromoKey])) {
            return res.status(400).json({ error: 'Этот промокод уже был использован на вашем устройстве!' });
          }

          record.credits += bonus;
          record.usedLabels.push(globalPromoKey);
          cookieVault[globalPromoKey] = true;
          writeCookieVault(res, cookieVault, secretSalt);
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
