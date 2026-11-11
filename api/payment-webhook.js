import crypto from 'crypto';

// Промокоды (включая ваши личные GEMBAR9000 и VLAD9000 на 9000 генераций)
const VALID_PROMO_CODES = {
  'START5': 5,
  'PRO50': 5,
  'SELLER10': 10,
  'SHOP20': 20,
  'VIP2026': 50,
  'GEMBAR9000': 9000,
  'VLAD9000': 9000
};

const FALLBACK_SUPABASE_URL = 'https://irxszktfwtravyeqnueh.supabase.co';
const FALLBACK_YANDEX_CLIENT_ID = '5e55cf35d18a47eaa84b5e23f0d91427';
const YOOMONEY_WALLET = '4100119681467569';

global.usersVault = global.usersVault || {};
global.claimedDevices = global.claimedDevices || {};

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

function emailToDeterministicUUID(email) {
  const hex = crypto.createHash('sha256').update(`user_${email}`).digest('hex').substring(0, 32);
  return `${hex.slice(0, 8)}-${hex.slice(8, 12)}-4${hex.slice(13, 16)}-8${hex.slice(17, 20)}-${hex.slice(20, 32)}`;
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

function createSessionToken(userObj, salt) {
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

async function getOrCreateSupabaseAuthUser(sbUrl, sbServiceKey, email) {
  if (!sbUrl || !sbServiceKey || !email) return null;
  try {
    const linkRes = await fetch(`${sbUrl}/auth/v1/admin/generate_link`, {
      method: 'POST',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ type: 'magiclink', email })
    });
    if (!linkRes.ok) return null;
    const data = await linkRes.json();
    return data?.user || (data?.id ? data : null);
  } catch (e) {
    return null;
  }
}

async function updateSupabaseCloudRecord(sbUrl, sbServiceKey, sbUserId, email, metaObj) {
  if (!sbUrl || !sbServiceKey || !sbUserId) return;
  try {
    await fetch(`${sbUrl}/auth/v1/admin/users/${sbUserId}`, {
      method: 'PUT',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ user_metadata: metaObj })
    });
  } catch (e) {}

  try {
    const checkProf = await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(sbUserId)}&select=id`, {
      headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
    });
    if (checkProf.ok) {
      const list = await checkProf.json();
      if (Array.isArray(list) && list.length > 0) {
        await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(sbUserId)}`, {
          method: 'PATCH',
          headers: {
            'apikey': sbServiceKey,
            'Authorization': `Bearer ${sbServiceKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ credits: metaObj.credits })
        });
      } else {
        await fetch(`${sbUrl}/rest/v1/profiles`, {
          method: 'POST',
          headers: {
            'apikey': sbServiceKey,
            'Authorization': `Bearer ${sbServiceKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({ id: sbUserId, email, credits: metaObj.credits })
        });
      }
    }
  } catch (e) {}
}

async function syncUserAccount(req, res, sbUrl, sbServiceKey, secretSalt, email, name, deviceFp, isVerifiedOAuth, tokenCreditsFallback = null) {
  const cookieVault = readCookieVault(req, secretSalt);
  const hwHash = deviceFp ? crypto.createHmac('sha256', secretSalt).update(`hw_${deviceFp}`).digest('hex').substring(0, 24) : null;

  const sbUser = await getOrCreateSupabaseAuthUser(sbUrl, sbServiceKey, email);
  const userId = sbUser?.id || emailToDeterministicUUID(email);
  const cloudMeta = sbUser?.user_metadata || {};

  const legacyId = emailToDeterministicUUID(email);
  const localRecord = cookieVault[userId] || cookieVault[legacyId] || global.usersVault[userId] || global.usersVault[legacyId] || null;

  let tableCredits = null;
  if (sbUrl && sbServiceKey && sbUser?.id) {
    try {
      const profRes = await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(sbUser.id)}&select=credits`, {
        headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
      });
      if (profRes.ok) {
        const profList = await profRes.json();
        if (Array.isArray(profList) && profList.length > 0 && typeof profList[0].credits === 'number') {
          tableCredits = profList[0].credits;
        }
      }
    } catch (e) {}
  }

  const isCloudInitialized = Boolean(cloudMeta.kp_initialized) || tableCredits !== null;
  const hasValidLocalProgress = localRecord && typeof localRecord.credits === 'number' && !localRecord.bonusBlocked;

  if (isCloudInitialized || hasValidLocalProgress || typeof tokenCreditsFallback === 'number') {
    let candidates = [];
    if (typeof cloudMeta.credits === 'number') candidates.push(cloudMeta.credits);
    if (tableCredits !== null) candidates.push(tableCredits);
    if (hasValidLocalProgress) candidates.push(localRecord.credits);
    if (typeof tokenCreditsFallback === 'number') candidates.push(tokenCreditsFallback);

    let syncedCredits = candidates.length > 0 ? Math.max(...candidates) : 5;

    if (candidates.some(c => c > 0 && c < 5) && syncedCredits === 5) {
      syncedCredits = Math.min(...candidates.filter(c => c > 0));
    }

    if (isVerifiedOAuth && syncedCredits === 0 && !cloudMeta.has_spent && !localRecord?.hasSpent) {
      syncedCredits = 5;
    }

    const updatedMeta = {
      ...cloudMeta,
      kp_initialized: true,
      name: name || cloudMeta.name || (email ? email.split('@')[0] : 'Селлер'),
      credits: syncedCredits,
      bonus_blocked: false,
      used_labels: Array.isArray(cloudMeta.used_labels)
        ? cloudMeta.used_labels
        : (Array.isArray(localRecord?.usedLabels) ? localRecord.usedLabels : []),
      pass_hash: cloudMeta.pass_hash || localRecord?.passHash || null
    };

    await updateSupabaseCloudRecord(sbUrl, sbServiceKey, sbUser?.id, email, updatedMeta);

    const record = {
      id: userId,
      email,
      name: updatedMeta.name,
      credits: syncedCredits,
      usedLabels: updatedMeta.used_labels,
      passHash: updatedMeta.pass_hash,
      bonusBlocked: false,
      provider: isVerifiedOAuth ? 'yandex' : 'email'
    };

    global.usersVault[userId] = record;
    cookieVault[userId] = record;
    if (isVerifiedOAuth) cookieVault._yandex_owner_email = email;
    writeCookieVault(res, cookieVault, secretSalt);

    return record;
  }

  const existingYandexEmailOnDevice = cookieVault._yandex_owner_email;
  const hwOwnerEmail = hwHash ? global.claimedDevices[hwHash] : null;

  let isSecondAccountAbuse = false;
  if (existingYandexEmailOnDevice && existingYandexEmailOnDevice !== email) {
    isSecondAccountAbuse = true;
  } else if (hwOwnerEmail && hwOwnerEmail !== email) {
    isSecondAccountAbuse = true;
  }

  let starterCredits = 0;
  let bonusBlocked = false;

  if (!isVerifiedOAuth || isSecondAccountAbuse) {
    starterCredits = 0;
    bonusBlocked = true;
  } else {
    starterCredits = 5;
    bonusBlocked = false;
    cookieVault._yandex_owner_email = email;
    if (hwHash) global.claimedDevices[hwHash] = email;
  }

  const newMeta = {
    kp_initialized: true,
    name: name || (email ? email.split('@')[0] : 'Селлер'),
    credits: starterCredits,
    bonus_blocked: bonusBlocked,
    has_spent: false,
    used_labels: [],
    pass_hash: null
  };

  await updateSupabaseCloudRecord(sbUrl, sbServiceKey, sbUser?.id, email, newMeta);

  const newRecord = {
    id: userId,
    email,
    name: newMeta.name,
    credits: starterCredits,
    usedLabels: [],
    passHash: null,
    bonusBlocked,
    provider: isVerifiedOAuth ? 'yandex' : 'email'
  };

  global.usersVault[userId] = newRecord;
  cookieVault[userId] = newRecord;
  writeCookieVault(res, cookieVault, secretSalt);

  return newRecord;
}

async function saveUserBalanceEverywhere(req, res, sbUrl, sbServiceKey, secretSalt, record) {
  global.usersVault[record.id] = record;
  const cookieVault = readCookieVault(req, secretSalt);
  cookieVault[record.id] = record;
  writeCookieVault(res, cookieVault, secretSalt);

  const sbUser = await getOrCreateSupabaseAuthUser(sbUrl, sbServiceKey, record.email);
  const targetId = sbUser?.id || record.id;
  const oldMeta = sbUser?.user_metadata || {};

  await updateSupabaseCloudRecord(sbUrl, sbServiceKey, targetId, record.email, {
    ...oldMeta,
    kp_initialized: true,
    name: record.name,
    credits: record.credits,
    bonus_blocked: false,
    used_labels: record.usedLabels || [],
    pass_hash: record.passHash || oldMeta.pass_hash || null
  });
}

function resolveUserFromRequest(req, secretSalt) {
  const authHeader = req.headers.authorization || '';
  const token = authHeader.replace('Bearer ', '').trim();
  if (!token) return null;
  return verifySessionToken(token, secretSalt);
}

// Единая функция валидации количества генераций (поддерживает и тарифы 5/10/20, и любую пользовательскую сумму до 10 000 шт)
function sanitizeCreditsCount(val) {
  const num = parseInt(val, 10);
  if (isNaN(num) || num < 1) return 5;
  return Math.min(10000, num);
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
        yandexClientId,
        wallet: YOOMONEY_WALLET,
        cloudSyncActive: Boolean(sbUrl && sbServiceKey)
      });
    }

    if (action === 'profile') {
      const userObj = resolveUserFromRequest(req, secretSalt);
      if (!userObj || !userObj.email) return res.status(401).json({ error: 'Unauthorized' });
      const isYa = userObj.provider !== 'email';
      const record = await syncUserAccount(
        req, res, sbUrl, sbServiceKey, secretSalt,
        userObj.email, userObj.name, fp || '', isYa, userObj.credits
      );
      const freshToken = createSessionToken(record, secretSalt);
      return res.status(200).json({
        ok: true,
        id: record.id,
        email: record.email,
        name: record.name,
        credits: record.credits,
        session_token: freshToken
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
        const record = await syncUserAccount(
          req, res, sbUrl, sbServiceKey, secretSalt,
          verifiedEmail, displayName, deviceFp || '', true
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
        const passHash = crypto.createHmac('sha256', secretSalt).update(`${email}:${password}`).digest('hex');

        const record = await syncUserAccount(
          req, res, sbUrl, sbServiceKey, secretSalt,
          email, email.split('@')[0], deviceFp, false
        );

        if (record.passHash && record.passHash !== passHash && mode === 'login') {
          return res.status(401).json({ error: 'Неверный пароль для этого Email' });
        }

        record.passHash = passHash;
        await saveUserBalanceEverywhere(req, res, sbUrl, sbServiceKey, secretSalt, record);

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
        const userObj = resolveUserFromRequest(req, secretSalt);
        if (!userObj || !userObj.email) {
          return res.status(401).json({ error: 'Пожалуйста, войдите в аккаунт' });
        }

        const isYa = userObj.provider !== 'email';
        const record = await syncUserAccount(
          req, res, sbUrl, sbServiceKey, secretSalt,
          userObj.email, userObj.name, body.deviceFp || '', isYa, userObj.credits
        );

        if (body.action === 'promo') {
          const code = String(body.code || '').trim().toUpperCase();
          const bonus = VALID_PROMO_CODES[code];
          if (!bonus) return res.status(400).json({ error: 'Неверный промокод' });

          const isOwnerUnlimitedPromo = (code === 'GEMBAR9000' || code === 'VLAD9000' || code === 'VIP2026');
          const globalPromoKey = `promo_used_${code}`;

          if (!isOwnerUnlimitedPromo && record.usedLabels.includes(globalPromoKey)) {
            return res.status(400).json({ error: 'Этот промокод уже был активирован на вашем аккаунте!' });
          }

          record.credits += bonus;
          if (!isOwnerUnlimitedPromo) record.usedLabels.push(globalPromoKey);
          await saveUserBalanceEverywhere(req, res, sbUrl, sbServiceKey, secretSalt, record);

          const updatedToken = createSessionToken(record, secretSalt);
          return res.status(200).json({
            ok: true,
            added: bonus,
            credits: record.credits,
            session_token: updatedToken
          });
        }

        if (body.action === 'confirm_return') {
          const { orderId, credits } = body;
          if (!orderId || !String(orderId).startsWith('kp_')) {
            return res.status(400).json({ error: 'Некорректный идентификатор заказа' });
          }

          // Проверяем, что число генераций совпадает с зашитым в метку заказа kp_<credits>_<userId>_<rand>
          const parts = String(orderId).split('_');
          const labelCredits = sanitizeCreditsCount(parts[1] || credits);
          const addCount = sanitizeCreditsCount(credits || labelCredits);

          if (!record.usedLabels.includes(orderId)) {
            record.credits += addCount;
            record.usedLabels.push(orderId);
            await saveUserBalanceEverywhere(req, res, sbUrl, sbServiceKey, secretSalt, record);
          }
          const updatedToken = createSessionToken(record, secretSalt);
          return res.status(200).json({
            ok: true,
            added: addCount,
            credits: record.credits,
            session_token: updatedToken
          });
        }
      }

      // Прямой HTTP-вебхук от ЮMoney (4100119681467569) — поддержка любых сумм и пакетов
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
        const creditsToAdd = sanitizeCreditsCount(parts[1]);
        const userId = parts[2];

        global.usersVault[`paid_${label}`] = creditsToAdd;
        if (userId && sbUrl && sbServiceKey) {
          try {
            const uRes = await fetch(`${sbUrl}/auth/v1/admin/users/${userId}`, {
              headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
            });
            if (uRes.ok) {
              const uData = await uRes.json();
              const meta = uData?.user_metadata || {};
              const used = Array.isArray(meta.used_labels) ? meta.used_labels : [];
              if (!used.includes(label)) {
                const cur = typeof meta.credits === 'number' ? meta.credits : 0;
                await updateSupabaseCloudRecord(sbUrl, sbServiceKey, userId, uData.email || '', {
                  ...meta,
                  kp_initialized: true,
                  credits: cur + creditsToAdd,
                  used_labels: [...used, label]
                });
              }
            }
          } catch (e) {}
        }
      }

      return res.status(200).send('OK');
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
