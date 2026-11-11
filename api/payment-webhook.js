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
global.claimedDevices = global.claimedDevices || {}; // hwHash -> ownerEmail

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
    provider: userObj.provider || 'yandex'
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
    const match = cookieHeader.split(';').map(c => c.trim()).find(c => c.startsWith('kp_vault_v3='));
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
    res.setHeader('Set-Cookie', `kp_vault_v3=${val}; Path=/; Max-Age=31536000; HttpOnly; SameSite=Lax`);
  } catch (e) {}
}

// Облачная синхронизация пользователя через системную таблицу auth.users и profiles в Supabase
async function fetchCloudUserState(sbUrl, sbAnonKey, sbServiceKey, secretSalt, email) {
  if (!sbUrl) return null;

  // 1. Попытка через Admin API (если задан SUPABASE_SERVICE_ROLE_KEY / SUPABASE_SECRET_KEY)
  if (sbServiceKey) {
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
      if (linkRes.ok) {
        const linkData = await linkRes.json();
        const u = linkData?.user || linkData;
        if (u?.id) {
          const meta = u.user_metadata || {};
          // Также проверяем таблицу profiles по реальному UUID из auth.users
          let profCredits = null;
          try {
            const pRes = await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${u.id}&select=credits`, {
              headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
            });
            if (pRes.ok) {
              const pList = await pRes.json();
              if (Array.isArray(pList) && pList.length > 0 && typeof pList[0].credits === 'number') {
                profCredits = pList[0].credits;
              }
            }
          } catch (e) {}

          const isInitialized = Boolean(meta.kp_init);
          const credits = typeof meta.credits === 'number'
            ? meta.credits
            : (profCredits !== null ? profCredits : null);

          return {
            supabaseUid: u.id,
            isInitialized,
            credits,
            genCount: meta.gen_count || 0,
            usedLabels: Array.isArray(meta.used_labels) ? meta.used_labels : [],
            passHash: meta.pass_hash || null,
            mode: 'admin'
          };
        }
      }
    } catch (e) {}
  }

  // 2. Резервная синхронизация через публичный SUPABASE_ANON_KEY (работает даже без Service Role Key!)
  const activeKey = sbAnonKey || sbServiceKey;
  if (activeKey) {
    try {
      const autoPassword = 'Kp!' + crypto.createHmac('sha256', secretSalt).update(`cloud_sync_${email}`).digest('hex').substring(0, 20);
      let tokenRes = await fetch(`${sbUrl}/auth/v1/token?grant_type=password`, {
        method: 'POST',
        headers: { 'apikey': activeKey, 'Content-Type': 'application/json' },
        body: JSON.stringify({ email, password: autoPassword })
      });

      if (!tokenRes.ok) {
        await fetch(`${sbUrl}/auth/v1/signup`, {
          method: 'POST',
          headers: { 'apikey': activeKey, 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password: autoPassword })
        });
        tokenRes = await fetch(`${sbUrl}/auth/v1/token?grant_type=password`, {
          method: 'POST',
          headers: { 'apikey': activeKey, 'Content-Type': 'application/json' },
          body: JSON.stringify({ email, password: autoPassword })
        });
      }

      if (tokenRes.ok) {
        const tokenData = await tokenRes.json();
        const u = tokenData?.user;
        const userJwt = tokenData?.access_token;
        if (u?.id && userJwt) {
          const meta = u.user_metadata || {};
          return {
            supabaseUid: u.id,
            userJwt,
            isInitialized: Boolean(meta.kp_init),
            credits: typeof meta.credits === 'number' ? meta.credits : null,
            genCount: meta.gen_count || 0,
            usedLabels: Array.isArray(meta.used_labels) ? meta.used_labels : [],
            passHash: meta.pass_hash || null,
            mode: 'user_jwt'
          };
        }
      }
    } catch (e) {}
  }

  return null;
}

async function saveCloudUserState(sbUrl, sbAnonKey, sbServiceKey, cloudState, record) {
  if (!sbUrl || !cloudState) return;

  const metaPayload = {
    kp_init: true,
    credits: record.credits,
    gen_count: record.genCount || 0,
    used_labels: (record.usedLabels || []).slice(-40),
    pass_hash: record.passHash || null
  };

  if (cloudState.mode === 'admin' && sbServiceKey && cloudState.supabaseUid) {
    try {
      await fetch(`${sbUrl}/auth/v1/admin/users/${cloudState.supabaseUid}`, {
        method: 'PUT',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ user_metadata: metaPayload })
      });
    } catch (e) {}

    try {
      await fetch(`${sbUrl}/rest/v1/profiles`, {
        method: 'POST',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json',
          'Prefer': 'resolution=merge-duplicates'
        },
        body: JSON.stringify({
          id: cloudState.supabaseUid,
          email: record.email,
          credits: record.credits
        })
      });
    } catch (e) {}
  } else if (cloudState.mode === 'user_jwt' && cloudState.userJwt) {
    const activeKey = sbAnonKey || sbServiceKey;
    try {
      await fetch(`${sbUrl}/auth/v1/user`, {
        method: 'PUT',
        headers: {
          'apikey': activeKey,
          'Authorization': `Bearer ${cloudState.userJwt}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ data: metaPayload })
      });
    } catch (e) {}
  }
}

// Загрузка или инициализация профиля с поддержкой кросс-девайс синхронизации (Телефон <-> ПК)
async function getOrSyncUserAccount(req, res, cfg, rawEmail, name, deviceFp, provider) {
  const { sbUrl, sbAnonKey, sbServiceKey, secretSalt } = cfg;
  const email = normalizeEmail(rawEmail);
  const userId = emailToDeterministicUUID(email);
  const isYandex = provider === 'yandex';

  const cookieVault = readCookieVault(req, secretSalt);
  const hwHash = deviceFp ? crypto.createHmac('sha256', secretSalt).update(`hw_${deviceFp}`).digest('hex').substring(0, 24) : null;

  // 1. Запрашиваем актуальное состояние аккаунта из облачной базы Supabase
  const cloudState = await fetchCloudUserState(sbUrl, sbAnonKey, sbServiceKey, secretSalt, email);
  const memRecord = global.usersVault[email] || cookieVault[email] || null;

  const accountExists = Boolean(
    (cloudState && cloudState.isInitialized && typeof cloudState.credits === 'number') ||
    (memRecord && memRecord.isInitialized && typeof memRecord.credits === 'number')
  );

  // А) Если этот аккаунт УЖЕ существует (например, вы вошли на телефоне, а теперь открыли ПК)
  if (accountExists) {
    let syncedCredits = (cloudState && typeof cloudState.credits === 'number')
      ? cloudState.credits
      : memRecord.credits;

    const genCount = Math.max(cloudState?.genCount || 0, memRecord?.genCount || 0);

    // Авто-восстановление, если из-за старого бага аккаунту Яндекса был ошибочно записан 0 при 0 генераций
    if (isYandex && syncedCredits === 0 && genCount === 0 && !memRecord?.bonusBlocked) {
      syncedCredits = 5;
    }

    const record = {
      id: cloudState?.supabaseUid || userId,
      email,
      name: name || memRecord?.name || email.split('@')[0],
      provider,
      isInitialized: true,
      credits: syncedCredits,
      genCount,
      usedLabels: cloudState?.usedLabels?.length ? cloudState.usedLabels : (memRecord?.usedLabels || []),
      passHash: cloudState?.passHash || memRecord?.passHash || null,
      bonusBlocked: false
    };

    if (isYandex && syncedCredits > 0) {
      cookieVault._bonus_owner_email = cookieVault._bonus_owner_email || email;
      if (hwHash && !global.claimedDevices[hwHash]) global.claimedDevices[hwHash] = email;
    }

    global.usersVault[email] = record;
    cookieVault[email] = record;
    writeCookieVault(res, cookieVault, secretSalt);
    await saveCloudUserState(sbUrl, sbAnonKey, sbServiceKey, cloudState, record);

    return record;
  }

  // Б) Это совершенно НОВЫЙ аккаунт. Проверяем антифрод только по текущему устройству (Hardware FP + Cookie)
  const cookieOwnerEmail = cookieVault._bonus_owner_email;
  const hwOwnerEmail = hwHash ? global.claimedDevices[hwHash] : null;

  let alreadyClaimedByOtherAccountOnThisDevice = false;
  if (cookieOwnerEmail && cookieOwnerEmail !== email) alreadyClaimedByOtherAccountOnThisDevice = true;
  if (hwOwnerEmail && hwOwnerEmail !== email) alreadyClaimedByOtherAccountOnThisDevice = true;

  let starterCredits = 0;
  let bonusBlocked = false;

  if (!isYandex) {
    // Регистрация по обычному Email/Паролю не дает бесплатных генераций (защита от генераторов фейковых почт)
    starterCredits = 0;
    bonusBlocked = true;
  } else if (alreadyClaimedByOtherAccountOnThisDevice) {
    // На ЭТОМ ЖЕ физическом устройстве уже получали бонус на другой аккаунт Яндекса
    starterCredits = 0;
    bonusBlocked = true;
  } else {
    starterCredits = 5;
    cookieVault._bonus_owner_email = email;
    if (hwHash) global.claimedDevices[hwHash] = email;
  }

  const newRecord = {
    id: cloudState?.supabaseUid || userId,
    email,
    name: name || email.split('@')[0],
    provider,
    isInitialized: true,
    credits: starterCredits,
    genCount: 0,
    usedLabels: [],
    passHash: null,
    bonusBlocked
  };

  global.usersVault[email] = newRecord;
  cookieVault[email] = newRecord;
  writeCookieVault(res, cookieVault, secretSalt);
  await saveCloudUserState(sbUrl, sbAnonKey, sbServiceKey, cloudState, newRecord);

  return newRecord;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Cache-Control', 'no-store, no-cache, must-revalidate, proxy-revalidate');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const cfg = getEnvConfig();
  const { sbUrl, sbAnonKey, sbServiceKey, yandexClientId, secretSalt } = cfg;

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
      const authHeader = req.headers.authorization || '';
      const token = authHeader.replace('Bearer ', '').trim();
      const userObj = verifySessionToken(token, secretSalt);
      if (!userObj || !userObj.email) return res.status(401).json({ error: 'Unauthorized' });

      const record = await getOrSyncUserAccount(
        req, res, cfg,
        userObj.email, userObj.name, fp || '', userObj.provider || 'yandex'
      );
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

      // А) Авторизация через Яндекс ID (Единый баланс между телефоном и ПК)
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

        const record = await getOrSyncUserAccount(req, res, cfg, rawEmail, displayName, deviceFp || '', 'yandex');
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

      // Б) Вход по Email + Пароль
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

        const record = await getOrSyncUserAccount(req, res, cfg, email, email.split('@')[0], deviceFp, 'email');

        if (record.passHash && record.passHash !== passHash && mode === 'login') {
          return res.status(401).json({ error: 'Неверный пароль для этого Email' });
        }

        record.passHash = passHash;
        const cloudState = await fetchCloudUserState(sbUrl, sbAnonKey, sbServiceKey, secretSalt, email);
        await saveCloudUserState(sbUrl, sbAnonKey, sbServiceKey, cloudState, record);

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

      // В) Промокоды и подтверждение оплаты
      if (body?.action === 'promo' || body?.action === 'confirm_return') {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.replace('Bearer ', '').trim();
        const userObj = verifySessionToken(token, secretSalt);
        if (!userObj || !userObj.email) {
          return res.status(401).json({ error: 'Пожалуйста, войдите в аккаунт' });
        }

        const record = await getOrSyncUserAccount(
          req, res, cfg,
          userObj.email, userObj.name, body.deviceFp || '', userObj.provider || 'yandex'
        );

        if (body.action === 'promo') {
          const code = String(body.code || '').trim().toUpperCase();
          const bonus = VALID_PROMO_CODES[code];
          if (!bonus) return res.status(400).json({ error: 'Неверный промокод' });

          const cookieVault = readCookieVault(req, secretSalt);
          const globalPromoKey = `promo_used_${code}`;

          if (code !== 'VIP2026' && (record.usedLabels.includes(globalPromoKey) || cookieVault[globalPromoKey])) {
            return res.status(400).json({ error: 'Этот промокод уже был активирован на вашем аккаунте!' });
          }

          record.credits += bonus;
          record.usedLabels.push(globalPromoKey);
          cookieVault[globalPromoKey] = true;
          cookieVault[record.email] = record;
          global.usersVault[record.email] = record;
          writeCookieVault(res, cookieVault, secretSalt);

          const cloudState = await fetchCloudUserState(sbUrl, sbAnonKey, sbServiceKey, secretSalt, record.email);
          await saveCloudUserState(sbUrl, sbAnonKey, sbServiceKey, cloudState, record);

          return res.status(200).json({ ok: true, added: bonus, credits: record.credits });
        }

        if (body.action === 'confirm_return') {
          const { orderId, credits } = body;
          const addCount = [5, 10, 20].includes(Number(credits)) ? Number(credits) : 5;
          if (!record.usedLabels.includes(orderId)) {
            record.credits += addCount;
            record.usedLabels.push(orderId);
            const cookieVault = readCookieVault(req, secretSalt);
            cookieVault[record.email] = record;
            global.usersVault[record.email] = record;
            writeCookieVault(res, cookieVault, secretSalt);

            const cloudState = await fetchCloudUserState(sbUrl, sbAnonKey, sbServiceKey, secretSalt, record.email);
            await saveCloudUserState(sbUrl, sbAnonKey, sbServiceKey, cloudState, record);
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
        const creditsToAdd = [5, 10, 20].includes(parsedCredits) ? parsedCredits : 5;
        global.usersVault[`paid_${label}`] = creditsToAdd;
      }

      return res.status(200).send('OK');
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
