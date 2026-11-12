import crypto from 'crypto';

const FALLBACK_SUPABASE_URL = 'https://irxszktfravyeqnueh.supabase.co';
const FALLBACK_YANDEX_CLIENT_ID = '5e55cf35d18a47eaa84b5e23f0d91427';
const YOOMONEY_WALLET = '4100119681467569';

const SESSION_TTL_MS = 30 * 24 * 60 * 60 * 1000;
const RATE_WINDOW_MS = 60 * 1000;

const BUILTIN_PROMOS = { 'START5': 5, 'PRO50': 5, 'SELLER10': 10, 'SHOP20': 20, 'VIP2026': 50 };

global.usersVault = global.usersVault || {};
global.claimedDevices = global.claimedDevices || {};
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
  const sbUrl = (findEnvVar(['SUPABASE_URL', 'NEXT_PUBLIC_SUPABASE_URL']) || FALLBACK_SUPABASE_URL).replace(/\/$/, '');
  const sbAnonKey = findEnvVar(['SUPABASE_ANON_KEY', 'NEXT_PUBLIC_SUPABASE_ANON_KEY', 'SUPABASE_PUBLISHABLE_KEY', 'NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY']);
  const sbServiceKey = findEnvVar(['SUPABASE_SERVICE_ROLE_KEY', 'SUPABASE_SECRET_KEY']);
  const yandexClientId = findEnvVar(['YANDEX_CLIENT_ID']) || FALLBACK_YANDEX_CLIENT_ID;
  const secretSalt = findEnvVar(['KARDPRO_SESSION_SALT', 'SESSION_SECRET']) || sbServiceKey;
  const allowedOrigins = (findEnvVar(['ALLOWED_ORIGINS']) || '').split(',').map(s => s.trim()).filter(Boolean);
  return { sbUrl, sbAnonKey, sbServiceKey, yandexClientId, secretSalt, allowedOrigins };
}

function getPromoCodes() {
  const codes = { ...BUILTIN_PROMOS };
  const ownerRaw = findEnvVar(['KARDPRO_OWNER_PROMOS']) || '';
  if (ownerRaw) {
    ownerRaw.split(',').forEach(entry => {
      const [code, cnt] = entry.trim().split(':');
      if (code && cnt) {
        const parsed = parseInt(cnt, 10);
        if (parsed > 0 && parsed <= 10000) codes[code.trim().toUpperCase()] = parsed;
      }
    });
  }
  return codes;
}

function getOwnerPromoWhitelist() {
  const raw = findEnvVar(['KARDPRO_OWNER_PROMOS']) || '';
  return new Set(raw.split(',').map(e => (e.split(':')[0] || '').trim().toUpperCase()).filter(Boolean));
}

function safeEqual(a, b) {
  if (typeof a !== 'string' || typeof b !== 'string') return false;
  const bufA = Buffer.from(a, 'utf8');
  const bufB = Buffer.from(b, 'utf8');
  if (bufA.length !== bufB.length) return false;
  try { return crypto.timingSafeEqual(bufA, bufB); } catch { return false; }
}

function createSessionToken(userObj, salt) {
  if (!salt) throw new Error('secretSalt не задан');
  const payload = Buffer.from(JSON.stringify({
    id: userObj.id, email: userObj.email, name: userObj.name,
    provider: userObj.provider || 'yandex',
    credits: typeof userObj.credits === 'number' ? userObj.credits : 0, ts: Date.now()
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
  if (!safeEqual(sig, expected)) return null;
  try {
    const decoded = JSON.parse(Buffer.from(payload, 'base64url').toString('utf-8'));
    if (typeof decoded.ts !== 'number') return null;
    if (Date.now() - decoded.ts > SESSION_TTL_MS) return null;
    if (decoded.ts - Date.now() > 5 * 60 * 1000) return null;
    if (!decoded.id || !decoded.email) return null;
    return decoded;
  } catch { return null; }
}

function resolveUserFromRequest(req, secretSalt) {
  const token = (req.headers.authorization || '').replace('Bearer ', '').trim();
  if (!token) return null;
  return verifySessionToken(token, secretSalt);
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

function writeCookieVault(res, vaultObj, salt) {
  try {
    let payload = vaultObj;
    let b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
    if (b64.length > 3000) {
      const entries = Object.entries(vaultObj);
      if (entries.length > 0) {
        payload = { [entries[entries.length - 1][0]]: entries[entries.length - 1][1] };
        b64 = Buffer.from(JSON.stringify(payload)).toString('base64url');
      }
    }
    if (b64.length > 3500) return;
    const sig = crypto.createHmac('sha256', salt).update(b64).digest('base64url');
    const val = encodeURIComponent(`${b64}.${sig}`);
    const isProd = process.env.VERCEL || process.env.NODE_ENV === 'production';
    const secureFlag = isProd ? ' Secure;' : '';
    res.setHeader('Set-Cookie', `kp_vault=${val}; Path=/; Max-Age=31536000; HttpOnly;${secureFlag} SameSite=Lax`);
  } catch {}
}

function creditsForRub(rub) {
  const r = Math.max(0, Number(rub) || 0);
  if (r < 50) return 0;
  if (r < 80) return Math.floor(r / 10);
  if (r < 150) return Math.floor(r / 8);
  if (r < 500) return Math.floor(r / 7.5);
  if (r < 1000) return Math.floor(r / 6.25);
  return Math.floor(r / 5);
}

function isValidAmountForCredits(amountRub, credits) {
  const amt = Number(amountRub);
  const cred = Number(credits);
  if (!Number.isFinite(amt) || amt <= 0) return false;
  if (!Number.isFinite(cred) || cred <= 0) return false;
  return cred <= creditsForRub(amt);
}

function checkRate(key, maxHits, windowMs = RATE_WINDOW_MS) {
  const now = Date.now();
  const bucket = global.rateBuckets.get(key);
  if (!bucket || now - bucket.start > windowMs) {
    global.rateBuckets.set(key, { start: now, hits: 1 });
    if (global.rateBuckets.size > 10000) {
      for (const [k, v] of global.rateBuckets) {
        if (now - v.start > windowMs) global.rateBuckets.delete(k);
      }
    }
    return { ok: true };
  }
  if (bucket.hits >= maxHits) return { ok: false, retryAfter: Math.ceil((bucket.start + windowMs - now) / 1000) };
  bucket.hits++;
  return { ok: true };
}

async function fetchWithTimeout(url, opts = {}, timeoutMs = 12000) {
  const ctrl = new AbortController();
  const timer = setTimeout(() => ctrl.abort(), timeoutMs);
  try { return await fetch(url, { ...opts, signal: ctrl.signal }); }
  finally { clearTimeout(timer); }
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
  if (yandexDomains.includes(domain)) domain = 'yandex.ru';
  if (domain === 'gmail.com' || domain === 'yandex.ru') local = local.replace(/\./g, '').replace(/-/g, '');
  return `${local}@${domain}`;
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

async function getOrCreateSupabaseUser(sbUrl, sbServiceKey, email, allowCreate = true) {
  if (!sbUrl || !sbServiceKey || !email) return null;
  const existing = await getSupabaseUserByEmail(sbUrl, sbServiceKey, email);
  if (existing) return existing;
  if (!allowCreate) return null;
  try {
    const linkRes = await fetchWithTimeout(`${sbUrl}/auth/v1/admin/generate_link`, {
      method: 'POST',
      headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({ type: 'magiclink', email })
    }, 8000);
    if (!linkRes.ok) return null;
    const data = await linkRes.json();
    return data?.user || (data?.id ? data : null);
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

async function updateSupabaseCloudRecord(sbUrl, sbServiceKey, sbUserId, email, data) {
  if (!sbUrl || !sbServiceKey || !sbUserId) return;
  try {
    await fetchWithTimeout(`${sbUrl}/auth/v1/admin/users/${sbUserId}`, {
      method: 'PUT',
      headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}`, 'Content-Type': 'application/json' },
      body: JSON.stringify({
        app_metadata: {
          kp_initialized: true,
          kp_credits: typeof data.credits === 'number' ? data.credits : 0,
          kp_has_spent: !!data.has_spent,
          kp_bonus_blocked: !!data.bonus_blocked,
          kp_pass_hash: data.pass_hash || null,
          kp_used_labels: Array.isArray(data.used_labels) ? data.used_labels.slice(-100) : []
        }
      })
    }, 8000);
  } catch (e) { console.error('[payment-webhook] auth PUT:', e.message); }

  try {
    const checkRes = await fetchWithTimeout(
      `${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(sbUserId)}&select=id`,
      { headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}` } }, 8000
    );
    if (checkRes.ok) {
      const list = await checkRes.json();
      const payload = { credits: typeof data.credits === 'number' ? data.credits : 0 };
      if (Array.isArray(list) && list.length > 0) {
        await fetchWithTimeout(`${sbUrl}/rest/v1/profiles?id=eq.${encodeURIComponent(sbUserId)}`, {
          method: 'PATCH',
          headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
          body: JSON.stringify(payload)
        }, 8000);
      } else {
        await fetchWithTimeout(`${sbUrl}/rest/v1/profiles`, {
          method: 'POST',
          headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}`, 'Content-Type': 'application/json', Prefer: 'return=minimal' },
          body: JSON.stringify({ id: sbUserId, email, ...payload })
        }, 8000);
      }
    }
  } catch (e) { console.error('[payment-webhook] profiles:', e.message); }
}

async function syncUserAccount(req, res, sbUrl, sbServiceKey, secretSalt, email, name, deviceFp, isVerifiedOAuth, allowCreate = true) {
  const cookieVault = readCookieVault(req, secretSalt);
  const hwHash = deviceFp ? crypto.createHmac('sha256', secretSalt).update(`hw_${deviceFp}`).digest('hex').substring(0, 24) : null;

  const sbUser = await getOrCreateSupabaseUser(sbUrl, sbServiceKey, email, allowCreate);
  const userId = sbUser?.id || emailToDeterministicUUID(email);
  const appMeta = sbUser?.app_metadata || {};

  let syncedCredits = 0, initialized = false;
  if (typeof appMeta.kp_credits === 'number') { syncedCredits = appMeta.kp_credits; initialized = true; }
  else if (sbUser?.id) {
    const pc = await getProfileCredits(sbUrl, sbServiceKey, sbUser.id);
    if (pc !== null) { syncedCredits = pc; initialized = true; }
  }

  const legacyId = emailToDeterministicUUID(email);
  const localRecord = cookieVault[userId] || cookieVault[legacyId] || global.usersVault[userId] || global.usersVault[legacyId] || null;
  if (!initialized && localRecord && typeof localRecord.credits === 'number' && !localRecord.bonusBlocked) {
    syncedCredits = localRecord.credits;
  }

  let bonusBlocked = !!appMeta.kp_bonus_blocked || !!localRecord?.bonusBlocked;
  let hasSpent = !!appMeta.kp_has_spent || !!localRecord?.hasSpent;
  let usedLabels = Array.isArray(appMeta.kp_used_labels) ? appMeta.kp_used_labels
    : Array.isArray(localRecord?.usedLabels) ? localRecord.usedLabels : [];
  let passHash = appMeta.kp_pass_hash || localRecord?.passHash || null;

  if (!initialized && isVerifiedOAuth) {
    if (hwHash && global.claimedDevices[hwHash] && global.claimedDevices[hwHash] !== email) {
      syncedCredits = 0; bonusBlocked = true;
    } else {
      syncedCredits = 5;
      if (hwHash) global.claimedDevices[hwHash] = email;
    }
  } else if (!initialized && !isVerifiedOAuth) {
    bonusBlocked = true;
  }

  const displayName = name || (email ? email.split('@')[0] : 'Селлер');
  const record = {
    id: userId, email, name: displayName, credits: syncedCredits,
    usedLabels, passHash, bonusBlocked, hasSpent,
    provider: isVerifiedOAuth ? 'yandex' : 'email'
  };

  await updateSupabaseCloudRecord(sbUrl, sbServiceKey, sbUser?.id, email, {
    credits: syncedCredits, used_labels: usedLabels, pass_hash: passHash,
    has_spent: hasSpent, bonus_blocked: bonusBlocked
  });

  global.usersVault[userId] = record;
  cookieVault[userId] = record;
  if (isVerifiedOAuth) cookieVault._yandex_owner_email = email;
  writeCookieVault(res, cookieVault, secretSalt);

  return record;
}

async function saveUserBalanceEverywhere(req, res, sbUrl, sbServiceKey, secretSalt, record) {
  global.usersVault[record.id] = record;
  const cookieVault = readCookieVault(req, secretSalt);
  cookieVault[record.id] = record;
  writeCookieVault(res, cookieVault, secretSalt);

  const sbUser = await getOrCreateSupabaseUser(sbUrl, sbServiceKey, record.email, true);
  const targetId = sbUser?.id || record.id;

  await updateSupabaseCloudRecord(sbUrl, sbServiceKey, targetId, record.email, {
    credits: record.credits, used_labels: record.usedLabels || [],
    pass_hash: record.passHash || sbUser?.app_metadata?.kp_pass_hash || null,
    has_spent: !!record.hasSpent, bonus_blocked: !!record.bonusBlocked
  });
}

function sanitizeCreditsCount(val) {
  const num = parseInt(val, 10);
  if (isNaN(num) || num < 1) return 5;
  return Math.min(10000, num);
}

export default async function handler(req, res) {
  const { sbUrl, sbAnonKey, sbServiceKey, yandexClientId, secretSalt, allowedOrigins } = getEnvConfig();
  const reqOrigin = req.headers.origin || '';

  if (allowedOrigins.length > 0) {
    if (allowedOrigins.includes(reqOrigin)) {
      res.setHeader('Access-Control-Allow-Origin', reqOrigin);
      res.setHeader('Vary', 'Origin');
    }
  } else {
    res.setHeader('Access-Control-Allow-Origin', '*');
    if (process.env.NODE_ENV === 'production') console.warn('[payment-webhook] ALLOWED_ORIGINS не задан!');
  }
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');
  res.setHeader('Access-Control-Allow-Credentials', 'true');

  if (req.method === 'OPTIONS') return res.status(200).end();
  if (!secretSalt) { console.error('[payment-webhook] secretSalt не задан!'); return res.status(500).json({ error: 'Server misconfiguration' }); }

  const clientIp = (req.headers['x-forwarded-for'] || '').split(',')[0].trim() || 'unknown';

  if (req.method === 'GET') {
    const { action, label, fp } = req.query;

    if (action === 'config') {
      return res.status(200).json({
        supabaseUrl: sbUrl, supabaseAnonKey: sbAnonKey,
        yandexClientId, wallet: YOOMONEY_WALLET,
        cloudSyncActive: Boolean(sbUrl && sbServiceKey)
      });
    }

    if (action === 'profile') {
      const rate = checkRate(`profile:${clientIp}`, 30);
      if (!rate.ok) { res.setHeader('Retry-After', String(rate.retryAfter)); return res.status(429).json({ error: 'RATE_LIMIT' }); }
      const userObj = resolveUserFromRequest(req, secretSalt);
      if (!userObj || !userObj.email) return res.status(401).json({ error: 'Unauthorized' });
      const record = await syncUserAccount(req, res, sbUrl, sbServiceKey, secretSalt, userObj.email, userObj.name, fp || '', userObj.provider !== 'email', false);
      return res.status(200).json({ ok: true, id: record.id, email: record.email, name: record.name, credits: record.credits, session_token: createSessionToken(record, secretSalt) });
    }

    if (action === 'check_payment') {
      const rate = checkRate(`check_pay:${clientIp}`, 60);
      if (!rate.ok) { res.setHeader('Retry-After', String(rate.retryAfter)); return res.status(429).json({ error: 'RATE_LIMIT' }); }
      const userObj = resolveUserFromRequest(req, secretSalt);
      if (!userObj || !userObj.email) return res.status(401).json({ error: 'Unauthorized' });
      const orderLabel = String(label || '').trim();
      if (!orderLabel) return res.status(400).json({ error: 'Missing label' });

      const sbUser = await getSupabaseUserByEmail(sbUrl, sbServiceKey, userObj.email);
      if (!sbUser) return res.status(200).json({ paid: false, credits: 0 });
      const appMeta = sbUser.app_metadata || {};
      const usedLabels = Array.isArray(appMeta.kp_used_labels) ? appMeta.kp_used_labels : [];
      const isPaid = usedLabels.includes(orderLabel);
      let credits = typeof appMeta.kp_credits === 'number' ? appMeta.kp_credits : 0;
      if (!isPaid) {
        const pc = await getProfileCredits(sbUrl, sbServiceKey, sbUser.id);
        if (pc !== null) credits = pc;
      }
      return res.status(200).json({ paid: isPaid, credits });
    }

    if (!label) return res.status(400).json({ error: 'Missing label' });
    if (global.usersVault[`paid_${label}`]) return res.status(200).json({ paid: true, credits: global.usersVault[`paid_${label}`] });
    return res.status(200).json({ paid: false });
  }

  if (req.method === 'POST') {
    try {
      const isJson = (req.headers['content-type'] || '').includes('application/json');
      const body = isJson
        ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body)
        : (typeof req.body === 'string' ? Object.fromEntries(new URLSearchParams(req.body)) : req.body);

      if (body?.action === 'social_auth') {
        const rate = checkRate(`social:${clientIp}`, 10);
        if (!rate.ok) { res.setHeader('Retry-After', String(rate.retryAfter)); return res.status(429).json({ error: 'RATE_LIMIT' }); }

        const { accessToken, clientProfile, deviceFp } = body;
        let rawEmail = '', displayName = '';
        if (accessToken) {
          try {
            const yaRes = await fetchWithTimeout('https://login.yandex.ru/info?format=json', { headers: { Authorization: `OAuth ${accessToken}` } }, 8000);
            if (yaRes.ok) {
              const yaData = await yaRes.json();
              rawEmail = yaData.default_email || (Array.isArray(yaData.emails) && yaData.emails[0]) || `${yaData.login || yaData.id}@yandex.ru`;
              displayName = yaData.display_name || yaData.real_name || yaData.login || rawEmail.split('@')[0];
            }
          } catch {}
        }
        if (!rawEmail && clientProfile?.email) { rawEmail = String(clientProfile.email); displayName = clientProfile.name || rawEmail.split('@')[0]; }
        if (!rawEmail) return res.status(401).json({ error: 'Не удалось получить профиль Яндекса' });

        const verifiedEmail = normalizeEmail(rawEmail);
        const record = await syncUserAccount(req, res, sbUrl, sbServiceKey, secretSalt, verifiedEmail, displayName, deviceFp || '', true, true);

        return res.status(200).json({
          ok: true, id: record.id, email: record.email, name: record.name, credits: record.credits,
          bonus_blocked: record.bonusBlocked, session_token: createSessionToken(record, secretSalt)
        });
      }

      if (body?.action === 'email_auth') {
        const rate = checkRate(`email_auth:${clientIp}`, 8);
        if (!rate.ok) { res.setHeader('Retry-After', String(rate.retryAfter)); return res.status(429).json({ error: `Подождите ${rate.retryAfter}с.` }); }

        const rawEmail = String(body.email || '').trim();
        const password = String(body.password || '').trim();
        const mode = body.mode || 'login';
        const deviceFp = body.deviceFp || '';
        if (!rawEmail || !rawEmail.includes('@') || password.length < 6) {
          return res.status(400).json({ error: 'Введите корректный Email и пароль (≥6 символов)' });
        }
        const email = normalizeEmail(rawEmail);
        const passHash = crypto.createHmac('sha256', secretSalt).update(`${email}:${password}`).digest('hex');

        const allowCreate = mode === 'signup';
        const record = await syncUserAccount(req, res, sbUrl, sbServiceKey, secretSalt, email, email.split('@')[0], deviceFp, false, allowCreate);

        if (mode === 'signup' && record.passHash) return res.status(409).json({ error: 'Аккаунт с этим Email уже существует' });
        if (mode === 'login' && !record.passHash) return res.status(404).json({ error: 'Аккаунт не найден. Зарегистрируйтесь.' });
        if (mode === 'login' && record.passHash && !safeEqual(record.passHash, passHash)) return res.status(401).json({ error: 'Неверный пароль' });

        record.passHash = passHash;
        await saveUserBalanceEverywhere(req, res, sbUrl, sbServiceKey, secretSalt, record);

        return res.status(200).json({
          ok: true, id: record.id, email: record.email, name: record.name, credits: record.credits,
          bonus_blocked: record.bonusBlocked, session_token: createSessionToken(record, secretSalt)
        });
      }

      if (body?.action === 'promo') {
        const rate = checkRate(`promo:${clientIp}`, 20);
        if (!rate.ok) { res.setHeader('Retry-After', String(rate.retryAfter)); return res.status(429).json({ error: 'RATE_LIMIT' }); }
        const userObj = resolveUserFromRequest(req, secretSalt);
        if (!userObj || !userObj.email) return res.status(401).json({ error: 'Войдите в аккаунт' });

        const record = await syncUserAccount(req, res, sbUrl, sbServiceKey, secretSalt, userObj.email, userObj.name, body.deviceFp || '', userObj.provider !== 'email', false);
        const code = String(body.code || '').trim().toUpperCase();
        const bonus = getPromoCodes()[code];
        if (!bonus) return res.status(400).json({ error: 'Неверный промокод' });

        const isOwnerUnlimited = getOwnerPromoWhitelist().has(code);
        const promoKey = `promo_used_${code}`;
        if (!isOwnerUnlimited && record.usedLabels.includes(promoKey)) {
          return res.status(400).json({ error: 'Промокод уже активирован на вашем аккаунте!' });
        }
        record.credits += bonus;
        if (!isOwnerUnlimited) record.usedLabels.push(promoKey);
        await saveUserBalanceEverywhere(req, res, sbUrl, sbServiceKey, secretSalt, record);
        return res.status(200).json({ ok: true, added: bonus, credits: record.credits, session_token: createSessionToken(record, secretSalt) });
      }

      if (body?.action === 'confirm_return') {
        const rate = checkRate(`confirm:${clientIp}`, 30);
        if (!rate.ok) { res.setHeader('Retry-After', String(rate.retryAfter)); return res.status(429).json({ error: 'RATE_LIMIT' }); }
        const userObj = resolveUserFromRequest(req, secretSalt);
        if (!userObj || !userObj.email) return res.status(401).json({ error: 'Войдите в аккаунт' });
        const orderId = String(body.orderId || '').trim();
        if (!orderId.startsWith('kp_')) return res.status(400).json({ error: 'Некорректный orderId' });

        const sbUser = await getSupabaseUserByEmail(sbUrl, sbServiceKey, userObj.email);
        const appMeta = sbUser?.app_metadata || {};
        const usedLabels = Array.isArray(appMeta.kp_used_labels) ? appMeta.kp_used_labels : [];
        return res.status(200).json({
          ok: true, paid: usedLabels.includes(orderId),
          credits: typeof appMeta.kp_credits === 'number' ? appMeta.kp_credits : 0,
          added: 0, session_token: createSessionToken(userObj, secretSalt)
        });
      }

      const yoomoneySecret = (findEnvVar(['YOOMONEY_NOTIFICATION_SECRET']) || '').trim();
      if (!yoomoneySecret) {
        console.error('[payment-webhook] YOOMONEY_NOTIFICATION_SECRET не задан');
        return res.status(503).send('Payment webhook disabled');
      }

      const {
        notification_type = '', operation_id = '', amount = '', currency = '',
        datetime = '', sender = '', codepro = '', label = '', sha1_hash = ''
      } = body || {};

      const checkString = `${notification_type}&${operation_id}&${amount}&${currency}&${datetime}&${sender}&${codepro}&${yoomoneySecret}&${label}`;
      const calculatedHash = crypto.createHash('sha1').update(checkString, 'utf-8').digest('hex');
      if (!safeEqual(calculatedHash, String(sha1_hash).toLowerCase())) {
        console.warn('[payment-webhook] Invalid sha1_hash:', operation_id);
        return res.status(400).send('Invalid signature');
      }

      if (String(currency) !== '643') return res.status(400).send('Unsupported currency');
      const amt = parseFloat(amount);
      if (!Number.isFinite(amt) || amt <= 0) return res.status(400).send('Invalid amount');
      if (!label || !label.startsWith('kp_')) return res.status(400).send('Invalid label');

      const parts = label.split('_');
      if (parts.length < 3) return res.status(400).send('Invalid label format');
      const creditsToAdd = sanitizeCreditsCount(parts[1]);
      const userId = parts[2];

      if (!isValidAmountForCredits(amt, creditsToAdd)) {
        console.warn(`[payment-webhook] amount ${amt}₽ insufficient for ${creditsToAdd} credits`);
        return res.status(400).send('Amount insufficient');
      }

      global.usersVault[`paid_${label}`] = creditsToAdd;

      if (userId && sbUrl && sbServiceKey) {
        try {
          const uRes = await fetchWithTimeout(`${sbUrl}/auth/v1/admin/users/${userId}`, { headers: { apikey: sbServiceKey, Authorization: `Bearer ${sbServiceKey}` } }, 8000);
          if (uRes.ok) {
            const uData = await uRes.json();
            const appMeta = uData?.app_metadata || {};
            const used = Array.isArray(appMeta.kp_used_labels) ? appMeta.kp_used_labels : [];
            if (!used.includes(label)) {
              const cur = typeof appMeta.kp_credits === 'number' ? appMeta.kp_credits : 0;
              await updateSupabaseCloudRecord(sbUrl, sbServiceKey, userId, uData.email || '', {
                credits: cur + creditsToAdd, used_labels: [...used, label],
                pass_hash: appMeta.kp_pass_hash || null,
                has_spent: !!appMeta.kp_has_spent, bonus_blocked: !!appMeta.kp_bonus_blocked
              });
              console.log(`[payment-webhook] OK user=${userId} ${cur}->${cur + creditsToAdd}`);
            } else {
              console.log(`[payment-webhook] duplicate webhook for ${label}`);
            }
          }
        } catch (e) { console.error('[payment-webhook] sync failed:', e.message); }
      }

      return res.status(200).send('OK');
    } catch (err) {
      console.error('[payment-webhook] error:', err.message);
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
