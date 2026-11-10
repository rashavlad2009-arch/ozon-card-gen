import crypto from 'crypto';

const VALID_PROMO_CODES = {
  'START5': 5,
  'PRO50': 5,
  'SELLER10': 10,
  'SHOP20': 20,
  'VIP2026': 50
};

function getEnvConfig() {
  const sbUrl = (process.env.SUPABASE_URL || process.env.NEXT_PUBLIC_SUPABASE_URL || '').trim().replace(/\/$/, '');
  const sbAnonKey = (
    process.env.SUPABASE_ANON_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_ANON_KEY ||
    process.env.SUPABASE_PUBLISHABLE_KEY ||
    process.env.NEXT_PUBLIC_SUPABASE_PUBLISHABLE_KEY ||
    ''
  ).trim();
  const sbServiceKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || process.env.SUPABASE_SECRET_KEY || '').trim();
  const yandexClientId = (process.env.YANDEX_CLIENT_ID || '').trim();
  const secretSalt = sbServiceKey || process.env.GROQ_API_KEY || 'kardpro_salt_2026';

  return { sbUrl, sbAnonKey, sbServiceKey, yandexClientId, secretSalt };
}

function signYandexSession(userId, salt) {
  const sig = crypto.createHmac('sha256', salt).update(String(userId)).digest('hex').substring(0, 24);
  return `ya_${userId}_${sig}`;
}

function verifyYandexSession(token, salt) {
  if (!token || !token.startsWith('ya_')) return null;
  const parts = token.split('_');
  if (parts.length !== 3) return null;
  const [, userId, sig] = parts;
  const expected = crypto.createHmac('sha256', salt).update(String(userId)).digest('hex').substring(0, 24);
  return sig === expected ? userId : null;
}

// Надежное чтение баланса (из таблицы profiles + резерв в auth.users.user_metadata)
async function getUserCredits(sbUrl, sbServiceKey, userId, email = '') {
  let metaCredits = null;
  let usedActions = [];

  try {
    const adminUserRes = await fetch(`${sbUrl}/auth/v1/admin/users/${userId}`, {
      headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
    });
    if (adminUserRes.ok) {
      const adminUser = await adminUserRes.json();
      const meta = adminUser?.user_metadata || {};
      if (typeof meta.credits === 'number') metaCredits = meta.credits;
      if (Array.isArray(meta.used_labels)) usedActions = meta.used_labels;
    }
  } catch (e) {}

  try {
    const profRes = await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${userId}&select=credits`, {
      headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
    });
    if (profRes.ok) {
      const profList = await profRes.json();
      if (Array.isArray(profList) && profList.length > 0 && typeof profList[0].credits === 'number') {
        return { credits: profList[0].credits, usedActions };
      }
      const initial = metaCredits !== null ? metaCredits : 5;
      await fetch(`${sbUrl}/rest/v1/profiles`, {
        method: 'POST',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ id: userId, email, credits: initial })
      });
      return { credits: initial, usedActions };
    }
  } catch (e) {}

  if (metaCredits !== null) {
    return { credits: metaCredits, usedActions };
  }

  await setUserCredits(sbUrl, sbServiceKey, userId, 5, usedActions);
  return { credits: 5, usedActions };
}

// Надежная запись баланса в оба хранилища Supabase
async function setUserCredits(sbUrl, sbServiceKey, userId, newCredits, usedActions = null) {
  try {
    await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${userId}`, {
      method: 'PATCH',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ credits: newCredits })
    });
  } catch (e) {}

  try {
    const metaPayload = { credits: newCredits };
    if (Array.isArray(usedActions)) metaPayload.used_labels = usedActions.slice(-50);
    await fetch(`${sbUrl}/auth/v1/admin/users/${userId}`, {
      method: 'PUT',
      headers: {
        'apikey': sbServiceKey,
        'Authorization': `Bearer ${sbServiceKey}`,
        'Content-Type': 'application/json'
      },
      body: JSON.stringify({ user_metadata: metaPayload })
    });
  } catch (e) {}
}

async function addCreditsOnce(sbUrl, sbServiceKey, label, userId, creditsToAdd) {
  const { credits: currentCredits, usedActions } = await getUserCredits(sbUrl, sbServiceKey, userId);

  if (usedActions.includes(label)) {
    return { alreadyCredited: true, newCredits: currentCredits };
  }

  try {
    const checkRes = await fetch(`${sbUrl}/rest/v1/payments_log?label=eq.${encodeURIComponent(label)}&select=label`, {
      headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
    });
    if (checkRes.ok) {
      const existing = await checkRes.json();
      if (Array.isArray(existing) && existing.length > 0) {
        return { alreadyCredited: true, newCredits: currentCredits };
      }
      await fetch(`${sbUrl}/rest/v1/payments_log`, {
        method: 'POST',
        headers: {
          'apikey': sbServiceKey,
          'Authorization': `Bearer ${sbServiceKey}`,
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ label, user_id: userId, credits: creditsToAdd })
      });
    }
  } catch (e) {}

  const newCredits = currentCredits + creditsToAdd;
  const updatedActions = [...usedActions, label];
  await setUserCredits(sbUrl, sbServiceKey, userId, newCredits, updatedActions);

  return { alreadyCredited: false, newCredits };
}

async function resolveUserIdFromToken(token, sbUrl, sbServiceKey, secretSalt) {
  if (!token) return null;
  const yaUserId = verifyYandexSession(token, secretSalt);
  if (yaUserId) return { id: yaUserId, email: '' };

  const userRes = await fetch(`${sbUrl}/auth/v1/user`, {
    headers: { 'Authorization': `Bearer ${token}`, 'apikey': sbServiceKey }
  });
  if (!userRes.ok) return null;
  const userData = await userRes.json();
  return userData?.id ? { id: userData.id, email: userData.email || '' } : null;
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const { sbUrl, sbAnonKey, sbServiceKey, yandexClientId, secretSalt } = getEnvConfig();

  // 1. GET-запросы: конфигурация, баланс профиля и проверка статуса платежа
  if (req.method === 'GET') {
    const { action, label } = req.query;

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
      const userObj = await resolveUserIdFromToken(token, sbUrl, sbServiceKey, secretSalt);
      if (!userObj) return res.status(401).json({ error: 'Unauthorized' });
      const { credits } = await getUserCredits(sbUrl, sbServiceKey, userObj.id, userObj.email);
      return res.status(200).json({ ok: true, id: userObj.id, credits });
    }

    if (!label) return res.status(400).json({ error: 'Missing label' });

    if (sbUrl && sbServiceKey) {
      try {
        const checkRes = await fetch(`${sbUrl}/rest/v1/payments_log?label=eq.${encodeURIComponent(label)}&select=credits`, {
          headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
        });
        if (checkRes.ok) {
          const list = await checkRes.json();
          if (Array.isArray(list) && list.length > 0) {
            return res.status(200).json({ paid: true, credits: list[0].credits });
          }
        }
      } catch (e) {}
    }

    return res.status(200).json({ paid: false });
  }

  // 2. POST-запросы: Авторизация Яндекс ID, Промокоды и Вебхук ЮMoney
  if (req.method === 'POST') {
    try {
      const isJson = (req.headers['content-type'] || '').includes('application/json');
      const body = isJson
        ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body)
        : (typeof req.body === 'string' ? Object.fromEntries(new URLSearchParams(req.body)) : req.body);

      // А) Авторизация через Яндекс ID с привязкой к базе Supabase
      if (body?.action === 'social_auth') {
        const { accessToken } = body;
        if (!accessToken) {
          return res.status(400).json({ error: 'Отсутствует токен Яндекс ID' });
        }

        const yaRes = await fetch('https://login.yandex.ru/info?format=json', {
          headers: { 'Authorization': `OAuth ${accessToken}` }
        });
        if (!yaRes.ok) {
          return res.status(401).json({ error: 'Ошибка проверки токена в Яндексе' });
        }

        const yaData = await yaRes.json();
        const verifiedEmail = (
          yaData.default_email ||
          (Array.isArray(yaData.emails) && yaData.emails[0]) ||
          `${yaData.login || yaData.id}@yandex.ru`
        ).toLowerCase();
        const displayName = yaData.display_name || yaData.real_name || yaData.login || verifiedEmail.split('@')[0];

        if (!sbUrl || !sbServiceKey) {
          return res.status(500).json({ error: 'В Vercel не заданы SUPABASE_URL или SUPABASE_SERVICE_ROLE_KEY' });
        }

        // Создаем или находим пользователя в Supabase через Admin generate_link
        const linkRes = await fetch(`${sbUrl}/auth/v1/admin/generate_link`, {
          method: 'POST',
          headers: {
            'apikey': sbServiceKey,
            'Authorization': `Bearer ${sbServiceKey}`,
            'Content-Type': 'application/json'
          },
          body: JSON.stringify({
            type: 'magiclink',
            email: verifiedEmail,
            data: { full_name: displayName }
          })
        });

        const linkData = await linkRes.json();
        const userId = linkData?.user?.id || linkData?.id;
        const tokenHash = linkData?.properties?.hashed_token || null;

        if (!userId) {
          return res.status(500).json({ error: 'Не удалось инициализировать профиль в базе данных' });
        }

        const { credits } = await getUserCredits(sbUrl, sbServiceKey, userId, verifiedEmail);
        const signedSessionToken = signYandexSession(userId, secretSalt);

        return res.status(200).json({
          ok: true,
          id: userId,
          email: verifiedEmail,
          name: displayName,
          credits,
          session_token: signedSessionToken,
          token_hash: tokenHash
        });
      }

      // Б) Промокоды и подтверждение возврата с оплаты ЮMoney
      if (body?.action === 'promo' || body?.action === 'confirm_return') {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.replace('Bearer ', '').trim();
        const userObj = await resolveUserIdFromToken(token, sbUrl, sbServiceKey, secretSalt);

        if (!userObj) {
          return res.status(401).json({ error: 'Пожалуйста, войдите в аккаунт' });
        }

        if (body.action === 'promo') {
          const code = (body.code || '').trim().toUpperCase();
          const bonus = VALID_PROMO_CODES[code];
          if (!bonus) return res.status(400).json({ error: 'Неверный промокод' });

          const promoLabel = code === 'VIP2026' ? `promo_${code}_${Date.now()}` : `promo_${code}_${userObj.id}`;
          const result = await addCreditsOnce(sbUrl, sbServiceKey, promoLabel, userObj.id, bonus);
          if (result.alreadyCredited) {
            return res.status(400).json({ error: 'Этот промокод уже был активирован на вашем аккаунте' });
          }
          return res.status(200).json({ ok: true, added: bonus, credits: result.newCredits });
        }

        if (body.action === 'confirm_return') {
          const { orderId, credits } = body;
          const addCount = [5, 10, 20].includes(Number(credits)) ? Number(credits) : 5;
          const result = await addCreditsOnce(sbUrl, sbServiceKey, orderId, userObj.id, addCount);
          return res.status(200).json({ ok: true, added: addCount, credits: result.newCredits });
        }
      }

      // В) Прием прямого HTTP-уведомления от ЮMoney
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

        if (sbUrl && sbServiceKey && userId && userId.length >= 20) {
          await addCreditsOnce(sbUrl, sbServiceKey, label, userId, creditsToAdd);
        }
      }

      return res.status(200).send('OK');
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
