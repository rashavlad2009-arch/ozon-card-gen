import crypto from 'crypto';

const VALID_PROMO_CODES = {
  'START5': 5,
  'PRO50': 5,
  'SELLER10': 10,
  'SHOP20': 20,
  'VIP2026': 50
};

global.localPayments = global.localPayments || {};
global.yandexProfiles = global.yandexProfiles || {};

async function addCreditsToSupabase(sbUrl, sbServiceKey, label, userId, creditsToAdd) {
  const checkRes = await fetch(`${sbUrl}/rest/v1/payments_log?label=eq.${encodeURIComponent(label)}&select=label`, {
    headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
  });
  const existing = await checkRes.json();
  if (Array.isArray(existing) && existing.length > 0) {
    return { alreadyCredited: true };
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

  const profRes = await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${userId}&select=credits`, {
    headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
  });
  const profList = await profRes.json();
  const currentCredits = (Array.isArray(profList) && profList[0]) ? profList[0].credits : 0;
  const newCredits = currentCredits + creditsToAdd;

  await fetch(`${sbUrl}/rest/v1/profiles?id=eq.${userId}`, {
    method: 'PATCH',
    headers: {
      'apikey': sbServiceKey,
      'Authorization': `Bearer ${sbServiceKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({ credits: newCredits })
  });

  return { alreadyCredited: false, newCredits };
}

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization');

  if (req.method === 'OPTIONS') return res.status(200).end();

  const sbUrl = (process.env.SUPABASE_URL || '').trim().replace(/\/$/, '');
  const sbAnonKey = (process.env.SUPABASE_ANON_KEY || '').trim();
  const sbServiceKey = (process.env.SUPABASE_SERVICE_ROLE_KEY || '').trim();
  const yandexClientId = (process.env.YANDEX_CLIENT_ID || '').trim();

  if (req.method === 'GET') {
    const { action, label } = req.query;

    if (action === 'config') {
      return res.status(200).json({
        supabaseUrl: sbUrl,
        supabaseAnonKey: sbAnonKey,
        yandexClientId
      });
    }

    if (!label) return res.status(400).json({ error: 'Missing label' });

    if (sbUrl && sbServiceKey) {
      const checkRes = await fetch(`${sbUrl}/rest/v1/payments_log?label=eq.${encodeURIComponent(label)}&select=credits`, {
        headers: { 'apikey': sbServiceKey, 'Authorization': `Bearer ${sbServiceKey}` }
      });
      const list = await checkRes.json();
      if (Array.isArray(list) && list.length > 0) {
        return res.status(200).json({ paid: true, credits: list[0].credits });
      }
    }

    if (global.localPayments[label]) {
      return res.status(200).json({ paid: true, credits: global.localPayments[label].credits });
    }

    return res.status(200).json({ paid: false });
  }

  if (req.method === 'POST') {
    try {
      const isJson = (req.headers['content-type'] || '').includes('application/json');
      const body = isJson
        ? (typeof req.body === 'string' ? JSON.parse(req.body) : req.body)
        : (typeof req.body === 'string' ? Object.fromEntries(new URLSearchParams(req.body)) : req.body);

      // А) Безотказная авторизация через Яндекс ID
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
        const verifiedEmail = yaData.default_email
          || (Array.isArray(yaData.emails) && yaData.emails[0])
          || `${yaData.login || yaData.id}@yandex.ru`;
        const displayName = yaData.display_name || yaData.real_name || yaData.login || verifiedEmail.split('@')[0];
        const yandexId = String(yaData.id || verifiedEmail);

        // Сохраняем профиль на сервере
        if (!global.yandexProfiles[yandexId]) {
          global.yandexProfiles[yandexId] = { credits: 5, email: verifiedEmail, name: displayName };
        }

        // Если Supabase полностью настроен (есть SUPABASE_SERVICE_ROLE_KEY), создаем также сессию Supabase
        let tokenHash = null;
        if (sbUrl && sbServiceKey) {
          try {
            const linkRes = await fetch(`${sbUrl}/auth/v1/admin/generate_link`, {
              method: 'POST',
              headers: {
                'apikey': sbServiceKey,
                'Authorization': `Bearer ${sbServiceKey}`,
                'Content-Type': 'application/json'
              },
              body: JSON.stringify({ type: 'magiclink', email: verifiedEmail })
            });
            const linkData = await linkRes.json();
            tokenHash = linkData?.properties?.hashed_token || null;
          } catch (e) {}
        }

        return res.status(200).json({
          ok: true,
          id: yandexId,
          email: verifiedEmail,
          name: displayName,
          credits: global.yandexProfiles[yandexId].credits,
          token_hash: tokenHash
        });
      }

      // Б) Промокоды и подтверждение возврата с оплаты
      if (body?.action === 'promo' || body?.action === 'confirm_return') {
        const authHeader = req.headers.authorization || '';
        const token = authHeader.replace('Bearer ', '').trim();

        if (!sbUrl || !sbServiceKey || !token || token.startsWith('ya_')) {
          if (body.action === 'promo') {
            const code = (body.code || '').trim().toUpperCase();
            const bonus = VALID_PROMO_CODES[code];
            if (!bonus) return res.status(400).json({ error: 'Неверный промокод' });
            return res.status(200).json({ ok: true, added: bonus });
          }
          if (body.action === 'confirm_return') {
            const addCount = [5, 10, 20].includes(Number(body.credits)) ? Number(body.credits) : 5;
            return res.status(200).json({ ok: true, added: addCount });
          }
        }

        const userRes = await fetch(`${sbUrl}/auth/v1/user`, {
          headers: { 'Authorization': `Bearer ${token}`, 'apikey': sbServiceKey }
        });
        if (!userRes.ok) return res.status(401).json({ error: 'Войдите в аккаунт' });
        const userData = await userRes.json();

        if (body.action === 'promo') {
          const code = (body.code || '').trim().toUpperCase();
          const bonus = VALID_PROMO_CODES[code];
          if (!bonus) return res.status(400).json({ error: 'Неверный промокод' });

          const promoLabel = code === 'VIP2026' ? `promo_${code}_${Date.now()}` : `promo_${code}_${userData.id}`;
          const result = await addCreditsToSupabase(sbUrl, sbServiceKey, promoLabel, userData.id, bonus);
          if (result.alreadyCredited) {
            return res.status(400).json({ error: 'Этот промокод уже был активирован на вашем аккаунте' });
          }
          return res.status(200).json({ ok: true, added: bonus, credits: result.newCredits });
        }

        if (body.action === 'confirm_return') {
          const { orderId, credits } = body;
          const addCount = [5, 10, 20].includes(Number(credits)) ? Number(credits) : 5;
          const result = await addCreditsToSupabase(sbUrl, sbServiceKey, orderId, userData.id, addCount);
          return res.status(200).json({ ok: true, added: addCount, credits: result.newCredits });
        }
      }

      // В) Вебхук ЮMoney
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

        global.localPayments[label] = { paid: true, credits: creditsToAdd };

        if (sbUrl && sbServiceKey && userId && userId.length >= 30) {
          await addCreditsToSupabase(sbUrl, sbServiceKey, label, userId, creditsToAdd);
        }
      }

      return res.status(200).send('OK');
    } catch (err) {
      return res.status(500).json({ error: err.message });
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
