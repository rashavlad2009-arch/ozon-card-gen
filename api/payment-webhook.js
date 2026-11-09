import crypto from 'crypto';

// Временное хранилище статусов заказов в памяти инстанса
// (для стабильной работы можно использовать бесплатный Vercel KV / Upstash Redis)
global.payments = global.payments || {};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // 1. Проверка статуса оплаты с фронтенда (GET ?label=...)
  if (req.method === 'GET') {
    const { label } = req.query;
    if (!label) return res.status(400).json({ error: 'Missing label' });
    
    const isPaid = !!global.payments[label];
    return res.status(200).json({ paid: isPaid });
  }

  // 2. Приём вебхука от ЮMoney (POST)
  if (req.method === 'POST') {
    try {
      const {
        notification_type,
        operation_id,
        amount,
        currency,
        datetime,
        sender,
        codepro,
        label,
        sha1_hash
      } = req.body;

      const secret = (process.env.YOOMONEY_NOTIFICATION_SECRET || '').trim();

      if (!secret) {
        console.error('YOOMONEY_NOTIFICATION_SECRET не задан в Environment Variables');
        return res.status(500).send('Secret not configured');
      }

      // Проверка хэша SHA-1 по спецификации ЮMoney
      const checkString = `${notification_type}&${operation_id}&${amount}&${currency}&${datetime}&${sender}&${codepro}&${secret}&${label}`;
      const calculatedHash = crypto.createHash('sha1').update(checkString, 'utf-8').digest('hex');

      if (calculatedHash !== sha1_hash) {
        console.warn('Неверный хэш платежа');
        return res.status(400).send('Invalid signature');
      }

      // Фиксируем оплату для переданного ID заказа (label)
      if (label) {
        global.payments[label] = true;
      }

      return res.status(200).send('OK');
    } catch (err) {
      console.error('Webhook error:', err);
      return res.status(500).send('Internal Error');
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
