import crypto from 'crypto';

// Хранилище подтвержденных платежей в памяти сервера
global.payments = global.payments || {};

export default async function handler(req, res) {
  res.setHeader('Access-Control-Allow-Origin', '*');
  res.setHeader('Access-Control-Allow-Methods', 'GET, POST, OPTIONS');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type');

  if (req.method === 'OPTIONS') {
    return res.status(200).end();
  }

  // 1. Запрос от фронтенда (проверка: прошла ли оплата по ID заказа label)
  if (req.method === 'GET') {
    const { label } = req.query;
    if (!label) {
      return res.status(400).json({ error: 'Missing label' });
    }

    const paymentInfo = global.payments[label];
    if (paymentInfo && paymentInfo.paid) {
      return res.status(200).json({
        paid: true,
        credits: paymentInfo.credits
      });
    }

    return res.status(200).json({ paid: false });
  }

  // 2. Прием HTTP-уведомления от ЮMoney после оплаты (POST)
  if (req.method === 'POST') {
    try {
      const body = typeof req.body === 'string'
        ? Object.fromEntries(new URLSearchParams(req.body))
        : (req.body || {});

      const {
        notification_type = '',
        operation_id = '',
        amount = '',
        withdraw_amount = '',
        currency = '',
        datetime = '',
        sender = '',
        codepro = '',
        label = '',
        sha1_hash = ''
      } = body;

      const secret = (process.env.YOOMONEY_NOTIFICATION_SECRET || '').trim();

      // Если секретное слово задано в Vercel, проверяем подлинность SHA-1 подписи
      if (secret) {
        const checkString = `${notification_type}&${operation_id}&${amount}&${currency}&${datetime}&${sender}&${codepro}&${secret}&${label}`;
        const calculatedHash = crypto.createHash('sha1').update(checkString, 'utf-8').digest('hex');

        if (calculatedHash !== sha1_hash) {
          console.warn('Неверный хэш уведомления ЮMoney');
          return res.status(400).send('Invalid signature');
        }
      }

      // Определяем выбранный тариф: 5 (50р), 10 (80р) или 20 (150р) генераций
      // Формат нашего label из index.html: kp_10_1731185000_ab12c
      let creditsToAdd = 5;
      if (label && label.startsWith('kp_')) {
        const parts = label.split('_');
        const parsed = parseInt(parts[1], 10);
        if ([5, 10, 20].includes(parsed)) {
          creditsToAdd = parsed;
        }
      } else {
        // Резервная проверка по сумме списания
        const paidSum = parseFloat(withdraw_amount || amount || '0');
        if (paidSum >= 140) creditsToAdd = 20;
        else if (paidSum >= 75) creditsToAdd = 10;
        else creditsToAdd = 5;
      }

      if (label) {
        global.payments[label] = {
          paid: true,
          credits: creditsToAdd,
          timestamp: Date.now()
        };
      }

      return res.status(200).send('OK');
    } catch (err) {
      console.error('Webhook error:', err);
      return res.status(500).send('Internal Server Error');
    }
  }

  return res.status(405).json({ error: 'Method not allowed' });
}
