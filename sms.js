const twilio = require('twilio');

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const whatsappFrom = process.env.TWILIO_WHATSAPP_FROM || 'whatsapp:+14155238886';

const client = accountSid && authToken ? twilio(accountSid, authToken) : null;

function toE164(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (digits.startsWith('963')) return `+${digits}`;
  if (digits.startsWith('0')) return `+963${digits.slice(1)}`;
  if (digits.length === 9) return `+963${digits}`;
  return `+${digits}`;
}

function isConfigured() {
  return Boolean(client && whatsappFrom);
}

async function sendOtp(phone, code) {
  if (!client) {
    throw new Error('TWILIO_ACCOUNT_SID and TWILIO_AUTH_TOKEN are required.');
  }

  return client.messages.create({
    from: whatsappFrom,
    to: `whatsapp:${toE164(phone)}`,
    body: `رمز التحقق لحرفتي هو: ${code}`
  });
}

module.exports = {
  sendOtp,
  toE164,
  isConfigured
};
