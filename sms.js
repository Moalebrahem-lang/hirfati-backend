const twilio = require('twilio');

const accountSid = process.env.TWILIO_ACCOUNT_SID;
const authToken = process.env.TWILIO_AUTH_TOKEN;
const whatsappFrom = process.env.TWILIO_WHATSAPP_FROM || 'whatsapp:+14155238886';
const whatsappProvider = String(process.env.WHATSAPP_PROVIDER || 'twilio').trim().toLowerCase();
const birdAccessKey = process.env.BIRD_ACCESS_KEY;
const birdWorkspaceId = process.env.BIRD_WORKSPACE_ID;
const birdChannelId = process.env.BIRD_WHATSAPP_CHANNEL_ID;
const birdTemplateName = process.env.BIRD_WHATSAPP_TEMPLATE_NAME;
const birdTemplateProjectId = process.env.BIRD_WHATSAPP_TEMPLATE_PROJECT_ID;
const birdTemplateVersion = process.env.BIRD_WHATSAPP_TEMPLATE_VERSION;
const birdTemplateLocale = process.env.BIRD_WHATSAPP_TEMPLATE_LOCALE || 'ar';

const client = accountSid && authToken ? twilio(accountSid, authToken) : null;

function toE164(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (digits.startsWith('963')) return `+${digits}`;
  if (digits.startsWith('0')) return `+963${digits.slice(1)}`;
  if (digits.length === 9) return `+963${digits}`;
  return `+${digits}`;
}

function isConfigured() {
  if (whatsappProvider === 'bird') return Boolean(birdAccessKey && birdWorkspaceId && birdChannelId);
  return Boolean(client && whatsappFrom);
}

async function sendBirdOtp(phone, code) {
  if (!birdAccessKey || !birdWorkspaceId || !birdChannelId) {
    const err = new Error('Bird WhatsApp is not configured.');
    err.code = 'WHATSAPP_NOT_CONFIGURED';
    throw err;
  }

  const text = `رمز التحقق لحرفتي هو: ${code}`;
  const payload = {
    receiver: {
      contacts: [{
        identifierKey: 'phonenumber',
        identifierValue: toE164(phone)
      }]
    },
    reference: `hirfati-otp-${Date.now()}`,
    ...(birdTemplateName ? {
      template: {
        name: birdTemplateName,
        ...(birdTemplateProjectId ? { projectId: birdTemplateProjectId } : {}),
        ...(birdTemplateVersion ? { version: birdTemplateVersion } : {}),
        locale: birdTemplateLocale,
        parameters: [{ type: 'string', key: 'code', value: String(code) }]
      }
    } : {
      body: { type: 'text', text: { text } }
    })
  };

  const response = await fetch(`https://api.bird.com/workspaces/${birdWorkspaceId}/channels/${birdChannelId}/messages`, {
    method: 'POST',
    headers: {
      Authorization: `AccessKey ${birdAccessKey}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify(payload)
  });

  if (!response.ok) {
    const body = await response.text();
    const err = new Error(`Bird WhatsApp rejected the message: ${response.status}`);
    err.code = 'WHATSAPP_SEND_FAILED';
    err.providerResponse = body.slice(0, 500);
    throw err;
  }

  return response.json();
}

async function sendOtp(phone, code) {
  if (whatsappProvider === 'bird') return sendBirdOtp(phone, code);

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
