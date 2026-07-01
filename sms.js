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
const dialog360ApiKey = process.env.DIALOG360_API_KEY;
const dialog360TemplateName = process.env.DIALOG360_TEMPLATE_NAME || 'hirfati_otp';
const dialog360TemplateLanguage = process.env.DIALOG360_TEMPLATE_LANGUAGE || 'ar';
const dialog360Endpoint = process.env.DIALOG360_ENDPOINT || 'https://waba-v2.360dialog.io/messages';
const genericOtpUrl = process.env.GENERIC_WHATSAPP_OTP_URL;
const genericApiKey = process.env.GENERIC_WHATSAPP_API_KEY;
const genericAuthHeader = process.env.GENERIC_WHATSAPP_AUTH_HEADER || 'Authorization';
const genericAuthPrefix = process.env.GENERIC_WHATSAPP_AUTH_PREFIX || 'Bearer';

const client = accountSid && authToken ? twilio(accountSid, authToken) : null;

function toE164(phone) {
  const digits = String(phone || '').replace(/\D/g, '');
  if (digits.startsWith('963')) return `+${digits}`;
  if (digits.startsWith('0')) return `+963${digits.slice(1)}`;
  if (digits.length === 9) return `+963${digits}`;
  return `+${digits}`;
}

function isConfigured() {
  if (whatsappProvider === 'disabled' || whatsappProvider === 'none') return false;
  if (whatsappProvider === 'bird') return Boolean(birdAccessKey && birdWorkspaceId && birdChannelId);
  if (whatsappProvider === '360dialog') return Boolean(dialog360ApiKey && dialog360TemplateName);
  if (whatsappProvider === 'generic') return Boolean(genericOtpUrl);
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

async function send360DialogOtp(phone, code) {
  if (!dialog360ApiKey || !dialog360TemplateName) {
    const err = new Error('360dialog WhatsApp is not configured.');
    err.code = 'WHATSAPP_NOT_CONFIGURED';
    throw err;
  }

  const response = await fetch(dialog360Endpoint, {
    method: 'POST',
    headers: {
      'D360-API-KEY': dialog360ApiKey,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      messaging_product: 'whatsapp',
      recipient_type: 'individual',
      to: toE164(phone).replace(/^\+/, ''),
      type: 'template',
      template: {
        name: dialog360TemplateName,
        language: { code: dialog360TemplateLanguage },
        components: [{
          type: 'body',
          parameters: [{ type: 'text', text: String(code) }]
        }]
      }
    })
  });

  if (!response.ok) {
    const body = await response.text();
    const err = new Error(`360dialog WhatsApp rejected the message: ${response.status}`);
    err.code = 'WHATSAPP_SEND_FAILED';
    err.providerResponse = body.slice(0, 500);
    throw err;
  }

  return response.json();
}

async function sendGenericOtp(phone, code) {
  if (!genericOtpUrl) {
    const err = new Error('Generic WhatsApp OTP provider is not configured.');
    err.code = 'WHATSAPP_NOT_CONFIGURED';
    throw err;
  }

  const headers = { 'Content-Type': 'application/json' };
  if (genericApiKey) headers[genericAuthHeader] = genericAuthPrefix ? `${genericAuthPrefix} ${genericApiKey}` : genericApiKey;
  const message = `رمز التحقق لحرفتي هو: ${code}`;
  const response = await fetch(genericOtpUrl, {
    method: 'POST',
    headers,
    body: JSON.stringify({
      phone: toE164(phone),
      to: toE164(phone),
      code: String(code),
      message
    })
  });

  if (!response.ok) {
    const body = await response.text();
    const err = new Error(`Generic WhatsApp OTP provider rejected the message: ${response.status}`);
    err.code = 'WHATSAPP_SEND_FAILED';
    err.providerResponse = body.slice(0, 500);
    throw err;
  }

  return response.json();
}

async function sendOtp(phone, code) {
  if (whatsappProvider === 'disabled' || whatsappProvider === 'none') {
    const err = new Error('WhatsApp provider is disabled.');
    err.code = 'WHATSAPP_NOT_CONFIGURED';
    throw err;
  }
  if (whatsappProvider === 'bird') return sendBirdOtp(phone, code);
  if (whatsappProvider === '360dialog') return send360DialogOtp(phone, code);
  if (whatsappProvider === 'generic') return sendGenericOtp(phone, code);

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
