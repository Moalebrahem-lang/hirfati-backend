const jwt = require('jsonwebtoken');

const FCM_SCOPE = 'https://www.googleapis.com/auth/firebase.messaging';
const OAUTH_TOKEN_URL = 'https://oauth2.googleapis.com/token';

let cachedAccessToken = null;
let cachedAccessTokenExpiresAt = 0;
let lastError = null;

function getServiceAccount() {
  const rawJson = process.env.FIREBASE_SERVICE_ACCOUNT_JSON;
  if (rawJson) {
    try {
      return JSON.parse(rawJson);
    } catch (err) {
      lastError = new Error('FIREBASE_SERVICE_ACCOUNT_JSON is not valid JSON.');
      return null;
    }
  }

  const projectId = process.env.FIREBASE_PROJECT_ID;
  const clientEmail = process.env.FIREBASE_CLIENT_EMAIL;
  const privateKey = process.env.FIREBASE_PRIVATE_KEY?.replace(/\\n/g, '\n');
  if (!projectId || !clientEmail || !privateKey) return null;
  return { project_id: projectId, client_email: clientEmail, private_key: privateKey };
}

function getProjectId(serviceAccount) {
  return process.env.FIREBASE_PROJECT_ID || serviceAccount?.project_id || null;
}

function isPushConfigured() {
  const serviceAccount = getServiceAccount();
  return Boolean(serviceAccount?.client_email && serviceAccount?.private_key && getProjectId(serviceAccount));
}

function pushStatus() {
  return {
    configured: isPushConfigured(),
    error: lastError?.message || null
  };
}

async function getAccessToken(serviceAccount) {
  if (cachedAccessToken && cachedAccessTokenExpiresAt - 60_000 > Date.now()) return cachedAccessToken;

  const now = Math.floor(Date.now() / 1000);
  const assertion = jwt.sign({
    iss: serviceAccount.client_email,
    scope: FCM_SCOPE,
    aud: OAUTH_TOKEN_URL,
    iat: now,
    exp: now + 3600
  }, serviceAccount.private_key, { algorithm: 'RS256' });

  const body = new URLSearchParams({
    grant_type: 'urn:ietf:params:oauth:grant-type:jwt-bearer',
    assertion
  });
  const response = await fetch(OAUTH_TOKEN_URL, {
    method: 'POST',
    headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
    body
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok || !data.access_token) {
    throw new Error(data.error_description || data.error || 'Unable to get Firebase access token.');
  }

  cachedAccessToken = data.access_token;
  cachedAccessTokenExpiresAt = Date.now() + Number(data.expires_in || 3600) * 1000;
  return cachedAccessToken;
}

async function sendOne(projectId, accessToken, token, payload) {
  const response = await fetch(`https://fcm.googleapis.com/v1/projects/${encodeURIComponent(projectId)}/messages:send`, {
    method: 'POST',
    headers: {
      Authorization: `Bearer ${accessToken}`,
      'Content-Type': 'application/json'
    },
    body: JSON.stringify({
      message: {
        token,
        notification: {
          title: payload.title || 'حرفتي',
          body: payload.body || payload.text || ''
        },
        data: Object.fromEntries(Object.entries(payload.data || {}).map(([key, value]) => [key, String(value ?? '')])),
        android: {
          priority: 'HIGH',
          notification: {
            channel_id: 'hirfati_default',
            sound: 'default'
          }
        }
      }
    })
  });
  const data = await response.json().catch(() => ({}));
  if (!response.ok) {
    const err = new Error(data.error?.message || 'FCM send failed.');
    err.status = response.status;
    err.details = data.error || null;
    throw err;
  }
  return data;
}

async function sendToTokens(tokens, payload = {}) {
  const cleanTokens = [...new Set((tokens || []).filter(Boolean))];
  if (!cleanTokens.length) return { successCount: 0, failureCount: 0, responses: [], disabled: false };

  const serviceAccount = getServiceAccount();
  const projectId = getProjectId(serviceAccount);
  if (!serviceAccount || !projectId) {
    return { successCount: 0, failureCount: cleanTokens.length, responses: [], disabled: true, error: 'FCM is not configured.' };
  }

  try {
    const accessToken = await getAccessToken(serviceAccount);
    const responses = await Promise.all(cleanTokens.map(async token => {
      try {
        await sendOne(projectId, accessToken, token, payload);
        return { success: true };
      } catch (err) {
        return { success: false, error: err.message };
      }
    }));
    lastError = null;
    return {
      successCount: responses.filter(item => item.success).length,
      failureCount: responses.filter(item => !item.success).length,
      responses,
      disabled: false
    };
  } catch (err) {
    lastError = err;
    return {
      successCount: 0,
      failureCount: cleanTokens.length,
      responses: cleanTokens.map(() => ({ success: false, error: err.message })),
      disabled: false,
      error: err.message
    };
  }
}

module.exports = {
  pushStatus,
  sendToTokens
};
