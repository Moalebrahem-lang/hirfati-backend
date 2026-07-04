const crypto = require('crypto');

const DATA_IMAGE_RE = /^data:image\/(png|jpe?g|webp);base64,[A-Za-z0-9+/=]+$/i;
const CLOUDINARY_URL_RE = /^https:\/\/res\.cloudinary\.com\/[^/]+\/image\/upload\//i;

function cloudinaryConfig() {
  return {
    cloudName: process.env.CLOUDINARY_CLOUD_NAME,
    apiKey: process.env.CLOUDINARY_API_KEY,
    apiSecret: process.env.CLOUDINARY_API_SECRET
  };
}

function isCloudinaryConfigured() {
  const { cloudName, apiKey, apiSecret } = cloudinaryConfig();
  return Boolean(cloudName && apiKey && apiSecret);
}

function isDataImage(value) {
  return typeof value === 'string' && DATA_IMAGE_RE.test(value);
}

function signParams(params, apiSecret) {
  const payload = Object.keys(params)
    .filter(key => params[key] !== undefined && params[key] !== null && params[key] !== '')
    .sort()
    .map(key => `${key}=${params[key]}`)
    .join('&');
  return crypto.createHash('sha1').update(`${payload}${apiSecret}`).digest('hex');
}

async function uploadImageDataUri(dataUri, { folder = 'hirfati/uploads', publicId } = {}) {
  if (!isDataImage(dataUri)) return dataUri;

  const { cloudName, apiKey, apiSecret } = cloudinaryConfig();
  if (!cloudName || !apiKey || !apiSecret) {
    const err = new Error('Cloudinary image storage is not configured.');
    err.code = 'IMAGE_STORAGE_NOT_CONFIGURED';
    throw err;
  }

  const timestamp = Math.floor(Date.now() / 1000);
  const signedParams = { folder, timestamp };
  if (publicId) signedParams.public_id = publicId;
  const signature = signParams(signedParams, apiSecret);

  const form = new FormData();
  form.append('file', dataUri);
  form.append('api_key', apiKey);
  form.append('timestamp', String(timestamp));
  form.append('folder', folder);
  if (publicId) form.append('public_id', publicId);
  form.append('signature', signature);

  const response = await fetch(`https://api.cloudinary.com/v1_1/${cloudName}/image/upload`, {
    method: 'POST',
    body: form
  });
  const body = await response.json().catch(() => ({}));
  if (!response.ok || !body.secure_url || !CLOUDINARY_URL_RE.test(body.secure_url)) {
    const err = new Error(body.error?.message || 'Cloudinary upload failed.');
    err.code = 'IMAGE_UPLOAD_FAILED';
    err.status = response.status;
    throw err;
  }
  return body.secure_url;
}

async function uploadImages(values = [], options = {}) {
  return Promise.all((values || []).map((value, index) => (
    isDataImage(value)
      ? uploadImageDataUri(value, {
        ...options,
        publicId: options.publicId ? `${options.publicId}-${index + 1}` : undefined
      })
      : value
  )));
}

function bufferToDataUri(file) {
  return `data:${file.mimetype};base64,${file.buffer.toString('base64')}`;
}

module.exports = {
  isCloudinaryConfigured,
  isDataImage,
  uploadImageDataUri,
  uploadImages,
  bufferToDataUri
};
