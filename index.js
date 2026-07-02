require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const Joi = require('joi');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { connect, cols, stripMongoId, normalizeMany, healthCheck } = require('./db');
const { sendOtp } = require('./sms');
const { sendVerificationEmail } = require('./email');
const { pushStatus, sendToTokens } = require('./push');
const createAdminDashboard = require('./adminDashboard');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET = process.env.JWT_SECRET || 'hirfati-secret-key-2024';
const DEFAULT_ALLOWED_ORIGINS = [
  'https://hirfati-backend-production.up.railway.app',
  'capacitor://localhost',
  'http://localhost',
  'http://localhost:3000',
  'http://localhost:8100'
];
const configuredOrigins = (process.env.CORS_ORIGINS || process.env.CORS_ORIGIN || '')
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);
const ALLOWED_ORIGINS = [...new Set([...DEFAULT_ALLOWED_ORIGINS, ...configuredOrigins])];
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 5);
const OTP_RATE_LIMIT_MS = Number(process.env.OTP_RATE_LIMIT_MS || 60 * 1000);
const ENABLE_OTP_AUTH = process.env.ENABLE_OTP_AUTH === 'true';
const EMAIL_CODE_TTL_MINUTES = Number(process.env.EMAIL_CODE_TTL_MINUTES || 10);
const PASSWORD_LOCK_MS = Number(process.env.PASSWORD_LOCK_MS || 15 * 60 * 1000);
const PASSWORD_MAX_FAILED_ATTEMPTS = Number(process.env.PASSWORD_MAX_FAILED_ATTEMPTS || 5);
const PASSWORD_BCRYPT_ROUNDS = Number(process.env.PASSWORD_BCRYPT_ROUNDS || 12);
const ACCESS_TOKEN_TTL = process.env.ACCESS_TOKEN_TTL || '20m';
const REFRESH_TOKEN_DAYS = Number(process.env.REFRESH_TOKEN_DAYS || 7);
const ENGAGEMENT_INTERVAL_MS = Number(process.env.ENGAGEMENT_INTERVAL_MS || 15 * 60 * 1000);
if (process.env.NODE_ENV === 'production' && SECRET === 'hirfati-secret-key-2024') {
  throw new Error('JWT_SECRET must be set to a strong secret in production.');
}
if (process.env.NODE_ENV === 'production' && !process.env.ENCRYPTION_KEY) {
  throw new Error('ENCRYPTION_KEY must be set to a separate strong secret in production.');
}
const createEncryptionKey = value => crypto.createHash('sha256').update(value).digest();
const ENCRYPTION_KEY = createEncryptionKey(process.env.ENCRYPTION_KEY || SECRET);
const LEGACY_ENCRYPTION_KEY = createEncryptionKey(SECRET);

app.disable('x-powered-by');
app.set('trust proxy', 1);
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
const corsOptions = {
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS origin is not allowed.'));
  },
  credentials: true
};
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: false, limit: '1mb' }));
const hasNoSqlOperator = value => {
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some(hasNoSqlOperator);
  return Object.entries(value).some(([key, child]) => (
    key.startsWith('$') || key.includes('.') || hasNoSqlOperator(child)
  ));
};
const hasSuspiciousString = value => {
  if (typeof value === 'string') return /<\s*script|javascript:|onerror\s*=|onload\s*=/i.test(value);
  if (!value || typeof value !== 'object') return false;
  if (Array.isArray(value)) return value.some(hasSuspiciousString);
  return Object.values(value).some(hasSuspiciousString);
};
const rejectUnsafeInput = (req, res, next) => {
  if (hasNoSqlOperator(req.body) || hasNoSqlOperator(req.query) || hasNoSqlOperator(req.params)) {
    return res.status(400).json({ error: 'المدخلات غير مسموحة.' });
  }
  if (hasSuspiciousString(req.body) || hasSuspiciousString(req.query) || hasSuspiciousString(req.params)) {
    return res.status(400).json({ error: 'المدخلات تحتوي محتوى غير آمن.' });
  }
  next();
};
const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX || 100),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'طلبات كثيرة. حاول لاحقاً.' }
});
const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.AUTH_RATE_LIMIT_MAX || 20),
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  message: { error: 'طلبات مصادقة كثيرة. حاول بعد 15 دقيقة.' }
});
const loginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.LOGIN_RATE_LIMIT_MAX || 5),
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  message: { error: 'محاولات دخول كثيرة. حاول بعد 15 دقيقة.' }
});
const requireOtpEnabled = (req, res, next) => {
  if (!ENABLE_OTP_AUTH) return res.status(410).json({ error: 'تسجيل الدخول عبر OTP غير مفعّل حالياً.' });
  next();
};
app.use('/api', cors(corsOptions));
app.use('/api', apiLimiter);
app.use('/api', rejectUnsafeInput);
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, '../frontend/build')));

app.get('/health', (req, res) => {
  res.json({ status: 'ok' });
});

const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, `${Date.now()}-${Math.random().toString(36).slice(2, 8)}${path.extname(file.originalname)}`);
  }
});
const upload = multer({
  storage,
  limits: { fileSize: 10 * 1024 * 1024 },
  fileFilter: (req, file, cb) => {
    if (!file.mimetype.startsWith('image/')) return cb(new Error('يسمح برفع الصور فقط.'));
    cb(null, true);
  }
});

const id = prefix => prefix + Math.random().toString(36).slice(2, 10);
const normalizePhone = phone => {
  const digits = String(phone || '').replace(/\D/g, '');
  if (digits.startsWith('963') && digits.length === 12) return `0${digits.slice(3)}`;
  return digits;
};
const createOtp = () => String(crypto.randomInt(1000, 10000));
const createResetCode = () => crypto.randomBytes(5).toString('base64url').replace(/[^A-Z0-9]/gi, '').toUpperCase().slice(0, 8).padEnd(8, '7');
const hashOtp = (phone, otp) => crypto
  .createHash('sha256')
  .update(`${normalizePhone(phone)}:${otp}:${SECRET}`)
  .digest('hex');
const hashResetCode = (phone, code) => crypto
  .createHash('sha256')
  .update(`${normalizePhone(phone)}:${String(code || '').toUpperCase()}:${SECRET}`)
  .digest('hex');
const createEmailCode = () => String(crypto.randomInt(100000, 1000000));
const hashEmailCode = (userId, code) => crypto
  .createHash('sha256')
  .update(`${userId}:${String(code || '').replace(/\D/g, '')}:${SECRET}`)
  .digest('hex');
const signAuthToken = user => jwt.sign({ id: user.id, role: user.role, type: 'access' }, SECRET, { expiresIn: ACCESS_TOKEN_TTL });
const hashRefreshToken = token => crypto.createHash('sha256').update(`${token}:${SECRET}`).digest('hex');
const encryptSensitive = value => {
  if (!value) return null;
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', ENCRYPTION_KEY, iv);
  const encrypted = Buffer.concat([cipher.update(String(value), 'utf8'), cipher.final()]);
  return {
    alg: 'aes-256-gcm',
    iv: iv.toString('base64url'),
    tag: cipher.getAuthTag().toString('base64url'),
    value: encrypted.toString('base64url')
  };
};
const decryptSensitive = payload => {
  if (!payload?.value || !payload?.iv || !payload?.tag) return null;
  const keys = [ENCRYPTION_KEY];
  if (!ENCRYPTION_KEY.equals(LEGACY_ENCRYPTION_KEY)) keys.push(LEGACY_ENCRYPTION_KEY);
  for (const key of keys) {
    try {
      const decipher = crypto.createDecipheriv('aes-256-gcm', key, Buffer.from(payload.iv, 'base64url'));
      decipher.setAuthTag(Buffer.from(payload.tag, 'base64url'));
      const decrypted = Buffer.concat([
        decipher.update(Buffer.from(payload.value, 'base64url')),
        decipher.final()
      ]);
      return decrypted.toString('utf8');
    } catch (err) {
      // Try the next key to support records encrypted before ENCRYPTION_KEY was introduced.
    }
  }
  return null;
};
const publicUser = user => {
  const clean = stripMongoId(user);
  delete clean.passwordHash;
  delete clean.recoveryAnswerHash;
  delete clean.recoveryQuestion;
  delete clean.passwordSetAt;
  delete clean.auth;
  delete clean.recoveryEmail;
  delete clean.recoveryEmailEnc;
  delete clean.emailVerification;
  return clean;
};
const isValidPin = pin => /^\d{4,6}$/.test(String(pin || ''));
const normalizeRecoveryAnswer = answer => String(answer || '').trim().toLowerCase().replace(/\s+/g, ' ');
const ipOf = req => String(req.headers['x-forwarded-for'] || req.ip || '').split(',')[0].trim();

const safeText = (max = 200) => Joi.string().trim().min(1).max(max);
const optionalText = (max = 200) => Joi.string().trim().allow('', null).max(max);
const phoneSchema = Joi.string().trim().min(7).max(24).pattern(/^[+\d\s().-]+$/).required();
const pinSchema = Joi.string().trim().pattern(/^\d{4,6}$/).required();
const idSchema = Joi.string().trim().min(2).max(40).pattern(/^[A-Za-z0-9_-]+$/);
const imageSchema = Joi.string().trim().max(8 * 1024 * 1024).pattern(/^(data:image\/(png|jpe?g|webp);base64,[A-Za-z0-9+/=]+|\/uploads\/[A-Za-z0-9_.-]+)$/);
const identityImageSchema = Joi.string().trim().max(6 * 1024 * 1024).pattern(/^data:image\/(png|jpe?g|webp);base64,[A-Za-z0-9+/=]+$/).required();
const schemas = {
  passwordRegister: Joi.object({
    phone: phoneSchema,
    pin: pinSchema,
    name: safeText(80).required(),
    role: Joi.string().valid('client', 'craftsman').default('client'),
    city: optionalText(60).default('دمشق'),
    specialty: optionalText(80),
    recoveryQuestion: safeText(120).required(),
    recoveryAnswer: safeText(120).required(),
    recoveryEmail: Joi.string().trim().email().max(160).required()
  }),
  passwordLogin: Joi.object({ phone: phoneSchema, pin: pinSchema }),
  recoveryStart: Joi.object({ phone: phoneSchema }),
  recoveryVerify: Joi.object({ phone: phoneSchema, recoveryAnswer: safeText(120).required(), newPin: pinSchema }),
  emailVerificationRequest: Joi.object({ email: Joi.string().trim().email().max(160).required() }),
  emailVerificationConfirm: Joi.object({ code: Joi.string().trim().pattern(/^\d{6}$/).required() }),
  otpRequest: Joi.object({ phone: phoneSchema }),
  otpVerify: Joi.object({ phone: phoneSchema, otp: Joi.string().trim().pattern(/^\d{4}$/).required() }),
  legacyRegister: Joi.object({
    registrationToken: Joi.string().trim().min(20).max(2000).required(),
    name: safeText(80).required(),
    role: Joi.string().valid('client', 'craftsman').default('client'),
    city: optionalText(60).default('دمشق'),
    specialty: optionalText(80)
  }),
  profile: Joi.object({
    name: optionalText(80),
    city: optionalText(60),
    bio: optionalText(600),
    range: Joi.number().integer().min(1).max(300),
    avatar: optionalText(2 * 1024 * 1024),
    specialty: optionalText(80)
  }).min(1),
  jobCreate: Joi.object({
    title: safeText(120).required(),
    desc: safeText(2000).required(),
    category: safeText(80).required(),
    city: safeText(60).required(),
    area: optionalText(100),
    photos: Joi.array().items(imageSchema).max(5).default([]),
    budget: Joi.alternatives().try(Joi.number().integer().min(0).max(1000000000), optionalText(60)),
    schedule: optionalText(80),
    urgency: Joi.string().valid('normal', 'urgent').default('normal')
  }),
  jobStatus: Joi.object({
    status: Joi.string().valid('open', 'matched', 'done', 'reviewed', 'cancelled').required(),
    chosenCraftsman: idSchema.allow('', null),
    cancelReason: optionalText(300)
  }),
  interestCreate: Joi.object({
    jobId: idSchema.required(),
    note: optionalText(600),
    estimate: Joi.alternatives().try(Joi.number().integer().min(0).max(1000000000), optionalText(80))
  }),
  interestStatus: Joi.object({ status: Joi.string().valid('accepted', 'rejected').required() }),
  messageCreate: Joi.object({
    jobId: idSchema.required(),
    receiverId: idSchema.required(),
    text: optionalText(2000),
    image: imageSchema.allow('', null)
  }).or('text', 'image'),
  reviewCreate: Joi.object({
    craftsmanId: idSchema.required(),
    rating: Joi.number().integer().min(1).max(5).required(),
    title: safeText(100).required(),
    text: safeText(1000).required()
  }),
  reportCreate: Joi.object({
    type: Joi.string().valid('user', 'job', 'message', 'review').required(),
    targetId: idSchema.required(),
    reason: safeText(400).required()
  }),
  refresh: Joi.object({
    refreshToken: Joi.string().trim().min(40).max(300).required()
  }),
  logout: Joi.object({
    refreshToken: Joi.string().trim().min(40).max(300)
  }),
  deviceToken: Joi.object({
    token: Joi.string().trim().min(20).max(4096).required(),
    platform: Joi.string().valid('ios', 'android', 'web', 'unknown').default('unknown'),
    deviceId: optionalText(120)
  }),
  campaign: Joi.object({
    title: safeText(90).required(),
    text: safeText(240).required(),
    target: Joi.string().valid('all', 'clients', 'craftsmen', 'city_craftsmen', 'city_clients').required(),
    city: optionalText(60),
    specialty: optionalText(80)
  }),
  identitySubmit: Joi.object({
    idCardImage: identityImageSchema,
    selfieImage: identityImageSchema,
    note: optionalText(500)
  }),
  identityRecoverySubmit: Joi.object({
    phone: phoneSchema,
    idCardImage: identityImageSchema,
    selfieImage: identityImageSchema,
    note: optionalText(500)
  }),
  identityDecision: Joi.object({
    status: Joi.string().valid('approved', 'rejected').required(),
    note: optionalText(500)
  }),
  identityReset: Joi.object({
    phone: phoneSchema,
    resetCode: Joi.string().trim().length(8).pattern(/^[A-Z0-9]+$/).required(),
    newPin: pinSchema
  })
};

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
const validateBody = schema => (req, res, next) => {
  const { value, error } = schema.validate(req.body, {
    abortEarly: false,
    stripUnknown: true,
    convert: true
  });
  if (error) return res.status(400).json({ error: 'تحقق من البيانات المدخلة.', details: error.details.map(d => d.message) });
  req.body = value;
  next();
};
const validateIdParam = (req, res, next) => {
  const { error } = idSchema.required().validate(req.params.id);
  if (error) return res.status(400).json({ error: 'المعرّف غير صحيح.' });
  next();
};
const requireAdmin = (req, res, next) => {
  if (req.user?.role !== 'admin') return res.status(403).json({ error: 'غير مسموح.' });
  next();
};
const requireVerifiedEmail = (req, res, next) => {
  if (req.currentUser?.emailVerificationRequired && !req.currentUser?.emailVerifiedAt) {
    return res.status(403).json({
      error: 'يرجى تأكيد البريد الإلكتروني قبل استخدام التطبيق.',
      requiresEmailVerification: true
    });
  }
  next();
};

const authenticate = async (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'يرجى تسجيل الدخول.' });
  try {
    const payload = jwt.verify(token, SECRET);
    if (payload.type !== 'access') return res.status(401).json({ error: 'جلسة الدخول غير صالحة.' });
    const user = await cols().users.findOne({ id: payload.id });
    if (!user) return res.status(401).json({ error: 'جلسة الدخول غير صالحة.' });
    if (user.disabledAt) return res.status(403).json({ error: 'تم تعطيل هذا الحساب من الإدارة.' });
    req.user = payload;
    req.currentUser = user;
    next();
  } catch (err) {
    res.status(401).json({ error: 'جلسة الدخول غير صالحة.' });
  }
};

async function issueRefreshToken(user, req) {
  const refreshToken = crypto.randomBytes(48).toString('base64url');
  await cols().refreshTokens.insertOne({
    id: id('rt'),
    userId: user.id,
    tokenHash: hashRefreshToken(refreshToken),
    createdAt: new Date(),
    expiresAt: new Date(Date.now() + REFRESH_TOKEN_DAYS * 24 * 60 * 60 * 1000),
    revokedAt: null,
    ip: ipOf(req) || null,
    userAgent: req.headers['user-agent'] || null
  });
  return refreshToken;
}

async function authPayload(user, req) {
  const cleanUser = publicUser(user);
  const refreshToken = await issueRefreshToken(cleanUser, req);
  const accessToken = signAuthToken(cleanUser);
  return {
    token: accessToken,
    accessToken,
    refreshToken,
    expiresIn: ACCESS_TOKEN_TTL,
    user: cleanUser
  };
}

async function addNotif(userId, type, text, jobId) {
  const notificationId = id('n');
  await cols().notifications.insertOne({
    id: notificationId,
    userId,
    type,
    text,
    jobId: jobId || null,
    at: Date.now(),
    read: 0
  });
  await sendPushToUsers([userId], {
    title: 'حرفتي',
    body: text,
    data: { type, jobId: jobId || '', notificationId }
  });
  return notificationId;
}

async function sendPushToUsers(userIds, payload) {
  const targetIds = [...new Set((userIds || []).filter(Boolean))];
  if (!targetIds.length) return { successCount: 0, failureCount: 0, disabled: false };
  const tokens = await cols().deviceTokens.find({
    userId: { $in: targetIds },
    disabledAt: null
  }).project({ token: 1 }).toArray();
  const result = await sendToTokens(tokens.map(item => item.token), payload);
  if (result.responses?.length) {
    const failedTokens = result.responses
      .map((response, index) => response.success ? null : tokens[index]?.token)
      .filter(Boolean);
    if (failedTokens.length) {
      await cols().deviceTokens.updateMany(
        { token: { $in: failedTokens } },
        { $set: { disabledAt: Date.now(), disabledReason: 'fcm_send_failed' } }
      );
    }
  }
  return result;
}

async function addBulkNotifications(userIds, type, text, jobId, pushPayload = {}) {
  const targetIds = [...new Set((userIds || []).filter(Boolean))];
  if (!targetIds.length) return { inserted: 0, push: { successCount: 0, failureCount: 0 } };
  const docs = targetIds.map(userId => ({
    id: id('n'),
    userId,
    type,
    text,
    jobId: jobId || null,
    at: Date.now(),
    read: 0
  }));
  await cols().notifications.insertMany(docs, { ordered: false });
  const push = await sendPushToUsers(targetIds, {
    title: pushPayload.title || 'حرفتي',
    body: pushPayload.body || text,
    data: { type, jobId: jobId || '', ...(pushPayload.data || {}) }
  });
  return { inserted: docs.length, push };
}

async function createEngagementOnce(key, type, userId, text, meta = {}) {
  const event = {
    id: id('eng'),
    key,
    type,
    userId,
    meta,
    createdAt: Date.now()
  };
  try {
    await cols().engagementEvents.insertOne(event);
    await addNotif(userId, type, text, meta.jobId || null);
    return true;
  } catch (err) {
    if (err.code === 11000) return false;
    throw err;
  }
}

function campaignFilter({ target, city, specialty }) {
  const active = { $or: [{ disabledAt: { $exists: false } }, { disabledAt: null }] };
  const filters = [active];
  if (target === 'clients') filters.push({ role: 'client' });
  if (target === 'craftsmen') filters.push({ role: 'craftsman' });
  if (target === 'city_craftsmen') filters.push({ role: 'craftsman', city });
  if (target === 'city_clients') filters.push({ role: 'client', city });
  if (specialty) filters.push({ specialty });
  return filters.length === 1 ? active : { $and: filters };
}

async function sendAdminCampaign({ title, text, target, city, specialty }, req) {
  const { value, error } = schemas.campaign.validate({ title, text, target, city, specialty }, {
    abortEarly: false,
    stripUnknown: true,
    convert: true
  });
  if (error) {
    const err = new Error('تحقق من بيانات الحملة.');
    err.status = 400;
    throw err;
  }
  ({ title, text, target, city, specialty } = value);
  if (hasSuspiciousString({ title, text, city, specialty })) {
    const err = new Error('محتوى الحملة يحتوي نصاً غير آمن.');
    err.status = 400;
    throw err;
  }
  if ((target === 'city_craftsmen' || target === 'city_clients') && !city) {
    const err = new Error('اختر المدينة لهذا النوع من الاستهداف.');
    err.status = 400;
    throw err;
  }
  const filter = campaignFilter({ target, city, specialty });
  const users = await cols().users.find(filter).project({ id: 1 }).limit(5000).toArray();
  const result = await addBulkNotifications(
    users.map(user => user.id),
    'campaign',
    text,
    null,
    { title, body: text, data: { campaign: 'manual', target } }
  );
  const campaign = {
    id: id('camp'),
    title,
    text,
    target,
    city: city || null,
    specialty: specialty || null,
    recipients: users.length,
    pushSuccess: result.push?.successCount || 0,
    pushFailure: result.push?.failureCount || 0,
    createdBy: req?.user?.id || 'admin-dashboard',
    createdAt: Date.now()
  };
  await cols().campaigns.insertOne(campaign);
  await logAudit('admin.campaign.sent', req || { headers: {} }, {
    userId: req?.user?.id || null,
    result: 'success',
    targetId: campaign.id,
    meta: { target, city: city || null, specialty: specialty || null, recipients: users.length }
  });
  return { campaign, result };
}

async function logRecoveryAttempt(phone, result, reason, req) {
  await cols().passwordRecoveryLogs.insertOne({
    id: id('pr'),
    phone,
    result,
    reason: reason || null,
    ip: ipOf(req) || null,
    userAgent: req.headers['user-agent'] || null,
    at: Date.now()
  });
}

async function logAudit(type, req, details = {}) {
  await cols().auditLogs.insertOne({
    id: id('a'),
    type,
    userId: req.user?.id || details.userId || null,
    phone: details.phone || null,
    result: details.result || null,
    targetId: details.targetId || null,
    meta: details.meta || null,
    ip: ipOf(req) || null,
    userAgent: req.headers['user-agent'] || null,
    at: Date.now()
  });
}

function isPasswordBlocked(user) {
  const blockedUntil = user?.auth?.loginBlockedUntil || 0;
  return blockedUntil && blockedUntil > Date.now();
}

async function recordPasswordFailure(phone) {
  const user = await cols().users.findOne({ phone });
  if (!user) return;
  const count = (user.auth?.failedLoginCount || 0) + 1;
  const update = { 'auth.failedLoginCount': count, 'auth.lastFailedLoginAt': Date.now() };
  if (count >= PASSWORD_MAX_FAILED_ATTEMPTS) {
    update['auth.loginBlockedUntil'] = Date.now() + PASSWORD_LOCK_MS;
  }
  await cols().users.updateOne({ phone }, { $set: update });
}

async function clearPasswordFailures(phone) {
  await cols().users.updateOne(
    { phone },
    { $set: { 'auth.failedLoginCount': 0, 'auth.loginBlockedUntil': 0, 'auth.lastLoginAt': Date.now() } }
  );
}

async function sendRealOtp(req, res, phone) {
  const existingOtp = await cols().otps.findOne({ phone, purpose: 'login' });
  const lastSentAt = existingOtp?.lastSentAt ? new Date(existingOtp.lastSentAt).getTime() : 0;
  const retryAfterMs = OTP_RATE_LIMIT_MS - (Date.now() - lastSentAt);
  if (retryAfterMs > 0) {
    return res.status(429).json({
      error: 'تم إرسال رمز مؤخراً. انتظر قليلاً قبل طلب رمز جديد.',
      retryAfterSeconds: Math.ceil(retryAfterMs / 1000)
    });
  }

  const otp = createOtp();
  await cols().otps.updateOne(
    { phone, purpose: 'login' },
    {
      $set: {
        phone,
        purpose: 'login',
        hash: hashOtp(phone, otp),
        attempts: 0,
        expiresAt: new Date(Date.now() + OTP_TTL_MINUTES * 60 * 1000),
        createdAt: new Date(),
        lastSentAt: new Date()
      }
    },
    { upsert: true }
  );

  try {
    await sendOtp(phone, otp);
  } catch (err) {
    console.error('Twilio WhatsApp OTP failed:', {
      status: err.status,
      code: err.code,
      message: err.message,
      moreInfo: err.moreInfo
    });
    await logAudit('auth.otp.send', req, { phone, result: 'failed', meta: { reason: 'whatsapp_send_failed', code: err.code || null } });
    return res.status(503).json({ error: 'تعذر إرسال رمز التحقق عبر واتساب حالياً.' });
  }

  await logAudit('auth.otp.send', req, { phone, result: 'success' });
  return res.json({ message: 'تم إرسال رمز التحقق عبر واتساب.', authMode: 'otp' });
}

async function handleOtpRequest(req, res, { legacy = false } = {}) {
  const phone = normalizePhone(req.body.phone);
  if (!phone || phone.length < 9) return res.status(400).json({ error: 'رقم الهاتف غير صحيح.' });

  if (ENABLE_OTP_AUTH) {
    return sendRealOtp(req, res, phone);
  }

  const user = await cols().users.findOne({ phone });
  await logAudit('auth.otp.compat', req, {
    phone,
    userId: user?.id || null,
    result: 'password_required',
    meta: { endpoint: legacy ? 'send-otp' : 'otp', userExists: Boolean(user), hasPassword: Boolean(user?.passwordHash) }
  });

  if (user?.passwordHash) {
    return res.json({
      message: 'هذا الحساب يستخدم تسجيل الدخول بالـ PIN.',
      authMode: 'password',
      requiresPin: true,
      userExists: true
    });
  }

  if (user && !user.passwordHash) {
    return res.status(409).json({
      error: 'هذا الحساب يحتاج إعداد PIN قبل تسجيل الدخول.',
      authMode: 'password',
      requiresPinSetup: true,
      userExists: true
    });
  }

  return res.json({
    message: 'أنشئ حساباً جديداً واختر PIN لتسجيل الدخول.',
    authMode: 'password',
    needsRegistration: true,
    userExists: false
  });
}

app.get('/api/health', asyncRoute(async (req, res) => {
  const status = await healthCheck();
  res.status(status.ok ? 200 : 503).json(status);
}));

// --- AUTH ---
app.post('/api/auth/password/register', authLimiter, validateBody(schemas.passwordRegister), asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const { pin, name, role, city, specialty, recoveryQuestion, recoveryAnswer, recoveryEmail } = req.body;

  if (!phone || phone.length < 9) return res.status(400).json({ error: 'رقم الهاتف غير صحيح.' });
  if (!isValidPin(pin)) return res.status(400).json({ error: 'اختر PIN من 4 إلى 6 أرقام.' });
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'أدخل الاسم.' });
  if (!recoveryQuestion || !String(recoveryQuestion).trim()) return res.status(400).json({ error: 'اختر سؤال أمان.' });
  if (!recoveryAnswer || normalizeRecoveryAnswer(recoveryAnswer).length < 2) return res.status(400).json({ error: 'أدخل إجابة أمان واضحة.' });

  const { users } = cols();
  const existing = await users.findOne({ phone });
  if (existing?.passwordHash) return res.status(409).json({ error: 'هذا الرقم مسجل مسبقاً. سجّل الدخول بالـ PIN.' });
  if (existing && !existing.passwordHash) {
    return res.status(409).json({ error: 'هذا الحساب موجود ويحتاج تفعيل كلمة مرور من الإدارة.' });
  }

  const passwordHash = await bcrypt.hash(String(pin), PASSWORD_BCRYPT_ROUNDS);
  const recoveryAnswerHash = await bcrypt.hash(normalizeRecoveryAnswer(recoveryAnswer), PASSWORD_BCRYPT_ROUNDS);
  const cleanName = String(name).trim();
  const user = {
    id: id('u'),
    name: cleanName,
    phone,
    role: role || 'client',
    city: city || 'دمشق',
    avatar: cleanName.slice(0, 2),
    specialty: role === 'craftsman' ? (specialty || null) : null,
    rating: 0,
    reviewsCount: 0,
    bio: '',
    verified: 0,
    warranty: 0,
    jobsDone: 0,
    range: 25,
    saved: [],
    createdAt: Date.now(),
    passwordHash,
    passwordSetAt: Date.now(),
    recoveryQuestion: String(recoveryQuestion).trim(),
    recoveryAnswerHash,
    recoveryEmailEnc: encryptSensitive(String(recoveryEmail).trim().toLowerCase()),
    emailVerificationRequired: true,
    emailVerifiedAt: null,
    auth: { failedLoginCount: 0, loginBlockedUntil: 0 }
  };

  await users.insertOne(user);
  await logAudit('auth.register', req, { phone, userId: user.id, result: 'success', meta: { role: user.role } });
  res.json(await authPayload(user, req));
}));

app.post('/api/auth/password/login', loginLimiter, validateBody(schemas.passwordLogin), asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const { pin } = req.body;
  if (!phone || phone.length < 9) return res.status(400).json({ error: 'رقم الهاتف غير صحيح.' });
  if (!isValidPin(pin)) return res.status(400).json({ error: 'PIN غير صحيح.' });

  const user = await cols().users.findOne({ phone });
  if (!user || !user.passwordHash) {
    await recordPasswordFailure(phone);
    await logAudit('auth.login', req, { phone, result: 'failed', meta: { reason: 'invalid_credentials' } });
    return res.status(401).json({ error: 'رقم الهاتف أو PIN غير صحيح.' });
  }
  if (user.disabledAt) {
    await logAudit('auth.login', req, { phone, userId: user.id, result: 'blocked', meta: { reason: 'account_disabled' } });
    return res.status(403).json({ error: 'تم تعطيل هذا الحساب من الإدارة.' });
  }
  if (isPasswordBlocked(user)) {
    const retryAfterSeconds = Math.ceil((user.auth.loginBlockedUntil - Date.now()) / 1000);
    await logAudit('auth.login', req, { phone, userId: user.id, result: 'blocked', meta: { retryAfterSeconds } });
    return res.status(429).json({ error: 'محاولات كثيرة. حاول لاحقاً.', retryAfterSeconds });
  }

  const ok = await bcrypt.compare(String(pin), user.passwordHash);
  if (!ok) {
    await recordPasswordFailure(phone);
    await logAudit('auth.login', req, { phone, userId: user.id, result: 'failed', meta: { reason: 'wrong_pin' } });
    return res.status(401).json({ error: 'رقم الهاتف أو PIN غير صحيح.' });
  }

  await clearPasswordFailures(phone);
  await logAudit('auth.login', req, { phone, userId: user.id, result: 'success' });
  res.json(await authPayload(user, req));
}));

app.post('/api/auth/password/recovery/start', authLimiter, validateBody(schemas.recoveryStart), asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  if (!phone || phone.length < 9) return res.status(400).json({ error: 'رقم الهاتف غير صحيح.' });

  const user = await cols().users.findOne({ phone });
  if (!user?.recoveryQuestion || !user?.recoveryAnswerHash) {
    await logRecoveryAttempt(phone, 'failed', 'missing_recovery_question', req);
    return res.status(404).json({ error: 'لا يوجد سؤال استرجاع لهذا الحساب.' });
  }

  await logRecoveryAttempt(phone, 'started', 'question_returned', req);
  res.json({ recoveryQuestion: user.recoveryQuestion });
}));

app.post('/api/auth/password/recovery/verify', authLimiter, validateBody(schemas.recoveryVerify), asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const { recoveryAnswer, newPin } = req.body;
  if (!phone || phone.length < 9) return res.status(400).json({ error: 'رقم الهاتف غير صحيح.' });
  if (!isValidPin(newPin)) return res.status(400).json({ error: 'اختر PIN جديد من 4 إلى 6 أرقام.' });

  const user = await cols().users.findOne({ phone });
  if (!user?.recoveryAnswerHash) {
    await logRecoveryAttempt(phone, 'failed', 'missing_recovery_setup', req);
    await logAudit('auth.password_recovery', req, { phone, result: 'failed', meta: { reason: 'missing_recovery_setup' } });
    return res.status(404).json({ error: 'لا يمكن استرجاع هذا الحساب حالياً.' });
  }
  if (isPasswordBlocked(user)) {
    await logRecoveryAttempt(phone, 'blocked', 'login_block_active', req);
    const retryAfterSeconds = Math.ceil((user.auth.loginBlockedUntil - Date.now()) / 1000);
    await logAudit('auth.password_recovery', req, { phone, userId: user.id, result: 'blocked', meta: { retryAfterSeconds } });
    return res.status(429).json({ error: 'محاولات كثيرة. حاول لاحقاً.', retryAfterSeconds });
  }

  const ok = await bcrypt.compare(normalizeRecoveryAnswer(recoveryAnswer), user.recoveryAnswerHash);
  if (!ok) {
    await recordPasswordFailure(phone);
    await logRecoveryAttempt(phone, 'failed', 'wrong_recovery_answer', req);
    await logAudit('auth.password_recovery', req, { phone, userId: user.id, result: 'failed', meta: { reason: 'wrong_recovery_answer' } });
    return res.status(401).json({ error: 'إجابة الاسترجاع غير صحيحة.' });
  }

  const passwordHash = await bcrypt.hash(String(newPin), PASSWORD_BCRYPT_ROUNDS);
  await cols().users.updateOne(
    { phone },
    {
      $set: {
        passwordHash,
        passwordSetAt: Date.now(),
        'auth.failedLoginCount': 0,
        'auth.loginBlockedUntil': 0,
        'auth.passwordRecoveredAt': Date.now()
      }
    }
  );
  await logRecoveryAttempt(phone, 'success', 'pin_reset', req);
  await logAudit('auth.password_recovery', req, { phone, userId: user.id, result: 'success' });

  const updated = await cols().users.findOne({ phone });
  res.json(await authPayload(updated, req));
}));

app.post('/api/auth/password/recovery/identity', authLimiter, validateBody(schemas.identityRecoverySubmit), asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const user = await cols().users.findOne({ phone });
  if (!user) return res.status(404).json({ error: 'لا يوجد حساب بهذا الرقم.' });

  const existing = await cols().identityRequests.findOne({
    type: 'password_recovery',
    phone,
    status: 'pending'
  });
  if (existing) return res.status(409).json({ error: 'يوجد طلب استرجاع قيد المراجعة.' });

  const request = {
    id: id('ir'),
    type: 'password_recovery',
    status: 'pending',
    userId: user.id,
    phone,
    role: user.role,
    name: user.name,
    idCardImageEnc: encryptSensitive(req.body.idCardImage),
    selfieImageEnc: encryptSensitive(req.body.selfieImage),
    note: req.body.note || null,
    createdAt: Date.now(),
    reviewedAt: null,
    reviewedBy: null
  };
  await cols().identityRequests.insertOne(request);
  await logAudit('identity.password_recovery.requested', req, { phone, userId: user.id, result: 'pending', targetId: request.id });
  res.json({ id: request.id, status: request.status, message: 'تم إرسال طلبك للمراجعة.' });
}));

app.post('/api/auth/password/recovery/identity/reset', authLimiter, validateBody(schemas.identityReset), asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const resetCode = String(req.body.resetCode || '').toUpperCase();
  const request = await cols().identityRequests.findOne({
    type: 'password_recovery',
    phone,
    status: 'approved',
    resetCodeHash: hashResetCode(phone, resetCode),
    resetUsedAt: null,
    resetExpiresAt: { $gt: Date.now() }
  });
  if (!request) {
    await logAudit('identity.password_recovery.reset', req, { phone, result: 'failed', meta: { reason: 'invalid_code' } });
    return res.status(401).json({ error: 'كود الاسترجاع غير صحيح أو منتهي.' });
  }

  const passwordHash = await bcrypt.hash(String(req.body.newPin), PASSWORD_BCRYPT_ROUNDS);
  await cols().users.updateOne(
    { id: request.userId },
    {
      $set: {
        passwordHash,
        passwordSetAt: Date.now(),
        'auth.failedLoginCount': 0,
        'auth.loginBlockedUntil': 0,
        'auth.passwordRecoveredAt': Date.now()
      }
    }
  );
  await cols().identityRequests.updateOne(
    { id: request.id },
    { $set: { resetUsedAt: Date.now(), resetCodeEnc: null } }
  );
  const user = await cols().users.findOne({ id: request.userId });
  await logAudit('identity.password_recovery.reset', req, { phone, userId: user.id, result: 'success', targetId: request.id });
  res.json(await authPayload(user, req));
}));

app.post('/api/auth/email/verification/request', authLimiter, authenticate, validateBody(schemas.emailVerificationRequest), asyncRoute(async (req, res) => {
  const email = String(req.body.email).trim().toLowerCase();
  const user = await cols().users.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'غير موجود.' });

  const code = createEmailCode();
  await sendVerificationEmail(email, code);

  await cols().users.updateOne(
    { id: req.user.id },
    {
      $set: {
        recoveryEmailEnc: encryptSensitive(email),
        emailVerification: {
          hash: hashEmailCode(req.user.id, code),
          expiresAt: Date.now() + EMAIL_CODE_TTL_MINUTES * 60 * 1000,
          attempts: 0,
          requestedAt: Date.now()
        },
        emailVerifiedAt: null
      }
    }
  );
  await logAudit('auth.email_verification.requested', req, { userId: req.user.id, phone: user.phone, result: 'sent' });
  res.json({ success: true, message: 'تم إرسال رمز التحقق إلى البريد الاحتياطي.' });
}));

app.post('/api/auth/email/verification/confirm', authLimiter, authenticate, validateBody(schemas.emailVerificationConfirm), asyncRoute(async (req, res) => {
  const user = await cols().users.findOne({ id: req.user.id });
  const verification = user?.emailVerification;
  if (!verification?.hash || !verification?.expiresAt) {
    await logAudit('auth.email_verification.confirm', req, { userId: req.user.id, result: 'failed', meta: { reason: 'missing_code' } });
    return res.status(404).json({ error: 'لا يوجد رمز تحقق نشط.' });
  }
  if (verification.expiresAt < Date.now()) {
    await logAudit('auth.email_verification.confirm', req, { userId: req.user.id, phone: user.phone, result: 'failed', meta: { reason: 'expired' } });
    return res.status(400).json({ error: 'انتهت صلاحية رمز التحقق.' });
  }
  if ((verification.attempts || 0) >= 5) {
    await logAudit('auth.email_verification.confirm', req, { userId: req.user.id, phone: user.phone, result: 'blocked', meta: { reason: 'too_many_attempts' } });
    return res.status(429).json({ error: 'محاولات كثيرة. اطلب رمزاً جديداً.' });
  }
  if (verification.hash !== hashEmailCode(req.user.id, req.body.code)) {
    await cols().users.updateOne({ id: req.user.id }, { $inc: { 'emailVerification.attempts': 1 } });
    await logAudit('auth.email_verification.confirm', req, { userId: req.user.id, phone: user.phone, result: 'failed', meta: { reason: 'wrong_code' } });
    return res.status(401).json({ error: 'رمز التحقق غير صحيح.' });
  }

  await cols().users.updateOne(
    { id: req.user.id },
    {
      $set: { emailVerifiedAt: Date.now() },
      $unset: { emailVerification: '', emailVerificationRequired: '' }
    }
  );
  await logAudit('auth.email_verification.confirm', req, { userId: req.user.id, phone: user.phone, result: 'success' });
  res.json({ success: true, message: 'تم تأكيد البريد الاحتياطي.' });
}));

app.post('/api/auth/otp', authLimiter, validateBody(schemas.otpRequest), asyncRoute((req, res) => handleOtpRequest(req, res)));

app.post('/api/auth/send-otp', authLimiter, validateBody(schemas.otpRequest), asyncRoute((req, res) => handleOtpRequest(req, res, { legacy: true })));

app.post('/api/auth/verify-otp', authLimiter, requireOtpEnabled, validateBody(schemas.otpVerify), asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const { otp } = req.body;
  const submittedOtp = String(otp || '').replace(/\D/g, '');

  if (!phone || phone.length < 9) return res.status(400).json({ error: 'رقم الهاتف غير صحيح.' });
  if (!submittedOtp || submittedOtp.length !== 4) return res.status(400).json({ error: 'رمز التحقق غير صحيح.' });

  const otpRecord = await cols().otps.findOne({ phone, purpose: 'login' });
  if (!otpRecord || otpRecord.expiresAt < new Date()) {
    return res.status(400).json({ error: 'انتهت صلاحية رمز التحقق. اطلب رمزاً جديداً.' });
  }
  if (otpRecord.attempts >= 5) {
    await cols().otps.deleteOne({ phone, purpose: 'login' });
    return res.status(429).json({ error: 'محاولات كثيرة. اطلب رمزاً جديداً.' });
  }
  if (otpRecord.hash !== hashOtp(phone, submittedOtp)) {
    await cols().otps.updateOne({ phone, purpose: 'login' }, { $inc: { attempts: 1 } });
    return res.status(400).json({ error: 'رمز التحقق غير صحيح.' });
  }

  const { users } = cols();
  const user = await users.findOne({ phone });
  await cols().otps.deleteOne({ phone, purpose: 'login' });

  if (user) {
    return res.json(await authPayload(user, req));
  }

  const registrationToken = jwt.sign({ phone, purpose: 'registration' }, SECRET, { expiresIn: '10m' });
  res.status(404).json({ error: 'المستخدم غير موجود.', needsRegistration: true, registrationToken });
}));

app.post('/api/auth/register', authLimiter, requireOtpEnabled, validateBody(schemas.legacyRegister), asyncRoute(async (req, res) => {
  const { registrationToken, name, role, city, specialty } = req.body;
  if (!registrationToken) return res.status(400).json({ error: 'جلسة التسجيل غير صالحة.' });
  if (!name || !String(name).trim()) return res.status(400).json({ error: 'أدخل الاسم.' });

  let payload;
  try {
    payload = jwt.verify(registrationToken, SECRET);
  } catch (err) {
    return res.status(401).json({ error: 'انتهت صلاحية جلسة التسجيل. اطلب رمزاً جديداً.' });
  }
  if (payload.purpose !== 'registration' || !payload.phone) {
    return res.status(401).json({ error: 'جلسة التسجيل غير صالحة.' });
  }

  const { users } = cols();
  let user = await users.findOne({ phone: payload.phone });
  if (!user) {
    const newUser = {
      id: id('u'),
      name,
      phone: payload.phone,
      role: role || 'client',
      city: city || 'دمشق',
      avatar: (name || '').slice(0, 2),
      specialty: role === 'craftsman' ? (specialty || null) : null,
      rating: 0,
      reviewsCount: 0,
      bio: '',
      verified: 0,
      warranty: 0,
      jobsDone: 0,
      range: 25,
      saved: [],
      createdAt: Date.now()
    };
    await users.insertOne(newUser);
    user = newUser;
  }

  res.json(await authPayload(user, req));
}));

app.post('/api/auth/login', loginLimiter, (req, res) => {
  res.status(410).json({ error: 'استخدم تسجيل الدخول بالـ PIN.' });
});

app.post('/api/auth/refresh', authLimiter, validateBody(schemas.refresh), asyncRoute(async (req, res) => {
  const tokenHash = hashRefreshToken(req.body.refreshToken);
  const stored = await cols().refreshTokens.findOne({ tokenHash, revokedAt: null });
  if (!stored || stored.expiresAt < new Date()) {
    await logAudit('auth.refresh', req, { result: 'failed', meta: { reason: 'invalid_refresh_token' } });
    return res.status(401).json({ error: 'جلسة الدخول منتهية. سجّل الدخول من جديد.' });
  }

  const user = await cols().users.findOne({ id: stored.userId });
  if (!user || user.disabledAt) {
    await cols().refreshTokens.updateOne({ id: stored.id }, { $set: { revokedAt: new Date() } });
    await logAudit('auth.refresh', req, { userId: stored.userId, result: 'failed', meta: { reason: user ? 'account_disabled' : 'missing_user' } });
    return res.status(401).json({ error: 'جلسة الدخول غير صالحة.' });
  }

  await cols().refreshTokens.updateOne({ id: stored.id }, { $set: { revokedAt: new Date(), rotatedAt: new Date() } });
  await logAudit('auth.refresh', req, { userId: user.id, result: 'success' });
  res.json(await authPayload(user, req));
}));

app.post('/api/auth/logout', authLimiter, validateBody(schemas.logout), asyncRoute(async (req, res) => {
  if (req.body.refreshToken) {
    await cols().refreshTokens.updateOne(
      { tokenHash: hashRefreshToken(req.body.refreshToken) },
      { $set: { revokedAt: new Date() } }
    );
  }
  await logAudit('auth.logout', req, { result: 'success' });
  res.json({ success: true });
}));

// --- USERS ---
app.get('/api/users/me', authenticate, asyncRoute(async (req, res) => {
  const user = await cols().users.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'غير موجود.' });
  res.json(publicUser(user));
}));

app.put('/api/users/profile', authenticate, requireVerifiedEmail, validateBody(schemas.profile), asyncRoute(async (req, res) => {
  const { name, city, bio, range, avatar, specialty } = req.body;
  const current = await cols().users.findOne({ id: req.user.id });
  if (!current) return res.status(404).json({ error: 'غير موجود.' });

  await cols().users.updateOne(
    { id: req.user.id },
    {
      $set: {
        name: name || current.name,
        city: city || current.city,
        bio: bio !== undefined ? bio : current.bio,
        range: range || current.range,
        avatar: avatar || current.avatar,
        specialty: specialty || current.specialty
      }
    }
  );
  await logAudit('user.profile_update', req, {
    userId: req.user.id,
    result: 'success',
    meta: { fields: Object.keys(req.body) }
  });
  res.json({ success: true });
}));

app.get('/api/users/craftsmen', authenticate, requireVerifiedEmail, asyncRoute(async (req, res) => {
  const users = await cols().users.find({ role: 'craftsman' }).sort({ rating: -1, name: 1 }).limit(500).toArray();
  res.json(users.map(publicUser));
}));

// --- IDENTITY REVIEW ---
app.post('/api/identity-requests', authenticate, requireVerifiedEmail, validateBody(schemas.identitySubmit), asyncRoute(async (req, res) => {
  const user = await cols().users.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'غير موجود.' });
  if (user.role !== 'craftsman') return res.status(403).json({ error: 'توثيق الهوية متاح للحرفيين حالياً.' });

  const existing = await cols().identityRequests.findOne({
    type: 'craftsman_verification',
    userId: req.user.id,
    status: 'pending'
  });
  if (existing) return res.status(409).json({ error: 'يوجد طلب توثيق قيد المراجعة.' });

  const request = {
    id: id('ir'),
    type: 'craftsman_verification',
    status: 'pending',
    userId: user.id,
    phone: user.phone,
    role: user.role,
    name: user.name,
    idCardImageEnc: encryptSensitive(req.body.idCardImage),
    selfieImageEnc: encryptSensitive(req.body.selfieImage),
    note: req.body.note || null,
    createdAt: Date.now(),
    reviewedAt: null,
    reviewedBy: null
  };
  await cols().identityRequests.insertOne(request);
  await logAudit('identity.verification.requested', req, { userId: user.id, phone: user.phone, result: 'pending', targetId: request.id });
  res.json({ id: request.id, status: request.status, message: 'تم إرسال طلب التوثيق.' });
}));

app.get('/api/admin/identity-requests', authenticate, requireVerifiedEmail, requireAdmin, asyncRoute(async (req, res) => {
  const requests = await cols().identityRequests.find({}).sort({ createdAt: -1 }).limit(500).toArray();
  res.json(requests.map(request => {
    const clean = stripMongoId(request);
    clean.idCardImage = decryptSensitive(request.idCardImageEnc);
    clean.selfieImage = decryptSensitive(request.selfieImageEnc);
    clean.resetCode = decryptSensitive(request.resetCodeEnc);
    delete clean.idCardImageEnc;
    delete clean.selfieImageEnc;
    delete clean.resetCodeEnc;
    delete clean.resetCodeHash;
    return clean;
  }));
}));

app.put('/api/admin/identity-requests/:id/status', authenticate, requireVerifiedEmail, requireAdmin, validateIdParam, validateBody(schemas.identityDecision), asyncRoute(async (req, res) => {
  const request = await cols().identityRequests.findOne({ id: req.params.id });
  if (!request) return res.status(404).json({ error: 'الطلب غير موجود.' });
  if (request.status !== 'pending') return res.status(409).json({ error: 'تمت مراجعة هذا الطلب مسبقاً.' });

  const update = {
    status: req.body.status,
    adminNote: req.body.note || null,
    reviewedAt: Date.now(),
    reviewedBy: req.user.id
  };
  let resetCode = null;
  if (req.body.status === 'approved' && request.type === 'craftsman_verification') {
    await cols().users.updateOne({ id: request.userId }, { $set: { verified: 1, identityVerifiedAt: Date.now() } });
  }
  if (req.body.status === 'approved' && request.type === 'password_recovery') {
    resetCode = createResetCode();
    update.resetCodeHash = hashResetCode(request.phone, resetCode);
    update.resetCodeEnc = encryptSensitive(resetCode);
    update.resetExpiresAt = Date.now() + 24 * 60 * 60 * 1000;
    update.resetUsedAt = null;
  }

  await cols().identityRequests.updateOne({ id: request.id }, { $set: update });
  await logAudit('identity.reviewed', req, {
    userId: request.userId,
    phone: request.phone,
    result: req.body.status,
    targetId: request.id,
    meta: { type: request.type }
  });
  res.json({ success: true, resetCode });
}));

app.post('/api/admin/campaigns', authenticate, requireVerifiedEmail, requireAdmin, validateBody(schemas.campaign), asyncRoute(async (req, res) => {
  const { campaign } = await sendAdminCampaign(req.body, req);
  res.json({ success: true, campaign });
}));

// --- JOBS ---
app.get('/api/jobs', authenticate, requireVerifiedEmail, asyncRoute(async (req, res) => {
  const filter = req.user.role === 'admin'
    ? {}
    : req.user.role === 'client'
      ? { clientId: req.user.id }
      : { $or: [{ status: 'open' }, { chosenCraftsman: req.user.id }, { clientId: req.user.id }] };
  const jobs = await cols().jobs.find(filter).sort({ createdAt: -1 }).limit(500).toArray();
  res.json(normalizeMany(jobs));
}));

app.post('/api/jobs', authenticate, requireVerifiedEmail, validateBody(schemas.jobCreate), asyncRoute(async (req, res) => {
  const { title, desc, category, city, area, photos, budget, schedule, urgency } = req.body;
  const job = {
    id: id('j'),
    title,
    desc,
    category,
    city,
    area: area || city,
    distance: Math.floor(Math.random() * 20) + 1,
    createdAt: Date.now(),
    clientId: req.user.id,
    status: 'open',
    photos: photos || [],
    budget: budget || null,
    schedule: schedule || null,
    urgency: urgency || 'normal',
    chosenCraftsman: null,
    cancelReason: null
  };
  await cols().jobs.insertOne(job);
  const craftsmen = await cols().users.find({
    role: 'craftsman',
    disabledAt: null,
    $and: [
      { $or: [{ city }, { serviceAreas: city }] },
      { $or: [{ specialty: category }, { specialty: null }] }
    ]
  }).project({ id: 1 }).limit(100).toArray();
  await addBulkNotifications(
    craftsmen.map(user => user.id),
    'new_job',
    `طلب جديد في ${category}: ${title.slice(0, 50)}`,
    job.id,
    { title: 'طلب جديد مناسب لك', body: `${category} في ${area || city}` }
  );
  res.json({ id: job.id });
}));

app.put('/api/jobs/:id/status', authenticate, requireVerifiedEmail, validateIdParam, validateBody(schemas.jobStatus), asyncRoute(async (req, res) => {
  const { status, chosenCraftsman, cancelReason } = req.body;
  const job = await cols().jobs.findOne({ id: req.params.id });
  if (!job) return res.status(404).json({ error: 'غير موجود.' });

  const isOwner = job.clientId === req.user.id;
  const isAdmin = req.user.role === 'admin';
  const isChosenCraftsman = job.chosenCraftsman && job.chosenCraftsman === req.user.id;
  if (!isOwner && !isAdmin && !(isChosenCraftsman && status === 'done')) {
    return res.status(403).json({ error: 'غير مسموح بتعديل هذا الطلب.' });
  }
  if (chosenCraftsman && !isOwner && !isAdmin) {
    return res.status(403).json({ error: 'اختيار الحرفي متاح لصاحب الطلب فقط.' });
  }

  await cols().jobs.updateOne(
    { id: req.params.id },
    { $set: { status, chosenCraftsman: chosenCraftsman || null, cancelReason: cancelReason || null } }
  );
  if (status === 'matched' && chosenCraftsman) await addNotif(chosenCraftsman, 'match', `بدأ العميل المحادثة معك: ${job.title.slice(0, 30)}`, job.id);
  if (status === 'cancelled' && job.chosenCraftsman) await addNotif(job.chosenCraftsman, 'cancel', `تم إلغاء الطلب: ${job.title.slice(0, 30)}`, job.id);
  res.json({ success: true });
}));

// --- INTERESTS ---
app.get('/api/interests', authenticate, requireVerifiedEmail, asyncRoute(async (req, res) => {
  let filter = {};
  if (req.user.role === 'craftsman') {
    filter = { craftsmanId: req.user.id };
  } else if (req.user.role === 'client') {
    const ownedJobs = await cols().jobs.find({ clientId: req.user.id }, { projection: { id: 1 } }).limit(500).toArray();
    filter = { jobId: { $in: ownedJobs.map(job => job.id) } };
  }
  const interests = await cols().interests.find(filter).sort({ createdAt: -1 }).limit(500).toArray();
  res.json(normalizeMany(interests));
}));

app.post('/api/interests', authenticate, requireVerifiedEmail, validateBody(schemas.interestCreate), asyncRoute(async (req, res) => {
  const { jobId, note, estimate } = req.body;
  if (req.user.role !== 'craftsman' && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'إرسال العروض متاح للحرفيين فقط.' });
  }
  const job = await cols().jobs.findOne({ id: jobId });
  if (!job) return res.status(404).json({ error: 'الطلب غير موجود.' });
  if (job.clientId === req.user.id) return res.status(403).json({ error: 'لا يمكنك إرسال عرض على طلبك.' });
  const existingInterest = await cols().interests.findOne({ jobId, craftsmanId: req.user.id });
  if (existingInterest) return res.status(409).json({ error: 'أرسلت عرضاً لهذا الطلب مسبقاً.' });
  const interest = {
    id: id('i'),
    jobId,
    craftsmanId: req.user.id,
    note: note || null,
    estimate: estimate || null,
    status: 'pending',
    createdAt: Date.now()
  };
  await cols().interests.insertOne(interest);

  const [, craftsman] = await Promise.all([
    Promise.resolve(job),
    cols().users.findOne({ id: req.user.id }, { projection: { name: 1 } })
  ]);
  if (job) await addNotif(job.clientId, 'interest', `${craftsman?.name || 'حرفي'} مهتم بطلبك: ${job.title.slice(0, 30)}`, jobId);
  res.json({ id: interest.id });
}));

app.put('/api/interests/:id/status', authenticate, requireVerifiedEmail, validateIdParam, validateBody(schemas.interestStatus), asyncRoute(async (req, res) => {
  const { status } = req.body;
  if (!['accepted', 'rejected'].includes(status)) return res.status(400).json({ error: 'حالة العرض غير صحيحة.' });

  const interest = await cols().interests.findOne({ id: req.params.id });
  if (!interest) return res.status(404).json({ error: 'غير موجود.' });

  const job = await cols().jobs.findOne({ id: interest.jobId });
  if (!job) return res.status(404).json({ error: 'الطلب غير موجود.' });
  if (job.clientId !== req.user.id && req.user.role !== 'admin') return res.status(403).json({ error: 'غير مسموح.' });

  await cols().interests.updateOne({ id: interest.id }, { $set: { status } });

  if (status === 'accepted') {
    await Promise.all([
      cols().jobs.updateOne(
        { id: job.id },
        { $set: { status: 'matched', chosenCraftsman: interest.craftsmanId } }
      ),
      cols().interests.updateMany(
        { jobId: job.id, id: { $ne: interest.id }, status: 'pending' },
        { $set: { status: 'rejected' } }
      )
    ]);
    await addNotif(interest.craftsmanId, 'offer_accepted', `تم قبول عرضك: ${job.title.slice(0, 30)}`, job.id);
  } else {
    await addNotif(interest.craftsmanId, 'offer_rejected', `تم رفض عرضك: ${job.title.slice(0, 30)}`, job.id);
  }

  res.json({ success: true });
}));

// --- MESSAGES ---
app.get('/api/messages', authenticate, requireVerifiedEmail, asyncRoute(async (req, res) => {
  const messages = await cols().messages.find({
    $or: [{ senderId: req.user.id }, { receiverId: req.user.id }]
  }).sort({ at: 1 }).limit(500).toArray();
  res.json(normalizeMany(messages));
}));

app.post('/api/messages', authenticate, requireVerifiedEmail, validateBody(schemas.messageCreate), asyncRoute(async (req, res) => {
  const { jobId, receiverId, text, image } = req.body;
  if (!text && !image) return res.status(400).json({ error: 'اكتب رسالة أو أرسل صورة.' });
  const job = await cols().jobs.findOne({ id: jobId });
  if (!job) return res.status(404).json({ error: 'الطلب غير موجود.' });
  const allowedParticipants = new Set([job.clientId, job.chosenCraftsman].filter(Boolean));
  if (!allowedParticipants.has(req.user.id) || !allowedParticipants.has(receiverId)) {
    return res.status(403).json({ error: 'غير مسموح بإرسال رسالة على هذا الطلب.' });
  }
  const message = {
    id: id('m'),
    jobId,
    senderId: req.user.id,
    receiverId,
    text: text || '',
    image: image || null,
    at: Date.now()
  };
  await cols().messages.insertOne(message);

  const sender = await cols().users.findOne({ id: req.user.id }, { projection: { name: 1 } });
  await addNotif(receiverId, 'msg', `رسالة من ${sender?.name || 'مستخدم'}`, jobId);
  res.json({ id: message.id });
}));

// --- NOTIFICATIONS ---
app.get('/api/notifications/push/status', authenticate, requireVerifiedEmail, asyncRoute(async (req, res) => {
  res.json(pushStatus());
}));

app.post('/api/notifications/device-token', authenticate, requireVerifiedEmail, validateBody(schemas.deviceToken), asyncRoute(async (req, res) => {
  const now = Date.now();
  await cols().deviceTokens.updateOne(
    { token: req.body.token },
    {
      $set: {
        userId: req.user.id,
        token: req.body.token,
        platform: req.body.platform || 'unknown',
        deviceId: req.body.deviceId || null,
        updatedAt: now,
        disabledAt: null,
        disabledReason: null
      },
      $setOnInsert: {
        id: id('dt'),
        createdAt: now
      }
    },
    { upsert: true }
  );
  await logAudit('notifications.device_token.registered', req, { userId: req.user.id, result: 'success', meta: { platform: req.body.platform || 'unknown' } });
  res.json({ success: true, push: pushStatus() });
}));

app.get('/api/notifications', authenticate, requireVerifiedEmail, asyncRoute(async (req, res) => {
  const notifications = await cols().notifications.find({
    userId: { $in: [req.user.id, 'all'] }
  }).sort({ at: -1 }).limit(200).toArray();
  res.json(normalizeMany(notifications));
}));

app.post('/api/notifications/read', authenticate, requireVerifiedEmail, asyncRoute(async (req, res) => {
  await cols().notifications.updateMany({ userId: req.user.id }, { $set: { read: 1 } });
  res.json({ success: true });
}));

// --- REVIEWS ---
app.get('/api/reviews', authenticate, requireVerifiedEmail, asyncRoute(async (req, res) => {
  const reviews = await cols().reviews.find({}).sort({ at: -1 }).limit(500).toArray();
  res.json(normalizeMany(reviews));
}));

app.post('/api/reviews', authenticate, requireVerifiedEmail, validateBody(schemas.reviewCreate), asyncRoute(async (req, res) => {
  const { craftsmanId, rating, title, text } = req.body;
  if (req.user.id === craftsmanId) return res.status(403).json({ error: 'لا يمكنك تقييم حسابك.' });
  const completedJob = await cols().jobs.findOne({
    clientId: req.user.id,
    chosenCraftsman: craftsmanId,
    status: { $in: ['done', 'reviewed'] }
  });
  if (!completedJob && req.user.role !== 'admin') {
    return res.status(403).json({ error: 'يمكن التقييم بعد إنهاء عمل حقيقي فقط.' });
  }
  const client = await cols().users.findOne({ id: req.user.id }, { projection: { name: 1, city: 1 } });
  const review = {
    id: id('r'),
    craftsmanId,
    clientId: req.user.id,
    clientName: `${client?.name?.split(' ')[0] || 'عميل'}، ${client?.city || ''}`,
    rating,
    title,
    text,
    at: Date.now()
  };
  await cols().reviews.insertOne(review);

  const stats = await cols().reviews.aggregate([
    { $match: { craftsmanId } },
    { $group: { _id: '$craftsmanId', avg: { $avg: '$rating' }, count: { $sum: 1 } } }
  ]).toArray();
  const stat = stats[0] || { avg: 0, count: 0 };
  await cols().users.updateOne(
    { id: craftsmanId },
    { $set: { rating: Math.round(stat.avg * 10) / 10, reviewsCount: stat.count }, $inc: { jobsDone: 1 } }
  );
  await addNotif(craftsmanId, 'review', `حصلت على تقييم ${rating} نجوم!`, null);
  if (rating === 5) {
    await addNotif(req.user.id, 'share_prompt', 'شكراً على تقييمك! إذا أعجبتك التجربة شارك حرفتي مع شخص يحتاج حرفي موثوق.', null);
  }
  res.json({ id: review.id });
}));

// --- REPORTS ---
app.post('/api/reports', authenticate, requireVerifiedEmail, validateBody(schemas.reportCreate), asyncRoute(async (req, res) => {
  const { type, targetId, reason } = req.body;
  const report = {
    id: id('rep'),
    type,
    targetId,
    reason,
    byId: req.user.id,
    at: Date.now()
  };
  await cols().reports.insertOne(report);
  res.json({ id: report.id });
}));

app.get('/api/reports', authenticate, requireVerifiedEmail, asyncRoute(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مسموح.' });
  const reports = await cols().reports.find({}).sort({ at: -1 }).limit(500).toArray();
  res.json(normalizeMany(reports));
}));

// --- UPLOAD ---
app.post('/api/upload', authenticate, requireVerifiedEmail, upload.array('photos', 5), (req, res) => {
  res.json({ urls: req.files.map(f => `/uploads/${f.filename}`) });
});

async function runEngagementTriggers() {
  const now = Date.now();
  const threeDaysAgo = now - 3 * 24 * 60 * 60 * 1000;
  const oneHourAgo = now - 60 * 60 * 1000;

  const inactiveClients = await cols().users.find({
    role: 'client',
    emailVerificationRequired: { $ne: true },
    disabledAt: null,
    $or: [
      { lastNoJobReminderAt: { $exists: false } },
      { lastNoJobReminderAt: { $lt: threeDaysAgo } }
    ],
    $expr: {
      $lt: [
        { $ifNull: ['$createdAt', '$passwordSetAt'] },
        threeDaysAgo
      ]
    }
  }).project({ id: 1, name: 1 }).limit(100).toArray();

  for (const user of inactiveClients) {
    const hasJob = await cols().jobs.findOne({ clientId: user.id }, { projection: { id: 1 } });
    if (!hasJob) {
      const sent = await createEngagementOnce(
        `client_no_job:${user.id}:${new Date(now).toISOString().slice(0, 10)}`,
        'client_no_job_reminder',
        user.id,
        'جاهز تبدأ؟ أضف طلبك الأول وسنوصلك بحرفيين مناسبين في مدينتك.',
        {}
      );
      if (sent) await cols().users.updateOne({ id: user.id }, { $set: { lastNoJobReminderAt: now } });
    }
  }

  const pendingJobs = await cols().jobs.find({
    status: 'open',
    createdAt: { $lt: oneHourAgo },
    $or: [
      { lastCraftsmanReminderAt: { $exists: false } },
      { lastCraftsmanReminderAt: { $lt: oneHourAgo } }
    ]
  }).sort({ createdAt: -1 }).limit(100).toArray();

  for (const job of pendingJobs) {
    const interested = await cols().interests.distinct('craftsmanId', { jobId: job.id });
    const craftsmen = await cols().users.find({
      role: 'craftsman',
      id: { $nin: interested },
      $and: [
        { $or: [{ city: job.city }, { serviceAreas: job.city }] },
        { $or: [{ specialty: job.category }, { specialty: null }] }
      ],
      disabledAt: null
    }).project({ id: 1 }).limit(50).toArray();
    const ids = craftsmen.map(user => user.id);
    if (ids.length) {
      await addBulkNotifications(
        ids,
        'craftsman_pending_job',
        `تذكير: طلب ${job.category} ينتظر عرضك في ${job.area || job.city}.`,
        job.id,
        { title: 'طلب ينتظر ردك', body: `${job.category} في ${job.area || job.city}` }
      );
      await cols().jobs.updateOne({ id: job.id }, { $set: { lastCraftsmanReminderAt: now } });
    }
  }
}

function startEngagementRunner() {
  if (process.env.ENGAGEMENT_TRIGGERS_ENABLED !== 'true') return;
  const run = () => runEngagementTriggers().catch(err => console.error('Engagement triggers failed:', err.message));
  setTimeout(run, 30 * 1000);
  setInterval(run, ENGAGEMENT_INTERVAL_MS);
}

app.use('/admin', createAdminDashboard({
  secret: SECRET,
  cols,
  connect,
  logAudit,
  decryptSensitive,
  hashResetCode,
  createResetCode,
  ipOf,
  sendAdminCampaign,
  pushStatus
}));

app.get('*', (req, res) => {
  const idx = path.join(__dirname, '../frontend/build/index.html');
  if (fs.existsSync(idx)) res.sendFile(idx);
  else res.status(404).json({ error: 'غير موجود.' });
});

app.use((err, req, res, next) => {
  if (err.message === 'CORS origin is not allowed.') {
    return res.status(403).json({ error: 'المصدر غير مسموح.' });
  }
  if (err.code === 'EMAIL_NOT_CONFIGURED') {
    return res.status(503).json({ error: 'خدمة البريد غير مفعلة حالياً.' });
  }
  if (err.code === 'EMAIL_SEND_FAILED') {
    return res.status(502).json({ error: 'تعذر إرسال البريد حالياً.' });
  }
  if (err.code === 'WHATSAPP_NOT_CONFIGURED') {
    return res.status(503).json({ error: 'خدمة واتساب غير مفعلة حالياً.' });
  }
  if (err.code === 'WHATSAPP_SEND_FAILED') {
    return res.status(502).json({ error: 'تعذر إرسال رسالة واتساب حالياً.' });
  }
  console.error(err);
  res.status(500).json({ error: 'حدث خطأ في الخادم.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 حِرفتي running on port ${PORT}`);
  connect()
    .then(() => {
      console.log('✅ MongoDB connected');
      startEngagementRunner();
    })
    .catch(err => console.error('MongoDB connection failed:', err.message));
});
