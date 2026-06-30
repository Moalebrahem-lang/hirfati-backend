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
const ALLOWED_ORIGINS = (process.env.CORS_ORIGINS || process.env.CORS_ORIGIN || DEFAULT_ALLOWED_ORIGINS.join(','))
  .split(',')
  .map(origin => origin.trim())
  .filter(Boolean);
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 5);
const OTP_RATE_LIMIT_MS = Number(process.env.OTP_RATE_LIMIT_MS || 60 * 1000);
const PASSWORD_LOCK_MS = Number(process.env.PASSWORD_LOCK_MS || 15 * 60 * 1000);
const PASSWORD_MAX_FAILED_ATTEMPTS = Number(process.env.PASSWORD_MAX_FAILED_ATTEMPTS || 5);
const PASSWORD_BCRYPT_ROUNDS = Number(process.env.PASSWORD_BCRYPT_ROUNDS || 12);

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors({
  origin(origin, cb) {
    if (!origin || ALLOWED_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error('CORS origin is not allowed.'));
  },
  credentials: true
}));
app.use(express.json({ limit: '50mb' }));
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
  max: Number(process.env.AUTH_RATE_LIMIT_MAX || 5),
  standardHeaders: true,
  legacyHeaders: false,
  skipSuccessfulRequests: false,
  message: { error: 'محاولات دخول كثيرة. حاول بعد 15 دقيقة.' }
});
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
const hashOtp = (phone, otp) => crypto
  .createHash('sha256')
  .update(`${normalizePhone(phone)}:${otp}:${SECRET}`)
  .digest('hex');
const signAuthToken = user => jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '30d' });
const publicUser = user => {
  const clean = stripMongoId(user);
  delete clean.passwordHash;
  delete clean.recoveryAnswerHash;
  delete clean.auth;
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
const imageSchema = Joi.string().max(8 * 1024 * 1024);
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
    recoveryEmail: Joi.string().trim().email().allow('', null).max(160)
  }),
  passwordLogin: Joi.object({ phone: phoneSchema, pin: pinSchema }),
  recoveryStart: Joi.object({ phone: phoneSchema }),
  recoveryVerify: Joi.object({ phone: phoneSchema, recoveryAnswer: safeText(120).required(), newPin: pinSchema }),
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

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'يرجى تسجيل الدخول.' });
  try {
    req.user = jwt.verify(token, SECRET);
    next();
  } catch (err) {
    res.status(401).json({ error: 'جلسة الدخول غير صالحة.' });
  }
};

async function addNotif(userId, type, text, jobId) {
  await cols().notifications.insertOne({
    id: id('n'),
    userId,
    type,
    text,
    jobId: jobId || null,
    at: Date.now(),
    read: 0
  });
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
    passwordHash,
    passwordSetAt: Date.now(),
    recoveryQuestion: String(recoveryQuestion).trim(),
    recoveryAnswerHash,
    recoveryEmail: recoveryEmail ? String(recoveryEmail).trim().toLowerCase() : null,
    auth: { failedLoginCount: 0, loginBlockedUntil: 0 }
  };

  await users.insertOne(user);
  await logAudit('auth.register', req, { phone, userId: user.id, result: 'success', meta: { role: user.role } });
  const cleanUser = publicUser(user);
  res.json({ token: signAuthToken(cleanUser), user: cleanUser });
}));

app.post('/api/auth/password/login', authLimiter, validateBody(schemas.passwordLogin), asyncRoute(async (req, res) => {
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
  const cleanUser = publicUser(user);
  res.json({ token: signAuthToken(cleanUser), user: cleanUser });
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

  const updated = publicUser(await cols().users.findOne({ phone }));
  res.json({ token: signAuthToken(updated), user: updated });
}));

app.post('/api/auth/otp', authLimiter, validateBody(schemas.otpRequest), asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  if (!phone || phone.length < 9) return res.status(400).json({ error: 'رقم الهاتف غير صحيح.' });

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
    return res.status(503).json({ error: 'تعذر إرسال رمز التحقق عبر واتساب حالياً.' });
  }

  res.json({ message: 'تم إرسال رمز التحقق عبر واتساب.' });
}));

app.post('/api/auth/verify-otp', authLimiter, validateBody(schemas.otpVerify), asyncRoute(async (req, res) => {
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
    const cleanUser = publicUser(user);
    return res.json({ token: signAuthToken(cleanUser), user: cleanUser });
  }

  const registrationToken = jwt.sign({ phone, purpose: 'registration' }, SECRET, { expiresIn: '10m' });
  res.status(404).json({ error: 'المستخدم غير موجود.', needsRegistration: true, registrationToken });
}));

app.post('/api/auth/register', authLimiter, validateBody(schemas.legacyRegister), asyncRoute(async (req, res) => {
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
      saved: []
    };
    await users.insertOne(newUser);
    user = newUser;
  }

  user = publicUser(user);
  res.json({ token: signAuthToken(user), user });
}));

app.post('/api/auth/login', authLimiter, (req, res) => {
  res.status(410).json({ error: 'استخدم /api/auth/verify-otp للتحقق من رمز الدخول.' });
});

// --- USERS ---
app.get('/api/users/me', authenticate, asyncRoute(async (req, res) => {
  const user = await cols().users.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'غير موجود.' });
  res.json(publicUser(user));
}));

app.put('/api/users/profile', authenticate, validateBody(schemas.profile), asyncRoute(async (req, res) => {
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

app.get('/api/users/craftsmen', authenticate, asyncRoute(async (req, res) => {
  const users = await cols().users.find({ role: 'craftsman' }).sort({ rating: -1, name: 1 }).toArray();
  res.json(users.map(publicUser));
}));

// --- JOBS ---
app.get('/api/jobs', authenticate, asyncRoute(async (req, res) => {
  const jobs = await cols().jobs.find({}).sort({ createdAt: -1 }).toArray();
  res.json(normalizeMany(jobs));
}));

app.post('/api/jobs', authenticate, validateBody(schemas.jobCreate), asyncRoute(async (req, res) => {
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
  res.json({ id: job.id });
}));

app.put('/api/jobs/:id/status', authenticate, validateIdParam, validateBody(schemas.jobStatus), asyncRoute(async (req, res) => {
  const { status, chosenCraftsman, cancelReason } = req.body;
  await cols().jobs.updateOne(
    { id: req.params.id },
    { $set: { status, chosenCraftsman: chosenCraftsman || null, cancelReason: cancelReason || null } }
  );
  const job = await cols().jobs.findOne({ id: req.params.id });
  if (!job) return res.status(404).json({ error: 'غير موجود.' });
  if (status === 'matched' && chosenCraftsman) await addNotif(chosenCraftsman, 'match', `بدأ العميل المحادثة معك: ${job.title.slice(0, 30)}`, job.id);
  if (status === 'cancelled' && job.chosenCraftsman) await addNotif(job.chosenCraftsman, 'cancel', `تم إلغاء الطلب: ${job.title.slice(0, 30)}`, job.id);
  res.json({ success: true });
}));

// --- INTERESTS ---
app.get('/api/interests', authenticate, asyncRoute(async (req, res) => {
  const interests = await cols().interests.find({}).sort({ createdAt: -1 }).toArray();
  res.json(normalizeMany(interests));
}));

app.post('/api/interests', authenticate, validateBody(schemas.interestCreate), asyncRoute(async (req, res) => {
  const { jobId, note, estimate } = req.body;
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

  const [job, craftsman] = await Promise.all([
    cols().jobs.findOne({ id: jobId }),
    cols().users.findOne({ id: req.user.id }, { projection: { name: 1 } })
  ]);
  if (job) await addNotif(job.clientId, 'interest', `${craftsman?.name || 'حرفي'} مهتم بطلبك: ${job.title.slice(0, 30)}`, jobId);
  res.json({ id: interest.id });
}));

app.put('/api/interests/:id/status', authenticate, validateIdParam, validateBody(schemas.interestStatus), asyncRoute(async (req, res) => {
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
app.get('/api/messages', authenticate, asyncRoute(async (req, res) => {
  const messages = await cols().messages.find({
    $or: [{ senderId: req.user.id }, { receiverId: req.user.id }]
  }).sort({ at: 1 }).toArray();
  res.json(normalizeMany(messages));
}));

app.post('/api/messages', authenticate, validateBody(schemas.messageCreate), asyncRoute(async (req, res) => {
  const { jobId, receiverId, text, image } = req.body;
  if (!text && !image) return res.status(400).json({ error: 'اكتب رسالة أو أرسل صورة.' });
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
app.get('/api/notifications', authenticate, asyncRoute(async (req, res) => {
  const notifications = await cols().notifications.find({
    userId: { $in: [req.user.id, 'all'] }
  }).sort({ at: -1 }).toArray();
  res.json(normalizeMany(notifications));
}));

app.post('/api/notifications/read', authenticate, asyncRoute(async (req, res) => {
  await cols().notifications.updateMany({ userId: req.user.id }, { $set: { read: 1 } });
  res.json({ success: true });
}));

// --- REVIEWS ---
app.get('/api/reviews', authenticate, asyncRoute(async (req, res) => {
  const reviews = await cols().reviews.find({}).sort({ at: -1 }).toArray();
  res.json(normalizeMany(reviews));
}));

app.post('/api/reviews', authenticate, validateBody(schemas.reviewCreate), asyncRoute(async (req, res) => {
  const { craftsmanId, rating, title, text } = req.body;
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
  res.json({ id: review.id });
}));

// --- REPORTS ---
app.post('/api/reports', authenticate, validateBody(schemas.reportCreate), asyncRoute(async (req, res) => {
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

app.get('/api/reports', authenticate, asyncRoute(async (req, res) => {
  if (req.user.role !== 'admin') return res.status(403).json({ error: 'غير مسموح.' });
  const reports = await cols().reports.find({}).sort({ at: -1 }).toArray();
  res.json(normalizeMany(reports));
}));

// --- UPLOAD ---
app.post('/api/upload', authenticate, upload.array('photos', 5), (req, res) => {
  res.json({ urls: req.files.map(f => `/uploads/${f.filename}`) });
});

app.get('*', (req, res) => {
  const idx = path.join(__dirname, '../frontend/build/index.html');
  if (fs.existsSync(idx)) res.sendFile(idx);
  else res.status(404).json({ error: 'غير موجود.' });
});

app.use((err, req, res, next) => {
  console.error(err);
  res.status(500).json({ error: 'حدث خطأ في الخادم.' });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`🚀 حِرفتي running on port ${PORT}`);
  connect()
    .then(() => console.log('✅ MongoDB connected'))
    .catch(err => console.error('MongoDB connection failed:', err.message));
});
