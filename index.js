require('dotenv').config();

const express = require('express');
const cors = require('cors');
const helmet = require('helmet');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const crypto = require('crypto');
const { connect, cols, stripMongoId, normalizeMany, healthCheck } = require('./db');
const { sendOtp } = require('./sms');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET = process.env.JWT_SECRET || 'hirfati-secret-key-2024';
const API_ORIGIN = process.env.CORS_ORIGIN || '*';
const OTP_TTL_MINUTES = Number(process.env.OTP_TTL_MINUTES || 5);
const DEMO_PHONES = ['0991112233', '0944556677', '0900000000'];

app.disable('x-powered-by');
app.use(helmet({
  contentSecurityPolicy: false,
  crossOriginEmbedderPolicy: false
}));
app.use(cors({ origin: API_ORIGIN }));
app.use(express.json({ limit: '50mb' }));
app.use('/api', rateLimit({
  windowMs: 15 * 60 * 1000,
  max: Number(process.env.RATE_LIMIT_MAX || 300),
  standardHeaders: true,
  legacyHeaders: false,
  message: { error: 'طلبات كثيرة. حاول لاحقاً.' }
}));
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
const normalizePhone = phone => String(phone || '').replace(/\D/g, '');
const createOtp = () => String(crypto.randomInt(1000, 10000));
const hashOtp = (phone, otp) => crypto
  .createHash('sha256')
  .update(`${normalizePhone(phone)}:${otp}:${SECRET}`)
  .digest('hex');

const asyncRoute = fn => (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);

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

app.get('/api/health', asyncRoute(async (req, res) => {
  const status = await healthCheck();
  res.status(status.ok ? 200 : 503).json(status);
}));

// --- AUTH ---
app.post('/api/auth/otp', asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  if (!phone || phone.length < 9) return res.status(400).json({ error: 'رقم الهاتف غير صحيح.' });

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
        createdAt: new Date()
      }
    },
    { upsert: true }
  );

  try {
    await sendOtp(phone, otp);
  } catch (err) {
    await cols().otps.deleteOne({ phone, purpose: 'login' });
    console.error('Twilio WhatsApp OTP failed:', err.message);
    return res.status(503).json({
      error: 'تعذر إرسال رمز التحقق عبر واتساب حالياً. تحقق من إعدادات الخدمة.'
    });
  }

  res.json({ message: 'تم إرسال رمز التحقق.' });
}));

app.post('/api/auth/login', asyncRoute(async (req, res) => {
  const phone = normalizePhone(req.body.phone);
  const { otp, name, role, city, specialty } = req.body;
  const submittedOtp = String(otp || '').replace(/\D/g, '');

  if (!phone || phone.length < 9) return res.status(400).json({ error: 'رقم الهاتف غير صحيح.' });
  if (!submittedOtp || submittedOtp.length !== 4) return res.status(400).json({ error: 'رمز التحقق غير صحيح.' });

  const demoOtpAllowed = submittedOtp === '1234' && DEMO_PHONES.includes(phone);
  if (!demoOtpAllowed) {
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
    await cols().otps.deleteOne({ phone, purpose: 'login' });
  }

  const { users } = cols();
  let user = await users.findOne({ phone });
  if (!user) {
    if (!name) return res.status(404).json({ error: 'المستخدم غير موجود.', needsRegistration: true });
    const newUser = {
      id: id('u'),
      name,
      phone,
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

  user = stripMongoId(user);
  const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '30d' });
  res.json({ token, user });
}));

// --- USERS ---
app.get('/api/users/me', authenticate, asyncRoute(async (req, res) => {
  const user = await cols().users.findOne({ id: req.user.id });
  if (!user) return res.status(404).json({ error: 'غير موجود.' });
  res.json(stripMongoId(user));
}));

app.put('/api/users/profile', authenticate, asyncRoute(async (req, res) => {
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
  res.json({ success: true });
}));

app.get('/api/users/craftsmen', authenticate, asyncRoute(async (req, res) => {
  const users = await cols().users.find({ role: 'craftsman' }).sort({ rating: -1, name: 1 }).toArray();
  res.json(normalizeMany(users));
}));

// --- JOBS ---
app.get('/api/jobs', authenticate, asyncRoute(async (req, res) => {
  const jobs = await cols().jobs.find({}).sort({ createdAt: -1 }).toArray();
  res.json(normalizeMany(jobs));
}));

app.post('/api/jobs', authenticate, asyncRoute(async (req, res) => {
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

app.put('/api/jobs/:id/status', authenticate, asyncRoute(async (req, res) => {
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

app.post('/api/interests', authenticate, asyncRoute(async (req, res) => {
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

app.put('/api/interests/:id/status', authenticate, asyncRoute(async (req, res) => {
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

app.post('/api/messages', authenticate, asyncRoute(async (req, res) => {
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

app.post('/api/reviews', authenticate, asyncRoute(async (req, res) => {
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
app.post('/api/reports', authenticate, asyncRoute(async (req, res) => {
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
