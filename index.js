const express = require('express');
const cors = require('cors');
const jwt = require('jsonwebtoken');
const multer = require('multer');
const path = require('path');
const fs = require('fs');
const db = require('./db');

const app = express();
const PORT = process.env.PORT || 5000;
const SECRET = 'hirfati-secret-key-2024';

app.use(cors());
app.use(express.json({ limit: '50mb' }));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));
app.use(express.static(path.join(__dirname, '../frontend/build')));

// Multer setup
const storage = multer.diskStorage({
  destination: (req, file, cb) => {
    const dir = path.join(__dirname, 'uploads');
    if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
    cb(null, dir);
  },
  filename: (req, file, cb) => {
    cb(null, Date.now() + '-' + Math.random().toString(36).slice(2,8) + path.extname(file.originalname));
  }
});
const upload = multer({ storage, limits: { fileSize: 10 * 1024 * 1024 } });

const authenticate = (req, res, next) => {
  const token = req.headers.authorization?.split(' ')[1];
  if (!token) return res.status(401).json({ error: 'No token' });
  try { req.user = jwt.verify(token, SECRET); next(); }
  catch (err) { res.status(401).json({ error: 'Invalid token' }); }
};

function addNotif(userId, type, text, jobId) {
  const id = 'n' + Math.random().toString(36).slice(2, 10);
  db.prepare('INSERT INTO notifications (id, userId, type, text, jobId, at) VALUES (?, ?, ?, ?, ?, ?)').run(id, userId, type, text, jobId || null, Date.now());
}

// --- AUTH ---
app.post('/api/auth/otp', (req, res) => {
  const { phone } = req.body;
  if (!phone || phone.length < 9) return res.status(400).json({ error: 'Invalid phone' });
  res.json({ message: 'OTP sent' });
});

app.post('/api/auth/login', (req, res) => {
  const { phone, otp, name, role, city, specialty } = req.body;
  if (otp !== '1234') return res.status(400).json({ error: 'Invalid OTP' });
  let user = db.prepare('SELECT * FROM users WHERE phone = ?').get(phone);
  if (!user) {
    if (!name) return res.status(404).json({ error: 'User not found', needsRegistration: true });
    const id = 'u' + Math.random().toString(36).slice(2, 10);
    const avatar = (name || '').slice(0, 2);
    db.prepare('INSERT INTO users (id, name, phone, role, city, avatar, specialty) VALUES (?, ?, ?, ?, ?, ?, ?)').run(id, name, phone, role || 'client', city || 'دمشق', avatar, specialty || null);
    user = db.prepare('SELECT * FROM users WHERE id = ?').get(id);
  }
  const token = jwt.sign({ id: user.id, role: user.role }, SECRET, { expiresIn: '30d' });
  res.json({ token, user: { ...user, saved: JSON.parse(user.saved || '[]') } });
});

// --- USERS ---
app.get('/api/users/me', authenticate, (req, res) => {
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  if (!user) return res.status(404).json({ error: 'Not found' });
  res.json({ ...user, saved: JSON.parse(user.saved || '[]') });
});

app.put('/api/users/profile', authenticate, (req, res) => {
  const { name, city, bio, range, avatar, specialty } = req.body;
  const user = db.prepare('SELECT * FROM users WHERE id = ?').get(req.user.id);
  db.prepare('UPDATE users SET name=?, city=?, bio=?, range=?, avatar=?, specialty=? WHERE id=?').run(
    name||user.name, city||user.city, bio!==undefined?bio:user.bio, range||user.range, avatar||user.avatar, specialty||user.specialty, req.user.id
  );
  res.json({ success: true });
});

app.get('/api/users/craftsmen', authenticate, (req, res) => {
  const all = db.prepare('SELECT * FROM users WHERE role IN (?, ?)').all('craftsman', 'client');
  res.json(all.map(u => ({ ...u, saved: JSON.parse(u.saved || '[]') })));
});

// --- JOBS ---
app.get('/api/jobs', authenticate, (req, res) => {
  const jobs = db.prepare('SELECT * FROM jobs ORDER BY createdAt DESC').all();
  res.json(jobs.map(j => ({ ...j, photos: JSON.parse(j.photos || '[]') })));
});

app.post('/api/jobs', authenticate, (req, res) => {
  const { title, desc, category, city, area, photos } = req.body;
  const id = 'j' + Math.random().toString(36).slice(2, 10);
  db.prepare('INSERT INTO jobs (id, title, desc, category, city, area, distance, createdAt, clientId, photos) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)').run(id, title, desc, category, city, area||city, Math.floor(Math.random()*20)+1, Date.now(), req.user.id, JSON.stringify(photos||[]));
  res.json({ id });
});

app.put('/api/jobs/:id/status', authenticate, (req, res) => {
  const { status, chosenCraftsman, cancelReason } = req.body;
  db.prepare('UPDATE jobs SET status=?, chosenCraftsman=?, cancelReason=? WHERE id=?').run(status, chosenCraftsman||null, cancelReason||null, req.params.id);
  const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(req.params.id);
  if (status==='matched' && chosenCraftsman) addNotif(chosenCraftsman, 'match', `بدأ العميل المحادثة معك: ${job.title.slice(0,30)}`, job.id);
  if (status==='cancelled' && job.chosenCraftsman) addNotif(job.chosenCraftsman, 'cancel', `تم إلغاء الطلب: ${job.title.slice(0,30)}`, job.id);
  res.json({ success: true });
});

// --- INTERESTS ---
app.get('/api/interests', authenticate, (req, res) => {
  res.json(db.prepare('SELECT * FROM interests').all());
});

app.post('/api/interests', authenticate, (req, res) => {
  const { jobId, note, estimate } = req.body;
  const id = 'i' + Math.random().toString(36).slice(2, 10);
  db.prepare('INSERT INTO interests (id, jobId, craftsmanId, note, estimate, createdAt) VALUES (?, ?, ?, ?, ?, ?)').run(id, jobId, req.user.id, note||null, estimate||null, Date.now());
  const job = db.prepare('SELECT * FROM jobs WHERE id = ?').get(jobId);
  const craftsman = db.prepare('SELECT name FROM users WHERE id = ?').get(req.user.id);
  if (job) addNotif(job.clientId, 'interest', `${craftsman?.name||'حرفي'} مهتم بطلبك: ${job.title.slice(0,30)}`, jobId);
  res.json({ id });
});

// --- MESSAGES ---
app.get('/api/messages', authenticate, (req, res) => {
  res.json(db.prepare('SELECT * FROM messages WHERE senderId=? OR receiverId=? ORDER BY at ASC').all(req.user.id, req.user.id));
});

app.post('/api/messages', authenticate, (req, res) => {
  const { jobId, receiverId, text } = req.body;
  const id = 'm' + Math.random().toString(36).slice(2, 10);
  db.prepare('INSERT INTO messages (id, jobId, senderId, receiverId, text, at) VALUES (?, ?, ?, ?, ?, ?)').run(id, jobId, req.user.id, receiverId, text, Date.now());
  const sender = db.prepare('SELECT name FROM users WHERE id = ?').get(req.user.id);
  addNotif(receiverId, 'msg', `رسالة من ${sender?.name||'مستخدم'}`, jobId);
  res.json({ id });
});

// --- NOTIFICATIONS ---
app.get('/api/notifications', authenticate, (req, res) => {
  res.json(db.prepare('SELECT * FROM notifications WHERE userId=? OR userId=? ORDER BY at DESC').all(req.user.id, 'all'));
});

app.post('/api/notifications/read', authenticate, (req, res) => {
  db.prepare('UPDATE notifications SET read=1 WHERE userId=?').run(req.user.id);
  res.json({ success: true });
});

// --- REVIEWS ---
app.get('/api/reviews', authenticate, (req, res) => {
  res.json(db.prepare('SELECT * FROM reviews ORDER BY at DESC').all());
});

app.post('/api/reviews', authenticate, (req, res) => {
  const { craftsmanId, rating, title, text } = req.body;
  const id = 'r' + Math.random().toString(36).slice(2, 10);
  const client = db.prepare('SELECT name, city FROM users WHERE id = ?').get(req.user.id);
  db.prepare('INSERT INTO reviews (id, craftsmanId, clientId, clientName, rating, title, text, at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)').run(id, craftsmanId, req.user.id, `${client?.name?.split(' ')[0]||'عميل'}، ${client?.city||''}`, rating, title, text, Date.now());
  const stats = db.prepare('SELECT AVG(rating) as avg, COUNT(*) as count FROM reviews WHERE craftsmanId = ?').get(craftsmanId);
  db.prepare('UPDATE users SET rating=?, reviewsCount=?, jobsDone=jobsDone+1 WHERE id=?').run(Math.round(stats.avg*10)/10, stats.count, craftsmanId);
  addNotif(craftsmanId, 'review', `حصلت على تقييم ${rating} نجوم!`, null);
  res.json({ id });
});

// --- REPORTS ---
app.post('/api/reports', authenticate, (req, res) => {
  const { type, targetId, reason } = req.body;
  const id = 'rep' + Math.random().toString(36).slice(2, 10);
  db.prepare('INSERT INTO reports (id, type, targetId, reason, byId, at) VALUES (?, ?, ?, ?, ?, ?)').run(id, type, targetId, reason, req.user.id, Date.now());
  res.json({ id });
});

// --- UPLOAD ---
app.post('/api/upload', authenticate, upload.array('photos', 5), (req, res) => {
  res.json({ urls: req.files.map(f => `/uploads/${f.filename}`) });
});

// Catch-all
app.get('*', (req, res) => {
  const idx = path.join(__dirname, '../frontend/build/index.html');
  if (fs.existsSync(idx)) res.sendFile(idx);
  else res.status(404).json({ error: 'Not found' });
});

app.listen(PORT, '0.0.0.0', () => console.log(`🚀 حِرفتي running on port ${PORT}`));
