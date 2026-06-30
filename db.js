require('dotenv').config();

const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || 'hirfati';
const PASSWORD_BCRYPT_ROUNDS = Number(process.env.PASSWORD_BCRYPT_ROUNDS || 12);

if (!MONGODB_URI) {
  throw new Error('MONGODB_URI is required. Set it to your MongoDB Atlas connection string.');
}

let database;
let lastError = null;

const demoUsers = [
  {
    id: 'demo-client',
    name: 'عميل تجريبي',
    phone: '0991112233',
    role: 'client',
    city: 'دمشق',
    avatar: 'عم',
    specialty: null,
    rating: 0,
    reviewsCount: 0,
    bio: '',
    verified: 1,
    warranty: 0,
    jobsDone: 0,
    range: 25,
    saved: []
  },
  {
    id: 'demo-craftsman',
    name: 'حرفي تجريبي',
    phone: '0944556677',
    role: 'craftsman',
    city: 'دمشق',
    avatar: 'حر',
    specialty: 'كهرباء',
    rating: 0,
    reviewsCount: 0,
    bio: 'حساب حرفي تجريبي لاختبار التطبيق.',
    verified: 1,
    warranty: 1,
    jobsDone: 0,
    range: 25,
    saved: [],
    experienceYears: 8,
    serviceAreas: ['دمشق', 'ريف دمشق'],
    portfolio: [
      { title: 'صيانة لوحة كهرباء', image: null },
      { title: 'تمديد إنارة منزلية', image: null },
      { title: 'تركيب قواطع حماية', image: null }
    ]
  },
  {
    id: 'admin',
    name: 'مدير النظام',
    phone: '0900000000',
    role: 'admin',
    city: 'دمشق',
    avatar: 'مد',
    specialty: null,
    rating: 0,
    reviewsCount: 0,
    bio: '',
    verified: 1,
    warranty: 0,
    jobsDone: 0,
    range: 25,
    saved: []
  }
];

const demoPins = {
  '0991112233': '1234'
};

function stripMongoId(doc) {
  if (!doc) return doc;
  const { _id, ...rest } = doc;
  return rest;
}

function normalizeMany(docs) {
  return docs.map(stripMongoId);
}

async function createIndexes(db) {
  await Promise.all([
    db.collection('users').createIndex({ phone: 1 }, { unique: true }),
    db.collection('users').createIndex({ id: 1 }, { unique: true }),
    db.collection('users').createIndex({ role: 1, city: 1 }),
    db.collection('jobs').createIndex({ id: 1 }, { unique: true }),
    db.collection('jobs').createIndex({ createdAt: -1 }),
    db.collection('jobs').createIndex({ status: 1, category: 1, city: 1 }),
    db.collection('jobs').createIndex({ clientId: 1 }),
    db.collection('interests').createIndex({ id: 1 }, { unique: true }),
    db.collection('interests').createIndex({ jobId: 1, craftsmanId: 1 }),
    db.collection('messages').createIndex({ jobId: 1, at: 1 }),
    db.collection('messages').createIndex({ senderId: 1, receiverId: 1, at: 1 }),
    db.collection('notifications').createIndex({ userId: 1, at: -1 }),
    db.collection('reviews').createIndex({ craftsmanId: 1, at: -1 }),
    db.collection('reports').createIndex({ targetId: 1, at: -1 }),
    db.collection('otps').createIndex({ phone: 1, purpose: 1 }),
    db.collection('otps').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('refreshTokens').createIndex({ tokenHash: 1 }, { unique: true }),
    db.collection('refreshTokens').createIndex({ userId: 1, expiresAt: -1 }),
    db.collection('refreshTokens').createIndex({ expiresAt: 1 }, { expireAfterSeconds: 0 }),
    db.collection('passwordRecoveryLogs').createIndex({ phone: 1, at: -1 }),
    db.collection('passwordRecoveryLogs').createIndex({ at: -1 }),
    db.collection('auditLogs').createIndex({ type: 1, at: -1 }),
    db.collection('auditLogs').createIndex({ userId: 1, at: -1 }),
    db.collection('auditLogs').createIndex({ phone: 1, at: -1 }),
    db.collection('identityRequests').createIndex({ id: 1 }, { unique: true }),
    db.collection('identityRequests').createIndex({ type: 1, status: 1, createdAt: -1 }),
    db.collection('identityRequests').createIndex({ userId: 1, createdAt: -1 }),
    db.collection('identityRequests').createIndex({ phone: 1, createdAt: -1 })
  ]);
}

async function seedDemoUsers(db) {
  const users = db.collection('users');
  await Promise.all(demoUsers.map(async user => {
    const update = {
      $set: {
        id: user.id,
        name: user.name,
        role: user.role,
        city: user.city,
        avatar: user.avatar,
        specialty: user.specialty,
        verified: user.verified,
        warranty: user.warranty,
        bio: user.bio,
        experienceYears: user.experienceYears,
        serviceAreas: user.serviceAreas,
        portfolio: user.portfolio
      },
      $setOnInsert: {
        rating: user.rating,
        reviewsCount: user.reviewsCount,
        jobsDone: user.jobsDone,
        range: user.range,
        saved: user.saved
      }
    };
    if (demoPins[user.phone]) {
      update.$set.passwordHash = await bcrypt.hash(demoPins[user.phone], PASSWORD_BCRYPT_ROUNDS);
      update.$set.passwordSetAt = Date.now();
      update.$set.recoveryQuestion = 'ما اسم المدرسة الأولى؟';
      update.$set.recoveryAnswerHash = await bcrypt.hash('تجريبي', PASSWORD_BCRYPT_ROUNDS);
      update.$set.auth = { failedLoginCount: 0, loginBlockedUntil: 0 };
    }
    return users.updateOne({ phone: user.phone }, update, { upsert: true });
  }));
}

async function connect() {
  if (database) return database;
  try {
    await mongoose.connect(process.env.MONGODB_URI, {
      serverSelectionTimeoutMS: 10000,
      ssl: true,
      tls: true,
      tlsAllowInvalidCertificates: true,
      tlsAllowInvalidHostnames: true,
      family: 4
    });
    database = mongoose.connection.useDb(DB_NAME).db;
    await createIndexes(database);
    await seedDemoUsers(database);
    lastError = null;
    return database;
  } catch (err) {
    lastError = err;
    throw err;
  }
}

function isConnected() {
  return Boolean(database);
}

async function healthCheck() {
  try {
    const db = database || await connect();
    await db.command({ ping: 1 });
    lastError = null;
    return { ok: true, db: 'mongodb', at: Date.now() };
  } catch (err) {
    lastError = err;
    return { ok: false, db: 'mongodb', error: err.message, at: Date.now() };
  }
}

function connectionError() {
  return lastError?.message || null;
}

function cols() {
  if (!database) throw new Error('Database is not connected yet.');
  return {
    users: database.collection('users'),
    jobs: database.collection('jobs'),
    interests: database.collection('interests'),
    messages: database.collection('messages'),
    notifications: database.collection('notifications'),
    reviews: database.collection('reviews'),
    reports: database.collection('reports'),
    otps: database.collection('otps'),
    refreshTokens: database.collection('refreshTokens'),
    passwordRecoveryLogs: database.collection('passwordRecoveryLogs'),
    auditLogs: database.collection('auditLogs'),
    identityRequests: database.collection('identityRequests')
  };
}

module.exports = {
  connect,
  cols,
  stripMongoId,
  normalizeMany,
  isConnected,
  healthCheck,
  connectionError
};
