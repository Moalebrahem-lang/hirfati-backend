require('dotenv').config();

const { MongoClient } = require('mongodb');

const MONGODB_URI = process.env.MONGODB_URI;
const DB_NAME = process.env.MONGODB_DB || 'hirfati';

if (!MONGODB_URI) {
  throw new Error('MONGODB_URI is required. Set it to your MongoDB Atlas connection string.');
}

const client = new MongoClient(MONGODB_URI, {
  maxPoolSize: Number(process.env.MONGODB_MAX_POOL_SIZE || 50),
  minPoolSize: Number(process.env.MONGODB_MIN_POOL_SIZE || 2),
  retryWrites: true
});

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
    db.collection('reports').createIndex({ targetId: 1, at: -1 })
  ]);
}

async function seedDemoUsers(db) {
  const users = db.collection('users');
  await Promise.all(demoUsers.map(user => users.updateOne(
    { phone: user.phone },
    {
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
    },
    { upsert: true }
  )));
}

async function connect() {
  if (database) return database;
  try {
    await client.connect();
    database = client.db(DB_NAME);
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
    reports: database.collection('reports')
  };
}

module.exports = {
  connect,
  cols,
  stripMongoId,
  normalizeMany,
  isConnected,
  connectionError
};
