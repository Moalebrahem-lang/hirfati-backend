const Database = require('better-sqlite3');
const path = require('path');

const db = new Database(path.join(__dirname, 'hirfati.db'));
db.pragma('journal_mode = WAL');

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    phone TEXT UNIQUE NOT NULL,
    role TEXT CHECK(role IN ('client', 'craftsman', 'admin')) NOT NULL,
    city TEXT DEFAULT 'دمشق',
    avatar TEXT,
    specialty TEXT,
    rating REAL DEFAULT 0,
    reviewsCount INTEGER DEFAULT 0,
    bio TEXT DEFAULT '',
    verified INTEGER DEFAULT 0,
    warranty INTEGER DEFAULT 0,
    jobsDone INTEGER DEFAULT 0,
    range INTEGER DEFAULT 25,
    saved TEXT DEFAULT '[]'
  );

  CREATE TABLE IF NOT EXISTS jobs (
    id TEXT PRIMARY KEY,
    title TEXT NOT NULL,
    desc TEXT NOT NULL,
    category TEXT NOT NULL,
    city TEXT NOT NULL,
    area TEXT,
    distance INTEGER DEFAULT 5,
    createdAt INTEGER NOT NULL,
    clientId TEXT NOT NULL,
    status TEXT DEFAULT 'open',
    photos TEXT DEFAULT '[]',
    chosenCraftsman TEXT,
    cancelReason TEXT
  );

  CREATE TABLE IF NOT EXISTS interests (
    id TEXT PRIMARY KEY,
    jobId TEXT NOT NULL,
    craftsmanId TEXT NOT NULL,
    note TEXT,
    estimate INTEGER,
    createdAt INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS messages (
    id TEXT PRIMARY KEY,
    jobId TEXT NOT NULL,
    senderId TEXT NOT NULL,
    receiverId TEXT NOT NULL,
    text TEXT NOT NULL,
    at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS reviews (
    id TEXT PRIMARY KEY,
    craftsmanId TEXT NOT NULL,
    clientId TEXT NOT NULL,
    clientName TEXT NOT NULL,
    rating INTEGER NOT NULL,
    title TEXT,
    text TEXT,
    at INTEGER NOT NULL
  );

  CREATE TABLE IF NOT EXISTS notifications (
    id TEXT PRIMARY KEY,
    userId TEXT NOT NULL,
    type TEXT NOT NULL,
    text TEXT NOT NULL,
    jobId TEXT,
    at INTEGER NOT NULL,
    read INTEGER DEFAULT 0
  );

  CREATE TABLE IF NOT EXISTS reports (
    id TEXT PRIMARY KEY,
    type TEXT NOT NULL,
    targetId TEXT NOT NULL,
    reason TEXT NOT NULL,
    byId TEXT NOT NULL,
    at INTEGER NOT NULL
  );
`);

// Seed admin account
const adminExists = db.prepare('SELECT id FROM users WHERE phone = ?').get('0900000000');
if (!adminExists) {
  db.prepare('INSERT INTO users (id, name, phone, role, city, avatar) VALUES (?, ?, ?, ?, ?, ?)').run('admin', 'مدير النظام', '0900000000', 'admin', 'دمشق', 'مد');
}

module.exports = db;
