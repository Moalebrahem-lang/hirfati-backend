const { spawn } = require('child_process');
const crypto = require('crypto');

require('../loadEnv')();
const { connect, cols } = require('../db');

const PORT = Number(process.env.SMOKE_TEST_PORT || 5057);
const BASE_URL = `http://127.0.0.1:${PORT}`;
const SECRET = process.env.JWT_SECRET || 'hirfati-secret-key-2024';
const stamp = Date.now();
const testStartedAt = Date.now();
const testPhone = `+31911${String(stamp).slice(-7)}`;
const normalizedTestPhone = testPhone.replace(/\D/g, '');
const testEmail = `hirfati-smoke-${stamp}@resend.dev`;

let server;
let testUserId;
let testJobId;

function logPass(name) {
  console.log(`PASS ${name}`);
}

function assert(condition, message) {
  if (!condition) throw new Error(message);
}

function hashEmailCode(userId, code) {
  return crypto
    .createHash('sha256')
    .update(`${userId}:${String(code).replace(/\D/g, '')}:${SECRET}`)
    .digest('hex');
}

async function request(path, options = {}) {
  const headers = {
    'content-type': 'application/json',
    ...(options.headers || {})
  };
  const res = await fetch(`${BASE_URL}${path}`, { ...options, headers });
  const text = await res.text();
  let body;
  try {
    body = JSON.parse(text);
  } catch {
    body = text;
  }
  return { status: res.status, body };
}

async function waitForServer(timeoutMs = 30000) {
  const started = Date.now();
  while (Date.now() - started < timeoutMs) {
    try {
      const res = await request('/api/health');
      if (res.status === 200 && res.body?.ok === true) return;
    } catch {
      // Server is still starting.
    }
    await new Promise(resolve => setTimeout(resolve, 500));
  }
  throw new Error('Smoke test server did not become healthy in time.');
}

function startServer() {
  server = spawn(process.execPath, ['index.js'], {
    cwd: require('path').join(__dirname, '..'),
    env: {
      ...process.env,
      PORT: String(PORT),
      NODE_ENV: 'test',
      ENGAGEMENT_TRIGGERS_ENABLED: 'false'
    },
    stdio: ['ignore', 'pipe', 'pipe']
  });

  server.stdout.on('data', chunk => {
    const line = String(chunk).trim();
    if (line && process.env.SMOKE_VERBOSE === 'true') console.log(line);
  });
  server.stderr.on('data', chunk => {
    const line = String(chunk).trim();
    if (line) console.error(line);
  });
  server.on('exit', code => {
    if (code && code !== 130 && code !== 143) {
      console.error(`Smoke test server exited with code ${code}`);
    }
  });
}

async function cleanup() {
  await connect();
  const testUserIds = [testUserId, 'demo-client', 'demo-craftsman'].filter(Boolean);
  await Promise.all([
    cols().jobs.deleteMany({ clientId: testUserId }),
    cols().notifications.deleteMany({ $or: [{ userId: testUserId }, { jobId: testJobId }] }),
    cols().refreshTokens.deleteMany({
      userId: { $in: testUserIds },
      createdAt: { $gte: new Date(testStartedAt) }
    }),
    cols().auditLogs.deleteMany({
      $or: [
        { userId: { $in: testUserIds } },
        { phone: normalizedTestPhone }
      ],
      at: { $gte: testStartedAt }
    }),
    cols().users.deleteMany({
      $or: [
        { id: testUserId },
        { phone: normalizedTestPhone }
      ].filter(Boolean)
    })
  ]);
}

async function run() {
  startServer();
  try {
    await waitForServer();
    logPass('health');

    const clientLogin = await request('/api/auth/password/login', {
      method: 'POST',
      body: JSON.stringify({ phone: '0991112233', pin: '1234' })
    });
    assert(clientLogin.status === 200 && clientLogin.body?.token && clientLogin.body?.user?.role === 'client', 'Demo client login failed.');
    logPass('demo client login');

    const craftsmanLogin = await request('/api/auth/password/login', {
      method: 'POST',
      body: JSON.stringify({ phone: '0944556677', pin: '1234' })
    });
    assert(craftsmanLogin.status === 200 && craftsmanLogin.body?.token && craftsmanLogin.body?.user?.role === 'craftsman', 'Demo craftsman login failed.');
    logPass('demo craftsman login');

    const register = await request('/api/auth/password/register', {
      method: 'POST',
      body: JSON.stringify({
        phone: testPhone,
        pin: '2468',
        name: 'اختبار تلقائي',
        role: 'client',
        city: 'دمشق',
        recoveryQuestion: 'ما كلمة الاختبار؟',
        recoveryAnswer: 'اختبار',
        recoveryEmail: testEmail
      })
    });
    assert(register.status === 200 && register.body?.token && register.body?.user?.emailVerificationRequired === true, `Registration failed with ${register.status}.`);
    testUserId = register.body.user.id;
    logPass('registration and email send');

    await connect();
    await cols().users.updateOne(
      { id: testUserId },
      {
        $set: {
          emailVerification: {
            hash: hashEmailCode(testUserId, '123456'),
            expiresAt: Date.now() + 10 * 60 * 1000,
            attempts: 0
          },
          emailVerificationRequired: true,
          emailVerifiedAt: null
        }
      }
    );

    const confirm = await request('/api/auth/email/verification/confirm', {
      method: 'POST',
      headers: { authorization: `Bearer ${register.body.token}` },
      body: JSON.stringify({ code: '123456' })
    });
    assert(confirm.status === 200 && confirm.body?.success === true, `Email verification failed with ${confirm.status}.`);
    logPass('email verification confirm');

    const loginNewUser = await request('/api/auth/password/login', {
      method: 'POST',
      body: JSON.stringify({ phone: testPhone, pin: '2468' })
    });
    assert(loginNewUser.status === 200 && loginNewUser.body?.token, `New user login failed with ${loginNewUser.status}.`);
    logPass('new user login');

    const auth = { authorization: `Bearer ${loginNewUser.body.token}` };
    const createJob = await request('/api/jobs', {
      method: 'POST',
      headers: auth,
      body: JSON.stringify({
        title: 'طلب اختبار تلقائي',
        desc: 'هذا الطلب ينشأ من smoke test ويتم حذفه تلقائياً.',
        category: 'كهرباء',
        city: 'دمشق',
        area: 'المزة',
        budget: 100000,
        schedule: 'اليوم',
        urgency: 'normal',
        photos: []
      })
    });
    assert(createJob.status === 200 && createJob.body?.id, `Job creation failed with ${createJob.status}.`);
    testJobId = createJob.body.id;
    logPass('job creation');

    const legacyJobs = await request('/api/jobs', { headers: auth });
    assert(legacyJobs.status === 200 && Array.isArray(legacyJobs.body) && legacyJobs.body.some(job => job.id === testJobId), 'Legacy jobs list failed.');
    logPass('legacy jobs list');

    const paginatedJobs = await request('/api/jobs?limit=1', { headers: auth });
    assert(
      paginatedJobs.status === 200
      && Array.isArray(paginatedJobs.body?.items)
      && Object.prototype.hasOwnProperty.call(paginatedJobs.body, 'nextCursor'),
      'Paginated jobs list failed.'
    );
    logPass('paginated jobs list');
  } finally {
    await cleanup().catch(err => console.error(`Cleanup failed: ${err.message}`));
    if (server && !server.killed) server.kill('SIGTERM');
  }
}

run()
  .then(() => {
    console.log('Smoke tests completed successfully.');
    process.exit(0);
  })
  .catch(err => {
    console.error(`Smoke tests failed: ${err.message}`);
    process.exit(1);
  });
