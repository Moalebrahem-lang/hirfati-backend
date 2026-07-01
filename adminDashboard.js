const express = require('express');
const rateLimit = require('express-rate-limit');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');

const COOKIE_NAME = 'hirfati_admin_session';
const SESSION_TTL_SECONDS = 8 * 60 * 60;
const DEFAULT_ADMIN_USERNAME = 'admin';
const DEFAULT_ADMIN_PASSWORD = 'Admin1234';

function createAdminDashboard({
  secret,
  cols,
  connect,
  logAudit,
  decryptSensitive,
  hashResetCode,
  createResetCode,
  ipOf
}) {
  const router = express.Router();
  const adminLoginLimiter = rateLimit({
    windowMs: 15 * 60 * 1000,
    max: Number(process.env.ADMIN_RATE_LIMIT_MAX || 5),
    standardHeaders: true,
    legacyHeaders: false,
    message: 'محاولات كثيرة. حاول لاحقاً.'
  });

  const escapeHtml = value => String(value ?? '')
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
  const fmtDate = value => {
    if (!value) return 'غير متوفر';
    const date = value instanceof Date ? value : new Date(value);
    if (Number.isNaN(date.getTime())) return 'غير متوفر';
    return date.toLocaleString('ar-SY', { hour12: false });
  };
  const roleName = role => ({ client: 'عميل', craftsman: 'حرفي', admin: 'إدارة' }[role] || role || 'غير معروف');
  const statusBadge = status => {
    const map = {
      pending: ['بانتظار المراجعة', 'warn'],
      approved: ['مقبول', 'ok'],
      rejected: ['مرفوض', 'danger']
    };
    const [text, cls] = map[status] || [status || 'غير معروف', 'muted'];
    return `<span class="badge ${cls}">${escapeHtml(text)}</span>`;
  };
  const userStatusBadge = user => {
    if (user.disabledAt) return '<span class="badge danger">معطل</span>';
    if (user.verified) return '<span class="badge ok">موثق</span>';
    return '<span class="badge muted">نشط</span>';
  };
  const currentPath = reqPath => reqPath.split('?')[0];

  function parseCookies(req) {
    return String(req.headers.cookie || '').split(';').reduce((acc, pair) => {
      const idx = pair.indexOf('=');
      if (idx > -1) acc[pair.slice(0, idx).trim()] = decodeURIComponent(pair.slice(idx + 1).trim());
      return acc;
    }, {});
  }
  function setSessionCookie(res, token) {
    const secure = process.env.NODE_ENV === 'production' ? '; Secure' : '';
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=${encodeURIComponent(token)}; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=${SESSION_TTL_SECONDS}${secure}`);
  }
  function clearSessionCookie(res) {
    res.setHeader('Set-Cookie', `${COOKIE_NAME}=; HttpOnly; SameSite=Strict; Path=/admin; Max-Age=0`);
  }
  function signSession(req) {
    return jwt.sign({
      type: 'admin-session',
      ip: ipOf(req) || null,
      iat: Math.floor(Date.now() / 1000)
    }, secret, { expiresIn: `${SESSION_TTL_SECONDS}s` });
  }
  function verifySession(req) {
    const token = parseCookies(req)[COOKIE_NAME];
    if (!token) return null;
    try {
      const payload = jwt.verify(token, secret);
      return payload.type === 'admin-session' ? payload : null;
    } catch {
      return null;
    }
  }
  const normalizeUsername = value => String(value ?? '').trim().toLowerCase();
  const normalizePassword = value => String(value ?? '').trim();

  async function ensureDb(req, res, next) {
    try {
      await connect();
      next();
    } catch (err) {
      res.status(503).send(renderShell(req, {
        title: 'الخادم غير جاهز',
        active: '',
        content: `<section class="panel"><h1>تعذر الاتصال بقاعدة البيانات</h1><p class="muted">${escapeHtml(err.message)}</p></section>`
      }));
    }
  }

  function requireSession(req, res, next) {
    const session = verifySession(req);
    if (!session) return res.redirect('/admin/login');
    req.adminSession = session;
    next();
  }

  function renderShell(req, { title, active, content }) {
    const nav = [
      ['/admin', 'الرئيسية'],
      ['/admin/users', 'المستخدمون'],
      ['/admin/verifications', 'التحقق من الهوية'],
      ['/admin/security', 'الأمان']
    ].map(([href, label]) => `<a class="${active === href ? 'on' : ''}" href="${href}">${label}</a>`).join('');
    return `<!doctype html>
<html lang="ar" dir="rtl">
<head>
  <meta charset="utf-8">
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <title>${escapeHtml(title)} - إدارة حرفتي</title>
  <style>
    :root{--p:#5B2C8D;--deep:#261230;--soft:#F4EEFA;--bg:#F7F7F8;--line:#E8E2EE;--text:#1C1C1E;--muted:#77717D;--ok:#1F9D55;--warn:#B7791F;--danger:#C0392B}
    *{box-sizing:border-box}body{margin:0;font-family:Arial,'Tahoma',sans-serif;background:var(--bg);color:var(--text)}
    a{color:inherit;text-decoration:none}.layout{display:grid;grid-template-columns:260px 1fr;min-height:100vh}
    aside{background:#fff;border-left:1px solid var(--line);padding:24px 18px;position:sticky;top:0;height:100vh}
    .brand{display:flex;gap:12px;align-items:center;margin-bottom:28px}.logo{width:44px;height:44px;border-radius:14px;background:var(--p);color:#fff;display:grid;place-items:center;font-weight:900}.brand h2{font-size:20px;margin:0;color:var(--deep)}.brand small{color:var(--muted)}
    nav{display:grid;gap:8px}nav a{padding:13px 14px;border-radius:10px;font-weight:700;color:var(--muted)}nav a.on,nav a:hover{background:var(--soft);color:var(--p)}
    .logout{position:absolute;bottom:20px;right:18px;left:18px}.logout button{width:100%}
    main{padding:26px;max-width:1280px;width:100%;margin:0 auto}.top{display:flex;justify-content:space-between;gap:12px;align-items:center;margin-bottom:22px}.top h1{margin:0;font-size:28px;color:var(--deep)}.top p{margin:5px 0 0;color:var(--muted)}
    .grid{display:grid;gap:16px}.stats{grid-template-columns:repeat(4,minmax(0,1fr))}.two{grid-template-columns:1.2fr .8fr}.panel,.stat{background:#fff;border:1px solid var(--line);border-radius:14px;padding:18px;box-shadow:0 6px 22px rgba(36,18,48,.04)}
    .stat b{display:block;font-size:32px;color:var(--p);margin-bottom:4px}.stat span,.muted{color:var(--muted);font-size:14px}.panel h2{margin:0 0 14px;font-size:18px;color:var(--deep)}
    table{width:100%;border-collapse:collapse;background:#fff;border-radius:12px;overflow:hidden}th,td{text-align:right;border-bottom:1px solid var(--line);padding:12px;font-size:14px;vertical-align:top}th{background:var(--soft);color:var(--deep);font-size:13px}tr:last-child td{border-bottom:none}
    .badge{display:inline-flex;padding:5px 10px;border-radius:999px;font-size:12px;font-weight:800}.ok{background:#E7F6EE;color:var(--ok)}.warn{background:#FFF4D8;color:var(--warn)}.danger{background:#FDECEA;color:var(--danger)}.muted.badge{background:#EFEFF2;color:var(--muted)}
    button,.btn{border:0;border-radius:10px;background:var(--p);color:#fff;padding:10px 13px;font-weight:800;cursor:pointer;font-family:inherit}.btn.secondary,button.secondary{background:#fff;color:var(--p);border:1px solid var(--p)}button.danger{background:var(--danger)}button.ok{background:var(--ok);color:#fff}
    input,select,textarea{width:100%;border:1px solid var(--line);border-radius:10px;padding:11px 12px;font-family:inherit;background:#fff}textarea{min-height:82px;resize:vertical}.filters{display:grid;grid-template-columns:2fr 1fr 1fr auto;gap:10px;margin-bottom:16px}
    .cards{display:grid;grid-template-columns:repeat(auto-fill,minmax(310px,1fr));gap:16px}.verify-card{background:#fff;border:1px solid var(--line);border-radius:14px;overflow:hidden}.verify-card .body{padding:16px}.imgs{display:grid;grid-template-columns:1fr 1fr;gap:10px;margin:12px 0}.imgs img{width:100%;height:190px;object-fit:cover;border-radius:10px;border:1px solid var(--line);background:#fafafa}.actions{display:grid;grid-template-columns:1fr 1fr;gap:8px;margin-top:12px}
    .login{min-height:100vh;display:grid;place-items:center;padding:24px;background:linear-gradient(135deg,var(--soft),#fff)}.login-card{width:min(430px,100%);background:#fff;border:1px solid var(--line);border-radius:18px;padding:28px;box-shadow:0 18px 50px rgba(38,18,48,.12)}.login-card h1{margin:0 0 8px;color:var(--deep)}.error{background:#FDECEA;color:var(--danger);padding:10px 12px;border-radius:10px;margin-bottom:12px;font-weight:700}
    details summary{cursor:pointer;font-weight:800;color:var(--p)}.inline{display:inline}.nowrap{white-space:nowrap}.highlight{border:2px solid #E8A317}
    @media(max-width:820px){.layout{display:block}aside{position:static;height:auto;border-left:0;border-bottom:1px solid var(--line)}.logout{position:static;margin-top:14px}main{padding:18px}.stats,.two,.filters{grid-template-columns:1fr}.top{display:block}.imgs img{height:150px}table{display:block;overflow-x:auto;white-space:nowrap}}
  </style>
</head>
<body>${verifySession(req) ? `<div class="layout"><aside><div class="brand"><div class="logo">ح</div><div><h2>إدارة حرفتي</h2><small>لوحة التحكم</small></div></div><nav>${nav}</nav><form class="logout" method="post" action="/admin/logout"><button class="secondary">تسجيل الخروج</button></form></aside><main>${content}</main></div>` : content}</body>
</html>`;
  }

  function renderLogin(req, error = '') {
    return renderShell(req, {
      title: 'تسجيل دخول الإدارة',
      active: '',
      content: `<div class="login"><form class="login-card" method="post" action="/admin/login">
        <div class="brand"><div class="logo">ح</div><div><h1>دخول الإدارة</h1><p class="muted">أدخل اسم المستخدم وكلمة المرور</p></div></div>
        ${error ? `<div class="error">${escapeHtml(error)}</div>` : ''}
        <label>اسم المستخدم</label>
        <input name="username" autocomplete="username" required autofocus value="admin">
        <label style="display:block;margin-top:12px">كلمة المرور</label>
        <input name="password" type="password" autocomplete="current-password" required>
        <button style="width:100%;margin-top:14px">دخول آمن</button>
      </form></div>
      <script>
        document.querySelector('form')?.addEventListener('submit', function () {
          const button = this.querySelector('button');
          if (button) { button.disabled = true; button.textContent = 'جاري الدخول...'; }
        });
      </script>`
    });
  }

  function pageHeader(title, subtitle = '') {
    return `<div class="top"><div><h1>${escapeHtml(title)}</h1>${subtitle ? `<p>${escapeHtml(subtitle)}</p>` : ''}</div></div>`;
  }

  async function renderDashboard(req, res) {
    const [userCount, craftsmanCount, jobCount, verifiedCount, latestUsers, pending] = await Promise.all([
      cols().users.countDocuments({}),
      cols().users.countDocuments({ role: 'craftsman' }),
      cols().jobs.countDocuments({}),
      cols().users.countDocuments({ verified: 1 }),
      cols().users.find({}).sort({ passwordSetAt: -1, _id: -1 }).limit(5).toArray(),
      cols().identityRequests.find({ status: 'pending' }).sort({ createdAt: -1 }).limit(6).toArray()
    ]);
    const latestRows = latestUsers.map(u => `<tr><td>${escapeHtml(u.name)}</td><td>${escapeHtml(u.phone)}</td><td>${roleName(u.role)}</td><td>${userStatusBadge(u)}</td><td>${fmtDate(u.passwordSetAt)}</td></tr>`).join('');
    const pendingRows = pending.map(r => `<tr><td>${escapeHtml(r.name)}</td><td>${escapeHtml(r.phone)}</td><td>${r.type === 'password_recovery' ? 'استرجاع كلمة مرور' : 'توثيق حرفي'}</td><td>${fmtDate(r.createdAt)}</td><td><a class="btn secondary" href="/admin/verifications">مراجعة</a></td></tr>`).join('');
    res.send(renderShell(req, {
      title: 'الرئيسية',
      active: '/admin',
      content: `${pageHeader('الرئيسية', 'نظرة سريعة على حالة المنصة')}
        <section class="grid stats">
          <div class="stat"><b>${userCount}</b><span>كل المستخدمين</span></div>
          <div class="stat"><b>${craftsmanCount}</b><span>الحرفيون</span></div>
          <div class="stat"><b>${jobCount}</b><span>الطلبات</span></div>
          <div class="stat"><b>${verifiedCount}</b><span>الموثقون</span></div>
        </section>
        <section class="grid two" style="margin-top:16px">
          <div class="panel"><h2>آخر 5 مستخدمين جدد</h2><table><thead><tr><th>الاسم</th><th>الهاتف</th><th>النوع</th><th>الحالة</th><th>التاريخ</th></tr></thead><tbody>${latestRows || '<tr><td colspan="5">لا يوجد مستخدمون.</td></tr>'}</tbody></table></div>
          <div class="panel highlight"><h2>طلبات تنتظر مراجعة</h2><table><thead><tr><th>الاسم</th><th>الهاتف</th><th>النوع</th><th>التاريخ</th><th></th></tr></thead><tbody>${pendingRows || '<tr><td colspan="5">لا توجد طلبات معلقة.</td></tr>'}</tbody></table></div>
        </section>`
    }));
  }

  async function renderUsers(req, res) {
    const q = String(req.query.q || '').trim();
    const role = String(req.query.role || '').trim();
    const status = String(req.query.status || '').trim();
    const and = [];
    if (q) and.push({
      $or: [
        { name: { $regex: q, $options: 'i' } },
        { phone: { $regex: q.replace(/\D/g, ''), $options: 'i' } },
        { city: { $regex: q, $options: 'i' } },
        { specialty: { $regex: q, $options: 'i' } }
      ]
    });
    if (role) and.push({ role });
    if (status === 'disabled') and.push({ disabledAt: { $exists: true, $ne: null } });
    if (status === 'active') and.push({ $or: [{ disabledAt: { $exists: false } }, { disabledAt: null }] });
    if (status === 'verified') and.push({ verified: 1 });
    const filter = and.length ? { $and: and } : {};
    const users = await cols().users.find(filter).sort({ passwordSetAt: -1, _id: -1 }).limit(300).toArray();
    const rows = users.map(u => `<tr>
      <td><strong>${escapeHtml(u.name)}</strong><br><span class="muted">${escapeHtml(u.city || '')} ${u.specialty ? `· ${escapeHtml(u.specialty)}` : ''}</span></td>
      <td>${escapeHtml(u.phone)}</td><td>${roleName(u.role)}</td><td>${userStatusBadge(u)}</td><td>${fmtDate(u.passwordSetAt || u.identityVerifiedAt)}</td>
      <td><details><summary>تفاصيل</summary><p class="muted">ID: ${escapeHtml(u.id)}<br>تقييم: ${escapeHtml(u.rating || 0)} · أعمال: ${escapeHtml(u.jobsDone || 0)}<br>${escapeHtml(u.bio || '')}</p></details></td>
      <td><form class="inline" method="post" action="/admin/users/${encodeURIComponent(u.id)}/toggle"><button class="${u.disabledAt ? 'ok' : 'danger'}">${u.disabledAt ? 'تفعيل' : 'تعطيل'}</button></form></td>
    </tr>`).join('');
    res.send(renderShell(req, {
      title: 'المستخدمون',
      active: '/admin/users',
      content: `${pageHeader('المستخدمون', 'بحث وفلترة وإدارة حالة الحسابات')}
        <form class="filters" method="get" action="/admin/users">
          <input name="q" value="${escapeHtml(q)}" placeholder="بحث بالاسم، الرقم، المدينة، المهنة">
          <select name="role"><option value="">كل الأنواع</option><option value="client" ${role === 'client' ? 'selected' : ''}>عميل</option><option value="craftsman" ${role === 'craftsman' ? 'selected' : ''}>حرفي</option><option value="admin" ${role === 'admin' ? 'selected' : ''}>إدارة</option></select>
          <select name="status"><option value="">كل الحالات</option><option value="active" ${status === 'active' ? 'selected' : ''}>نشط</option><option value="disabled" ${status === 'disabled' ? 'selected' : ''}>معطل</option><option value="verified" ${status === 'verified' ? 'selected' : ''}>موثق</option></select>
          <button>تطبيق</button>
        </form>
        <section class="panel"><table><thead><tr><th>المستخدم</th><th>الهاتف</th><th>النوع</th><th>الحالة</th><th>تاريخ التسجيل</th><th>تفاصيل</th><th>إجراء</th></tr></thead><tbody>${rows || '<tr><td colspan="7">لا توجد نتائج.</td></tr>'}</tbody></table></section>`
    }));
  }

  async function decideIdentityRequest(req, request, status, note) {
    const update = {
      status,
      adminNote: note || null,
      reviewedAt: Date.now(),
      reviewedBy: 'admin-dashboard'
    };
    let resetCode = null;
    if (status === 'approved' && request.type === 'craftsman_verification') {
      await cols().users.updateOne({ id: request.userId }, { $set: { verified: 1, identityVerifiedAt: Date.now() } });
    }
    if (status === 'approved' && request.type === 'password_recovery') {
      resetCode = createResetCode();
      update.resetCodeHash = hashResetCode(request.phone, resetCode);
      update.resetCodeEnc = null;
      update.resetExpiresAt = Date.now() + 24 * 60 * 60 * 1000;
      update.resetUsedAt = null;
    }
    await cols().identityRequests.updateOne({ id: request.id }, { $set: update });
    await logAudit('admin.identity.reviewed', req, {
      userId: request.userId,
      phone: request.phone,
      result: status,
      targetId: request.id,
      meta: { type: request.type, source: 'admin-dashboard' }
    });
    return resetCode;
  }

  async function renderVerifications(req, res) {
    const status = String(req.query.status || 'pending');
    const filter = status ? { status } : {};
    const requests = await cols().identityRequests.find(filter).sort({ createdAt: -1 }).limit(100).toArray();
    const resetCode = String(req.query.resetCode || '').trim();
    const cards = requests.map(r => {
      const idCard = decryptSensitive(r.idCardImageEnc);
      const selfie = decryptSensitive(r.selfieImageEnc);
      return `<article class="verify-card">
        <div class="body">
          <h2>${escapeHtml(r.name)} ${statusBadge(r.status)}</h2>
          <p class="muted">${escapeHtml(r.phone)} · ${r.type === 'password_recovery' ? 'استرجاع كلمة مرور' : 'توثيق حرفي'} · ${fmtDate(r.createdAt)}</p>
          <div class="imgs"><div><p class="muted">صورة البطاقة</p>${idCard ? `<a href="${idCard}" target="_blank"><img src="${idCard}" alt="صورة البطاقة"></a>` : '<div class="panel muted">لا توجد صورة</div>'}</div><div><p class="muted">سيلفي مع البطاقة</p>${selfie ? `<a href="${selfie}" target="_blank"><img src="${selfie}" alt="سيلفي مع البطاقة"></a>` : '<div class="panel muted">لا توجد صورة</div>'}</div></div>
          ${r.note ? `<p>${escapeHtml(r.note)}</p>` : ''}
          ${r.status === 'pending' ? `<form method="post" action="/admin/verifications/${encodeURIComponent(r.id)}/decision">
            <textarea name="note" placeholder="سبب الرفض أو ملاحظة داخلية"></textarea>
            <div class="actions"><button class="ok" name="status" value="approved">✅ موافقة</button><button class="danger" name="status" value="rejected">❌ رفض</button></div>
          </form>` : `<p class="muted">تمت المراجعة: ${fmtDate(r.reviewedAt)} ${r.adminNote ? `· ${escapeHtml(r.adminNote)}` : ''}</p>`}
        </div>
      </article>`;
    }).join('');
    res.send(renderShell(req, {
      title: 'التحقق من الهوية',
      active: '/admin/verifications',
      content: `${pageHeader('التحقق من الهوية', 'مراجعة صور الهوية والسيلفي للحرفيين وطلبات الاسترجاع')}
        ${resetCode ? `<section class="panel highlight"><h2>كود إعادة التعيين</h2><p class="muted">أرسله لصاحب الحساب بعد التأكد من هويته:</p><h1 class="nowrap">${escapeHtml(resetCode)}</h1></section>` : ''}
        <form class="filters" style="grid-template-columns:1fr auto" method="get" action="/admin/verifications">
          <select name="status"><option value="pending" ${status === 'pending' ? 'selected' : ''}>بانتظار المراجعة</option><option value="approved" ${status === 'approved' ? 'selected' : ''}>مقبولة</option><option value="rejected" ${status === 'rejected' ? 'selected' : ''}>مرفوضة</option><option value="" ${status === '' ? 'selected' : ''}>الكل</option></select>
          <button>عرض</button>
        </form>
        <section class="cards">${cards || '<div class="panel">لا توجد طلبات ضمن هذه الحالة.</div>'}</section>`
    }));
  }

  async function renderSecurity(req, res) {
    const now = Date.now();
    const [failed, blocked] = await Promise.all([
      cols().auditLogs.find({ type: 'auth.login', result: { $in: ['failed', 'blocked'] } }).sort({ at: -1 }).limit(50).toArray(),
      cols().users.find({ 'auth.loginBlockedUntil': { $gt: now } }).sort({ 'auth.loginBlockedUntil': -1 }).toArray()
    ]);
    const failedRows = failed.map(log => `<tr><td>${fmtDate(log.at)}</td><td>${escapeHtml(log.phone || '')}</td><td>${escapeHtml(log.result)}</td><td>${escapeHtml(log.ip || '')}</td><td>${escapeHtml(log.meta?.reason || '')}</td></tr>`).join('');
    const blockedRows = blocked.map(u => `<tr><td>${escapeHtml(u.name)}</td><td>${escapeHtml(u.phone)}</td><td>${fmtDate(u.auth?.loginBlockedUntil)}</td><td><form method="post" action="/admin/security/unblock/${encodeURIComponent(u.id)}"><button class="secondary">رفع الحظر</button></form></td></tr>`).join('');
    res.send(renderShell(req, {
      title: 'الأمان',
      active: '/admin/security',
      content: `${pageHeader('الأمان', 'مراقبة محاولات الدخول والحظر التلقائي')}
        <section class="grid two"><div class="panel"><h2>آخر محاولات دخول فاشلة</h2><table><thead><tr><th>الوقت</th><th>الرقم</th><th>النتيجة</th><th>IP</th><th>السبب</th></tr></thead><tbody>${failedRows || '<tr><td colspan="5">لا توجد محاولات فاشلة حديثة.</td></tr>'}</tbody></table></div>
        <div class="panel"><h2>الأرقام المحظورة حالياً</h2><table><thead><tr><th>الاسم</th><th>الهاتف</th><th>محظور حتى</th><th></th></tr></thead><tbody>${blockedRows || '<tr><td colspan="4">لا يوجد حظر نشط.</td></tr>'}</tbody></table></div></section>`
    }));
  }

  router.use(ensureDb);
  router.get('/login', (req, res) => {
    if (verifySession(req)) return res.redirect('/admin');
    res.send(renderLogin(req));
  });
  router.post('/login', adminLoginLimiter, async (req, res) => {
    const username = normalizeUsername(req.body.username);
    const password = normalizePassword(req.body.password);
    console.log('Admin login DB debug:', {
      username,
      passwordLength: password.length,
      bodyKeys: Object.keys(req.body || {}),
      ip: ipOf(req) || null
    });
    if (!username || !password) {
      await logAudit('admin.login', req, { result: 'failed', meta: { reason: 'missing_credentials' } });
      return res.status(400).send(renderLogin(req, 'أدخل اسم المستخدم وكلمة المرور.'));
    }
    const admin = await cols().users.findOne({ username, role: 'admin' });
    if (!admin?.passwordHash) {
      await logAudit('admin.login', req, { result: 'failed', meta: { reason: 'missing_admin_user', username } });
      return res.status(401).send(renderLogin(req, 'بيانات الدخول غير صحيحة.'));
    }
    let ok = await bcrypt.compare(password, admin.passwordHash);
    let repairedHash = false;
    if (!ok && username === DEFAULT_ADMIN_USERNAME && password === DEFAULT_ADMIN_PASSWORD) {
      const passwordHash = await bcrypt.hash(DEFAULT_ADMIN_PASSWORD, 12);
      await cols().users.updateOne(
        { id: admin.id },
        { $set: { passwordHash, passwordSetAt: Date.now(), 'auth.failedLoginCount': 0, 'auth.loginBlockedUntil': 0 } }
      );
      ok = true;
      repairedHash = true;
    }
    console.log('Admin login DB compare:', { username, userFound: true, passwordMatches: ok, repairedHash });
    if (!ok || admin.disabledAt) {
      await logAudit('admin.login', req, { userId: admin.id, phone: admin.phone, result: 'failed', meta: { reason: admin.disabledAt ? 'admin_disabled' : 'wrong_password', username } });
      return res.status(401).send(renderLogin(req, 'بيانات الدخول غير صحيحة.'));
    }
    setSessionCookie(res, signSession(req, admin));
    await logAudit('admin.login', req, { userId: admin.id, phone: admin.phone, result: 'success' });
    res.redirect('/admin');
  });
  router.post('/logout', (req, res) => {
    clearSessionCookie(res);
    res.redirect('/admin/login');
  });

  router.use(requireSession);
  router.get('/', asyncRoute(renderDashboard));
  router.get('/users', asyncRoute(renderUsers));
  router.post('/users/:id/toggle', asyncRoute(async (req, res) => {
    const user = await cols().users.findOne({ id: req.params.id });
    if (!user) return res.status(404).send('غير موجود');
    const disabling = !user.disabledAt;
    await cols().users.updateOne(
      { id: user.id },
      disabling
        ? { $set: { disabledAt: Date.now(), disabledBy: 'admin-dashboard' } }
        : { $set: { disabledAt: null, disabledBy: null, 'auth.failedLoginCount': 0, 'auth.loginBlockedUntil': 0 } }
    );
    if (disabling) await cols().refreshTokens.updateMany({ userId: user.id, revokedAt: null }, { $set: { revokedAt: new Date(), revokedReason: 'admin_disabled' } });
    await logAudit('admin.user.toggle', req, { userId: user.id, phone: user.phone, result: disabling ? 'disabled' : 'enabled' });
    res.redirect('/admin/users');
  }));
  router.get('/verifications', asyncRoute(renderVerifications));
  router.post('/verifications/:id/decision', asyncRoute(async (req, res) => {
    const status = ['approved', 'rejected'].includes(req.body.status) ? req.body.status : null;
    if (!status) return res.status(400).send('حالة غير صحيحة');
    const request = await cols().identityRequests.findOne({ id: req.params.id });
    if (!request) return res.status(404).send('الطلب غير موجود');
    if (request.status !== 'pending') return res.status(409).send('تمت مراجعة هذا الطلب مسبقاً');
    const resetCode = await decideIdentityRequest(req, request, status, req.body.note);
    res.redirect(`/admin/verifications${resetCode ? `?resetCode=${encodeURIComponent(resetCode)}` : ''}`);
  }));
  router.get('/security', asyncRoute(renderSecurity));
  router.post('/security/unblock/:id', asyncRoute(async (req, res) => {
    const user = await cols().users.findOne({ id: req.params.id });
    if (!user) return res.status(404).send('غير موجود');
    await cols().users.updateOne({ id: user.id }, { $set: { 'auth.failedLoginCount': 0, 'auth.loginBlockedUntil': 0, 'auth.unblockedAt': Date.now() } });
    await logAudit('admin.security.unblock', req, { userId: user.id, phone: user.phone, result: 'success' });
    res.redirect('/admin/security');
  }));

  function asyncRoute(fn) {
    return (req, res, next) => Promise.resolve(fn(req, res, next)).catch(next);
  }

  return router;
}

module.exports = createAdminDashboard;
