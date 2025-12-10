// Load environment variables from .env
require('dotenv').config();

const path = require('path');
const express = require('express');
const session = require('express-session');
const app = express();
const SQLiteStore = require('connect-sqlite3')(session);
const crypto = require('crypto');
const rateLimit = require('express-rate-limit');
const helmet = require('helmet');



const sqlite3 = require('sqlite3').verbose();


const PDFDocument = require('pdfkit');
const fs = require('fs');


const QRCode = require('qrcode');
const multer = require('multer');
const sendMail = require('./mailer'); // after other require statements
console.log("Using database:", path.resolve('customers.db'));

const logoBase64 = fs.readFileSync(path.join(__dirname, 'public/images/rkllogo.png')).toString('base64');

const { validateCustomer } = require('./validators/customerValidators');
const { validateInvoiceCreate, validateInvoiceUpdate, validateInvoicePayment } = require('./validators/invoiceValidators');
const {
  validateInvoiceIdParam,
  validateInvoiceItemCreate,
  validateInvoiceItemUpdate,
  validateInvoiceItemDelete
} = require('./validators/invoiceItemValidators');
const {
  validateCustomerIdParam,
  validateBookingCreate,
  validateBookingUpdate,
  validateBookingSlotUpdate,
  validateBookingDelete,
  validateAllocationGet,
  validateBookingsToAllocateQuery,
  validateAllocationSingle,
  validateAllocationBatch
} = require('./validators/bookingValidators');
const {
  validateItemIdParam,
  validateTrackingIdParam,
  validateTrackingIdDelete,
  validateTrackingCreate,
  validateTrackingUpdate,
  validateQuickTrack
} = require('./validators/trackingValidators');
const {
  validateStaffLogin,
  validateStaffCreate,
  validateStaffUpdate,
  validateStaffPasswordReset
} = require('./validators/staffValidators');



// Routers / middleware
const { requireAuth, requireAdmin, requirePortal, requireStaff } = require('./auth_middleware');

const storage = multer.diskStorage({
  destination: function (req, file, cb) {
    cb(null, 'uploads');
  },
  filename: function (req, file, cb) {
    const ext = path.extname(file.originalname);
    const uniqueName = `${Date.now()}-${Math.round(Math.random() * 1e9)}${ext}`;
    cb(null, uniqueName);
  }
});

// Liberal but safe: up to 15MB per image
const MAX_FILE_SIZE = 15 * 1024 * 1024; // 15 MB

const ALLOWED_MIME_TYPES = [
  'image/jpeg',
  'image/png',
  'image/gif',
  'image/webp',
  'image/heic',
  'image/heif'
];

const upload = multer({
  storage,
  limits: {
    fileSize: MAX_FILE_SIZE
  },
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      // You can log this for debugging
      console.warn('🚫 Rejected upload with type:', file.mimetype);
      const err = new Error('Only image uploads are allowed');
      err.code = 'INVALID_FILE_TYPE';
      return cb(err);
    }
    cb(null, true);
  }
});



const port = 3000;

// Databases
const db = new sqlite3.Database('users.db');
const customerDB = new sqlite3.Database('customers.db');
console.log('📂 Absolute path to customers.db =', path.resolve('customers.db'));

// =========================
// Audit log table (Wave 3F)
// =========================
customerDB.serialize(() => {
  customerDB.run(`
    CREATE TABLE IF NOT EXISTS audit_log (
      LogID INTEGER PRIMARY KEY AUTOINCREMENT,
      Timestamp TEXT NOT NULL,
      Zone TEXT,
      UserID INTEGER,
      Username TEXT,
      Role TEXT,
      Action TEXT NOT NULL,
      EntityType TEXT,
      EntityID TEXT,
      Details TEXT,
      IP TEXT
    )
  `, (err) => {
    if (err) {
      console.error('❌ Failed to ensure audit_log table exists:', err);
    } else {
      console.log('✅ audit_log table is ready');
    }
  });
});


// =========================
// Wave 3: Login protection
// =========================

// How long we remember attempts
const LOGIN_WINDOW_MS = 15 * 60 * 1000; // 15 minutes

// After this many failures in the window → hard lock
const LOGIN_HARD_LOCK_THRESHOLD = 10;

// How long hard lock lasts
const LOGIN_HARD_LOCK_DURATION_MS = 3 * 60 * 60 * 1000; // 3 hours

// We’ll track attempts separately per zone (main, staff, portal)
const loginAttempts = {
  main: new Map(),   // key: username (or email)
  staff: new Map(),
  portal: new Map()
};

// Helper to get the structure for a zone/key
function getLoginState(zone, key) {
  const map = loginAttempts[zone];
  if (!map) return null;

  let state = map.get(key);
  const now = Date.now();

  if (!state) {
    state = {
      count: 0,
      firstAttemptAt: now,
      lockedUntil: 0
    };
    map.set(key, state);
  } else {
    // Reset window if it's too old
    if (now - state.firstAttemptAt > LOGIN_WINDOW_MS && now > state.lockedUntil) {
      state.count = 0;
      state.firstAttemptAt = now;
    }
  }

  return state;
}

// Check if a username is currently locked
function isLoginLocked(zone, key) {
  const state = getLoginState(zone, key);
  const now = Date.now();

  if (state.lockedUntil && now < state.lockedUntil) {
    const remainingMs = state.lockedUntil - now;
    return { locked: true, remainingMs };
  }

  return { locked: false, remainingMs: 0 };
}

// Record a failed attempt
function registerLoginFailure(zone, key) {
  const state = getLoginState(zone, key);
  const now = Date.now();

  state.count += 1;

  // If threshold reached, hard lock for 3 hours
  if (state.count >= LOGIN_HARD_LOCK_THRESHOLD) {
    state.lockedUntil = now + LOGIN_HARD_LOCK_DURATION_MS;
  }
}

// Reset attempts on successful login
function resetLoginAttempts(zone, key) {
  const map = loginAttempts[zone];
  if (!map) return;
  map.delete(key);
}

// Helper to format remaining lock time in minutes
function formatMinutes(ms) {
  return Math.ceil(ms / (60 * 1000));
}

// =========================
// Wave 3: IP rate limiting for logins
// =========================

// Main /login – more generous (browser form)
const mainLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000, // 15 minutes
  max: 30,                  // 30 attempts per IP per 15 minutes
  standardHeaders: true,
  legacyHeaders: false
});

// Staff API login – stricter (called via fetch / XHR)
const staffLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,                  // 20 attempts per IP per 15 minutes
  standardHeaders: true,
  legacyHeaders: false
});

// Customer portal login – quite strict
const portalLoginLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,                  // 20 attempts per IP per 15 minutes
  standardHeaders: true,
  legacyHeaders: false
});

// =========================
// Audit log helper
// =========================
function logAction(req, { action, entityType, entityId = null, details = null }) {
  try {
    let zone = null;
    let userId = null;
    let username = null;
    let role = null;

    if (req.session && req.session.staffUser) {
      zone = 'staff';
      userId = req.session.staffUser.id;
      username = req.session.staffUser.username;
      role = req.session.staffUser.role;
    } else if (req.session && req.session.mainUser) {
      zone = 'main';
      userId = req.session.mainUser.id;
      username = req.session.mainUser.username;
      role = req.session.mainUser.role;
    } else if (req.session && req.session.portalUser) {
      zone = 'portal';
      userId = req.session.portalUser; // CustomerID
      username = 'portal-customer';
      role = 'portal';
    }

    const ip =
      (req.headers['x-forwarded-for'] || '')
        .toString()
        .split(',')[0]
        .trim() ||
      req.ip ||
      null;

    const timestamp = new Date().toISOString();
    const entityIdStr = entityId != null ? String(entityId) : null;
    let detailsStr = null;

    if (details) {
      try {
        detailsStr = JSON.stringify(details);
      } catch (e) {
        detailsStr = String(details);
      }
    }

    customerDB.run(
      `
      INSERT INTO audit_log
        (Timestamp, Zone, UserID, Username, Role, Action, EntityType, EntityID, Details, IP)
      VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
      `,
      [
        timestamp,
        zone,
        userId,
        username,
        role,
        action,
        entityType,
        entityIdStr,
        detailsStr,
        ip,
      ],
      (err) => {
        if (err) {
          console.error('❌ Failed to write audit log:', err);
        }
      }
    );
  } catch (err) {
    console.error('❌ Unexpected error in logAction:', err);
  }
}

// 💳 Referral credit helper
function getReferralCreditForCustomer(customerId) {
  const REWARD_VALUE = 20;  // £20 per successful referral
  const BONUS_VALUE  = 50;  // £50 per 5-referral bonus

  return new Promise((resolve, reject) => {
    // 1) How much has this customer earned?
    customerDB.get(`
      SELECT 
        COALESCE(SUM(CASE WHEN RewardIssued = 1 THEN 1 ELSE 0 END), 0) AS rewards,
        COALESCE(SUM(CASE WHEN BonusIssued  = 1 THEN 1 ELSE 0 END), 0) AS bonuses
      FROM referrals
      WHERE ReferrerID = ?
    `, [customerId], (err, earnRow) => {
      if (err) return reject(err);

      const rewards = earnRow?.rewards || 0;
      const bonuses = earnRow?.bonuses || 0;
      const totalEarned = (rewards * REWARD_VALUE) + (bonuses * BONUS_VALUE);

      // 2) How much of that has already been used on invoices?
      customerDB.get(`
        SELECT COALESCE(SUM(p.AmountPaid), 0) AS used
        FROM payments p
        JOIN invoices i ON p.InvoiceID = i.InvoiceID
        WHERE i.CustomerID = ? AND p.PaymentMethod = 'Referral Credit'
      `, [customerId], (err2, usedRow) => {
        if (err2) return reject(err2);

        const used = usedRow?.used || 0;
        const available = Math.max(totalEarned - used, 0);

        resolve({
          rewards,
          bonuses,
          totalEarned,
          used,
          available
        });
      });
    });
  });
}


// Session middleware
// ======================
// SESSION CONFIGURATION
// ======================

app.disable('x-powered-by');        // remove Express fingerprint
app.set('trust proxy', 1);          // needed behind nginx / proxy

const isProd = process.env.NODE_ENV === 'production';

// 🔒 Security headers via Helmet
app.use(helmet({
  // Your app uses a lot of existing HTML/JS; a strict CSP
  // will almost certainly break things, so we start with CSP off.
  contentSecurityPolicy: false,
  // COEP can also break things with iframes / PDFs / older browsers
  crossOriginEmbedderPolicy: false,
  referrerPolicy: { policy: 'strict-origin-when-cross-origin' }
}));

// Extra HSTS only in production + HTTPS
if (isProd) {
  app.use(
    helmet.hsts({
      maxAge: 31536000,     // 1 year in seconds
      includeSubDomains: true,
      preload: false        // flip to true if/when you submit to hstspreload.org
    })
  );
}


// Main DB / dashboard session
app.use(session({
  name: 'rkl.sid',
  secret: process.env.SESSION_SECRET_MAIN || 'dev_main_secret_change_me',
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax',
    secure: isProd,                 // only HTTPS in production
    maxAge: 1000 * 60 * 60 * 8      // 8 hours
  }
}));

// Customer portal session (only /portal + /api/portal)
app.use(['/portal', '/api/portal'], session({
  name: 'rkl.portal',
  secret: process.env.SESSION_SECRET_PORTAL || 'dev_portal_secret_change_me',
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax',                // can tighten later
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 8
  }
}));

// Staff/Admin session (only /staff + /api/staff)
app.use(['/staff', '/api/staff'], session({
  name: 'rkl.staff',
  secret: process.env.SESSION_SECRET_STAFF || 'dev_staff_secret_change_me',
  resave: false,
  saveUninitialized: false,
  store: new SQLiteStore({ db: 'sessions.sqlite', dir: __dirname }),
  cookie: {
    httpOnly: true,
    sameSite: 'lax',                // could become 'strict' if you like
    secure: isProd,
    maxAge: 1000 * 60 * 60 * 4      // shorter for staff, optional
  }
}));

// Modern CSRF replacement: Action Token pattern
function generateActionToken(req) {
  const token = crypto.randomBytes(32).toString('hex');
  req.session.actionToken = token;
  req.session.actionTokenExpires = Date.now() + 1000 * 60 * 10; // 10 minutes
  return token;
}

function validateActionToken(req, res, next) {
  const clientToken =
    req.headers['x-action-token'] ||          // AJAX / fetch
    (req.body && req.body._actionToken) ||    // HTML forms (POST)
    (req.query && req.query._actionToken);    // fallback (GET/DELETE with query)

  if (!clientToken) {
    return res.status(403).json({ error: 'Missing Action Token' });
  }

  const serverToken = req.session.actionToken;
  const expiry = req.session.actionTokenExpires;

  if (!serverToken || clientToken !== serverToken) {
    return res.status(403).json({ error: 'Invalid Action Token' });
  }

  if (!expiry || Date.now() > expiry) {
    return res.status(403).json({ error: 'Action Token expired' });
  }

  next();
}


app.get('/api/get-action-token', requireAuth, (req, res) => {
  const token = generateActionToken(req);
  res.json({ actionToken: token });
});


// Middleware
app.use(express.json({ limit: '5mb' }));
app.use(express.urlencoded({ extended: true, limit: '5mb' }));
app.use(express.static('public'));
app.use('/uploads', express.static(path.join(__dirname, 'uploads')));


const feedbackRoutes = require('./feedback_routes');

// Wrap feedback/CRM routes so all mutating actions require an Action Token
app.use((req, res, next) => {
  // Only intercept URLs that start with "/feedback"
  if (!req.path.startsWith('/feedback')) {
    return next();
  }

  const method = req.method.toUpperCase();
  const needsToken =
    method === 'POST' ||
    method === 'PUT'  ||
    method === 'PATCH'||
    method === 'DELETE';

  if (!needsToken) {
    // Safe: GET /feedback/:customerId, /feedback/replies/:id, /feedback/invoices/:id, etc.
    return feedbackRoutes(req, res, next);
  }

  // For any mutating request under /feedback*, enforce Action Token
  validateActionToken(req, res, (err) => {
    if (err) return; // validateActionToken already sent a response
    feedbackRoutes(req, res, next);
  });
});


const presetItemsRoutes = require('./preset_items_routes');

// 🔐 Wrap /presets* so all mutating routes require an Action Token
app.use(
  (req, res, next) => {
    // Only intercept /presets and /presets/...
    if (!req.path.startsWith('/presets')) {
      return next();
    }

    const method = req.method.toUpperCase();
    const needsToken =
      method === 'POST' ||
      method === 'PUT'  ||
      method === 'PATCH'||
      method === 'DELETE';

    if (!needsToken) {
      // Safe: GET /presets, etc.
      return presetItemsRoutes(req, res, next);
    }

    // For any mutating request under /presets, enforce Action Token
    validateActionToken(req, res, (err) => {
      if (err) return; // validateActionToken already sent a response
      presetItemsRoutes(req, res, next);
    });
  }
);

const containerRoutes = require('./container_routes');

app.use(
  '/containers',
  (req, res, next) => {
    const method = req.method.toUpperCase();

    const needsToken =
      method === 'POST' ||
      method === 'PUT'  ||
      method === 'PATCH'||
      method === 'DELETE';

    if (!needsToken) {
      // safe: GET /containers/all, /containers/:id, etc.
      return containerRoutes(req, res, next);
    }

    // For any mutating request under /containers, enforce Action Token
    validateActionToken(req, res, (err) => {
      if (err) return; // validateActionToken already sent a response
      containerRoutes(req, res, next);
    });
  }
);


const customerPortalRoutes = require('./customer_portal_routes');
// IP limiter for portal login endpoint specifically
app.use('/portal/login', portalLoginLimiter);
// ✅ One clear prefix for all portal APIs:
app.use('/api/portal', customerPortalRoutes);

const reportsRoutes = require('./reports_routes');
app.use('/api/reports', reportsRoutes);


// Dummy user (for login fallback)
const user = {
  username: 'admin',
  password: 'password123'
};

// Routes

// Serve login page
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// --- START RBAC LOGIN FIX ---
const bcrypt = require('bcryptjs');

// ✅ Unified login for main database (index.html → dashboard → customer.html)
app.post('/login', mainLoginLimiter, (req, res) => {
  const { username, password } = req.body;
  const zone = 'main';
  const key = (username || '').toLowerCase().trim();

  // 1️⃣ Check if this username is currently locked
  const { locked, remainingMs } = isLoginLocked(zone, key);
  if (locked) {
    const mins = formatMinutes(remainingMs);
    return res
      .status(429)
      .send(
        `<h2>Too many attempts</h2>
         <p>Your account is temporarily locked. Please try again in about ${mins} minutes.</p>
         <p>If you believe this is an error, contact an administrator.</p>`
      );
  }

  const sql = `SELECT * FROM staff_users WHERE username = ? LIMIT 1`;
  db.get(sql, [username], async (err, row) => {
    if (err) {
      console.error('Login DB error:', err);
      return res.status(500).send('Internal server error');
    }

    // 2️⃣ No user / no hash → count as failure
    if (!row || !row.PasswordHash) {
      registerLoginFailure(zone, key);
      return res
        .status(401)
        .send('<h2>Login failed</h2><p>Invalid username or password.</p>');
    }

    // 3️⃣ Compare bcrypt hash
    const valid = await bcrypt.compare(password, row.PasswordHash);
    if (!valid) {
      registerLoginFailure(zone, key);
      return res
        .status(401)
        .send('<h2>Login failed</h2><p>Invalid username or password.</p>');
    }

    // 4️⃣ Success → reset attempts
    resetLoginAttempts(zone, key);

    // 🔐 ADD THIS: regenerate session before setting login flags
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error('Session regenerate error (main login):', regenErr);
        return res.status(500).send('Login error, please try again.');
      }

      // ✅ MAIN DB login flags
      req.session.mainUser = {
        id: row.UserID,
        username: row.Username,
        role: row.Role,
      };
      req.session.mainAuthenticated = true;

      // Backwards-compatibility flags
      req.session.user = req.session.mainUser;
      req.session.authenticated = true;

      console.log(`✅ Main DB login by ${row.Username} (${row.Role})`);

      res.redirect('/dashboard');
    });
  });
});




// --- END RBAC LOGIN FIX ---

// Staff login
// NEW: Staff login under staff API (uses rkl.staff cookie)
app.post('/api/staff/login', staffLoginLimiter, validateStaffLogin, async (req, res) => {
  const { username, password } = req.body;
  const zone = 'staff';
  const key = (username || '').toLowerCase().trim();

  // 1️⃣ Check lock
  const { locked, remainingMs } = isLoginLocked(zone, key);
  if (locked) {
    const mins = formatMinutes(remainingMs);
    return res
      .status(429)
      .json({
        error: `Too many attempts. Please try again in about ${mins} minutes or contact an administrator.`
      });
  }

  db.get(`SELECT * FROM staff_users WHERE Username = ?`, [username], async (err, user) => {
    if (err) {
      console.error('Staff login DB error:', err);
      return res.status(500).json({ error: "DB error" });
    }

    if (!user || !user.PasswordHash) {
      registerLoginFailure(zone, key);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    const valid = await bcrypt.compare(password, user.PasswordHash);
    if (!valid) {
      registerLoginFailure(zone, key);
      return res.status(401).json({ error: "Invalid credentials" });
    }

    // 2️⃣ Success → reset attempts
    resetLoginAttempts(zone, key);

    // 🔐 ADD THIS: regenerate session before setting flags
    req.session.regenerate((regenErr) => {
      if (regenErr) {
        console.error('Session regenerate error (staff login):', regenErr);
        return res.status(500).json({ error: 'Login error, please try again.' });
      }

      // ✅ STAFF / ADMIN login flags
      req.session.staffUser = {
        id: user.UserID,
        username: user.Username,
        role: user.Role,
      };
      req.session.staffAuthenticated = true;

      console.log(`✅ Staff/Admin login by ${user.Username} (${user.Role})`);

      res.json({ success: true, role: user.Role });
    });
  });
});




app.get(
  '/staff/login',
  (req, res) => res.sendFile(path.join(__dirname, 'public', 'staff-login.html'))
);

// Staff dashboard – Admin only (using staff flags via requireAdmin)
app.get(
  '/staff/dashboard',
  requireAdmin,
  (req, res) =>
    res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'))
);

// Staff-only route – must be logged in as staff
app.get(
  '/reports/audit',
  requireStaff,
  (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'audit-log.html'));
  }
);

app.get('/staff/manage-staff.html', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'manage-staff.html'));
});

app.get('/staff/admin-dashboard.html', requireAdmin, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'admin-dashboard.html'));
});





// Staff Action Token endpoint – uses staff session + requireStaff
app.get('/api/staff/get-action-token', requireStaff, (req, res) => {
  const token = generateActionToken(req);
  res.json({ actionToken: token });
});


app.get('/session-check', (req, res) => {
  const main = req.session.mainUser;
  const mainAuthed = req.session.mainAuthenticated;
  const staff = req.session.staffUser;
  const staffAuthed = req.session.staffAuthenticated;

  // Normalise role names (support role / Role)
  const mainRole = main && (main.role || main.Role);
  const staffRole = staff && (staff.role || staff.Role);

  // 1️⃣ Prefer any ADMIN, no matter which context
  if (staffAuthed && staff && staffRole === 'Admin') {
    return res.json({
      loggedIn: true,
      role: 'Admin',
      context: 'staff',
    });
  }

  if (mainAuthed && main && mainRole === 'Admin') {
    return res.json({
      loggedIn: true,
      role: 'Admin',
      context: 'main',
    });
  }

  // 2️⃣ Non-admin, main session
  if (mainAuthed && main) {
    return res.json({
      loggedIn: true,
      role: mainRole || 'Staff',
      context: 'main',
    });
  }

  // 3️⃣ Non-admin, staff session
  if (staffAuthed && staff) {
    return res.json({
      loggedIn: true,
      role: staffRole || 'Staff',
      context: 'staff',
    });
  }

  // 4️⃣ Not logged in anywhere
  return res.json({ loggedIn: false });
});




// Get all staff login accounts (Admin only)
app.get('/api/staff-users', requireAdmin, (req, res) => {
  db.all(`SELECT UserID, Username, Role FROM staff_users`, [], (err, rows) => {
    if (err) return res.status(500).json({ error: "DB error" });
    res.json(rows);
  });
});


// Add new staff user (Admin only)
app.post('/api/staff-users', validateStaffCreate, requireAdmin, validateActionToken, (req, res) => {
  const { username, password, role } = req.body;
  bcrypt.hash(password, 10, (err, hash) => {
    if (err) return res.status(500).json({ error: "Hashing failed" });
    db.run(`INSERT INTO staff_users (Username, PasswordHash, Role) VALUES (?, ?, ?)`,
      [username, hash, role],
      function (err) {
        if (err) return res.status(500).json({ error: "Failed to add user" });
        res.json({ success: true, userId: this.lastID });
      });
  });
});

// Delete staff user (Admin only)
app.delete('/api/staff-users/:id', requireAdmin, validateActionToken, (req, res) => {
  db.run(`DELETE FROM staff_users WHERE UserID = ?`, [req.params.id], function (err) {
    if (err) return res.status(500).json({ error: "Failed to delete user" });
    res.json({ success: true });
  });
});

// ✅ Update existing staff member (username, role, optional password)
app.put('/api/staff-users/:id', requireAdmin, validateActionToken, validateStaffUpdate, async (req, res) => {
  const { id } = req.params;
  const { username, role, password } = req.body;

  if (!username || !role) {
    return res.status(400).json({ error: 'Username and role are required' });
  }

  try {
    let sql;
    let params;

    if (password && password.trim() !== '') {
      // If a new password is provided, hash it and update PasswordHash
      const hashed = await bcrypt.hash(password, 10);
      sql = `
        UPDATE staff_users
        SET Username = ?, Role = ?, PasswordHash = ?
        WHERE UserID = ?
      `;
      params = [username, role, hashed, id];
    } else {
      // No password provided: only update Username and Role
      sql = `
        UPDATE staff_users
        SET Username = ?, Role = ?
        WHERE UserID = ?
      `;
      params = [username, role, id];
    }

    db.run(sql, params, function (err) {
      if (err) {
        console.error('❌ Failed to update staff user:', err.message);
        return res.status(500).json({ error: 'Failed to update user' });
      }

      if (this.changes === 0) {
        return res.status(404).json({ error: 'User not found' });
      }

      return res.json({ success: true });
    });
  } catch (err) {
    console.error('❌ Error in staff update handler:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }
});

// =========================
// Audit Log API
// =========================
app.get('/api/audit-log', requireStaff, (req, res) => {
  const {
    limit = 100,
    offset = 0,
    from,
    to,
    user,
    action,
    entityType,
  } = req.query;

  const params = [];
  const where = [];

  if (from) {
    where.push('Timestamp >= ?');
    params.push(from);
  }

  if (to) {
    where.push('Timestamp <= ?');
    params.push(to);
  }

  if (user) {
    where.push('Username = ?');
    params.push(user);
  }

  if (action) {
    where.push('Action = ?');
    params.push(action);
  }

  if (entityType) {
    where.push('EntityType = ?');
    params.push(entityType);
  }

  const whereClause = where.length ? `WHERE ${where.join(' AND ')}` : '';
  const sql = `
    SELECT
      LogID,
      Timestamp,
      Zone,
      UserID,
      Username,
      Role,
      Action,
      EntityType,
      EntityID,
      Details,
      IP
    FROM audit_log
    ${whereClause}
    ORDER BY Timestamp DESC
    LIMIT ? OFFSET ?
  `;

  params.push(Number(limit));
  params.push(Number(offset));

  customerDB.all(sql, params, (err, rows) => {
    if (err) {
      console.error('❌ Error reading audit log:', err);
      return res.status(500).json({ error: 'Failed to load audit log' });
    }

    // Try to parse Details JSON for convenience
    const parsed = rows.map(r => {
      let details = null;
      if (r.Details) {
        try {
          details = JSON.parse(r.Details);
        } catch {
          details = r.Details;
        }
      }
      return { ...r, Details: details };
    });

    res.json(parsed);
  });
});



// Dashboard route
// --- START DASHBOARD GUARD ---
app.get('/dashboard', requireAuth, (req, res) => {
  // Allow both main + staff/admin sessions
  // if (!req.session.user && !req.session.authenticated) {
  //  return res.redirect('/index.html');
  //}
  res.sendFile(path.join(__dirname, 'public', 'customer.html'));
});
// --- END DASHBOARD GUARD ---



// =======================
// LOGOUT ROUTES
// =======================

// Main DB logout (index.html / customer.html etc.)
app.get('/logout', (req, res) => {
  // Only clear MAIN flags
  delete req.session.mainUser;
  delete req.session.mainAuthenticated;

  // (Optional backwards-compatibility clean-up)
  delete req.session.user;
  delete req.session.authenticated;

  req.session.save(err => {
    if (err) console.error('Error saving session on main logout', err);
    return res.redirect('/index.html');
  });
});

// Customer portal logout
app.get('/portal/logout', (req, res) => {
  // Only clear PORTAL flags
  delete req.session.portalUser;
  delete req.session.portalAuthenticated;
  delete req.session.customerId;

  req.session.save(err => {
    if (err) console.error('Error saving session on portal logout', err);
    return res.redirect('/portal-login.html');
  });
});

// Staff/Admin logout
app.get('/staff/logout', (req, res) => {
  // Only clear STAFF flags
  delete req.session.staffUser;
  delete req.session.staffAuthenticated;

  req.session.save(err => {
    if (err) console.error('Error saving session on staff logout', err);
    return res.redirect('/staff-login.html');
  });
});



// ✅ Route: List of Partially Shipped Invoices
app.get('/invoices/partially-shipped', requireAuth, (req, res) => {
  customerDB.all(`
    SELECT 
      i.InvoiceID,
      i.InvoiceNumber,
      i.InvoiceDate,
      i.ReceiverName,
      IFNULL(SUM(ii.TotalCost), 0) AS TotalAmount,
      IFNULL((SELECT SUM(p.AmountPaid) FROM payments p WHERE p.InvoiceID = i.InvoiceID), 0) AS TotalPaid,
      IFNULL(SUM(ii.TotalCost), 0) - IFNULL((SELECT SUM(p.AmountPaid) FROM payments p WHERE p.InvoiceID = i.InvoiceID), 0) AS Balance,
      CASE 
        WHEN IFNULL(SUM(ii.TotalCost), 0) - IFNULL((SELECT SUM(p.AmountPaid) FROM payments p WHERE p.InvoiceID = i.InvoiceID), 0) <= 0 THEN 'Paid'
        WHEN IFNULL((SELECT SUM(p.AmountPaid) FROM payments p WHERE p.InvoiceID = i.InvoiceID), 0) > 0 THEN 'Partial'
        ELSE 'Unpaid'
      END AS PaymentStatus
    FROM invoices i
    JOIN invoice_items ii ON i.InvoiceID = ii.InvoiceID
    JOIN (
      SELECT 
        t.ItemID, 
        MAX(t.Timestamp) AS LatestTimestamp
      FROM tracking t
      GROUP BY t.ItemID
    ) lt ON lt.ItemID = ii.ItemID
    JOIN tracking t2 ON t2.ItemID = lt.ItemID AND t2.Timestamp = lt.LatestTimestamp
    GROUP BY i.InvoiceID
    HAVING 
      SUM(CASE WHEN t2.Stage = 'Shipped' THEN 1 ELSE 0 END) > 0
      AND SUM(CASE WHEN t2.Stage IN ('Picked up', 'Received (London)') THEN 1 ELSE 0 END) > 0
    ORDER BY i.InvoiceID DESC
  `, [], (err, rows) => {
    if (err) {
      console.error('❌ Error in /invoices/partially-shipped:', err);
      res.status(500).json({ error: err.message });
    } else {
      res.json(rows);
    }
  });
});

app.get('/invoices/partially-loaded-items', requireAuth, (req, res) => {
  const invoiceId = req.query.invoiceId;
  if (!invoiceId) return res.status(400).json({ error: 'Missing invoiceId' });

  const sql = `
    SELECT 
      ii.ItemID, ii.ItemName, ii.Quantity, ii.TotalCost, ii.ItemQR
    FROM invoice_items ii
    LEFT JOIN (
      SELECT ItemID, Stage, MAX(Timestamp) as Latest
      FROM tracking
      GROUP BY ItemID
    ) t ON ii.ItemID = t.ItemID
    WHERE ii.InvoiceID = ? AND (t.Stage = 'Picked up' OR t.Stage = 'Received (London)')
  `;

  customerDB.all(sql, [invoiceId], (err, rows) => {
    if (err) {
      console.error('❌ Error fetching partially loaded items:', err);
      return res.status(500).json({ error: 'Failed to load items' });
    }
    res.json(rows);
  });
});

// Customers API route
app.get('/customers', requireAuth, (req, res) => {
    customerDB.all(
    `SELECT CustomerID, [First Name], [Last Name], Company, [Address 1], [Post Code]
     FROM customers
     ORDER BY CustomerID DESC`,
    [],
    (err, rows) => {
      if (err) {
        console.error('❌ Failed to load customers:', err);
        return res.status(500).json({ error: 'Failed to retrieve customers' });
      }
      res.json(rows);
    }
  );
});


//Add customer form route
app.get('/add-customer-form', requireAuth, (req, res) => {
    if (req.session?.user) {
      res.sendFile(path.join(__dirname, 'public', 'add-customer.html'));
    } else {
      res.redirect('/');
    }
  });

  // correct one
  app.post('/add-customer', requireAuth, validateActionToken, validateCustomer, (req, res) => {
  const data = req.body;

  // 🔹 Normalise "Referral code (optional)" field
  // Accepts: "42", "C00042", "F42", "#42" etc. → stores 42
  let referredBy = null;
  if (data.ReferredBy && data.ReferredBy.trim() !== '') {
    const raw = data.ReferredBy.trim();
    const match = raw.match(/(\d+)/); // first run of digits anywhere in the string
    if (match) {
      referredBy = parseInt(match[1], 10);
    }
  }

  customerDB.run(
    `INSERT INTO customers 
    (Company, [First Name], [Last Name], [E-mail Address], [Phone 1], [Address 1], [Post Code], Country, Type, Category, ReferralSource, Notes, ReferredBy)
    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    [
      data.Company,
      data.FirstName,
      data.LastName,
      data.Email,
      data.Phone1,
      data.Address1,
      data.PostCode,
      data.Country,
      data.Type,
      data.Category,
      data.ReferralSource,
      data.Notes || '',
      referredBy    // ✅ use the normalised numeric ID (or null)
    ],
    function (err) {
      if (err) {
        console.error(err);
        return res.send('Failed to add customer');
      }

                // after `if (err) { ... }` and before res.redirect(...)
logAction(req, {
  action: 'CUSTOMER_CREATE',
  entityType: 'Customer',
  entityId: this.lastID,
  details: {
    company: data.Company || null,
    firstName: data.FirstName || null,
    lastName: data.LastName || null,
    category: data.Category || null,
    type: data.Type || null
  }
});

      res.redirect(`/view-customer?id=${this.lastID}`);
    }
  );
});
  
  app.get('/view-customer', requireAuth, (req, res) => {
    if (req.session?.user) {
      res.sendFile(path.join(__dirname, 'public', 'view-customer.html'));
    } else {
      res.redirect('/');
    }
  });
  
  app.get('/customer/:id', requireAuth, (req, res) => {
    const id = req.params.id;
    customerDB.get(`SELECT * FROM customers WHERE CustomerID = ?`, [id], (err, row) => {
      if (err) {
        console.error(err);
        return res.status(500).json({ error: 'Error retrieving customer' });
      }
      res.json(row);
    });
  });
  
  app.post('/customer/:id', requireAuth, validateActionToken, validateCustomer, (req, res) => {
    const id = req.params.id;
    const d = req.body;
  
    customerDB.run(
      `UPDATE customers SET 
        Company = ?, 
        [First Name] = ?, 
        [Last Name] = ?, 
        [E-mail Address] = ?, 
        [Phone 1] = ?, 
        [Phone 2] = ?, 
        [Phone 3] = ?, 
        [Fax Number] = ?, 
        [Address 1] = ?, 
        [Address 2] = ?, 
        [Address 3] = ?, 
        [Post Code] = ?, 
        Country = ?, 
        [Web Page] = ?, 
        Type = ?, 
        Category = ?, 
        Notes = ?
       WHERE CustomerID = ?`,
      [
        d.Company, d.FirstName, d.LastName, d.Email,
        d.Phone1, d.Phone2, d.Phone3, d.FaxNumber,
        d.Address1, d.Address2, d.Address3,
        d.PostCode, d.Country, d.WebPage,
        d.Type, d.Category, d.Notes, id
      ],
      function (err) {
        if (err) {
          console.error(err);
          return res.status(500).send('Failed to update customer');
        }

        logAction(req, {
  action: 'CUSTOMER_UPDATE',
  entityType: 'Customer',
  entityId: id,
  details: {
    company: d.Company || null,
    firstName: d.FirstName || null,
    lastName: d.LastName || null,
    category: d.Category || null,
    type: d.Type || null
  }
});

        res.send('Customer updated');
      }
    );
  });
 
  app.delete('/customer/:id', requireAuth, validateActionToken, (req, res) => {
  const id = req.params.id;
  customerDB.run(`DELETE FROM customers WHERE CustomerID = ?`, [id], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to delete customer' });
    }

    logAction(req, {
      action: 'CUSTOMER_DELETE',
      entityType: 'Customer',
      entityId: id,
      details: null
    });

    console.log("Deleting customer ID:", id);
    res.json({ success: true });
  });
});


//Add bookings form route

app.get('/bookings', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'bookings.html'));
  } else {
    res.redirect('/');
  }
});
  
app.get('/bookings/:customerId', requireAuth, validateCustomerIdParam, (req, res) => {
  const { customerId } = req.params;
  customerDB.all(
    `SELECT * FROM bookings WHERE CustomerID = ? ORDER BY BookingID DESC`,
    [customerId],
    (err, rows) => {
      if (err) return res.status(500).json({ error: 'Failed to retrieve bookings' });
      res.json(rows);
    }
  );
});

app.post('/bookings/:customerId', requireAuth, validateActionToken, validateBookingCreate, (req, res) => {
  const customerId = req.params.customerId;
  const data = req.body;
  const status = data.Status || 'Pending';

  customerDB.run(
    `INSERT INTO bookings 
      (CustomerID, [Afternoon/Evening], [Booking Date], BookingSlot, Notes, Status, InvoiceID, CreatedAt)
     VALUES (?, ?, ?, ?, ?, ?, ?, datetime('now'))`,
    [
      customerId,
      data.AfternoonEvening || '',
      data.BookingDate,
      data.BookingSlot || 1,
      data.Notes,
      status,
      null
    ],
    function (err) {
      if (err) {
        console.error('❌ Booking insert failed:', err.message);
        return res.status(500).send('Failed to save booking');
      }

      logAction(req, {
  action: 'BOOKING_CREATE',
  entityType: 'Booking',
  entityId: this.lastID,
  details: {
    customerId,
    bookingDate: data.BookingDate,
    slot: data.BookingSlot || 1,
    status: status,
    notes: data.Notes || null
  }
});


      // 📧 Lookup customer info
      customerDB.get(
        `SELECT [First Name], [E-mail Address] FROM customers WHERE CustomerID = ?`,
        [customerId],
        (err2, customer) => {
          if (err2 || !customer || !customer["E-mail Address"]) {
            console.log("Booking saved, but no email sent.");
            return res.send('Booking saved (no email)');
          }

          // 📧 Send confirmation email
          const to = customer["E-mail Address"];
          const name = customer["First Name"];
          const subject = "✅ Booking Confirmed – Rockel Shipping";
          const text = `Hi ${name},\n\nYour booking for ${data.BookingDate} has been confirmed.\n\nThank you,\nRockel Shipping`;

          sendMail(to, subject, text).then(() => {
            console.log(`📧 Booking email sent to ${to}`);
            res.send('Booking saved and email sent');
          }).catch(err => {
            console.error('❌ Email error:', err);
            res.send('Booking saved (email failed)');
          });
        }
      );
    }
  );
});

app.put('/bookings/:bookingId/slot', requireAuth, validateActionToken, validateBookingSlotUpdate, (req, res) => {
  const { bookingId } = req.params;
  const { BookingSlot } = req.body;

  if (!BookingSlot) return res.status(400).send('Missing BookingSlot');

  customerDB.run(
    `UPDATE bookings SET BookingSlot = ? WHERE BookingID = ?`,
    [BookingSlot, bookingId],
    function (err) {
      if (err) {
        console.error('❌ Booking slot update failed:', err.message);
        return res.status(500).send('Failed to update booking slot');
      }

      logAction(req, {
  action: 'BOOKING_SLOT_UPDATE',
  entityType: 'Booking',
  entityId: bookingId,
  details: {
    bookingSlot: BookingSlot
  }
});

      res.send('Booking slot updated');
    }
  );
});

app.put('/bookings/:bookingId', requireAuth, validateActionToken, validateBookingUpdate, (req, res) => {
  const { bookingId } = req.params;
  const data = req.body;

  customerDB.run(
    `UPDATE bookings SET 
      [Afternoon/Evening] = ?, 
      [Booking Date] = ?, 
      BookingSlot = ?, 
      Notes = ?, 
      Status = ? 
     WHERE BookingID = ?`,
    [
      data.AfternoonEvening,
      data.BookingDate,
      data.BookingSlot,  // ❌ removed default || 1
      data.Notes,
      data.Status,
      bookingId
    ],
    function (err) {
      if (err) {
        console.error('❌ Booking update failed:', err.message);
        return res.status(500).send('Failed to update booking');
      }

      logAction(req, {
  action: 'BOOKING_UPDATE',
  entityType: 'Booking',
  entityId: bookingId,
  details: {
    bookingDate: data.BookingDate,
    slot: data.BookingSlot,
    status: data.Status,
    notes: data.Notes || null
  }
});

      res.send('Booking updated');
    }
  );
});

app.delete('/bookings/:bookingId', requireAuth, validateActionToken, validateBookingDelete, (req, res) => {
  const { bookingId } = req.params;

  customerDB.run(
    `DELETE FROM bookings WHERE BookingID = ?`,
    [bookingId],
    function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Failed to delete booking');
      }

      logAction(req, {
  action: 'BOOKING_DELETE',
  entityType: 'Booking',
  entityId: bookingId,
  details: null
});

      res.send('Booking deleted');
    }
  );
});

//Job/bookings allocations of staff and vans
app.get('/staff-form', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'staff-form.html')); // Works only if the file is here
});

app.get('/staff-allocation', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'staff-allocation.html'));
});

app.get('/booking-allocation-form', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'booking-allocation-form.html'));
});
// Add others as needed

app.post('/allocate-job', requireAuth, validateActionToken, validateAllocationSingle, (req, res) => {
  const { BookingID, DriverName, Helper1Name, Helper2Name, Van, Notes } = req.body;

  customerDB.run(`
    INSERT INTO job_allocations 
    (BookingID, DriverName, Helper1Name, Helper2Name, Van, Notes) 
    VALUES (?, ?, ?, ?, ?, ?)`,
    [BookingID, DriverName, Helper1Name, Helper2Name, Van, Notes],
    function (err) {
      if (err) {
        console.error('❌ Failed to save allocation:', err.message);
        return res.status(500).send('Failed to save job allocation');
      }

      logAction(req, {
  action: 'JOB_ALLOCATE_SINGLE',
  entityType: 'JobAllocation',
  entityId: BookingID,
  details: { BookingID, DriverName, Helper1Name, Helper2Name, Van, Notes }
});

      res.send('Job allocation saved');
    }
  );
});

app.get('/api/allocations/:bookingId', requireAuth, validateAllocationGet, (req, res) => {
  const bookingId = req.params.bookingId;

  customerDB.get(`SELECT * FROM job_allocations WHERE BookingID = ?`, [bookingId], (err, row) => {
    if (err) {
      console.error('❌ Failed to fetch allocation:', err.message);
      return res.status(500).json({ error: 'Failed to fetch allocation' });
    }
    res.json(row || {});
  });
});

app.post('/add-staff', requireAuth, (req, res) => {
  const { Name, Role, Phone, Status, Notes } = req.body;
  const sql = `
    INSERT INTO staff (Name, Role, Phone, Status, Notes)
    VALUES (?, ?, ?, ?, ?)`;
  customerDB.run(sql, [Name, Role || 'Helper', Phone, Status || 'Active', Notes], function (err) {
    if (err) {
      console.error('❌ Failed to add staff:', err.message);
      return res.status(500).send('Failed to add staff');
    }
    res.send('Staff member added');
  });
});

app.get('/api/staff/all', requireAuth, (req, res) => {
  const query = `SELECT * FROM staff ORDER BY Name`;
  customerDB.all(query, [], (err, rows) => {
    if (err) {
      console.error('❌ Failed to load staff:', err.message);
      return res.status(500).json({ error: 'Failed to fetch staff' });
    }
    res.json(rows);
  });
});

app.post('/staff', requireAuth, requireAdmin, validateActionToken, (req, res) => {
  const { Name, Role, Phone, Notes, Status } = req.body;
  const query = `
    INSERT INTO staff (Name, Role, Phone, Notes, Status)
    VALUES (?, ?, ?, ?, ?)
  `;
  const params = [Name, Role, Phone, Notes, Status];

  customerDB.run(query, params, function (err) {
    if (err) {
      console.error('❌ Failed to add staff:', err.message);
      return res.status(500).json({ error: 'Failed to add staff' });
    }
    res.json({ message: 'Staff added', StaffID: this.lastID });
  });
});

app.put('/staff/:id', requireAuth, requireAdmin, validateActionToken, (req, res) => {
  const { Name, Role, Phone, Notes, Status } = req.body;
  const query = `
    UPDATE staff
    SET Name = ?, Role = ?, Phone = ?, Notes = ?, Status = ?
    WHERE StaffID = ?
  `;
  const params = [Name, Role, Phone, Notes, Status, req.params.id];

  customerDB.run(query, params, function (err) {
    if (err) {
      console.error('❌ Failed to update staff:', err.message);
      return res.status(500).json({ error: 'Failed to update staff' });
    }

    logAction(req, {
  action: 'STAFF_UPDATE',
  entityType: 'Staff',
  entityId: req.params.id,
  details: { Name, Role, Phone, Status }
});

    res.json({ message: 'Staff updated' });
  });
});

app.delete('/staff/:id',
  requireAuth,
  requireAdmin,
  validateActionToken,
  (req, res) => {
    const { id } = req.params;

    const sql = `DELETE FROM staff WHERE StaffID = ?`;
    customerDB.run(sql, [id], function (err) {
      if (err) {
        console.error('❌ Failed to delete staff:', err.message);
        return res.status(500).json({ error: 'Failed to delete staff' });
      }

      logAction(req, {
  action: 'STAFF_DELETE',
  entityType: 'Staff',
  entityId: id,
  details: null
});

      res.json({ message: 'Staff deleted' });
    });
  }
);


app.get('/api/staff', requireAuth, (req, res) => {
  customerDB.all(`SELECT * FROM staff WHERE Status = 'Active' ORDER BY Role, Name`, (err, rows) => {
    if (err) {
      console.error('❌ Failed to fetch staff:', err.message);
      return res.status(500).json({ error: 'Failed to fetch staff' });
    }
    res.json(rows);
  });
});

app.put('/update-staff/:id', requireAuth, (req, res) => {
  const { Name, Role, Phone, Status, Notes } = req.body;
  const { id } = req.params;

  const sql = `
    UPDATE staff SET Name = ?, Role = ?, Phone = ?, Status = ?, Notes = ?
    WHERE StaffID = ?`;
  customerDB.run(sql, [Name, Role, Phone, Status, Notes, id], function (err) {
    if (err) {
      console.error('❌ Failed to update staff:', err.message);
      return res.status(500).send('Failed to update staff');
    }
    res.send('Staff member updated');
  });
});

app.get('/api/bookings-to-allocate', requireAuth, validateBookingsToAllocateQuery, (req, res) => {
  const { date, region, slot } = req.query;

  let sql = `
    SELECT b.*,
       c.[First Name] || ' ' || c.[Last Name] AS CustomerName,
       c.Category,
       c.[Address 1] AS Address1,
       c.[Post Code] AS PostCode,
       c.[Phone 1],
       c.[Phone 2]
    FROM bookings b
    LEFT JOIN customers c ON b.CustomerID = c.CustomerID
    LEFT JOIN job_allocations a ON b.BookingID = a.BookingID
    WHERE 1 = 1
  `;

  const params = [];

  if (date) {
    sql += ` AND b.[Booking Date] = ?`;
    params.push(date);
  }

  if (region) {
    sql += ` AND c.Category = ?`;
    params.push(region);
  }

  if (slot) {
    sql += ` AND b.BookingSlot = ?`;
    params.push(slot);
  }

  sql += ` ORDER BY b.[Booking Date] DESC`;

  

customerDB.all(sql, params, (err, rows) => {
  if (err) {
    console.error('❌ Failed to load filtered bookings:', err.message);
    console.error('SQL Query:', sql);
    console.error('Params:', params);
    return res.status(500).json({ error: err.message });
  }
  res.json(rows);
  });
});


app.post('/allocate-jobs-batch', requireAuth, validateActionToken, validateAllocationBatch, (req, res) => {
  const allocations = req.body;

  if (!Array.isArray(allocations) || allocations.length === 0) {
    return res.status(400).send('No data provided.');
  }

  customerDB.serialize(() => {
    customerDB.run('BEGIN TRANSACTION');
    try {
      allocations.forEach(({ BookingID, DriverName, Helper1Name, Helper2Name, Van, Notes }) => {
        // Delete existing allocation if any
        customerDB.run('DELETE FROM job_allocations WHERE BookingID = ?', [BookingID]);

        // Insert new one
        customerDB.run(`
          INSERT INTO job_allocations (BookingID, DriverName, Helper1Name, Helper2Name, Van, Notes)
          VALUES (?, ?, ?, ?, ?, ?)
        `, [BookingID, DriverName, Helper1Name, Helper2Name, Van, Notes]);
      });
      customerDB.run('COMMIT');

      logAction(req, {
  action: 'JOB_ALLOCATE_BATCH',
  entityType: 'JobAllocation',
  entityId: null,
  details: {
    count: allocations.length,
    bookingIds: allocations.map(a => a.BookingID)
  }
});

      res.send('✅ Allocations saved successfully.');
    } catch (err) {
      customerDB.run('ROLLBACK');
      console.error('❌ Error during allocation batch:', err);
      res.status(500).send('Failed to save allocations.');
    }
  });
});

//Job list bookings route
app.get('/api/bookings/job-list', requireAuth, (req, res) => {
  const query = `
    SELECT b.*, b.[Booking Date] AS BookingDate,
           c.[First Name] AS FirstName,
           c.[Last Name] AS LastName,
           c.Category AS Region,
           c.[Address 1] AS Address1,
           c.[Post Code] AS PostCode,
           c.[Phone 1] AS Phone1,
           c.[Phone 2] AS Phone2,
           c.[Phone 3] AS Phone3,
           a.DriverName, a.Helper1Name, a.Helper2Name, a.Van
    FROM bookings b
    LEFT JOIN customers c ON b.CustomerID = c.CustomerID
    LEFT JOIN job_allocations a ON b.BookingID = a.BookingID
    ORDER BY b.[Booking Date] DESC
  `;

  customerDB.all(query, [], (err, rows) => {
    if (err) {
      console.error('❌ Failed to load job list:', err.message);
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

// Job list page (dashboard view)
app.get('/job-list', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'job-list.html'));
  } else {
    res.redirect('/');
  }
});

// Job list printable/export page
app.get('/job-list-print', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'job-list-print.html'));
  } else {
    res.redirect('/');
  }
});

// Job-list-all routes
app.get('/job-list-all', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'job-list-all.html'));
  } else {
    res.redirect('/');
  }
});

// 🔄 NEW: Return all bookings (not filtered by date)
app.get('/api/bookings/job-list-all', requireAuth, (req, res) => {
  const query = `
    SELECT 
      b.BookingID,
      b.[Booking Date] AS BookingDate,
      b.[Afternoon/Evening],
      b.BookingSlot,
      b.Status,
      b.Notes,
      b.CustomerID,
      c.[First Name] AS FirstName,
      c.[Last Name] AS LastName,
      c.[Phone 1] AS Phone1,
      c.[Phone 2] AS Phone2,
      c.[Phone 3] AS Phone3,
      c.[Address 1] AS Address1,
      c.[Post Code] AS PostCode,
      c.Category AS Region
    FROM bookings b
    JOIN customers c ON c.CustomerID = b.CustomerID
    ORDER BY b.[Booking Date] DESC, c.Category ASC, b.BookingSlot ASC
  `;

  customerDB.all(query, [], (err, rows) => {
    if (err) {
      console.error('❌ Failed to fetch full job list:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.get('/booking-allocation-form', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'booking-allocation-form.html'));
  } else {
    res.redirect('/');
  }
});

// ---- JOB LIST EXPORT (CSV) ----
// Optional filters: ?date=YYYY-MM-DD&region=London
app.get('/job-list-export', requireAuth, (req, res) => {
  const { date, region } = req.query;

  const where = [];
  const params = [];

  if (date) {
    // If your table uses `Booking Date` or `PickupDate`, change below:
    where.push("date(b.[Booking Date]) = date(?)");
    params.push(date);
  }
  if (region) {
    // If your table stores Region on customers or bookings, adjust join/field name:
    where.push("(c.Region = ? OR b.Region = ?)");
    params.push(region, region);
  }

  const sql = `
    SELECT
      b.BookingID,
      c.[First Name] AS FirstName,
      c.[Last Name]  AS LastName,
      c.[Post Code]  AS PostCode,
      b.[Booking Date] AS BookingDate,
      b.[Afternoon/Evening] AS Slot,
      b.Notes,
      b.Status
    FROM bookings b
    LEFT JOIN customers c ON c.CustomerID = b.CustomerID
    ${where.length ? 'WHERE ' + where.join(' AND ') : ''}
    ORDER BY b.[Booking Date] ASC, b.BookingID ASC
  `;

  customerDB.all(sql, params, (err, rows) => {
    if (err) return res.status(500).send('DB error');

    // Build CSV
    const header = [
      'BookingID','FirstName','LastName','PostCode','BookingDate','Slot','Notes','Status'
    ];
    const lines = [header.join(',')];

    (rows || []).forEach(r => {
      const vals = [
        r.BookingID,
        (r.FirstName || '').replace(/,/g, ' '),
        (r.LastName || '').replace(/,/g, ' '),
        (r.PostCode || '').replace(/,/g, ' '),
        r.BookingDate || '',
        r.Slot || '',
        (r.Notes || '').replace(/\r?\n/g,' ').replace(/,/g,' '),
        r.Status || ''
      ];
      lines.push(vals.join(','));
    });

    const csv = lines.join('\n');
    res.setHeader('Content-Type', 'text/csv; charset=utf-8');
    res.setHeader('Content-Disposition', `attachment; filename="job-list${date?'-'+date:''}.csv"`);
    res.send(csv);
  });
});


//Invoices list route
// ✅ GET full list of all invoices with correct totals and status
app.get('/invoices/all', requireAuth, (req, res) => {
  const query = `
    SELECT 
      i.InvoiceID,
      i.InvoiceNumber,
      i.InvoiceDate,
      i.ReceiverName,
      i.CustomerID,
      i.Delivery,
      c.[First Name] || ' ' || c.[Last Name] AS CustomerFullName,
      (SELECT COALESCE(SUM(TotalCost), 0) FROM invoice_items WHERE InvoiceID = i.InvoiceID) AS TotalAmount,
      (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) AS AmountPaid,
      CASE 
        WHEN (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) = 0 THEN 'Unpaid'
        WHEN (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) >= 
             (SELECT COALESCE(SUM(TotalCost), 0) FROM invoice_items WHERE InvoiceID = i.InvoiceID) THEN 'Paid'
        ELSE 'Partial'
      END AS Status
    FROM invoices i
    LEFT JOIN customers c ON c.CustomerID = i.CustomerID
    ORDER BY i.InvoiceID DESC
  `;

  customerDB.all(query, [], (err, rows) => {
    if (err) {
      console.error('Failed to fetch invoice list:', err);
      return res.status(500).json({ error: 'Failed to fetch invoices' });
    }
    res.json(rows);
  });
});

app.get('/invoices-list', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'invoices-list.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/invoices/single/:id', requireAuth, (req, res) => {
  const { id } = req.params;

  const invoiceQuery = `
    SELECT i.*, c.[First Name], c.[Last Name], c.Company AS CustomerCompany, c.[E-mail Address], 
           c.[Phone 1], c.[Phone 2], c.[Phone 3], c.[Address 1], c.[Address 2], c.[Post Code], c.Country
    FROM invoices i
    LEFT JOIN customers c ON i.CustomerID = c.CustomerID
    WHERE i.InvoiceID = ?
  `;

  const companyQuery = `SELECT * FROM company_settings LIMIT 1`;

  customerDB.get(invoiceQuery, [id], (err, invoice) => {
    if (err || !invoice) {
      console.error('❌ Invoice query failed:', err);
      return res.status(500).json({ error: 'Failed to fetch invoice' });
    }

    customerDB.get(companyQuery, [], (err, company) => {
      if (err) {
        console.error('❌ Company query failed:', err);
        return res.status(500).json({ error: 'Failed to fetch company settings' });
      }

      customerDB.all(`SELECT * FROM invoice_items WHERE InvoiceID = ?`, [id], (err, items) => {
        if (err) {
          console.error('❌ Items query failed:', err);
          return res.status(500).json({ error: 'Failed to fetch items' });
        }

        res.json({
          invoice,
          company,
          items
        });
      });
    });
  });
});

app.get('/edit-invoice', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'edit-invoice.html'));
  } else {
    res.redirect('/');
  }
});

app.delete('/invoices/:invoiceId', requireAuth, validateActionToken, (req, res) => {
  const { invoiceId } = req.params;

  customerDB.run(`DELETE FROM invoices WHERE InvoiceID = ?`, [invoiceId], function (err) {
    if (err) {
      console.error('Failed to delete invoice:', err);
      return res.status(500).json({ error: 'Failed to delete invoice' });
    }
    res.json({ success: true });
  });
});

//Add invoices form route

app.get('/invoices', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'invoices.html'));
  } else {
    res.redirect('/');
  }
});

// Get invoices list for a customer with correct totals
// --- 1. GET invoices list for a customer ---
app.get('/invoices/:customerId', requireAuth, (req, res) => {
  const { customerId } = req.params;
  const query = `
    SELECT 
      i.InvoiceID,
      i.InvoiceNumber,
      i.InvoiceDate,
      i.ReceiverName,
      i.CustomerID,
      i.Delivery,
      (SELECT COALESCE(SUM(TotalCost), 0) FROM invoice_items WHERE InvoiceID = i.InvoiceID) AS TotalAmount,
      (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) AS AmountPaid,
      CASE 
        WHEN COALESCE((SELECT SUM(AmountPaid) FROM payments WHERE InvoiceID = i.InvoiceID), 0) = 0 THEN 'Unpaid'
        WHEN COALESCE((SELECT SUM(AmountPaid) FROM payments WHERE InvoiceID = i.InvoiceID), 0) >= 
             COALESCE((SELECT SUM(TotalCost) FROM invoice_items WHERE InvoiceID = i.InvoiceID), 0) THEN 'Paid'
        ELSE 'Partial'
      END AS Status
    FROM invoices i
    WHERE i.CustomerID = ?
    ORDER BY i.InvoiceDate DESC
  `;

  customerDB.all(query, [customerId], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch invoices' });
    res.json(rows);
  });
});

// --- 2. GET single invoice summary (renamed to avoid clash) ---
app.get('/api/invoices/:invoiceId/summary', requireAuth, (req, res) => {
  const { invoiceId } = req.params;
  const query = `
    SELECT 
      i.InvoiceID,
      i.InvoiceNumber,
      i.InvoiceDate,
      i.ReceiverName,
      i.CustomerID,
      c.[First Name],
      c.[Last Name],
      (SELECT COALESCE(SUM(TotalCost), 0) FROM invoice_items WHERE InvoiceID = i.InvoiceID) AS TotalAmount,
      (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) AS AmountPaid
    FROM invoices i
    LEFT JOIN customers c ON c.CustomerID = i.CustomerID
    WHERE i.InvoiceID = ?
  `;

  customerDB.get(query, [invoiceId], (err, invoice) => {
    if (err || !invoice) return res.status(500).json({ error: 'Failed to fetch invoice' });
    const Balance = (invoice.TotalAmount - invoice.AmountPaid).toFixed(2);
    res.json({ invoice: { ...invoice, Balance: parseFloat(Balance) } });
  });
});


// --- 3. GET invoice payments summary + list ---
app.get('/invoice-payments/:invoiceId', requireAuth, (req, res) => {
  const { invoiceId } = req.params;

  const paymentsQuery = `SELECT * FROM payments WHERE InvoiceID = ? ORDER BY PaymentDate DESC`;
  const summaryQuery = `
    SELECT 
      i.CustomerID,
      (SELECT COALESCE(SUM(TotalCost), 0) FROM invoice_items WHERE InvoiceID = i.InvoiceID) AS Subtotal,
      (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) AS TotalPaid
    FROM invoices i
    WHERE i.InvoiceID = ?
  `;

  customerDB.all(paymentsQuery, [invoiceId], (err, payments) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch payments' });

    customerDB.get(summaryQuery, [invoiceId], (err, summary) => {
      if (err) return res.status(500).json({ error: 'Failed to fetch summary' });

      const { Subtotal = 0, TotalPaid = 0, CustomerID = null } = summary || {};
      const Outstanding = (Subtotal - TotalPaid).toFixed(2);

      res.json({
        payments,
        Subtotal: parseFloat(Subtotal),
        TotalPaid: parseFloat(TotalPaid),
        Outstanding: parseFloat(Outstanding),
        customerId: CustomerID
      });
    });
  });
});

// 💳 API: Apply referral credit to an invoice
app.post('/api/invoices/:invoiceId/apply-referral-credit',
  requireAuth,
  validateActionToken,
  async (req, res) => {

  const { invoiceId } = req.params;
  const rawAmount      = req.body.amount;
  const requestedAmount = rawAmount ? parseFloat(rawAmount) : null;

  if (rawAmount && (!Number.isFinite(requestedAmount) || requestedAmount <= 0)) {
    return res.status(400).json({ error: 'Invalid credit amount' });
  }

  try {
    // 1) Load invoice + current totals
    const invoice = await new Promise((resolve, reject) => {
      customerDB.get(`
        SELECT 
          i.InvoiceID,
          i.CustomerID,
          COALESCE((
            SELECT SUM(TotalCost) FROM invoice_items WHERE InvoiceID = i.InvoiceID
          ), 0) AS Subtotal,
          COALESCE((
            SELECT SUM(AmountPaid) FROM payments WHERE InvoiceID = i.InvoiceID
          ), 0) AS TotalPaid
        FROM invoices i
        WHERE i.InvoiceID = ?
      `, [invoiceId], (err, row) => {
        if (err) return reject(err);
        resolve(row);
      });
    });

    if (!invoice) {
      return res.status(404).json({ error: 'Invoice not found' });
    }

    const balance = invoice.Subtotal - invoice.TotalPaid;
    if (balance <= 0) {
      return res.status(400).json({ error: 'Invoice has no outstanding balance' });
    }

    // 2) Get credit for this invoice's customer
    const credit = await getReferralCreditForCustomer(invoice.CustomerID);
    if (credit.available <= 0) {
      return res.status(400).json({ error: 'No referral credit available' });
    }

    // 3) Decide how much to apply
    let amountToApply = requestedAmount || credit.available;
    amountToApply = Math.min(amountToApply, credit.available, balance);

    if (!Number.isFinite(amountToApply) || amountToApply <= 0) {
      return res.status(400).json({ error: 'Nothing to apply' });
    }

    // 4) Insert a payment entry using referral credit
    await new Promise((resolve, reject) => {
      customerDB.run(`
        INSERT INTO payments (InvoiceID, AmountPaid, PaymentDate, PaymentMethod)
        VALUES (?, ?, date('now'), 'Referral Credit')
      `, [invoiceId, amountToApply], function (err) {
        if (err) return reject(err);
        resolve();
      });
    });

    // 5) Audit log
    logAction(req, {
      action: 'REFERRAL_CREDIT_APPLIED',
      entityType: 'Invoice',
      entityId: invoiceId,
      details: {
        amount: amountToApply,
        customerId: invoice.CustomerID
      }
    });

    // 6) Return updated credit + balance
    const updatedCredit = await getReferralCreditForCustomer(invoice.CustomerID);

    const newBalance = balance - amountToApply;

    res.json({
      success: true,
      applied: amountToApply,
      remainingCredit: updatedCredit.available,
      newBalance
    });
  } catch (err) {
    console.error('Failed to apply referral credit:', err);
    res.status(500).json({ error: 'Failed to apply referral credit' });
  }
});


app.post('/invoices/update/:invoiceId', requireAuth, validateActionToken, validateInvoiceUpdate, (req, res) => {
  const { invoiceId } = req.params;
  const d = req.body;

  customerDB.run(`
    UPDATE invoices SET
      InvoiceDate = ?, ReceiverName = ?, Email = ?, Phone1 = ?, Phone2 = ?, Phone3 = ?,
      Address1 = ?, Address2 = ?, PostCode = ?, Country = ?, Notes = ?, Delivery = ?
    WHERE InvoiceID = ?
  `,
  [
    d.InvoiceDate, d.ReceiverName, d.Email, d.Phone1, d.Phone2, d.Phone3,
    d.Address1, d.Address2, d.PostCode, d.Country, d.Notes || '',
    d.Delivery === '1' ? 1 : 0,
    invoiceId
  ],  
  function (err) {
    if (err) {
      console.error('Failed to update invoice:', err);
      return res.status(500).send('Failed to update invoice');
    }

        // 📝 Audit log: invoice updated
    logAction(req, {
      action: 'INVOICE_UPDATE',
      entityType: 'Invoice',
      entityId: invoiceId,
      details: {
        invoiceDate: d.InvoiceDate,
        receiverName: d.ReceiverName || null
      }
    });

    res.json({ success: true });

  });
});

app.post('/invoices/:customerId', requireAuth, validateActionToken, validateInvoiceCreate, (req, res) => {
  const { customerId } = req.params;
  const data = req.body;
  const year = new Date().getFullYear().toString().slice(-2);
  const baseNumber = 10000;

  // Get next invoice number
  customerDB.get(`
    SELECT InvoiceNumber FROM invoices WHERE InvoiceNumber LIKE '%/${year}' ORDER BY InvoiceID DESC LIMIT 1
  `, [], (err, row) => {
    let nextNum = baseNumber;
    if (row && row.InvoiceNumber) {
      const [lastNum] = row.InvoiceNumber.split('/');
      nextNum = parseInt(lastNum) + 1;
    }

    const invoiceNumber = `${nextNum}/${year}`;
    const fields = [
      invoiceNumber, customerId,
      data.InvoiceDate, data.ReceiverName, data.Email,
      data.Phone1, data.Phone2, data.Phone3,
      data.Address1, data.Address2,
      data.PostCode, data.Country,
      data.Notes || '',
      '', // Placeholder for InvoiceQR
      data.Delivery === '1' ? 1 : 0
    ];    

    customerDB.run(`
      INSERT INTO invoices (
        InvoiceNumber, CustomerID, InvoiceDate, ReceiverName, Email,
        Phone1, Phone2, Phone3, Address1, Address2, PostCode, Country,
        Notes, InvoiceQR, Delivery
      ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
    `, fields, function (err) {
      if (err) {
        console.error(err);
        return res.status(500).send('Failed to create invoice');
      }


            const newInvoiceId = this.lastID;

      // 📝 Audit log: invoice created
      logAction(req, {
        action: 'INVOICE_CREATE',
        entityType: 'Invoice',
        entityId: newInvoiceId,
        details: {
          invoiceNumber,
          customerId,
          invoiceDate: data.InvoiceDate,
          receiverName: data.ReceiverName || null
        }
      });

      res.json({
        success: true,
        invoiceId: newInvoiceId,
        invoiceNumber
      });

    });
  });
});

// =======================
// EMAIL INVOICE ROUTE
// =======================
app.post('/email/invoice/:invoiceId', requireAuth, validateActionToken, async (req, res) => {
  const { invoiceId } = req.params;

  try {
    // 1. Fetch invoice + customer
    const invoiceSql = `
    SELECT 
      i.*,
      c.[First Name] || ' ' || c.[Last Name] AS CustomerName,
      c.[Last Name] AS CustomerLastName,
      c.Company AS CustomerCompany,
      c.[Address 1] AS CustomerAddress1,
      c.[Address 2] AS CustomerAddress2,
      c.[Post Code] AS CustomerPostCode,
      c.Country AS CustomerCountry,
      c.[Phone 1] AS CustomerPhone1,
      c.[Phone 2] AS CustomerPhone2,
      c.[Phone 3] AS CustomerPhone3,
      c.[E-mail Address] AS Email
    FROM invoices i
    LEFT JOIN customers c ON i.CustomerID = c.CustomerID
    WHERE i.InvoiceID = ?;
  `;

    const invoice = await new Promise((resolve, reject) => {
      customerDB.get(invoiceSql, [invoiceId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!invoice) return res.status(404).json({ error: 'Invoice not found' });
    if (!invoice.Email) return res.status(400).json({ error: 'No email address on file' });

    // Fetch items
    const items = await new Promise((resolve, reject) => {
      customerDB.all(`SELECT * FROM invoice_items WHERE InvoiceID = ?`, [invoiceId],
        (err, rows) => (err ? reject(err) : resolve(rows)));
    });

    // Fetch payments
    const payments = await new Promise((resolve, reject) => {
      customerDB.all(`SELECT * FROM payments WHERE InvoiceID = ?`, [invoiceId],
        (err, rows) => (err ? reject(err) : resolve(rows)));
    });

    // Fetch company settings (London + Freetown)
    const companySql = `SELECT * FROM company_settings LIMIT 1`;
    const company = await new Promise((resolve, reject) => {
      customerDB.get(companySql, [], (err, row) => (err ? reject(err) : resolve(row)));
    });

    // 2. Totals
    const subtotal = items.reduce((sum, it) => sum + (it.TotalCost || 0), 0);
    const paid = payments.reduce((sum, p) => sum + (p.AmountPaid || 0), 0);
    const balance = subtotal - paid;

    // 3. Create PDF
    const doc = new PDFDocument({ margin: 40 });
    let buffers = [];
    doc.on('data', buffers.push.bind(buffers));
    doc.on('end', async () => {
      const pdfBuffer = Buffer.concat(buffers);

      // 4. Email body
      let body = `
        <p>Dear ${invoice.CustomerName},</p>
        <p>Please find attached your invoice <strong>${invoice.InvoiceNumber}</strong>.</p>
        <p><strong>Total:</strong> £${subtotal.toFixed(2)}<br/>
           <strong>Paid:</strong> £${paid.toFixed(2)}<br/>
           <strong>Balance:</strong> £${balance.toFixed(2)}</p>
      `;

      if (balance > 0) {
        body += `
          <h3>Payment Information</h3>
          <div style="background:#f8f9fa; padding:10px; border-radius:6px;">
            Bank: Rockel Bank Ltd<br/>
            Sort Code: 12-34-56<br/>
            Account: 12345678<br/>
            Reference: ${invoice.InvoiceNumber}
          </div>
          <p>You can also pay online here: 
            <a href="https://rockelshippingcompany.com/portal-pay.html?invoiceId=${invoiceId}">
              Pay Invoice ${invoice.InvoiceNumber}
            </a>
          </p>
        `;
      }

      body += `
        <p>You can view this and all your invoices here:<br/>
          <a href="https://rockelshippingcompany.com/portal-invoices.html?customerId=${invoice.CustomerID}">
            Customer Portal
          </a>
        </p>
      `;

      const subject = balance > 0
        ? `❗ Payment Due – Invoice ${invoice.InvoiceNumber}`
        : `🧾 Invoice ${invoice.InvoiceNumber} – Rockel Shipping`;

      // 5. Send Email
      await sendMail(
        invoice.Email,
        subject,
        '',
        body,
        [{ filename: `Invoice-${invoice.InvoiceNumber}.pdf`, content: pdfBuffer }]
      );

      res.json({ success: true });
    });

    // --- PDF CONTENT ---
    // Company details
    // --- Company (London) Office ---
    doc.fontSize(14).text(company.CompanyName || "Rockel Shipping Company", { align: "left" });
    doc.fontSize(10).text(company.Address || "");
    if (company.PostCode) doc.text(company.PostCode);
    if (company.Country) doc.text(company.Country);
    doc.text(`Tel: ${[company.Phone1, company.Phone2, company.Phone3].filter(Boolean).join(', ')}`);
    if (company.Email) doc.text(`Email: ${company.Email}`);
    if (company.Website) doc.text(company.Website);
    doc.moveDown(1);


    // Freetown Office
    if (company.FreetownAddress) {
      doc.fontSize(12).text("Freetown Office:", { underline: true });
      doc.fontSize(10).text(company.FreetownAddress);
      doc.text(`Tel: ${company.FreetownPhone1 || ''}${company.FreetownPhone2 ? ', ' + company.FreetownPhone2 : ''}`);
      doc.moveDown(2);
    }

    // Invoice header
    doc.fontSize(18).text("INVOICE", { align: "center" });
    doc.moveDown();

    // Invoice + customer details
    doc.fontSize(12).text(`Invoice Number: ${invoice.InvoiceNumber}`);
    doc.text(`Date: ${invoice.InvoiceDate}`);
    doc.text(`Customer: ${invoice.CustomerName}`);
    doc.moveDown();

    // --- Sender (Customer) ---
    doc.moveDown(1);
    doc.fontSize(12).text("Sender (Customer):", { underline: true });
    doc.fontSize(10)
      .text(`Name: ${invoice.CustomerFirstName || ''} ${invoice.CustomerLastName || ''}`)
      .text(`Company: ${invoice.CustomerCompany || ''}`)
      .text(`Address: ${(invoice.CustomerAddress1 || '')} ${(invoice.CustomerAddress2 || '')}`)
      .text(`Post Code: ${invoice.CustomerPostCode || ''}`)
      .text(`Country: ${invoice.CustomerCountry || ''}`)
      .text(`Phone: ${[invoice.CustomerPhone1, invoice.CustomerPhone2, invoice.CustomerPhone3].filter(Boolean).join(', ')}`);

    // --- Receiver ---
    doc.moveDown(1);
    doc.fontSize(12).text("Receiver:", { underline: true });
    doc.fontSize(10)
      .text(`Name: ${invoice.ReceiverName || ''}`)
      .text(`Email: ${invoice.Email || ''}`)
      .text(`Phone: ${[invoice.Phone1, invoice.Phone2, invoice.Phone3].filter(Boolean).join(', ')}`)
      .text(`Address: ${(invoice.Address1 || '')} ${(invoice.Address2 || '')} ${(invoice.PostCode || '')}`)
      .text(`Country: ${invoice.Country || ''}`);


    // Table header
    const tableTop = doc.y;
    doc.fontSize(12).text("Item", 50, tableTop, { width: 180 });
    doc.text("Qty", 240, tableTop, { width: 40, align: "right" });
    doc.text("Unit Cost", 300, tableTop, { width: 80, align: "right" });
    doc.text("Total", 400, tableTop, { width: 100, align: "right" });
    doc.moveTo(50, tableTop + 15).lineTo(520, tableTop + 15).stroke();
    doc.moveDown();

    // Table rows
    items.forEach(it => {
      const qty = it.Quantity || 0;
      const cost = parseFloat(it.UnitCost || 0);
      const total = parseFloat(it.TotalCost || qty * cost);

      const y = doc.y;
      doc.fontSize(10).text(it.ItemName || "", 50, y, { width: 180 });
      doc.text(qty.toString(), 240, y, { width: 40, align: "right" });
      doc.text(`£${cost.toFixed(2)}`, 300, y, { width: 80, align: "right" });
      doc.text(`£${total.toFixed(2)}`, 400, y, { width: 100, align: "right" });

      doc.moveDown();
    });


    // Totals
    doc.moveTo(50, doc.y).lineTo(550, doc.y).stroke();
    doc.fontSize(12).text(`Subtotal: £${subtotal.toFixed(2)}`, 400, doc.y);
    doc.text(`Paid: £${paid.toFixed(2)}`, 400, doc.y + 15);
    doc.font("Helvetica-Bold").text(`Balance: £${balance.toFixed(2)}`, 400, doc.y + 30);
    doc.font("Helvetica");

    // ✅ Bank Details
    doc.moveDown(2);
    doc.fontSize(12).text("Payment Information", { underline: true });
    doc.fontSize(10).text("Account Name: Rockel Shipping Company Limited");
    doc.text("Account Number: 84463236");
    doc.text("Sort Code: 09-01-27");
    doc.text(`Reference: ${invoice.InvoiceNumber} + Surname`);
    doc.moveDown(2);

    // Terms
    if (company.Terms) {
      doc.addPage(); // put terms on a new page if long
      doc.fontSize(12).text("Notes / Terms", { underline: true });
      doc.moveDown(0.5);

      doc.fontSize(8);
      company.Terms.split(/\r?\n/).forEach(line => {
        if (line.trim() === "") {
          doc.moveDown(0.5); // blank line
        } else {
          doc.text(line, { width: 500, align: "left" });
        }
      });
    }

    doc.end();

  } catch (err) {
    console.error('Email send error:', err);
    res.status(500).json({ error: 'Failed to send invoice email' });
  }
});

//Add invoice items route

app.get('/invoice-items', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'invoice-items.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/api/invoice-items-with-tracking/:invoiceId', requireAuth, validateInvoiceIdParam, (req, res) => {
  const { invoiceId } = req.params;

  const query = `
    SELECT 
      ii.*,
      (SELECT Stage FROM tracking 
       WHERE ItemID = ii.ItemID 
       ORDER BY Timestamp DESC LIMIT 1) AS LatestStage
    FROM invoice_items ii
    WHERE ii.InvoiceID = ?
  `;

  customerDB.all(query, [invoiceId], (err, rows) => {
    if (err) {
      console.error('❌ Failed to fetch items with tracking:', err.message);
      return res.status(500).json({ error: 'Failed to load items' });
    }
    res.json(rows);
  });
});

app.get('/invoice-items/:invoiceId', requireAuth, validateInvoiceIdParam, (req, res) => {
  const { invoiceId } = req.params;

  customerDB.all(`
    SELECT * FROM invoice_items WHERE InvoiceID = ?
  `, [invoiceId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to fetch items' });
    }
    res.json(rows);
  });
});

app.post('/invoice-items/:invoiceId', requireAuth, validateActionToken, validateInvoiceIdParam, (req, res) => {
  const { invoiceId } = req.params;
  const d = req.body;
  const total = parseFloat(d.Quantity) * parseFloat(d.UnitCost);

  // Step 1: Insert the item with empty QR for now
  customerDB.run(`
    INSERT INTO invoice_items (
      InvoiceID, ItemName, Description, Quantity, UnitCost, TotalCost, ContainerID, ItemQR
    ) VALUES (?, ?, ?, ?, ?, ?, ?, '')
  `, [invoiceId, d.ItemName, d.Description, d.Quantity, d.UnitCost, total, d.ContainerID || null], function (err) {
    if (err) {
      console.error('❌ Failed to add item:', err);
      return res.status(500).send('Failed to add item');
    }

    const newItemId = this.lastID;
    const itemQR = `${newItemId}`;

    // Step 2: Update the QR code
    customerDB.run(
      `UPDATE invoice_items SET ItemQR = ? WHERE ItemID = ?`,
      [itemQR, newItemId],
      err2 => {
        if (err2) {
          console.error('❌ Failed to update QR:', err2);
          return res.status(500).send('Item added but QR update failed');
        }

        // Step 3: Insert default 'Picked up' tracking
        const now = new Date().toISOString();
        customerDB.run(
          `INSERT INTO tracking (ItemID, Stage, Timestamp, ItemQR, ContainerID, Location, Notes)
           VALUES (?, 'Picked up', ?, ?, NULL, '', '')`,
          [newItemId, now, itemQR],
          err3 => {
            if (err3) {
              console.error('❌ Failed to insert tracking:', err3);
              return res.status(500).send('Item and QR saved, but tracking failed');
            }

            // Step 4: Respond with QR info
            res.json({
              message: 'Item added with QR and picked up status',
              qr: itemQR
            });
          }
        );
      }
    );
  });
});

app.put('/invoice-items/:itemId', requireAuth, validateActionToken, validateInvoiceIdParam, (req, res) => {
  const itemId = req.params.itemId;
  const { ItemName, Description, Quantity, UnitCost } = req.body;
  const TotalCost = parseFloat(UnitCost) * parseInt(Quantity);

  customerDB.run(
    `UPDATE invoice_items SET ItemName = ?, Description = ?, Quantity = ?, UnitCost = ?, TotalCost = ? WHERE ItemID = ?`,
    [ItemName, Description, Quantity, UnitCost, TotalCost, itemId],
    function (err) {
      if (err) {
        console.error('❌ Error updating item:', err);
        return res.status(500).json({ error: 'Update failed' });
      }
      res.json({ message: 'Item updated successfully' });
    }
  );
});

app.delete('/invoice-items/:itemId', requireAuth, validateActionToken, validateInvoiceIdParam, (req, res) => {
  const { itemId } = req.params;

  customerDB.run(`DELETE FROM invoice_items WHERE ItemID = ?`, [itemId], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to delete item' });
    }
    res.json({ success: true });
  });
});

// Generate QR for an invoice
app.get('/qr/invoice/:invoiceId', requireAuth, async (req, res) => {
  const invoiceId = req.params.invoiceId;
  try {
    const qr = await QRCode.toDataURL(`https://yourdomain.com/invoice-detail.html?invoiceId=${invoiceId}`);
    res.type('image/png');
    res.send(Buffer.from(qr.split(',')[1], 'base64'));
  } catch (err) {
    res.status(500).send('QR generation failed');
  }
});

// Generate QR for an item
app.get('/qr/item/:itemId', requireAuth, async (req, res) => {
  const itemId = req.params.itemId;
  try {
    const qr = await QRCode.toDataURL(`https://yourdomain.com/track-item?itemId=${itemId}`);
    res.type('image/png');
    res.send(Buffer.from(qr.split(',')[1], 'base64'));
  } catch (err) {
    res.status(500).send('QR generation failed');
  }
});

app.get('/api/item/:itemId', requireAuth, (req, res) => {
  const itemId = req.params.itemId;

  customerDB.get(`
    SELECT ii.ItemName, ii.ItemQR, i.InvoiceNumber
    FROM invoice_items ii
    LEFT JOIN invoices i ON ii.InvoiceID = i.InvoiceID
    WHERE ii.ItemID = ?
  `, [itemId], (err, row) => {
    if (err) {
      console.error('Failed to fetch item info:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    if (!row) return res.status(404).json({ error: 'Item not found' });

    res.json(row);
  });
});

// Reporting dashboard pages (serve from /public folder)
app.get('/finance-revenue-report', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'finance-revenue-report.html'));
});

app.get('/customer-reports', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'customer-reports.html'));
});

app.get('/staff-reports', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'staff-reports.html'));
});

app.get('/reports/audit', requireStaff, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'audit-log.html'));
});

// Feedback list page (staff/admin)
app.get('/feedback-list', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'feedback-list.html'));
});

app.get('/feedback-dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'feedback-dashboard.html'));
});

app.get('/reporting', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'reporting.html'));
});

app.get('/referrals-ledger', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'referrals-ledger.html'));
});

app.get('/referrals-dashboard', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'referrals-dashboard.html'));
});

app.get('/finance-aged-receivables', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'finance-aged-receivables.html'));
});
app.get('/customer-inactive', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'customer-inactive.html'));
});
app.get('/staff-job-logs', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'staff-job-logs.html'));
});

app.post('/api/invoices/:invoiceId/mark-paid', requireAuth, validateActionToken, (req, res) => {
  const invoiceId = req.params.invoiceId;

  customerDB.get(`
    SELECT c.CustomerID, c.ReferredBy
    FROM invoices i
    JOIN customers c ON i.CustomerID = c.CustomerID
    WHERE i.InvoiceID = ?
  `, [invoiceId], (err, result) => {
    if (err || !result) return res.json({ message: 'Invoice not found' });

    const { CustomerID, ReferredBy } = result;

    if (!ReferredBy || ReferredBy === CustomerID) return res.json({ message: 'No valid referrer' });

    // Check if this is the customer's first fully paid invoice
    customerDB.get(`
      SELECT COUNT(*) AS PaidInvoices
      FROM invoices
      WHERE CustomerID = ? AND InvoiceID IN (
        SELECT InvoiceID FROM invoice_items
        GROUP BY InvoiceID
        HAVING SUM(TotalCost) <= (
          SELECT IFNULL(SUM(AmountPaid), 0)
          FROM payments
          WHERE InvoiceID = invoice_items.InvoiceID
        )
      )
    `, [CustomerID], (err2, row) => {
      if (err2 || row.PaidInvoices !== 1) {
        return res.json({ message: 'Not first paid invoice — no referral' });
      }

      // Record reward for referrer
      customerDB.run(`
        INSERT INTO referrals (
          ReferrerID, ReferredCustomerID, InvoiceID,
          RewardIssued, BonusIssued, CreatedAt
        ) VALUES (?, ?, ?, 1, 0, datetime('now'))
      `, [ReferredBy, CustomerID, invoiceId], (err3) => {
        if (err3) console.error("❌ Failed to reward referrer:", err3);
        else console.log(`✅ Referrer ${ReferredBy} rewarded`);

        // Record reward for referred customer
        customerDB.run(`
          INSERT INTO referrals (
            ReferrerID, ReferredCustomerID, InvoiceID,
            RewardIssued, BonusIssued, CreatedAt
          ) VALUES (?, ?, ?, 1, 0, datetime('now'))
        `, [CustomerID, CustomerID, invoiceId], (err4) => {
          if (err4) console.error("❌ Failed to reward referred customer:", err4);
          else console.log(`✅ Referred customer ${CustomerID} rewarded`);
        });

        // Check if referrer qualifies for bonus
        customerDB.get(`
          SELECT COUNT(*) AS PaidReferrals FROM referrals
          WHERE ReferrerID = ? AND RewardIssued = 1 AND ReferredCustomerID != ReferrerID
        `, [ReferredBy], (err5, countRow) => {
          if (err5 || countRow.PaidReferrals < 5) return;

          customerDB.get(`
            SELECT COUNT(*) AS BonusGiven FROM referrals
            WHERE ReferrerID = ? AND BonusIssued = 1
          `, [ReferredBy], (err6, bonusRow) => {
            if (!err6 && bonusRow.BonusGiven === 0) {
              customerDB.run(`
                INSERT INTO referrals (
                  ReferrerID, ReferredCustomerID, InvoiceID,
                  RewardIssued, BonusIssued, CreatedAt
                ) VALUES (?, NULL, NULL, 0, 1, datetime('now'))
              `, [ReferredBy], (bonusErr) => {
                if (!bonusErr) console.log(`🎉 £50 bonus issued to ReferrerID ${ReferredBy}`);
              });
            }
          });
        });

        logAction(req, {
  action: 'REFERRAL_MARK_PAID',
  entityType: 'Invoice',
  entityId: invoiceId,
  details: {
    customerId: CustomerID,
    referredBy: ReferredBy
  }
});


        res.json({ message: 'Referral rewards issued' });
      });
    });
  });
});

app.get('/api/customers/:customerId/referral-summary', requireAuth, (req, res) => {
  const id = req.params.customerId;

  customerDB.get(`
    SELECT COUNT(*) AS totalReferrals FROM referrals
    WHERE ReferrerID = ? AND RewardIssued = 1
  `, [id], (err, row) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch referral data' });

    customerDB.get(`
      SELECT COUNT(*) AS bonusIssued FROM referrals
      WHERE ReferrerID = ? AND BonusIssued = 1
    `, [id], (err2, row2) => {
      if (err2) return res.json({ totalReferrals: row.totalReferrals, bonusIssued: false });
      res.json({ totalReferrals: row.totalReferrals, bonusIssued: row2.bonusIssued > 0 });
    });
  });
});

// 💳 API: Get referral credit balance for a customer
app.get('/api/customers/:customerId/referral-credit', requireAuth, async (req, res) => {
  const { customerId } = req.params;

  try {
    const credit = await getReferralCreditForCustomer(customerId);
    res.json(credit);
  } catch (err) {
    console.error('Failed to calculate referral credit:', err);
    res.status(500).json({ error: 'Failed to calculate referral credit' });
  }
});



app.get('/api/referrals/summary', requireAuth, (req, res) => {
  const { start, end, region } = req.query;
  const params = [];

  let whereClause = `1 = 1`;

  if (start) {
    whereClause += ` AND r.CreatedAt >= ?`;
    params.push(start + ' 00:00:00');
  }
  if (end) {
    whereClause += ` AND r.CreatedAt <= ?`;
    params.push(end + ' 23:59:59');
  }
  if (region) {
    whereClause += ` AND c.Category = ?`;
    params.push(region);
  }

  const query = `
    SELECT
      r.ReferrerID,
      cu.[First Name] || ' ' || cu.[Last Name] AS Name,
      cu.Category,
      SUM(CASE WHEN r.RewardIssued = 1 THEN 1 ELSE 0 END) AS TotalReferrals,
      MAX(CASE WHEN r.BonusIssued = 1 THEN 1 ELSE 0 END) AS BonusGiven
    FROM referrals r
    JOIN customers cu ON cu.CustomerID = r.ReferrerID
    LEFT JOIN customers c ON r.ReferredCustomerID = c.CustomerID
    WHERE ${whereClause}
    GROUP BY r.ReferrerID
    ORDER BY TotalReferrals DESC
  `;

  customerDB.all(query, params, (err, rows) => {
    if (err) {
      console.error('❌ Failed to load referral dashboard:', err);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.get('/api/customers/:customerId/referral-history', requireAuth, (req, res) => {
  const { customerId } = req.params;

  customerDB.all(`
    SELECT r.*, 
      referred.[First Name] || ' ' || referred.[Last Name] AS ReferredName,
      referrer.[First Name] || ' ' || referrer.[Last Name] AS ReferrerName
    FROM referrals r
    LEFT JOIN customers referred ON r.ReferredCustomerID = referred.CustomerID
    LEFT JOIN customers referrer ON r.ReferrerID = referrer.CustomerID
    WHERE r.ReferrerID = ? OR r.ReferredCustomerID = ?
    ORDER BY r.CreatedAt DESC
  `, [customerId, customerId], (err, rows) => {
    if (err) {
      console.error("❌ Failed to load referral history:", err);
      return res.status(500).json({ error: 'Failed to load referral history' });
    }
    res.json(rows);
  });
});

app.get('/api/invoice/:invoiceId/referral-reward', requireAuth, (req, res) => {
  const { invoiceId } = req.params;
  customerDB.get(`
    SELECT r.*, 
      referred.[First Name] || ' ' || referred.[Last Name] AS ReferredName,
      referrer.[First Name] || ' ' || referrer.[Last Name] AS ReferrerName
    FROM referrals r
    LEFT JOIN customers referred ON r.ReferredCustomerID = referred.CustomerID
    LEFT JOIN customers referrer ON r.ReferrerID = referrer.CustomerID
    WHERE r.InvoiceID = ?
  `, [invoiceId], (err, row) => {
    if (err || !row) return res.json(null);
    res.json(row);
  });
});

app.get('/api/referrals/ledger', requireAuth, (req, res) => {
  customerDB.all(`
    SELECT 
      r.CreatedAt,
      COALESCE(referred.[First Name] || ' ' || referred.[Last Name], '—') AS CustomerName,
      CASE
        WHEN r.BonusIssued = 1 THEN 'Bonus'
        WHEN r.RewardIssued = 1 AND r.ReferredCustomerID IS NOT NULL THEN 'Referral Reward'
        WHEN r.RewardIssued = 1 AND r.ReferredCustomerID IS NULL THEN 'Welcome Reward'
        ELSE '—'
      END AS Type,
      r.InvoiceID,
      CASE 
        WHEN r.BonusIssued = 1 THEN 50
        ELSE 20
      END AS Amount,
      '✅ Issued' AS Status
    FROM referrals r
    LEFT JOIN customers referred ON r.ReferrerID = referred.CustomerID
    ORDER BY r.CreatedAt DESC
  `, (err, rows) => {
    if (err) {
      console.error("❌ Failed to load referral ledger:", err);
      return res.status(500).json({ error: 'Failed to load ledger' });
    }
    res.json(rows);
  });
});

//QR scan routes
app.get('/status-selection', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'status-selection.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/scan-status', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'scan-status.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/scan-batch', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'scan-batch.html'));
  } else {
    res.redirect('/');
  }
});

//Add invoice items route

app.get('/invoice-payments', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'invoice-payments.html'));
  } else {
    res.redirect('/');
  }
});

// Get payments AND live invoice summary


app.post('/invoice-payments/:invoiceId', requireAuth, validateActionToken, validateInvoicePayment, (req, res) => {
  const invoiceId = req.params.invoiceId;
  const d = req.body;

  customerDB.run(`
    INSERT INTO payments (InvoiceID, AmountPaid, PaymentDate, PaymentMethod)
    VALUES (?, ?, ?, ?)
  `, [invoiceId, d.AmountPaid, d.PaymentDate, d.PaymentMethod], async function (err) {
    if (err) {
      console.error(err);
      return res.status(500).send('Failed to add payment');
    }

        const paymentId = this.lastID;

    // 📝 Audit log: payment added
    logAction(req, {
      action: 'PAYMENT_ADD',
      entityType: 'Payment',
      entityId: paymentId,
      details: {
        invoiceId,
        amount: d.AmountPaid,
        paymentDate: d.PaymentDate,
        method: d.PaymentMethod
      }
    });


    try {
      // 1️⃣ Get invoice + customer info
      const invoice = await new Promise((resolve, reject) => {
        customerDB.get(`
          SELECT i.*, 
                 c.[First Name], c.[E-mail Address]
          FROM invoices i
          LEFT JOIN customers c ON c.CustomerID = i.CustomerID
          WHERE i.InvoiceID = ?
        `, [invoiceId], (err, row) => err ? reject(err) : resolve(row));
      });

      if (!invoice || !invoice["E-mail Address"]) {
        console.log('Payment recorded but no email sent (no email address).');
        return res.send('Payment added (no email)');
      }

      // 2️⃣ Get items and all payments
      const items = await new Promise((resolve, reject) => {
        customerDB.all(
          `SELECT ItemName, Description, Quantity, UnitCost, TotalCost 
           FROM invoice_items WHERE InvoiceID = ?`,
          [invoiceId],
          (err, rows) => err ? reject(err) : resolve(rows)
        );
      });

      const payments = await new Promise((resolve, reject) => {
        customerDB.all(
          `SELECT AmountPaid FROM payments WHERE InvoiceID = ?`,
          [invoiceId],
          (err, rows) => err ? reject(err) : resolve(rows)
        );
      });

      const subtotal = items.reduce((sum, i) => sum + (i.TotalCost || 0), 0);
      const paid = payments.reduce((sum, p) => sum + parseFloat(p.AmountPaid || 0), 0);
      const balance = subtotal - paid;

      const itemRows = items.map(i => `
        <tr>
          <td>${i.ItemName}</td>
          <td>${i.Description || ''}</td>
          <td>${i.Quantity}</td>
          <td>£${Number(i.UnitCost || 0).toFixed(2)}</td>
          <td>£${Number(i.TotalCost || 0).toFixed(2)}</td>
        </tr>`).join('');

      const logoBase64 = fs.readFileSync(
        path.join(__dirname, 'public/images/rkllogo.png')
      ).toString('base64');

      const html = `
        <div style="font-family: Arial; max-width: 800px; margin: auto;">
          <div style="display: flex; justify-content: space-between; align-items: center;">
            <img src="data:image/png;base64,${logoBase64}" alt="Rockel Logo"
                 style="height: 45px; width: auto; max-width: 200px;" />
            <div style="text-align: right; font-size: 14px;">
              <strong>Rockel Shipping Company</strong><br/>
              14 Jones Street, Freetown<br/>
              📞 +232 76 123 456 / +232 99 123 456<br/>
              🌐 www.RockelShippingCompany.com
            </div>
          </div>
          <hr style="margin: 20px 0;" />
          <h2>Invoice #${invoice.InvoiceNumber}</h2>
          <p>Date: ${invoice.InvoiceDate}</p>
          <p>Hi ${invoice["First Name"]},</p>
          <p>We’ve received a payment of £${Number(d.AmountPaid).toFixed(2)} 
             for your invoice. Here's the updated breakdown:</p>
          <table border="1" cellpadding="6" cellspacing="0"
                 style="border-collapse: collapse; width: 100%;">
            <thead>
              <tr>
                <th>Item</th><th>Description</th><th>Qty</th><th>Unit</th><th>Total</th>
              </tr>
            </thead>
            <tbody>${itemRows}</tbody>
            <tfoot>
              <tr>
                <td colspan="4"><strong>Subtotal</strong></td>
                <td>£${subtotal.toFixed(2)}</td>
              </tr>
              <tr>
                <td colspan="4"><strong>Total Paid</strong></td>
                <td>£${paid.toFixed(2)}</td>
              </tr>
              <tr>
                <td colspan="4"><strong>Balance</strong></td>
                <td>£${balance.toFixed(2)}</td>
              </tr>
            </tfoot>
          </table>
          <p style="margin-top: 20px;">Thank you for your business!</p>
        </div>
      `;

      await sendMail(
        invoice["E-mail Address"],
        `✅ Payment Received – Invoice ${invoice.InvoiceNumber}`,
        '',
        html
      );

      return res.send('Payment added and email sent');
    } catch (error) {
      console.error("❌ Payment email error:", error);
      // Don’t block the UI if email fails – payment is already saved
      return res.send('Payment added (email error)');
    }
  });
});

app.delete('/invoice-payments/:paymentId', requireAuth, validateActionToken, (req, res) => {
  const { paymentId } = req.params;

  customerDB.run(`DELETE FROM payments WHERE PaymentID = ?`, [paymentId], function (err) {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to delete payment' });
    }
    res.json({ success: true });
  });
});

// Serve preset-items.html
app.get('/preset-items', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'preset-items.html'));
  } else {
    res.redirect('/');
}
});

//Invoices tracking summary routes
app.get('/invoices/tracking-summary/:invoiceId', requireAuth, (req, res) => {
  const invoiceId = req.params.invoiceId;

  const query = `
    SELECT t.Stage
    FROM invoice_items i
    LEFT JOIN (
      SELECT ItemID, MAX(Timestamp) as MaxTime
      FROM tracking
      GROUP BY ItemID
    ) latest ON latest.ItemID = i.ItemID
    LEFT JOIN tracking t ON t.ItemID = i.ItemID AND t.Timestamp = latest.MaxTime
    WHERE i.InvoiceID = ?
  `;

  customerDB.all(query, [invoiceId], (err, rows) => {
    if (err) {
      console.error("❌ Tracking summary error:", err.message);
      return res.status(500).send('Failed to fetch tracking status');
    }

    const stages = rows.map(r => r.Stage).filter(Boolean);

    const summary = summarizeTrackingStatus(stages);
    res.json({ summary });
  });

  function summarizeTrackingStatus(stages) {
    const inLondon = ['Picked up', 'Received (London)'];
    const receivedFT = ['Collected (Customer)', 'Delivered'];

    if (stages.length === 0) return 'No Data';
    if (stages.every(s => inLondon.includes(s))) return 'In London';
    if (stages.every(s => s === 'Shipped')) return 'Shipped';
    if (stages.some(s => s === 'Shipped') && stages.some(s => inLondon.includes(s)))
      return 'Partially Shipped';
    if (stages.every(s => s === 'Arrived (Freetown)')) return 'Arrived';
    if (stages.every(s => receivedFT.includes(s))) return 'Received FT';
    return 'Mixed';
  }
});

//Debug left behind list route
// ✅ TEMP DEBUG: Invoices with at least one Picked up item
app.get('/debug/invoices-pickedup', requireAuth, (req, res) => {
  const query = `
    SELECT DISTINCT i.InvoiceID, i.InvoiceNumber
    FROM invoices i
    JOIN invoice_items ii ON i.InvoiceID = ii.InvoiceID
    JOIN tracking t ON ii.ItemID = t.ItemID
    WHERE t.Stage = 'Picked up'
    ORDER BY i.InvoiceID DESC;
  `;

  customerDB.all(query, [], (err, rows) => {
    if (err) {
      console.error('SQL Error:', err.message);
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/debug/invoices-unshipped', requireAuth, (req, res) => {
  customerDB.all(`
    SELECT DISTINCT i.InvoiceID, i.InvoiceNumber
    FROM invoices i
    JOIN invoice_items ii ON ii.InvoiceID = i.InvoiceID
    JOIN tracking t ON t.ItemID = ii.ItemID
    WHERE t.Stage IN ('Picked up', 'Received (London)')
    ORDER BY i.InvoiceID DESC
  `, (err, rows) => {
    if (err) {
      console.error("Error fetching unshipped invoices:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

app.get('/debug/invoices-shipped', requireAuth, (req, res) => {
  customerDB.all(`
    SELECT DISTINCT i.InvoiceID, i.InvoiceNumber
    FROM invoices i
    JOIN invoice_items ii ON ii.InvoiceID = i.InvoiceID
    JOIN tracking t ON t.ItemID = ii.ItemID
    WHERE t.Stage IN ('Shipped', 'Arrived (Freetown)', 'Collected (Customer)', 'Delivered')
    ORDER BY i.InvoiceID DESC
  `, (err, rows) => {
    if (err) {
      console.error("Error fetching shipped invoices:", err);
      return res.status(500).json({ error: err.message });
    }
    res.json(rows);
  });
});

//partially shipped routes



// ✅ Route: List of Partially Shipped Invoices



//Add container invoice list route
app.get('/container-invoice-list', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'container-invoice-list.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/container-invoice-list-print', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'container-invoice-list-print.html'));
  } else {
    res.redirect('/');
  }
});


app.get('/api/container/:containerId/invoices', requireAuth, (req, res) => {
  const { containerId } = req.params;

  const query = `
    SELECT i.*, 
           c.[First Name] || ' ' || c.[Last Name] AS CustomerName,
           c.[Phone 1] || ', ' || c.[Phone 2] || ', ' || c.[Phone 3] AS CustomerPhones,
           (SELECT COALESCE(SUM(TotalCost), 0) FROM invoice_items WHERE InvoiceID = i.InvoiceID) AS TotalAmount,
           (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) AS AmountPaid
    FROM invoices i
    LEFT JOIN customers c ON c.CustomerID = i.CustomerID
    WHERE EXISTS (
      SELECT 1 FROM invoice_items it WHERE it.InvoiceID = i.InvoiceID AND it.ContainerID = ?
    )
  `;

  customerDB.all(query, [containerId], async (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch invoices' });

    const results = await Promise.all(rows.map(async inv => {
      const items = await new Promise((resolve, reject) => {
        customerDB.all(
          `SELECT ItemName, Quantity, UnitCost FROM invoice_items WHERE InvoiceID = ? AND ContainerID = ?`,
          [inv.InvoiceID, containerId],
          (err, items) => err ? reject(err) : resolve(items)
        );
      });

      const totalItemCount = await new Promise((resolve, reject) => {
        customerDB.get(
          `SELECT COUNT(*) AS count FROM invoice_items WHERE InvoiceID = ?`,
          [inv.InvoiceID],
          (err, row) => err ? reject(err) : resolve(row.count)
        );
      });

      return {
        InvoiceID: inv.InvoiceID,
        InvoiceNumber: inv.InvoiceNumber,
        CustomerName: inv.CustomerName,
        CustomerPhones: inv.CustomerPhones,
        ReceiverName: inv.ReceiverName,
        ReceiverPhones: [inv.Phone1, inv.Phone2, inv.Phone3].filter(Boolean).join(', '),
        Address1: inv.Address1,
        Address2: inv.Address2,
        PostCode: inv.PostCode,
        Country: inv.Country,
        Notes: inv.Notes,
        TotalAmount: parseFloat(inv.TotalAmount),
        Outstanding: Math.max(0, parseFloat(inv.TotalAmount) - parseFloat(inv.AmountPaid || 0)),
        Status: (parseFloat(inv.AmountPaid) >= parseFloat(inv.TotalAmount)) ? 'Paid' :
                (parseFloat(inv.AmountPaid) > 0) ? 'Partial' : 'Unpaid',
        Items: items,
        AllItemsOnContainer: totalItemCount === items.length
      };
    }));

    res.json(results);
  });
});

// Add tracking routes
const trackingRoutes = require('./tracking_routes');
app.use(trackingRoutes);





app.get('/track-item', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'track-item.html'));
  } else {
    res.redirect('/');
  }
});

app.put('/track-item/update/:trackingId', requireAuth, validateActionToken, validateTrackingIdParam, validateTrackingUpdate, upload.single('Image'), (req, res) => {
  const trackingId = req.params.trackingId;
  const { Stage, Timestamp, Notes, ContainerID, SignatureData, Location } = req.body;

  const fields = [
    "Stage = ?",
    "Timestamp = ?",
    "Notes = ?",
    "ContainerID = ?",
    "Location = ?"
  ];
  const params = [
    Stage,
    Timestamp,
    Notes,
    ContainerID || null,
    Location || null
  ];

  // Handle image file upload
  if (req.file && req.file.filename) {
    fields.push("Image = ?");
    params.push(req.file.filename);
  }

  // Handle signature image from base64
  if (SignatureData && SignatureData.startsWith('data:image')) {
    const base64Data = SignatureData.replace(/^data:image\/\w+;base64,/, '');
    const signatureFilename = `signature-${Date.now()}.png`;
    const filePath = path.join(__dirname, 'uploads', signatureFilename);
    try {
      fs.writeFileSync(filePath, base64Data, 'base64');
      fields.push("Signature = ?");
      params.push(signatureFilename);
    } catch (err) {
      console.error("Error saving signature image:", err);
      return res.status(500).json({ error: 'Failed to save signature image' });
    }
  }

  fields.push("UpdatedAt = CURRENT_TIMESTAMP");
  params.push(trackingId);

  const query = `UPDATE tracking SET ${fields.join(', ')} WHERE TrackingID = ?`;

  customerDB.run(query, params, function (err) {
    if (err) {
      console.error("❌ Failed to update tracking:", err.message);
      return res.status(500).json({ error: 'Failed to update tracking' });
    }

    logAction(req, {
  action: 'TRACKING_UPDATE',
  entityType: 'Tracking',
  entityId: trackingId,
  details: {
    stage: Stage,
    timestamp: Timestamp,
    containerId: ContainerID || null,
    location: Location || null
  }
});

    res.json({ message: 'Tracking updated successfully' });
  });
});

// --- STEP 3: Optional - View Tracking History ---
app.get('/track-history/:itemId', requireAuth, validateItemIdParam, (req, res) => {
  const { itemId } = req.params;
  customerDB.all(`
    SELECT * FROM tracking WHERE ItemID = ? ORDER BY Timestamp DESC
  `, [itemId], (err, rows) => {
    if (err) {
      console.error('Failed to fetch tracking history:', err);
      return res.status(500).json({ error: 'Failed to load tracking history' });
    }
    res.json(rows);
  });
});

// In server.js or tracking_routes.js (if using modular structure)

// Fetch containers eligible for shipment (not yet arrived in Freetown)
app.get('/eligible-containers', requireAuth, (req, res) => {
  customerDB.all(`
    SELECT ContainerID, ContainerNumber 
    FROM containers 
    WHERE Status != 'Arrived' 
    ORDER BY ContainerID DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch containers' });
    res.json(rows);
  });
});

// Fetch all containers
app.get('/all-containers', requireAuth, (req, res) => {
  customerDB.all(`
    SELECT ContainerID, ContainerNumber 
    FROM containers 
    ORDER BY ContainerID DESC
  `, [], (err, rows) => {
    if (err) return res.status(500).json({ error: 'Failed to fetch all containers' });
    res.json(rows);
  });
});

// Submit tracking data

app.get('/track-item/history/:itemId', requireAuth, (req, res) => {
  const { itemId } = req.params;
  const query = `
    SELECT t.*, t.ContainerID, c.ContainerNumber 
    FROM tracking t
    LEFT JOIN containers c ON t.Stage = 'Shipped' AND c.ContainerID = t.ContainerID
    WHERE t.ItemID = ?
    ORDER BY t.Timestamp DESC
  `;

  customerDB.all(query, [itemId], (err, rows) => {
    if (err) {
      console.error(err);
      return res.status(500).json({ error: 'Failed to load tracking history' });
    }
    res.json(rows);
  });
});

app.post('/track-item/:itemId', requireAuth, validateActionToken, validateItemIdParam, validateTrackingCreate, upload.single('Image'), (req, res) => {
    const itemId = req.params.itemId;
    const d = req.body;
    const imagePath = req.file ? req.file.filename : null;
  
    let signatureFileName = null;
  
    if (d.SignatureData && d.SignatureData.startsWith('data:image')) {
      const base64Data = d.SignatureData.replace(/^data:image\/png;base64,/, '');
      signatureFileName = `signature-${Date.now()}.png`;
      fs.writeFileSync(path.join(__dirname, 'uploads', signatureFileName), base64Data, 'base64');
    }
  
    customerDB.run(
      `INSERT INTO tracking (ItemID, ItemQR, Stage, Timestamp, Location, Notes, Image, ContainerID, Signature)
       VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      [
        itemId,
        d.ItemQR || '',
        d.Stage || '',
        d.Timestamp || new Date().toISOString(),
        d.Location || '',
        d.Notes || '',
        imagePath,
        d.Stage === 'Shipped' ? d.ContainerID : null,
        signatureFileName
      ],
      function (err) {
        if (err) {
          console.error('Failed to insert tracking:', err);
          return res.status(500).send('Failed to add tracking info');
        }
    
        // ✅ Add this block below:
        if (d.Stage === 'Shipped' && d.ContainerID) {
          customerDB.run(
            `UPDATE invoice_items SET ContainerID = ? WHERE ItemID = ?`,
            [d.ContainerID, itemId],
            err => {
              if (err) {
                console.error('Failed to update invoice_items.ContainerID:', err);
              } else {
                console.log(`Linked Item ${itemId} to Container ${d.ContainerID}`);
              }
            }
          );
        }

        logAction(req, {
  action: 'TRACKING_ADD',
  entityType: 'Tracking',
  entityId: this.lastID, // inside the DB.run callback
  details: {
    itemId,
    stage: d.Stage,
    containerId: d.Stage === 'Shipped' ? d.ContainerID || null : null
  }
});
    
        res.send('Tracking added');
      }
    );    
  });


app.get('/track-item/meta/:itemId', requireAuth, validateItemIdParam, (req, res) => {
  const { itemId } = req.params;
  customerDB.get(`SELECT InvoiceID FROM invoice_items WHERE ItemID = ?`, [itemId], (err, row) => {
    if (err || !row) return res.status(404).json({ error: 'Not found' });
    res.json(row);
  });
});

app.delete('/track-item/:id', requireAuth, validateActionToken, validateTrackingIdDelete, (req, res) => {
  const trackingId = req.params.id;
  customerDB.run(`DELETE FROM tracking WHERE TrackingID = ?`, [trackingId], function (err) {
    if (err) {
      console.error('Failed to delete tracking entry:', err);
      return res.status(500).send('Error deleting tracking entry');
    }

    logAction(req, {
  action: 'TRACKING_DELETE',
  entityType: 'Tracking',
  entityId: trackingId,
  details: null
});

    res.sendStatus(200);
  });
});

// Get company settings
app.get('/company-settings', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'company-settings.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/api/company-settings', requireAuth, (req, res) => {
  customerDB.get(`SELECT * FROM company_settings WHERE id = 1`, [], (err, row) => {
    if (err) {
      console.error('Fetch error:', err);
      return res.status(500).json({ error: 'Failed to fetch company settings' });
    }
    res.json(row || {});
  });
});


// Save/update company settings
app.post('/api/company-settings', requireAuth, validateActionToken, (req, res) => {
  const d = req.body;

  const fields = [
    d.CompanyName, d.Address, d.PostCode, d.Country,
    d.Phone1, d.Phone2, d.Phone3, d.Email, d.Website,
    d.FreetownAddress, d.FreetownPhone1, d.FreetownPhone2, d.Terms
  ];

  // Ensure one row exists
  const ensureRowSql = `INSERT OR IGNORE INTO company_settings (id, CompanyName) VALUES (1, '')`;
  customerDB.run(ensureRowSql, [], (err) => {
    if (err) {
      console.error('Failed to ensure row:', err);
      return res.status(500).json({ error: 'Failed to ensure settings row' });
    }

    // Always update row id=1
    const updateSql = `
      UPDATE company_settings SET
        CompanyName = ?, Address = ?, PostCode = ?, Country = ?,
        Phone1 = ?, Phone2 = ?, Phone3 = ?, Email = ?, Website = ?,
        FreetownAddress = ?, FreetownPhone1 = ?, FreetownPhone2 = ?, Terms = ?
      WHERE id = 1
    `;


    customerDB.run(updateSql, fields, function (err2) {
      if (err2) {
        console.error('Update error:', err2);
        res.status(500).json({ error: 'Failed to update settings' });
      } 
      
      else {

        logAction(req, {
  action: 'COMPANY_SETTINGS_UPDATE',
  entityType: 'CompanySettings',
  entityId: 1,
  details: {
    companyName: d.CompanyName,
    address: d.Address,
    postCode: d.PostCode,
    country: d.Country
  }
});

        res.json({ success: true });
      }
    });
  });
});

//Invoice detail route
app.get('/invoice-details/:invoiceId', requireAuth, (req, res) => {
  const { invoiceId } = req.params;

  const invoiceQuery = `
    SELECT 
      i.*, 
      c.[First Name] AS CustomerFirstName,
      c.[Last Name] AS CustomerLastName,
      c.Company AS CustomerCompany,
      c.[Address 1] AS CustomerAddress1,
      c.[Address 2] AS CustomerAddress2,
      c.[Post Code] AS CustomerPostCode,
      c.Country AS CustomerCountry,
      c.[Phone 1] AS CustomerPhone1,
      c.[Phone 2] AS CustomerPhone2,
      c.[Phone 3] AS CustomerPhone3,
      cs.CompanyName,
      cs.Address AS CompanyAddress,
      cs.PostCode AS CompanyPostCode,
      cs.Country AS CompanyCountry,
      cs.Phone1 AS CompanyPhone1,
      cs.Phone2 AS CompanyPhone2,
      cs.Phone3 AS CompanyPhone3,
      cs.Email AS CompanyEmail,
      cs.Website AS CompanyWebsite,
      cs.FreetownAddress,
      cs.FreetownPhone1,
      cs.FreetownPhone2,
      cs.Terms
    FROM invoices i
    LEFT JOIN customers c ON i.CustomerID = c.CustomerID
    LEFT JOIN company_settings cs ON 1=1
    WHERE i.InvoiceID = ?
  `;

  customerDB.get(invoiceQuery, [invoiceId], (err, invoice) => {
    if (err || !invoice) {
      console.error('❌ Failed to fetch invoice detail:', err);
      return res.status(500).json({ error: 'Failed to fetch invoice detail' });
    }

    customerDB.all(`SELECT * FROM invoice_items WHERE InvoiceID = ?`, [invoiceId], (err, items) => {
      if (err) {
        console.error('❌ Failed to fetch items:', err);
        return res.status(500).json({ error: 'Failed to fetch invoice items' });
      }

      customerDB.all(`SELECT * FROM payments WHERE InvoiceID = ? ORDER BY PaymentDate ASC`, [invoiceId], (err, payments) => {
        if (err) {
          console.error('❌ Failed to fetch payments:', err);
          return res.status(500).json({ error: 'Failed to fetch payments' });
        }

        res.json({ ...invoice, items, payments });
      });
    });
  });
});

app.get('/invoice-detail.html', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'invoice-detail.html'));
  } else {
    res.redirect('/');
  }
});

//Add FT invoice message route
app.get('/api/invoice-message/:invoiceId', requireAuth, (req, res) => {
  const invoiceId = req.params.invoiceId;

  const query = `
    SELECT 
      i.InvoiceNumber, 
      c."First Name" || ' ' || c."Last Name" AS Sender, 
      i.ReceiverName, i.Address1, i.Address2, i.PostCode, i.Country,
      IFNULL(SUM(p.AmountPaid), 0) as AmountPaid,
      (SELECT SUM(TotalCost) FROM invoice_items WHERE InvoiceID = i.InvoiceID) as InvoiceTotal
    FROM invoices i
    JOIN customers c ON c.CustomerID = i.CustomerID
    LEFT JOIN payments p ON p.InvoiceID = i.InvoiceID
    WHERE i.InvoiceID = ?
  `;

  customerDB.get(query, [invoiceId], (err, invoice) => {
    if (err || !invoice) {
      console.error(err);
      return res.status(500).send("Invoice lookup failed");
    }

    customerDB.all(`
      SELECT ii.ItemName, ii.Quantity, ii.ContainerID AS Container, t.Stage
      FROM invoice_items ii
      LEFT JOIN (
        SELECT ItemID, MAX(Stage) as Stage FROM tracking GROUP BY ItemID
      ) t ON t.ItemID = ii.ItemID
      WHERE ii.InvoiceID = ?
    `, [invoiceId], (err2, items) => {
      if (err2) {
        console.error(err2);
        return res.status(500).send("Item lookup failed");
      }

      const status = invoice.AmountPaid >= invoice.InvoiceTotal
        ? 'Paid'
        : invoice.AmountPaid === 0
          ? 'Unpaid'
          : 'Partial';

      res.json({
        InvoiceNumber: invoice.InvoiceNumber,
        Sender: invoice.Sender,
        ReceiverName: invoice.ReceiverName,
        Address1: invoice.Address1,
        Address2: invoice.Address2,
        PostCode: invoice.PostCode,
        Country: invoice.Country,
        AmountPaid: invoice.AmountPaid,
        Outstanding: Math.max(invoice.InvoiceTotal - invoice.AmountPaid, 0),
        InvoiceStatus: status,
        Items: items
      });
    });
  });
});

//Add debtors list routes
app.get('/debtors-list', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'debtors-list.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/api/debtors', requireAuth, (req, res) => {
  const query = `
    SELECT 
      i.InvoiceID,
      i.InvoiceNumber,
      i.InvoiceDate,
      c.[First Name] || ' ' || c.[Last Name] AS CustomerName,
      c.[Phone 1], c.[Phone 2], c.[Phone 3],
      c.Type, c.Category AS Region,
      (SELECT COALESCE(SUM(TotalCost), 0) FROM invoice_items WHERE InvoiceID = i.InvoiceID) AS Total,
      (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) AS Paid
    FROM invoices i
    LEFT JOIN customers c ON c.CustomerID = i.CustomerID
    ORDER BY i.InvoiceDate DESC
  `;

  customerDB.all(query, [], async (err, rows) => {
    if (err) {
      console.error('❌ Failed to fetch debtors:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    const filtered = await Promise.all(rows.map(async row => {
      const Outstanding = parseFloat(row.Total) - parseFloat(row.Paid || 0);
      if (Outstanding <= 0) return null;

      // Containers linked to this invoice
      const containers = await new Promise((resolve, reject) => {
        customerDB.all(`
          SELECT DISTINCT ContainerID 
          FROM invoice_items 
          WHERE InvoiceID = ? AND ContainerID IS NOT NULL
        `, [row.InvoiceID], (err, results) =>
          err ? reject(err) : resolve(results.map(r => r.ContainerID))
        );
      });

      // Latest tracking stage (optional)
      const tracking = await new Promise((resolve, reject) => {
        customerDB.get(`
          SELECT Stage 
          FROM tracking 
          WHERE ItemID IN (SELECT ItemID FROM invoice_items WHERE InvoiceID = ?) 
          ORDER BY Timestamp DESC LIMIT 1
        `, [row.InvoiceID], (err, r) =>
          err ? reject(err) : resolve(r?.Stage || '')
        );
      });

      return {
        ...row,
        Total: parseFloat(row.Total),
        Paid: parseFloat(row.Paid || 0),
        Outstanding: Outstanding,
        ContainerIDs: containers,
        TrackingStatus: tracking
      };
    }));

    res.json(filtered.filter(Boolean));
  });
});

//ADD QR tracking routes
app.get('/api/track-lookup', requireAuth, (req, res) => {
  const { qr = '', invoice = '' } = req.query;

  let query = `
  SELECT 
    ii.ItemID,
    ii.ItemName,
    ii.ItemQR,
    ii.InvoiceID,
    ii.Quantity,
    ii.UnitCost,
    i.InvoiceNumber,
    CASE 
      WHEN (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) = 0 THEN 'Unpaid'
      WHEN (SELECT COALESCE(SUM(AmountPaid), 0) FROM payments WHERE InvoiceID = i.InvoiceID) >= 
           (SELECT COALESCE(SUM(TotalCost), 0) FROM invoice_items WHERE InvoiceID = i.InvoiceID) THEN 'Paid'
      ELSE 'Partial'
    END AS InvoiceStatus
  FROM invoice_items ii
  JOIN invoices i ON ii.InvoiceID = i.InvoiceID
  WHERE 1 = 1
`;
  const params = [];

  if (qr) {
    if (!isNaN(qr)) {
      query += ` AND ii.ItemID = ?`;
      params.push(parseInt(qr));
    } else {
      query += ` AND ii.ItemQR = ?`;
      params.push(qr);
    }
  }

  if (invoice && invoice.length >= 4) {
    query += ` AND i.InvoiceNumber LIKE ?`;
    params.push(`${invoice}%`);
  }



  customerDB.all(query, params, (err, rows) => {
    if (err) {
      console.error('❌ Track lookup failed:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }
    res.json(rows);
  });
});

app.post('/api/track-item/:itemId', requireAuth, validateActionToken, validateItemIdParam,  validateQuickTrack,async (req, res) => {
  const { itemId } = req.params;
  const { Stage, ContainerID, Notes = '' } = req.body;
  const timestamp = new Date().toISOString();
  const username =
  (req.session.staffUser && req.session.staffUser.username) ||
  (req.session.mainUser && req.session.mainUser.username) ||
  (req.session.user && req.session.user.username) ||
  'unknown';

  try {
    // Get total quantity for this item
    const item = await new Promise((resolve, reject) => {
      customerDB.get(`SELECT Quantity FROM invoice_items WHERE ItemID = ?`, [itemId], (err, row) => {
        if (err) reject(err);
        else resolve(row);
      });
    });

    if (!item || !item.Quantity) {
      return res.status(404).send('Item not found or no quantity specified');
    }

    const quantity = item.Quantity;

    // Count how many times this stage has been confirmed for this item
    const confirmedCount = await new Promise((resolve, reject) => {
      customerDB.get(`SELECT COUNT(*) as count FROM tracking WHERE ItemID = ? AND Stage = ?`, [itemId, Stage], (err, row) => {
        if (err) reject(err);
        else resolve(row.count);
      });
    });

    if (confirmedCount >= quantity) {
      return res.status(400).json({ message: `❌ All ${quantity} units already tracked for this stage.` });
    }

    // Insert tracking record
    await new Promise((resolve, reject) => {
        customerDB.run(
          `INSERT INTO tracking (ItemID, Stage, Timestamp, ContainerID, PerformedBy, Notes) VALUES (?, ?, ?, ?, ?, ?)`,
          [itemId, Stage, timestamp, ContainerID || null, username, Notes || ''],


        function (err) {
          if (err) reject(err);
          else resolve();
        }
      );
    });

    res.json({
      message: `✅ Confirmed ${confirmedCount + 1} of ${quantity} units.`,
      confirmedCount: confirmedCount + 1,
      total: quantity
    });

    logAction(req, {
  action: 'TRACKING_QUICK_STAGE',
  entityType: 'Tracking',
  entityId: itemId,
  details: {
    stage: Stage,
    containerId: ContainerID || null,
    confirmedCount: confirmedCount + 1,
    total: quantity
  }
});

  } catch (err) {
    console.error('Tracking error:', err);
    res.status(500).send('Server error');
  }
});

app.get('/container-volume-counter', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'container-volume-counter.html'));
});

// A. Tracked Item Volume
app.get('/api/volume/items', requireAuth, (req, res) => {
  const query = `
    SELECT SUM(ii.TotalCost) AS total
    FROM invoice_items ii
    JOIN tracking t ON ii.ItemID = t.ItemID
    WHERE t.Stage IN ('Picked up', 'Received (London)')
  `;
  customerDB.get(query, [], (err, row) => {
    if (err) return res.status(500).json({ error: 'Failed to load item volume' });
    const total = row.total || 0;
    const volume = total / 425;
    const percent = (volume / 74.6) * 100;
    res.json({ total, volume: volume.toFixed(2), percent: percent.toFixed(1) });
  });
});

// B. Forecast Volume from Bookings
app.get('/api/volume/bookings', requireAuth, (req, res) => {
  const { start, end } = req.query;
  const query = `
    SELECT COUNT(*) AS count
    FROM bookings
    WHERE [Booking Date] BETWEEN ? AND ?
  `;
  customerDB.get(query, [start, end], (err, row) => {
    if (err) return res.status(500).json({ error: 'Failed to load booking volume' });
    const count = row.count || 0;
    const estTotal = count * 250;
    const volume = estTotal / 425;
    const percent = (volume / 74.6) * 100;
    res.json({ count, estTotal, volume: volume.toFixed(2), percent: percent.toFixed(1) });
  });
});

app.get('/api/reports/revenue-by-month', requireAuth, (req, res) => {
  const query = `
    SELECT 
      strftime('%Y-%m', i.InvoiceDate) AS Month,
      COUNT(DISTINCT i.InvoiceID) AS InvoiceCount,
      COUNT(DISTINCT b.BookingID) AS BookingCount,
      SUM(ii.TotalCost) AS TotalRevenue,
      COALESCE(SUM(ii.TotalCost), 0) - COALESCE((
        SELECT SUM(p.AmountPaid)
        FROM payments p
        JOIN invoices ip ON p.InvoiceID = ip.InvoiceID
        WHERE strftime('%Y-%m', ip.InvoiceDate) = strftime('%Y-%m', i.InvoiceDate)
      ), 0) AS OutstandingBalance
    FROM invoices i
    LEFT JOIN invoice_items ii ON ii.InvoiceID = i.InvoiceID
    LEFT JOIN bookings b ON i.CustomerID = b.CustomerID 
      AND strftime('%Y-%m', b.[Booking Date]) = strftime('%Y-%m', i.InvoiceDate)
    GROUP BY Month
    ORDER BY Month DESC
  `;

  customerDB.all(query, [], (err, rows) => {
    if (err) {
      console.error("❌ Revenue report error:", err);
      return res.status(500).json({ error: "Failed to fetch revenue data" });
    }
    res.json(rows);
  });
});

//Add text list routes

app.get('/area-text-list', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'area-text-list.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/booking-text-list', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'booking-text-list.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/invoice-text-list', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'invoice-text-list.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/debtors-text-list', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'debtors-text-list.html'));
  } else {
    res.redirect('/');
  }
});

app.get('/api/textlist/area', requireAuth, (req, res) => {
  const { region = '', category = '' } = req.query;

  const query = `
    SELECT 
      [First Name] || ' ' || [Last Name] AS Name,
      [Phone 1] AS Phone1,
      [Phone 2] AS Phone2,
      Category,
      Type AS CategoryType
    FROM customers
    WHERE 
      (? = '' OR Category = ?)
      AND (? = '' OR Type = ?)
  `;

  customerDB.all(query, [region, region, category, category], (err, rows) => {
    if (err) {
      console.error('❌ Failed to fetch area text list:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    // Filter to numbers starting with 07 only
    const filtered = rows.map(row => ({
      Name: row.Name,
      Phone1: row.Phone1 && row.Phone1.startsWith('07') ? row.Phone1 : '',
      Phone2: row.Phone2 && row.Phone2.startsWith('07') ? row.Phone2 : '',
      Region: row.Category,
      Category: row.CategoryType
    })).filter(r => r.Phone1 || r.Phone2);

    res.json(filtered);
  });
});

app.get('/api/textlist/bookings', requireAuth, (req, res) => {
  const {
    region = '',
    category = '',
    start = '',
    end = '',
    ae = '',       // NEW: Afternoon/Evening text filter
    slot = ''      // NEW: numeric BookingSlot filter (1–9)
  } = req.query;

  const sql = `
    SELECT 
      c.[First Name] || ' ' || c.[Last Name] AS Name,
      c.[Phone 1] AS Phone1,
      c.[Phone 2] AS Phone2,
      c.Category AS Region,
      c.Type AS Category,
      b.[Booking Date] AS BookingDate,
      b.[Afternoon/Evening] AS AfternoonEvening,
      b.BookingSlot
    FROM bookings b
    JOIN customers c ON c.CustomerID = b.CustomerID
    WHERE 
      (? = '' OR c.Category = ?)
      AND (? = '' OR c.Type = ?)
      AND (? = '' OR DATE(b.[Booking Date]) >= DATE(?))
      AND (? = '' OR DATE(b.[Booking Date]) <= DATE(?))
      AND (? = '' OR b.[Afternoon/Evening] = ?)
      AND (? = '' OR b.BookingSlot = ?)
  `;

  const params = [
    region, region,
    category, category,
    start, start,
    end, end,
    ae, ae,
    slot, slot
  ];

  customerDB.all(sql, params, (err, rows) => {
    if (err) {
      console.error('❌ Failed to fetch booking text list:', err.message);
      return res.status(500).json({ error: 'Database error' });
    }

    // Only mobile numbers (07...) and include both A/E + Slot back to the UI
    const filtered = rows.map(row => ({
      Name: row.Name,
      Phone1: row.Phone1 && row.Phone1.startsWith('07') ? row.Phone1 : '',
      Phone2: row.Phone2 && row.Phone2.startsWith('07') ? row.Phone2 : '',
      Region: row.Region,
      Category: row.Category,
      BookingDate: row.BookingDate,
      AfternoonEvening: row.AfternoonEvening || '',
      BookingSlot: row.BookingSlot || ''
    })).filter(r => r.Phone1 || r.Phone2);

    res.json(filtered);
  });
});


app.get('/api/textlist/invoices',  requireAuth, (req, res) => {
  const { region = '', category = '', start = '', end = '', status = '', container = '', outstanding = '' } = req.query;

  const query = `
    SELECT 
      c.[First Name] || ' ' || c.[Last Name] AS Name,
      c.[Phone 1] AS Phone1,
      c.[Phone 2] AS Phone2,
      c.Category AS Region,
      c.Type AS Category,
      i.InvoiceDate,
      i.InvoiceID
    FROM invoices i
    LEFT JOIN customers c ON c.CustomerID = i.CustomerID
    WHERE 
      (? = '' OR c.Category = ?)
      AND (? = '' OR c.Type = ?)
      AND (? = '' OR DATE(i.InvoiceDate) >= DATE(?))
      AND (? = '' OR DATE(i.InvoiceDate) <= DATE(?))
  `;

  customerDB.all(query, [region, region, category, category, start, start, end, end], async (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    const results = await Promise.all(rows.map(async row => {
      const containerIDs = await new Promise((resolve, reject) => {
        customerDB.all(
          `SELECT DISTINCT ContainerID FROM invoice_items WHERE InvoiceID = ? AND ContainerID IS NOT NULL`,
          [row.InvoiceID],
          (err, rows) => err ? reject(err) : resolve(rows.map(r => r.ContainerID))
        );
      });

      const paid = await new Promise((resolve, reject) => {
        customerDB.get(
          `SELECT COALESCE(SUM(AmountPaid), 0) AS Paid FROM payments WHERE InvoiceID = ?`,
          [row.InvoiceID],
          (err, row) => err ? reject(err) : resolve(row.Paid)
        );
      });

      const total = await new Promise((resolve, reject) => {
        customerDB.get(
          `SELECT COALESCE(SUM(TotalCost), 0) AS Total FROM invoice_items WHERE InvoiceID = ?`,
          [row.InvoiceID],
          (err, row) => err ? reject(err) : resolve(row.Total)
        );
      });

      const hasOutstanding = total - paid > 0;

      return {
        ...row,
        Phone1: row.Phone1?.startsWith('07') ? row.Phone1 : '',
        Phone2: row.Phone2?.startsWith('07') ? row.Phone2 : '',
        Containers: containerIDs,
        Outstanding: hasOutstanding,
        InvoiceTotal: total,
        AmountPaid: paid
      };
    }));

    const filtered = results.filter(r =>
      (r.Phone1 || r.Phone2) &&
      (container === '' || r.Containers.includes(parseInt(container))) &&
      (outstanding === '' || (outstanding === 'yes' && r.Outstanding) || (outstanding === 'no' && !r.Outstanding))
    );

    res.json(filtered);
  });
});

app.get('/api/textlist/debtors',  requireAuth, (req, res) => {
  const { region = '', category = '', status = '', container = '', outstanding = '' } = req.query;

  const query = `
    SELECT 
      i.InvoiceID,
      c.[First Name] || ' ' || c.[Last Name] AS Name,
      c.[Phone 1] AS Phone1,
      c.[Phone 2] AS Phone2,
      c.Category AS Region,
      c.Type AS Category
    FROM invoices i
    LEFT JOIN customers c ON c.CustomerID = i.CustomerID
    WHERE 
      (? = '' OR c.Category = ?)
      AND (? = '' OR c.Type = ?)
  `;

  customerDB.all(query, [region, region, category, category], async (err, rows) => {
    if (err) return res.status(500).json({ error: 'Database error' });

    const results = await Promise.all(rows.map(async row => {
      const total = await new Promise((resolve, reject) => {
        customerDB.get(
          `SELECT COALESCE(SUM(TotalCost), 0) AS Total FROM invoice_items WHERE InvoiceID = ?`,
          [row.InvoiceID],
          (err, row) => err ? reject(err) : resolve(row.Total)
        );
      });

      const paid = await new Promise((resolve, reject) => {
        customerDB.get(
          `SELECT COALESCE(SUM(AmountPaid), 0) AS Paid FROM payments WHERE InvoiceID = ?`,
          [row.InvoiceID],
          (err, row) => err ? reject(err) : resolve(row.Paid)
        );
      });

      const containers = await new Promise((resolve, reject) => {
        customerDB.all(
          `SELECT DISTINCT ContainerID FROM invoice_items WHERE InvoiceID = ? AND ContainerID IS NOT NULL`,
          [row.InvoiceID],
          (err, rows) => err ? reject(err) : resolve(rows.map(r => r.ContainerID))
        );
      });

      const stage = await new Promise((resolve, reject) => {
        customerDB.get(
          `SELECT Stage FROM tracking WHERE ItemID IN (SELECT ItemID FROM invoice_items WHERE InvoiceID = ?) ORDER BY Timestamp DESC LIMIT 1`,
          [row.InvoiceID],
          (err, r) => err ? reject(err) : resolve(r?.Stage || '')
        );
      });

      const isOutstanding = total - paid > 0;

      return {
        ...row,
        Phone1: row.Phone1?.startsWith('07') ? row.Phone1 : '',
        Phone2: row.Phone2?.startsWith('07') ? row.Phone2 : '',
        Outstanding: isOutstanding,
        Containers: containers,
        GoodsStatus: stage
      };
    }));

    const filtered = results.filter(r =>
      (r.Phone1 || r.Phone2) &&
      (container === '' || r.Containers.includes(parseInt(container))) &&
      (status === '' || r.GoodsStatus === status) &&
      (outstanding === '' || (outstanding === 'yes' && r.Outstanding) || (outstanding === 'no' && !r.Outstanding))
    );

    res.json(filtered);
  });
});





// Serve container-related HTML pages
app.get('/containers-list', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'containers-list.html'));
});

app.get('/edit-container', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'edit-container.html'));
});

app.get('/add-container', requireAuth, (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'add-container.html'));
});

app.get('/partially-shipped', requireAuth, (req, res) => {
  if (req.session?.user) {
    res.sendFile(path.join(__dirname, 'public', 'partially-shipped.html'));
  } else {
    res.redirect('/');
  }
});

// --- Global error handler (including multer upload errors) ---
app.use((err, req, res, next) => {
  // Multer-specific errors (size, too many files, etc.)
  if (err instanceof multer.MulterError) {
    console.error('⚠️ Multer error:', err);
    if (err.code === 'LIMIT_FILE_SIZE') {
      return res.status(400).json({
        error: `File too large. Max size is ${MAX_FILE_SIZE / (1024 * 1024)} MB.`
      });
    }
    return res.status(400).json({ error: err.message });
  }

  // Our own INVALID_FILE_TYPE error from fileFilter
  if (err && err.code === 'INVALID_FILE_TYPE') {
    console.error('⚠️ Invalid file type:', err.message);
    return res.status(400).json({ error: 'Only image files are allowed.' });
  }

  // Fallback: pass to default error handler or next middleware
  if (err) {
    console.error('⚠️ Unhandled error:', err);
    return res.status(500).json({ error: 'Internal server error' });
  }

  next();
});


// Start server
console.log('Setup complete. Starting server...');
app.listen(port, () => {
  console.log(`Server running at http://localhost:${port}`);
});

console.log('✅ Server started on port 3000');

