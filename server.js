/**
 * TrustLayer Backend — single-file build
 * Node.js/Express + PostgreSQL API: auth, heuristic scam analyzer,
 * community reporting, and site-wide stats.
 *
 * Everything (schema, routes, analyzer logic) lives in this one file
 * for minimal-friction deployment on Render.
 *
 * Env vars: DATABASE_URL, JWT_SECRET, CORS_ORIGIN, NODE_ENV, PORT
 */

require('dotenv').config();

const express = require('express');
const cors = require('cors');
const rateLimit = require('express-rate-limit');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { Pool } = require('pg');

// ---------------------------------------------------------------------------
// Database
// ---------------------------------------------------------------------------

const connectionString = process.env.DATABASE_URL;

const pool = new Pool({
  connectionString,
  ssl: connectionString && connectionString.includes('render.com')
    ? { rejectUnauthorized: false }
    : (process.env.NODE_ENV === 'production' ? { rejectUnauthorized: false } : false),
});

const SCHEMA_SQL = `
CREATE TABLE IF NOT EXISTS users (
  id SERIAL PRIMARY KEY,
  account_type TEXT NOT NULL DEFAULT 'individual',
  full_name TEXT NOT NULL,
  email TEXT NOT NULL UNIQUE,
  dial_code TEXT,
  phone_number TEXT,
  country TEXT,
  password_hash TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS scans (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  input_text TEXT NOT NULL,
  score INTEGER NOT NULL,
  risk_level TEXT NOT NULL,
  flags JSONB NOT NULL DEFAULT '[]',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS reports (
  id SERIAL PRIMARY KEY,
  user_id INTEGER REFERENCES users(id) ON DELETE SET NULL,
  reporter_name TEXT,
  category TEXT NOT NULL DEFAULT 'other',
  description TEXT NOT NULL,
  target TEXT,
  status TEXT NOT NULL DEFAULT 'open',
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_scans_created_at ON scans (created_at DESC);
CREATE INDEX IF NOT EXISTS idx_reports_created_at ON reports (created_at DESC);
`;

async function initSchema() {
  await pool.query(SCHEMA_SQL);
}

// ---------------------------------------------------------------------------
// Auth helpers
// ---------------------------------------------------------------------------

const JWT_SECRET = process.env.JWT_SECRET || 'dev-secret-change-me';
const JWT_EXPIRES_IN = '7d';

function signToken(user) {
  return jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, { expiresIn: JWT_EXPIRES_IN });
}

function sanitizeUser(row) {
  if (!row) return null;
  return {
    id: row.id,
    accountType: row.account_type,
    fullName: row.full_name,
    email: row.email,
    dialCode: row.dial_code,
    phoneNumber: row.phone_number,
    country: row.country,
    createdAt: row.created_at,
  };
}

// Populates req.user if a valid Bearer token is present; does not reject if absent.
async function optionalAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return next();
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
  } catch (err) {
    // Invalid/expired token on an optional-auth route: ignore, proceed unauthenticated.
  }
  next();
}

// Requires a valid Bearer token; rejects with 401 otherwise.
function requireAuth(req, res, next) {
  const header = req.headers.authorization || '';
  const token = header.startsWith('Bearer ') ? header.slice(7) : null;
  if (!token) return res.status(401).json({ error: 'Missing or invalid Authorization header' });
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch (err) {
    return res.status(401).json({ error: 'Invalid or expired token' });
  }
}

// ---------------------------------------------------------------------------
// Heuristic scam analyzer
// ---------------------------------------------------------------------------
// Self-contained rule-based engine — no external paid APIs. Scores 0–100
// (higher = riskier) and returns a list of human-readable flags.

const URL_REGEX = /\b((?:https?:\/\/)?(?:www\.)?[a-z0-9-]+\.[a-z]{2,}(?:\/[^\s]*)?)\b/gi;
const IP_URL_REGEX = /\b(?:https?:\/\/)?(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})(?:\/[^\s]*)?\b/g;
const PHONE_REGEX = /(\+?\d[\d\s().-]{7,}\d)/g;

const SHORTENER_DOMAINS = [
  'bit.ly', 'tinyurl.com', 't.co', 'goo.gl', 'ow.ly', 'is.gd', 'buff.ly',
  'rebrand.ly', 'cutt.ly', 'shorturl.at', 'tiny.cc',
];

const SUSPICIOUS_TLDS = ['.xyz', '.top', '.cn', '.ru', '.tk', '.ml', '.ga', '.cf', '.gq', '.click', '.link'];

const URGENCY_PHRASES = [
  'act now', 'urgent', 'immediately', 'act fast', 'limited time', 'expires today',
  'final notice', 'last chance', 'verify your account', 'account suspended',
  'will be suspended', 'will be closed', 'unusual activity', 'confirm your identity',
  'right now', 'as soon as possible', 'before it', 'time-sensitive',
];

const MONEY_PHRASES = [
  'wire transfer', 'gift card', 'bitcoin', 'crypto', 'cryptocurrency', 'western union',
  'processing fee', 'advance fee', 'send money', 'bank details', 'account number',
  'routing number', 'pay upfront', 'refundable deposit', 'clearance fee', 'customs fee',
  'social security number', 'ssn', 'date of birth', 'card number', 'cvv', 'pin number',
];

const PRIZE_PHRASES = [
  'you have won', "you've won", 'congratulations you', 'claim your prize', 'lottery',
  'inheritance', 'free gift', 'you are a winner', 'selected winner',
];

const AUTHORITY_IMPERSONATION = [
  'irs', 'social security', 'tax refund', 'customs office', 'law enforcement',
  'arrest warrant', 'court order', 'immigration office',
];

const CREDENTIAL_PHISHING = [
  'reset your password', 'update your payment', 'login to verify', 'click here to verify',
  'confirm your password', 'security alert', 'unauthorized login',
];

function countMatches(text, phrases) {
  const lower = text.toLowerCase();
  return phrases.filter((p) => lower.includes(p));
}

function analyzeText(input) {
  const text = String(input || '');
  const flags = [];
  let score = 0;

  const urlsFound = Array.from(new Set((text.match(URL_REGEX) || []).map((u) => u.trim())));
  const phonesFound = Array.from(new Set((text.match(PHONE_REGEX) || []).map((p) => p.trim())))
    .filter((p) => p.replace(/\D/g, '').length >= 8);

  // URL-based signals
  if (urlsFound.length > 0) {
    score += 8;
    flags.push(`Contains ${urlsFound.length} link${urlsFound.length > 1 ? 's' : ''}`);

    const hasShortener = urlsFound.some((u) => SHORTENER_DOMAINS.some((d) => u.toLowerCase().includes(d)));
    if (hasShortener) {
      score += 20;
      flags.push('Uses a link-shortening service, which can hide the true destination');
    }

    const hasSuspiciousTld = urlsFound.some((u) => SUSPICIOUS_TLDS.some((tld) => u.toLowerCase().includes(tld)));
    if (hasSuspiciousTld) {
      score += 15;
      flags.push('Link uses a domain extension commonly associated with scam sites');
    }

  }

  const ipUrlsFound = Array.from(new Set((text.match(IP_URL_REGEX) || []).map((u) => u.trim())));
  if (ipUrlsFound.length > 0) {
    if (urlsFound.length === 0) {
      score += 8;
      flags.push(`Contains ${ipUrlsFound.length} link${ipUrlsFound.length > 1 ? 's' : ''}`);
    }
    score += 22;
    flags.push('Link points to a raw IP address instead of a normal domain');
  }

  // Phone numbers
  if (phonesFound.length > 0) {
    score += 5;
    flags.push('Contains a phone number');
  }

  // Phrase-based signals
  const urgencyHits = countMatches(text, URGENCY_PHRASES);
  if (urgencyHits.length > 0) {
    score += Math.min(26, 14 + (urgencyHits.length - 1) * 8);
    flags.push('Uses urgency or pressure language to rush a decision');
  }

  const moneyHits = countMatches(text, MONEY_PHRASES);
  if (moneyHits.length > 0) {
    score += Math.min(30, 16 + (moneyHits.length - 1) * 10);
    flags.push('Requests payment, financial details, or an unusual payment method');
  }

  const prizeHits = countMatches(text, PRIZE_PHRASES);
  if (prizeHits.length > 0) {
    score += Math.min(26, 16 + (prizeHits.length - 1) * 10);
    flags.push('Claims an unexpected prize, lottery win, or inheritance');
  }

  const authorityHits = countMatches(text, AUTHORITY_IMPERSONATION);
  if (authorityHits.length > 0) {
    score += Math.min(28, 18 + (authorityHits.length - 1) * 10);
    flags.push('Impersonates a government agency or law enforcement');
  }

  const credHits = countMatches(text, CREDENTIAL_PHISHING);
  if (credHits.length > 0) {
    score += Math.min(24, 14 + (credHits.length - 1) * 10);
    flags.push('Asks you to log in, reset a password, or "verify" credentials via a link');
  }

  // Combo bonus: a message stacking several *distinct* deception categories is
  // materially more dangerous than the sum of isolated signals suggests.
  const categoryHitCount = [urgencyHits, moneyHits, prizeHits, authorityHits, credHits]
    .filter((hits) => hits.length > 0).length;
  if (categoryHitCount >= 3) {
    score += 18;
    flags.push('Combines multiple distinct scam tactics in one message');
  } else if (categoryHitCount === 2) {
    score += 8;
  }

  // Generic-greeting / mass-message signal
  if (/\b(dear (customer|user|sir\/madam|beneficiary)|valued customer)\b/i.test(text)) {
    score += 8;
    flags.push('Uses a generic greeting instead of your name, typical of mass-sent scams');
  }

  // Excessive urgency punctuation / all-caps shouting
  const exclamations = (text.match(/!/g) || []).length;
  if (exclamations >= 3) {
    score += 5;
    flags.push('Excessive exclamation marks, often used to create false urgency');
  }
  const capsWords = (text.match(/\b[A-Z]{4,}\b/g) || []).length;
  if (capsWords >= 2) {
    score += 5;
    flags.push('Contains multiple all-caps words, a common attention-grabbing scam tactic');
  }

  // Very short input with a bare link and nothing else is mildly suspicious
  if (urlsFound.length > 0 && text.trim().split(/\s+/).length <= 6) {
    score += 6;
    flags.push('Message is little more than a bare link with no context');
  }

  score = Math.max(0, Math.min(100, Math.round(score)));

  let riskLevel = 'low';
  if (score >= 60) riskLevel = 'high';
  else if (score >= 30) riskLevel = 'medium';

  if (flags.length === 0) {
    flags.push('No common scam indicators detected');
  }

  const allUrlsFound = Array.from(new Set([...urlsFound, ...ipUrlsFound]));

  return { score, riskLevel, flags, urlsFound: allUrlsFound, phonesFound };
}

// ---------------------------------------------------------------------------
// App setup
// ---------------------------------------------------------------------------

const app = express();
const PORT = process.env.PORT || 3000;

const allowedOrigins = (process.env.CORS_ORIGIN || '*')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

app.use(cors({
  origin: allowedOrigins.includes('*') ? true : allowedOrigins,
}));
app.use(express.json({ limit: '200kb' }));

const limiter = rateLimit({
  windowMs: 60 * 1000,
  max: 60,
  standardHeaders: true,
  legacyHeaders: false,
});
app.use('/api/', limiter);

app.get('/', (req, res) => {
  res.json({ ok: true, service: 'trustlayer-backend' });
});

app.get('/health', async (req, res) => {
  try {
    await pool.query('SELECT 1');
    res.json({ status: 'ok', db: 'connected' });
  } catch (err) {
    res.status(500).json({ status: 'error', db: 'unavailable' });
  }
});

// ---------------------------------------------------------------------------
// Routes: /api/auth
// ---------------------------------------------------------------------------

const authRouter = express.Router();

authRouter.post('/signup', async (req, res) => {
  try {
    const {
      accountType = 'individual',
      fullName,
      email,
      dialCode,
      phoneNumber,
      country,
      password,
    } = req.body || {};

    if (!fullName || !email || !password) {
      return res.status(400).json({ error: 'fullName, email, and password are required' });
    }
    if (String(password).length < 8) {
      return res.status(400).json({ error: 'Password must be at least 8 characters' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const existing = await pool.query('SELECT id FROM users WHERE email = $1', [normalizedEmail]);
    if (existing.rows.length > 0) {
      return res.status(409).json({ error: 'An account with this email already exists' });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const result = await pool.query(
      `INSERT INTO users (account_type, full_name, email, dial_code, phone_number, country, password_hash)
       VALUES ($1, $2, $3, $4, $5, $6, $7)
       RETURNING *`,
      [accountType, fullName, normalizedEmail, dialCode || null, phoneNumber || null, country || null, passwordHash]
    );

    const user = result.rows[0];
    const token = signToken(user);
    res.status(201).json({ token, user: sanitizeUser(user) });
  } catch (err) {
    console.error('Signup error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

authRouter.post('/login', async (req, res) => {
  try {
    const { email, password } = req.body || {};
    if (!email || !password) {
      return res.status(400).json({ error: 'email and password are required' });
    }

    const normalizedEmail = String(email).trim().toLowerCase();
    const result = await pool.query('SELECT * FROM users WHERE email = $1', [normalizedEmail]);
    const user = result.rows[0];
    if (!user) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const valid = await bcrypt.compare(password, user.password_hash);
    if (!valid) {
      return res.status(401).json({ error: 'Invalid email or password' });
    }

    const token = signToken(user);
    res.json({ token, user: sanitizeUser(user) });
  } catch (err) {
    console.error('Login error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

authRouter.get('/me', requireAuth, async (req, res) => {
  try {
    const result = await pool.query('SELECT * FROM users WHERE id = $1', [req.userId]);
    const user = result.rows[0];
    if (!user) return res.status(404).json({ error: 'User not found' });
    res.json({ user: sanitizeUser(user) });
  } catch (err) {
    console.error('Me error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Routes: /api/analyze
// ---------------------------------------------------------------------------

const analyzeRouter = express.Router();

analyzeRouter.post('/', optionalAuth, async (req, res) => {
  try {
    const { input } = req.body || {};
    if (!input || !String(input).trim()) {
      return res.status(400).json({ error: 'input is required' });
    }

    const { score, riskLevel, flags, urlsFound, phonesFound } = analyzeText(input);

    const result = await pool.query(
      `INSERT INTO scans (user_id, input_text, score, risk_level, flags)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING id`,
      [req.userId || null, String(input), score, riskLevel, JSON.stringify(flags)]
    );

    res.json({
      id: result.rows[0].id,
      score,
      riskLevel,
      flags,
      urlsFound,
      phonesFound,
    });
  } catch (err) {
    console.error('Analyze error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Routes: /api/reports
// ---------------------------------------------------------------------------

const reportsRouter = express.Router();

reportsRouter.post('/', optionalAuth, async (req, res) => {
  try {
    const { category = 'other', description, target, reporterName } = req.body || {};
    if (!description || !String(description).trim()) {
      return res.status(400).json({ error: 'description is required' });
    }

    const result = await pool.query(
      `INSERT INTO reports (user_id, reporter_name, category, description, target)
       VALUES ($1, $2, $3, $4, $5)
       RETURNING *`,
      [req.userId || null, reporterName || null, category, description, target || null]
    );

    res.status(201).json({ report: result.rows[0] });
  } catch (err) {
    console.error('Create report error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

reportsRouter.get('/', async (req, res) => {
  try {
    const limit = Math.min(100, Math.max(1, parseInt(req.query.limit, 10) || 20));
    const result = await pool.query(
      'SELECT * FROM reports ORDER BY created_at DESC LIMIT $1',
      [limit]
    );
    res.json({ reports: result.rows });
  } catch (err) {
    console.error('List reports error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Routes: /api/stats
// ---------------------------------------------------------------------------

const statsRouter = express.Router();

statsRouter.get('/', async (req, res) => {
  try {
    const [scansResult, highRiskResult, reportsResult, usersResult] = await Promise.all([
      pool.query('SELECT COUNT(*)::int AS count FROM scans'),
      pool.query("SELECT COUNT(*)::int AS count FROM scans WHERE risk_level = 'high'"),
      pool.query('SELECT COUNT(*)::int AS count FROM reports'),
      pool.query('SELECT COUNT(*)::int AS count FROM users'),
    ]);

    res.json({
      totalScans: scansResult.rows[0].count,
      highRiskScans: highRiskResult.rows[0].count,
      totalReports: reportsResult.rows[0].count,
      totalUsers: usersResult.rows[0].count,
    });
  } catch (err) {
    console.error('Stats error', err);
    res.status(500).json({ error: 'Internal server error' });
  }
});

// ---------------------------------------------------------------------------
// Mount routers
// ---------------------------------------------------------------------------

app.use('/api/auth', authRouter);
app.use('/api/analyze', analyzeRouter);
app.use('/api/reports', reportsRouter);
app.use('/api/stats', statsRouter);

app.use((req, res) => {
  res.status(404).json({ error: 'Not found' });
});

// eslint-disable-next-line no-unused-vars
app.use((err, req, res, next) => {
  console.error('Unhandled error', err);
  res.status(500).json({ error: 'Internal server error' });
});

// ---------------------------------------------------------------------------
// Start
// ---------------------------------------------------------------------------

async function start() {
  try {
    await initSchema();
    console.log('Database schema ready');
  } catch (err) {
    console.error('Failed to initialize database schema', err);
    process.exit(1);
  }

  app.listen(PORT, () => {
    console.log(`TrustLayer backend listening on port ${PORT}`);
  });
}

start();
