/**
 * ============================================================================
 * TrustLayer Backend — single-file build
 * ============================================================================
 * Everything (config, models, middleware, services, controllers, routes) is
 * consolidated into this one file, in dependency order:
 *   1. Package requires
 *   2. Config (Mongo, Cloudinary, OpenAI, Stripe, Nodemailer)
 *   3. Utils (JWT, hashing, response helpers, AppError, catchAsync, validate)
 *   4. Models (Mongoose schemas)
 *   5. Middleware (auth, admin, upload, sanitize, rate limiting, logging, errors)
 *   6. Services (AI, URL/VirusTotal/SafeBrowsing, OCR, QR, Cloudinary, email,
 *      Stripe subscriptions, scan quota, phone risk)
 *   7. Controllers (route handler logic)
 *   8. Routers + app assembly + server start
 *
 * Functionally identical to the modular version — split back into files under
 * config/ controllers/ middleware/ models/ routes/ services/ utils/ any time
 * this grows unwieldy to maintain as one file.
 * ============================================================================
 */

require('dotenv').config();

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const express = require('express');
const helmet = require('helmet');
const cors = require('cors');
const compression = require('compression');
const cookieParser = require('cookie-parser');
const morgan = require('morgan');
const rateLimit = require('express-rate-limit');
const multer = require('multer');
const mongoose = require('mongoose');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');
const { body, validationResult } = require('express-validator');
const xss = require('xss');
const axios = require('axios');
const { v2: cloudinaryLib } = require('cloudinary');
const OpenAI = require('openai');
const Stripe = require('stripe');
const nodemailer = require('nodemailer');
const Tesseract = require('tesseract.js');
const Jimp = require('jimp');
const QrCode = require('qrcode-reader');


/* ============================================================================
 * 2. CONFIG
 * ========================================================================== */

const connectDB = async () => {
  try {
    mongoose.set('strictQuery', true);
    const conn = await mongoose.connect(process.env.MONGO_URI, {
      serverSelectionTimeoutMS: 10000,
    });
    console.log(`[MongoDB] Connected: ${conn.connection.host}`);

    mongoose.connection.on('error', (err) => {
      console.error('[MongoDB] Connection error:', err.message);
    });
    mongoose.connection.on('disconnected', () => {
      console.warn('[MongoDB] Disconnected. Reconnection is handled by the driver.');
    });
  } catch (error) {
    console.error(`[MongoDB] Initial connection failed: ${error.message}`);
    process.exit(1);
  }
};

cloudinaryLib.config({
  cloud_name: process.env.CLOUDINARY_CLOUD_NAME,
  api_key: process.env.CLOUDINARY_API_KEY,
  api_secret: process.env.CLOUDINARY_API_SECRET,
  secure: true,
});
const cloudinary = cloudinaryLib;

if (!process.env.OPENAI_API_KEY) {
  console.warn('[OpenAI] OPENAI_API_KEY is not set. AI scan endpoints will fail until it is configured.');
}
const openai = new OpenAI({ apiKey: process.env.OPENAI_API_KEY });

if (!process.env.STRIPE_SECRET_KEY) {
  console.warn('[Stripe] STRIPE_SECRET_KEY is not set. Subscription endpoints will fail until it is configured.');
}
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY, { apiVersion: '2024-06-20' });

const mailTransporter = nodemailer.createTransport({
  host: process.env.EMAIL_HOST,
  port: Number(process.env.EMAIL_PORT) || 587,
  secure: Number(process.env.EMAIL_PORT) === 465,
  auth: { user: process.env.EMAIL_USER, pass: process.env.EMAIL_PASS },
});
mailTransporter.verify((error) => {
  if (error) console.warn('[Nodemailer] Transport verification failed:', error.message);
  else console.log('[Nodemailer] Ready to send emails.');
});

/* ============================================================================
 * 3. UTILS
 * ========================================================================== */

class AppError extends Error {
  constructor(message, statusCode = 500, errors = null) {
    super(message);
    this.statusCode = statusCode;
    this.errors = errors;
    this.isOperational = true;
    Error.captureStackTrace(this, this.constructor);
  }
}

const catchAsync = (fn) => (req, res, next) => {
  Promise.resolve(fn(req, res, next)).catch(next);
};

const signAccessToken = (payload) =>
  jwt.sign(payload, process.env.JWT_SECRET, { expiresIn: process.env.JWT_ACCESS_EXPIRES || '15m' });

const signRefreshToken = (payload) =>
  jwt.sign(payload, process.env.JWT_REFRESH_SECRET, { expiresIn: process.env.JWT_REFRESH_EXPIRES || '30d' });

const verifyAccessToken = (token) => jwt.verify(token, process.env.JWT_SECRET);
const verifyRefreshToken = (token) => jwt.verify(token, process.env.JWT_REFRESH_SECRET);

const hashPassword = async (plainText) => bcrypt.hash(plainText, 12);
const comparePassword = async (plainText, hash) => bcrypt.compare(plainText, hash);

const sendSuccess = (res, statusCode, message, data = null, meta = null) => {
  const bodyOut = { success: true, message };
  if (data !== null) bodyOut.data = data;
  if (meta !== null) bodyOut.meta = meta;
  return res.status(statusCode).json(bodyOut);
};

const sendError = (res, statusCode, message, errors = null) => {
  const bodyOut = { success: false, message };
  if (errors !== null) bodyOut.errors = errors;
  return res.status(statusCode).json(bodyOut);
};

const hashToken = (token) => crypto.createHash('sha256').update(token).digest('hex');

const validate = (validations) => async (req, res, next) => {
  await Promise.all(validations.map((validation) => validation.run(req)));
  const errors = validationResult(req);
  if (errors.isEmpty()) return next();
  const formatted = errors.array().map((err) => ({ field: err.path, message: err.msg }));
  return next(new AppError('Validation failed', 422, formatted));
};

/* ============================================================================
 * 4. MODELS
 * ========================================================================== */

const userSchema = new mongoose.Schema(
  {
    name: { type: String, required: [true, 'Name is required'], trim: true, maxlength: 100 },
    email: { type: String, required: [true, 'Email is required'], unique: true, lowercase: true, trim: true },
    password: { type: String, required: [true, 'Password is required'], minlength: 8, select: false },
    avatar: {
      url: { type: String, default: '' },
      publicId: { type: String, default: '' },
    },
    verified: { type: Boolean, default: false },
    plan: { type: String, enum: ['free', 'premium', 'enterprise'], default: 'free' },
    scansRemaining: { type: Number, default: 10 },
    subscriptionStatus: { type: String, enum: ['none', 'active', 'canceled', 'past_due'], default: 'none' },
    stripeCustomerId: { type: String, default: null },
    stripeSubscriptionId: { type: String, default: null },
    role: { type: String, enum: ['user', 'admin'], default: 'user' },
    refreshTokenHash: { type: String, default: null, select: false },
  },
  { timestamps: true }
);
userSchema.index({ email: 1 });
const User = mongoose.model('User', userSchema);

const scanHistorySchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    scanType: { type: String, enum: ['text', 'url', 'email', 'image', 'qr', 'phone'], required: true },
    input: { type: mongoose.Schema.Types.Mixed },
    riskScore: { type: Number, min: 0, max: 100 },
    classification: { type: String },
    result: { type: mongoose.Schema.Types.Mixed },
  },
  { timestamps: true }
);
scanHistorySchema.index({ user: 1, createdAt: -1 });
const ScanHistory = mongoose.model('ScanHistory', scanHistorySchema);

const subscriptionSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    plan: { type: String, enum: ['free', 'premium', 'enterprise'], required: true },
    stripeCustomerId: String,
    stripeSubscriptionId: String,
    stripePriceId: String,
    status: {
      type: String,
      enum: ['incomplete', 'active', 'past_due', 'canceled', 'unpaid', 'trialing'],
      default: 'incomplete',
    },
    currentPeriodEnd: Date,
    cancelAtPeriodEnd: { type: Boolean, default: false },
  },
  { timestamps: true }
);
const Subscription = mongoose.model('Subscription', subscriptionSchema);

const verificationTokenSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    tokenHash: { type: String, required: true },
    expiresAt: { type: Date, required: true },
  },
  { timestamps: true }
);
verificationTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const VerificationToken = mongoose.model('VerificationToken', verificationTokenSchema);

const passwordResetTokenSchema = new mongoose.Schema(
  {
    user: { type: mongoose.Schema.Types.ObjectId, ref: 'User', required: true, index: true },
    tokenHash: { type: String, required: true },
    expiresAt: { type: Date, required: true },
    used: { type: Boolean, default: false },
  },
  { timestamps: true }
);
passwordResetTokenSchema.index({ expiresAt: 1 }, { expireAfterSeconds: 0 });
const PasswordResetToken = mongoose.model('PasswordResetToken', passwordResetTokenSchema);

/* ============================================================================
 * 5. MIDDLEWARE
 * ========================================================================== */

const authenticate = catchAsync(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) {
    return next(new AppError('Authentication required', 401));
  }
  const token = authHeader.split(' ')[1];
  let decoded;
  try {
    decoded = verifyAccessToken(token);
  } catch (err) {
    return next(new AppError('Invalid or expired token', 401));
  }
  const user = await User.findById(decoded.id);
  if (!user) return next(new AppError('User no longer exists', 401));
  req.user = user;
  next();
});

const optionalAuthenticate = catchAsync(async (req, res, next) => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith('Bearer ')) return next();
  const token = authHeader.split(' ')[1];
  try {
    const decoded = verifyAccessToken(token);
    const user = await User.findById(decoded.id);
    if (user) req.user = user;
  } catch (err) {
    // Invalid token on an optional route just means "treat as guest"
  }
  next();
});

const requireAdmin = (req, res, next) => {
  if (!req.user) return next(new AppError('Authentication required', 401));
  if (req.user.role !== 'admin') return next(new AppError('Admin access required', 403));
  next();
};

const uploadStorage = multer.memoryStorage();
const ALLOWED_MIME_TYPES = ['image/jpeg', 'image/png', 'image/webp', 'image/gif'];
const upload = multer({
  storage: uploadStorage,
  fileFilter: (req, file, cb) => {
    if (!ALLOWED_MIME_TYPES.includes(file.mimetype)) {
      return cb(new AppError(`Unsupported file type: ${file.mimetype}`, 400));
    }
    cb(null, true);
  },
  limits: { fileSize: 8 * 1024 * 1024 },
});

const sanitizeValue = (value) => {
  if (typeof value === 'string') return xss(value);
  if (Array.isArray(value)) return value.map(sanitizeValue);
  if (value && typeof value === 'object') {
    const clean = {};
    for (const key of Object.keys(value)) {
      if (key.startsWith('$') || key.includes('.')) continue;
      clean[key] = sanitizeValue(value[key]);
    }
    return clean;
  }
  return value;
};

const sanitizeInputs = (req, res, next) => {
  if (req.body && typeof req.body === 'object') req.body = sanitizeValue(req.body);
  if (req.params && typeof req.params === 'object') {
    for (const key of Object.keys(req.params)) req.params[key] = sanitizeValue(req.params[key]);
  }
  // req.query is left untouched (read-only getter in newer Express versions);
  // query values are validated per-route via express-validator instead.
  next();
};

const apiLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 300,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many requests. Please try again later.' },
});

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  max: 20,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Too many auth attempts. Please try again later.' },
});

const scanLimiter = rateLimit({
  windowMs: 60 * 1000,
  max: 15,
  standardHeaders: true,
  legacyHeaders: false,
  message: { success: false, message: 'Scan rate limit exceeded. Please slow down.' },
});

const logsDir = path.join(__dirname, 'logs');
if (!fs.existsSync(logsDir)) fs.mkdirSync(logsDir, { recursive: true });

const accessLogPath = path.join(__dirname, 'logs', 'access.log');
const accessLogStream = fs.createWriteStream(accessLogPath, { flags: 'a' });
const consoleLogger = morgan('dev');
const fileLogger = morgan('combined', { stream: accessLogStream });
const requestLogger = (req, res, next) => {
  fileLogger(req, res, () => {
    if (process.env.NODE_ENV !== 'production') return consoleLogger(req, res, next);
    next();
  });
};

const errorLogFile = path.join(__dirname, 'logs', 'error.log');
const logErrorToFile = (err, req) => {
  const entry = `[${new Date().toISOString()}] ${req.method} ${req.originalUrl} - ${err.message}\n${err.stack}\n\n`;
  fs.appendFile(errorLogFile, entry, (writeErr) => {
    if (writeErr) console.error('[ErrorHandler] Failed to write error log:', writeErr.message);
  });
};

const normalizeError = (err) => {
  if (err.name === 'CastError') return new AppError(`Invalid ${err.path}: ${err.value}`, 400);
  if (err.code === 11000) {
    const field = Object.keys(err.keyValue || {})[0] || 'field';
    return new AppError(`Duplicate value for ${field}`, 409);
  }
  if (err.name === 'ValidationError') {
    const errors = Object.values(err.errors).map((e) => ({ field: e.path, message: e.message }));
    return new AppError('Validation failed', 422, errors);
  }
  if (err.name === 'JsonWebTokenError') return new AppError('Invalid token', 401);
  if (err.name === 'TokenExpiredError') return new AppError('Token expired', 401);
  if (err.name === 'MulterError') return new AppError(`Upload error: ${err.message}`, 400);
  return err;
};

const notFound = (req, res, next) => {
  next(new AppError(`Route not found: ${req.originalUrl}`, 404));
};

const errorHandler = (err, req, res, next) => {
  const normalized = normalizeError(err);
  const statusCode = normalized.statusCode || 500;
  const isOperational = normalized.isOperational || false;
  if (!isOperational) console.error('[UNEXPECTED ERROR]', err);
  logErrorToFile(err, req);
  res.status(statusCode).json({
    success: false,
    message: isOperational ? normalized.message : 'Internal server error',
    ...(normalized.errors ? { errors: normalized.errors } : {}),
    ...(process.env.NODE_ENV === 'development' && !isOperational ? { stack: err.stack } : {}),
  });
};

/* ============================================================================
 * 6. SERVICES
 * ========================================================================== */

/* ---- AI scam analysis (OpenAI) ---- */
const AI_MODEL = 'gpt-4o-mini';
const AI_SYSTEM_PROMPT = `You are a scam and fraud detection analyst. You examine text (messages, emails, or extracted image text) for signs of scams, phishing, fraud, or social engineering.
Respond ONLY with strict JSON, no markdown, no commentary, matching exactly this schema:
{
  "riskScore": <integer 0-100, 100 = certainly a scam>,
  "classification": <one of "Safe", "Suspicious", "Likely Scam">,
  "confidence": <integer 0-100>,
  "reasons": [<short strings explaining the key signals found>],
  "recommendation": <one short actionable sentence for the end user>
}`;

const clampScore = (value) => {
  const n = Number(value);
  if (Number.isNaN(n)) return 50;
  return Math.max(0, Math.min(100, Math.round(n)));
};

const analyzeTextForScam = async (text, contextLabel = 'message') => {
  if (!text || !text.trim()) throw new AppError('No text provided for analysis', 400);

  let completion;
  try {
    completion = await openai.chat.completions.create({
      model: AI_MODEL,
      temperature: 0.2,
      response_format: { type: 'json_object' },
      messages: [
        { role: 'system', content: AI_SYSTEM_PROMPT },
        { role: 'user', content: `Analyze the following ${contextLabel} for scam indicators:\n\n${text}` },
      ],
    });
  } catch (err) {
    throw new AppError(`AI analysis failed: ${err.message}`, 502);
  }

  const raw = completion.choices?.[0]?.message?.content;
  if (!raw) throw new AppError('AI analysis returned no content', 502);

  let parsed;
  try {
    parsed = JSON.parse(raw);
  } catch (err) {
    throw new AppError('Failed to parse AI analysis response', 502);
  }

  return {
    riskScore: clampScore(parsed.riskScore),
    classification: parsed.classification || 'Suspicious',
    confidence: clampScore(parsed.confidence),
    reasons: Array.isArray(parsed.reasons) ? parsed.reasons : [],
    recommendation: parsed.recommendation || 'Exercise caution and verify the source independently.',
  };
};

const analyzeEmailForScam = async ({ sender, subject, body: emailBody }) => {
  const composed = `Sender: ${sender || 'unknown'}\nSubject: ${subject || '(no subject)'}\n\nBody:\n${emailBody || ''}`;
  const result = await analyzeTextForScam(composed, 'email');

  const bodyLower = (emailBody || '').toLowerCase();
  const subjectLower = (subject || '').toLowerCase();
  const combined = `${subjectLower} ${bodyLower}`;

  result.detectedPatterns = {
    phishing: /verify your account|click here|suspended|confirm your identity/.test(combined),
    businessEmailCompromise: /wire transfer|urgent payment|ceo|ceo request|change of bank/.test(combined),
    fakeInvoice: /invoice attached|overdue invoice|payment due|invoice #/.test(combined),
    lotteryScam: /you have won|lottery|claim your prize/.test(combined),
    investmentScam: /guaranteed return|crypto investment|double your money/.test(combined),
  };

  return result;
};

/* ---- URL analysis (VirusTotal + Google Safe Browsing) ---- */
const checkGoogleSafeBrowsing = async (url) => {
  const apiKey = process.env.GOOGLE_SAFE_BROWSING_API_KEY;
  if (!apiKey) return { checked: false, threatFound: false, threats: [], reason: 'API key not configured' };

  try {
    const response = await axios.post(
      `https://safebrowsing.googleapis.com/v4/threatMatches:find?key=${apiKey}`,
      {
        client: { clientId: 'trustlayer', clientVersion: '1.0.0' },
        threatInfo: {
          threatTypes: ['MALWARE', 'SOCIAL_ENGINEERING', 'UNWANTED_SOFTWARE', 'POTENTIALLY_HARMFUL_APPLICATION'],
          platformTypes: ['ANY_PLATFORM'],
          threatEntryTypes: ['URL'],
          threatEntries: [{ url }],
        },
      }
    );
    const matches = response.data?.matches || [];
    return { checked: true, threatFound: matches.length > 0, threats: matches.map((m) => m.threatType) };
  } catch (err) {
    return { checked: false, threatFound: false, threats: [], reason: err.message };
  }
};

const checkVirusTotal = async (url) => {
  const apiKey = process.env.VIRUSTOTAL_API_KEY;
  if (!apiKey) return { checked: false, malicious: 0, suspicious: 0, harmless: 0, reason: 'API key not configured' };

  const headers = { 'x-apikey': apiKey };
  try {
    const submitResponse = await axios.post(
      'https://www.virustotal.com/api/v3/urls',
      new URLSearchParams({ url }).toString(),
      { headers: { ...headers, 'Content-Type': 'application/x-www-form-urlencoded' } }
    );
    const analysisId = submitResponse.data?.data?.id;
    if (!analysisId) return { checked: false, malicious: 0, suspicious: 0, harmless: 0, reason: 'No analysis ID returned' };

    for (let attempt = 0; attempt < 3; attempt += 1) {
      await new Promise((resolve) => setTimeout(resolve, 1500));
      const analysisResponse = await axios.get(`https://www.virustotal.com/api/v3/analyses/${analysisId}`, { headers });
      const status = analysisResponse.data?.data?.attributes?.status;
      if (status === 'completed') {
        const stats = analysisResponse.data.data.attributes.stats;
        return {
          checked: true,
          malicious: stats.malicious || 0,
          suspicious: stats.suspicious || 0,
          harmless: stats.harmless || 0,
          undetected: stats.undetected || 0,
        };
      }
    }
    return { checked: true, pending: true, malicious: 0, suspicious: 0, harmless: 0 };
  } catch (err) {
    return { checked: false, malicious: 0, suspicious: 0, harmless: 0, reason: err.message };
  }
};

const analyzeUrl = async (url) => {
  if (!url || !/^https?:\/\//i.test(url)) throw new AppError('A valid http(s) URL is required', 400);

  const [safeBrowsing, virusTotal] = await Promise.all([checkGoogleSafeBrowsing(url), checkVirusTotal(url)]);

  let riskScore = 5;
  if (safeBrowsing.threatFound) riskScore += 60;
  riskScore += Math.min(virusTotal.malicious * 10, 35);
  riskScore += Math.min(virusTotal.suspicious * 5, 15);
  riskScore = Math.max(0, Math.min(100, riskScore));

  let classification = 'Safe';
  if (riskScore >= 70) classification = 'Likely Scam';
  else if (riskScore >= 35) classification = 'Suspicious';

  let domain = null;
  try {
    domain = new URL(url).hostname;
  } catch (err) {
    domain = null;
  }

  return {
    url,
    domain,
    riskScore,
    classification,
    reputation: { googleSafeBrowsing: safeBrowsing, virusTotal },
    phishingStatus: safeBrowsing.threats.includes('SOCIAL_ENGINEERING') ? 'Detected' : 'Not detected',
    malwareDetection:
      safeBrowsing.threats.includes('MALWARE') || virusTotal.malicious > 0 ? 'Detected' : 'Not detected',
    recommendation:
      classification === 'Safe'
        ? 'No known threats detected. Still verify the sender before entering credentials.'
        : 'Avoid clicking this link or entering any personal information.',
  };
};

/* ---- OCR (Tesseract.js) ---- */
const extractTextFromImage = async (buffer) => {
  if (!buffer) throw new AppError('No image buffer provided for OCR', 400);
  try {
    const {
      data: { text },
    } = await Tesseract.recognize(buffer, 'eng');
    return (text || '').trim();
  } catch (err) {
    throw new AppError(`OCR extraction failed: ${err.message}`, 502);
  }
};

/* ---- QR decoding (Jimp + qrcode-reader) ---- */
const decodeQrCode = async (buffer) => {
  if (!buffer) throw new AppError('No image buffer provided for QR decoding', 400);
  let image;
  try {
    image = await Jimp.read(buffer);
  } catch (err) {
    throw new AppError('Could not read the uploaded image', 400);
  }
  return new Promise((resolve, reject) => {
    const qr = new QrCode();
    qr.callback = (err, value) => {
      if (err || !value) return reject(new AppError('No QR code could be detected in the image', 422));
      resolve(value.result);
    };
    qr.decode(image.bitmap);
  });
};

/* ---- Cloudinary uploads ---- */
const uploadBuffer = (buffer, folder = 'trustlayer/misc') =>
  new Promise((resolve, reject) => {
    const stream = cloudinary.uploader.upload_stream({ folder, resource_type: 'image' }, (error, result) => {
      if (error) return reject(new AppError(`Cloudinary upload failed: ${error.message}`, 502));
      resolve(result);
    });
    stream.end(buffer);
  });

const deleteAsset = async (publicId) => {
  if (!publicId) return;
  try {
    await cloudinary.uploader.destroy(publicId);
  } catch (err) {
    console.warn('[Cloudinary] Failed to delete asset:', err.message);
  }
};

/* ---- Email notifications (Nodemailer) ---- */
const MAIL_FROM = process.env.EMAIL_FROM || 'TrustLayer <no-reply@trustlayer.app>';

const sendMail = async ({ to, subject, html }) => {
  try {
    await mailTransporter.sendMail({ from: MAIL_FROM, to, subject, html });
  } catch (err) {
    console.error(`[EmailService] Failed to send "${subject}" to ${to}:`, err.message);
  }
};

const sendVerificationEmail = async (email, name, verifyUrl) => {
  await sendMail({
    to: email,
    subject: 'Verify your TrustLayer account',
    html: `<p>Hi ${name},</p>
      <p>Thanks for signing up for TrustLayer. Please verify your email address by clicking the link below:</p>
      <p><a href="${verifyUrl}">${verifyUrl}</a></p>
      <p>This link expires in 24 hours.</p>`,
  });
};

const sendPasswordResetEmail = async (email, name, resetUrl) => {
  await sendMail({
    to: email,
    subject: 'Reset your TrustLayer password',
    html: `<p>Hi ${name},</p>
      <p>We received a request to reset your password. Click the link below to choose a new one:</p>
      <p><a href="${resetUrl}">${resetUrl}</a></p>
      <p>If you didn't request this, you can safely ignore this email. This link expires in 1 hour.</p>`,
  });
};

const sendScamAlertEmail = async (email, name, classification, riskScore) => {
  await sendMail({
    to: email,
    subject: `TrustLayer Alert: ${classification} detected`,
    html: `<p>Hi ${name},</p>
      <p>A recent scan you ran was classified as <strong>${classification}</strong> with a risk score of ${riskScore}/100.</p>
      <p>Log in to your TrustLayer dashboard for the full breakdown.</p>`,
  });
};

/* ---- Stripe subscriptions ---- */
const STRIPE_PRICE_IDS = {
  premium: process.env.STRIPE_PRICE_PREMIUM,
  enterprise: process.env.STRIPE_PRICE_ENTERPRISE,
};
const PLAN_SCAN_QUOTAS = { free: 10, premium: 200, enterprise: Infinity };

const getOrCreateStripeCustomer = async (user) => {
  if (user.stripeCustomerId) return user.stripeCustomerId;
  const customer = await stripe.customers.create({
    email: user.email,
    name: user.name,
    metadata: { userId: user._id.toString() },
  });
  user.stripeCustomerId = customer.id;
  await user.save();
  return customer.id;
};

const createCheckoutSession = async (user, plan) => {
  if (!['premium', 'enterprise'].includes(plan)) {
    throw new AppError('Invalid plan. Choose "premium" or "enterprise".', 400);
  }
  const priceId = STRIPE_PRICE_IDS[plan];
  if (!priceId) throw new AppError(`Stripe price ID for "${plan}" is not configured`, 500);

  const customerId = await getOrCreateStripeCustomer(user);

  const session = await stripe.checkout.sessions.create({
    mode: 'subscription',
    customer: customerId,
    line_items: [{ price: priceId, quantity: 1 }],
    success_url: `${process.env.CLIENT_URL}/billing/success?session_id={CHECKOUT_SESSION_ID}`,
    cancel_url: `${process.env.CLIENT_URL}/billing/cancel`,
    metadata: { userId: user._id.toString(), plan },
  });

  return session;
};

const handleStripeWebhookEvent = async (event) => {
  switch (event.type) {
    case 'checkout.session.completed': {
      const session = event.data.object;
      const userId = session.metadata?.userId;
      const plan = session.metadata?.plan;
      if (!userId || !plan) break;

      const subscription = await stripe.subscriptions.retrieve(session.subscription);

      await User.findByIdAndUpdate(userId, {
        plan,
        subscriptionStatus: 'active',
        stripeSubscriptionId: subscription.id,
        scansRemaining: PLAN_SCAN_QUOTAS[plan],
      });

      await Subscription.create({
        user: userId,
        plan,
        stripeCustomerId: session.customer,
        stripeSubscriptionId: subscription.id,
        stripePriceId: subscription.items.data[0]?.price?.id,
        status: subscription.status,
        currentPeriodEnd: new Date(subscription.current_period_end * 1000),
      });
      break;
    }
    case 'customer.subscription.updated': {
      const subscription = event.data.object;
      await Subscription.findOneAndUpdate(
        { stripeSubscriptionId: subscription.id },
        {
          status: subscription.status,
          currentPeriodEnd: new Date(subscription.current_period_end * 1000),
          cancelAtPeriodEnd: subscription.cancel_at_period_end,
        }
      );
      const statusMap = { active: 'active', past_due: 'past_due', canceled: 'canceled', unpaid: 'past_due' };
      await User.findOneAndUpdate(
        { stripeSubscriptionId: subscription.id },
        { subscriptionStatus: statusMap[subscription.status] || 'active' }
      );
      break;
    }
    case 'customer.subscription.deleted': {
      const subscription = event.data.object;
      await User.findOneAndUpdate(
        { stripeSubscriptionId: subscription.id },
        { plan: 'free', subscriptionStatus: 'canceled', scansRemaining: PLAN_SCAN_QUOTAS.free }
      );
      await Subscription.findOneAndUpdate({ stripeSubscriptionId: subscription.id }, { status: 'canceled' });
      break;
    }
    default:
      break;
  }
  return event.type;
};

/* ---- Scan quota enforcement ---- */
const consumeScan = async (user) => {
  if (!user) return;
  if (user.plan === 'enterprise') return;
  if (user.scansRemaining <= 0) {
    throw new AppError('You have used all scans included in your current plan. Please upgrade to continue.', 403);
  }
  user.scansRemaining -= 1;
  await user.save();
};

/* ---- Phone risk heuristics ---- */
const PHONE_HIGH_RISK_PREFIXES = ['+1900', '+44900', '+232', '+234'];

const analyzePhone = async (phoneNumber) => {
  if (!phoneNumber || !/^\+?[0-9\s\-()]{6,20}$/.test(phoneNumber)) {
    throw new AppError('A valid phone number is required (E.164 format recommended)', 400);
  }

  const normalized = phoneNumber.replace(/[\s\-()]/g, '');
  let riskScore = 5;
  const reasons = [];

  if (PHONE_HIGH_RISK_PREFIXES.some((prefix) => normalized.startsWith(prefix))) {
    riskScore += 40;
    reasons.push('Number prefix is commonly associated with premium-rate or scam call campaigns.');
  }

  const digitsOnly = normalized.replace(/\D/g, '');
  if (/(\d)\1{5,}/.test(digitsOnly)) {
    riskScore += 20;
    reasons.push('Number contains an unusually long run of repeated digits.');
  }
  if (/0123456|1234567|9876543/.test(digitsOnly)) {
    riskScore += 15;
    reasons.push('Number contains a sequential digit pattern often seen in spoofed numbers.');
  }
  if (!normalized.startsWith('+')) {
    reasons.push('No country code provided - risk assessment may be less accurate.');
  }

  riskScore = Math.max(0, Math.min(100, riskScore));
  let classification = 'Low Risk';
  if (riskScore >= 60) classification = 'High Risk';
  else if (riskScore >= 30) classification = 'Moderate Risk';

  return {
    phoneNumber: normalized,
    spamProbability: riskScore,
    classification,
    scamReports: reasons.length,
    reasons: reasons.length ? reasons : ['No known risk patterns detected.'],
    recommendation:
      classification === 'Low Risk'
        ? 'No strong risk indicators found. Standard caution still applies with unknown callers.'
        : 'Exercise caution - avoid sharing personal or financial information with this number.',
  };
};

/* ============================================================================
 * 7. CONTROLLERS
 * ========================================================================== */

const REFRESH_COOKIE_NAME = 'trustlayer_refresh';
const REFRESH_COOKIE_OPTIONS = {
  httpOnly: true,
  secure: process.env.NODE_ENV === 'production',
  sameSite: 'lax',
  maxAge: 30 * 24 * 60 * 60 * 1000,
  path: '/api/auth',
};

const buildUserPayload = (user) => ({
  id: user._id,
  name: user.name,
  email: user.email,
  avatar: user.avatar,
  verified: user.verified,
  plan: user.plan,
  scansRemaining: user.scansRemaining,
  subscriptionStatus: user.subscriptionStatus,
  role: user.role,
  createdAt: user.createdAt,
});

const issueTokensAndRespond = async (res, user, statusCode, message) => {
  const accessToken = signAccessToken({ id: user._id, role: user.role });
  const refreshToken = signRefreshToken({ id: user._id });
  user.refreshTokenHash = hashToken(refreshToken);
  await user.save();
  res.cookie(REFRESH_COOKIE_NAME, refreshToken, REFRESH_COOKIE_OPTIONS);
  return sendSuccess(res, statusCode, message, { user: buildUserPayload(user), accessToken });
};

/* ---- Auth controller ---- */
const register = catchAsync(async (req, res, next) => {
  const { name, email, password } = req.body;
  const existing = await User.findOne({ email: email.toLowerCase() });
  if (existing) return next(new AppError('An account with this email already exists', 409));

  const passwordHash = await hashPassword(password);
  const user = await User.create({ name, email: email.toLowerCase(), password: passwordHash });

  const rawToken = crypto.randomBytes(32).toString('hex');
  await VerificationToken.create({
    user: user._id,
    tokenHash: hashToken(rawToken),
    expiresAt: new Date(Date.now() + 24 * 60 * 60 * 1000),
  });

  const verifyUrl = `${process.env.CLIENT_URL}/verify-email?token=${rawToken}&uid=${user._id}`;
  await sendVerificationEmail(user.email, user.name, verifyUrl);

  await issueTokensAndRespond(res, user, 201, 'Account created. Please check your email to verify your address.');
});

const login = catchAsync(async (req, res, next) => {
  const { email, password } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() }).select('+password');
  if (!user) return next(new AppError('Invalid email or password', 401));
  const isMatch = await comparePassword(password, user.password);
  if (!isMatch) return next(new AppError('Invalid email or password', 401));
  await issueTokensAndRespond(res, user, 200, 'Login successful');
});

const logout = catchAsync(async (req, res) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE_NAME];
  if (refreshToken) {
    try {
      const decoded = verifyRefreshToken(refreshToken);
      await User.findByIdAndUpdate(decoded.id, { refreshTokenHash: null });
    } catch (err) {
      // Token invalid/expired - nothing to clean up server-side.
    }
  }
  res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
  return sendSuccess(res, 200, 'Logged out successfully');
});

const refresh = catchAsync(async (req, res, next) => {
  const refreshToken = req.cookies?.[REFRESH_COOKIE_NAME];
  if (!refreshToken) return next(new AppError('No refresh token provided', 401));

  let decoded;
  try {
    decoded = verifyRefreshToken(refreshToken);
  } catch (err) {
    return next(new AppError('Invalid or expired refresh token', 401));
  }

  const user = await User.findById(decoded.id).select('+refreshTokenHash');
  if (!user || user.refreshTokenHash !== hashToken(refreshToken)) {
    return next(new AppError('Refresh token has been revoked', 401));
  }

  const accessToken = signAccessToken({ id: user._id, role: user.role });
  return sendSuccess(res, 200, 'Token refreshed', { accessToken });
});

const verifyEmail = catchAsync(async (req, res, next) => {
  const { token, uid } = req.body;
  if (!token || !uid) return next(new AppError('Verification token and user ID are required', 400));

  const record = await VerificationToken.findOne({ user: uid, tokenHash: hashToken(token) });
  if (!record) return next(new AppError('Invalid or expired verification link', 400));

  await User.findByIdAndUpdate(uid, { verified: true });
  await VerificationToken.deleteOne({ _id: record._id });

  return sendSuccess(res, 200, 'Email verified successfully');
});

const forgotPassword = catchAsync(async (req, res) => {
  const { email } = req.body;
  const user = await User.findOne({ email: email.toLowerCase() });
  if (!user) return sendSuccess(res, 200, 'If that email is registered, a reset link has been sent.');

  const rawToken = crypto.randomBytes(32).toString('hex');
  await PasswordResetToken.create({
    user: user._id,
    tokenHash: hashToken(rawToken),
    expiresAt: new Date(Date.now() + 60 * 60 * 1000),
  });

  const resetUrl = `${process.env.CLIENT_URL}/reset-password?token=${rawToken}&uid=${user._id}`;
  await sendPasswordResetEmail(user.email, user.name, resetUrl);

  return sendSuccess(res, 200, 'If that email is registered, a reset link has been sent.');
});

const resetPassword = catchAsync(async (req, res, next) => {
  const { token, uid, newPassword } = req.body;
  const record = await PasswordResetToken.findOne({ user: uid, tokenHash: hashToken(token), used: false });
  if (!record || record.expiresAt < new Date()) return next(new AppError('Invalid or expired reset link', 400));

  const passwordHash = await hashPassword(newPassword);
  await User.findByIdAndUpdate(uid, { password: passwordHash, refreshTokenHash: null });

  record.used = true;
  await record.save();

  return sendSuccess(res, 200, 'Password reset successfully. Please log in with your new password.');
});

/* ---- User controller ---- */
const getProfile = catchAsync(async (req, res) => {
  return sendSuccess(res, 200, 'Profile fetched', { user: buildUserPayload(req.user) });
});

const updateProfile = catchAsync(async (req, res) => {
  const { name } = req.body;
  if (name) req.user.name = name;
  await req.user.save();
  return sendSuccess(res, 200, 'Profile updated', { user: buildUserPayload(req.user) });
});

const uploadAvatar = catchAsync(async (req, res, next) => {
  if (!req.file) return next(new AppError('No image file provided', 400));
  if (req.user.avatar?.publicId) await deleteAsset(req.user.avatar.publicId);
  const result = await uploadBuffer(req.file.buffer, 'trustlayer/avatars');
  req.user.avatar = { url: result.secure_url, publicId: result.public_id };
  await req.user.save();
  return sendSuccess(res, 200, 'Avatar uploaded', { user: buildUserPayload(req.user) });
});

const deleteAccount = catchAsync(async (req, res) => {
  if (req.user.avatar?.publicId) await deleteAsset(req.user.avatar.publicId);
  await User.findByIdAndDelete(req.user._id);
  res.clearCookie(REFRESH_COOKIE_NAME, { path: '/api/auth' });
  return sendSuccess(res, 200, 'Account deleted successfully');
});

/* ---- Scan controller ---- */
const recordScan = async (user, scanType, input, result) => {
  if (!user) return null;
  const record = await ScanHistory.create({
    user: user._id,
    scanType,
    input,
    riskScore: result.riskScore,
    classification: result.classification,
    result,
  });
  if (result.classification === 'Likely Scam') {
    sendScamAlertEmail(user.email, user.name, result.classification, result.riskScore);
  }
  return record._id;
};

const scanText = catchAsync(async (req, res, next) => {
  const { text } = req.body;
  if (!text || !text.trim()) return next(new AppError('Field "text" is required', 400));
  await consumeScan(req.user);
  const result = await analyzeTextForScam(text, 'message');
  const scanId = await recordScan(req.user, 'text', { text }, result);
  return sendSuccess(res, 200, 'Text analyzed', { ...result, scanId });
});

const scanUrl = catchAsync(async (req, res, next) => {
  const { url } = req.body;
  if (!url) return next(new AppError('Field "url" is required', 400));
  await consumeScan(req.user);
  const result = await analyzeUrl(url);
  const scanId = await recordScan(req.user, 'url', { url }, result);
  return sendSuccess(res, 200, 'URL analyzed', { ...result, scanId });
});

const scanEmail = catchAsync(async (req, res, next) => {
  const { sender, subject, body: emailBody } = req.body;
  if (!emailBody || !emailBody.trim()) return next(new AppError('Field "body" is required', 400));
  await consumeScan(req.user);
  const result = await analyzeEmailForScam({ sender, subject, body: emailBody });
  const scanId = await recordScan(req.user, 'email', { sender, subject, body: emailBody }, result);
  return sendSuccess(res, 200, 'Email analyzed', { ...result, scanId });
});

const scanImage = catchAsync(async (req, res, next) => {
  if (!req.file) return next(new AppError('An image file is required', 400));
  await consumeScan(req.user);
  const extractedText = await extractTextFromImage(req.file.buffer);

  if (!extractedText) {
    return sendSuccess(res, 200, 'No readable text found in image', {
      riskScore: 0,
      classification: 'Safe',
      confidence: 0,
      reasons: ['No text could be extracted from the image.'],
      recommendation: 'Try uploading a clearer image if you expected text to be detected.',
      extractedText: '',
    });
  }

  const result = await analyzeTextForScam(extractedText, 'text extracted from an image');
  result.extractedText = extractedText;
  const scanId = await recordScan(req.user, 'image', { extractedText }, result);
  return sendSuccess(res, 200, 'Image analyzed', { ...result, scanId });
});

const scanQr = catchAsync(async (req, res, next) => {
  if (!req.file) return next(new AppError('An image file containing a QR code is required', 400));
  await consumeScan(req.user);
  const decoded = await decodeQrCode(req.file.buffer);

  let result;
  if (/^https?:\/\//i.test(decoded)) {
    result = await analyzeUrl(decoded);
  } else {
    result = await analyzeTextForScam(decoded, 'QR code payload');
  }
  result.decodedValue = decoded;
  const scanId = await recordScan(req.user, 'qr', { decodedValue: decoded }, result);
  return sendSuccess(res, 200, 'QR code analyzed', { ...result, scanId });
});

const checkPhone = catchAsync(async (req, res, next) => {
  const { phoneNumber } = req.body;
  if (!phoneNumber) return next(new AppError('Field "phoneNumber" is required', 400));
  await consumeScan(req.user);
  const result = await analyzePhone(phoneNumber);
  const scanId = await recordScan(req.user, 'phone', { phoneNumber }, result);
  return sendSuccess(res, 200, 'Phone number analyzed', { ...result, scanId });
});

/* ---- History controller ---- */
const getHistory = catchAsync(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(50, parseInt(req.query.limit, 10) || 20);
  const skip = (page - 1) * limit;

  const filter = { user: req.user._id };
  if (req.query.scanType) filter.scanType = req.query.scanType;

  const [items, total] = await Promise.all([
    ScanHistory.find(filter).sort({ createdAt: -1 }).skip(skip).limit(limit),
    ScanHistory.countDocuments(filter),
  ]);

  return sendSuccess(res, 200, 'History fetched', { items }, {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
});

const deleteHistoryItem = catchAsync(async (req, res, next) => {
  const item = await ScanHistory.findOne({ _id: req.params.id, user: req.user._id });
  if (!item) return next(new AppError('History item not found', 404));
  await item.deleteOne();
  return sendSuccess(res, 200, 'History item deleted');
});

/* ---- Dashboard controller ---- */
const startOfToday = () => {
  const d = new Date();
  d.setHours(0, 0, 0, 0);
  return d;
};
const startOfWeek = () => {
  const d = new Date();
  d.setDate(d.getDate() - 7);
  return d;
};

const getDashboard = catchAsync(async (req, res) => {
  const userId = req.user._id;
  const [totalScans, todayScans, weeklyScans, scamDetections, safeDetections] = await Promise.all([
    ScanHistory.countDocuments({ user: userId }),
    ScanHistory.countDocuments({ user: userId, createdAt: { $gte: startOfToday() } }),
    ScanHistory.countDocuments({ user: userId, createdAt: { $gte: startOfWeek() } }),
    ScanHistory.countDocuments({ user: userId, classification: 'Likely Scam' }),
    ScanHistory.countDocuments({ user: userId, classification: 'Safe' }),
  ]);

  return sendSuccess(res, 200, 'Dashboard fetched', {
    totalScans,
    todayScans,
    weeklyScans,
    scamDetections,
    safeDetections,
    subscriptionStatus: req.user.subscriptionStatus,
    plan: req.user.plan,
    scansRemaining: req.user.plan === 'enterprise' ? 'unlimited' : req.user.scansRemaining,
  });
});

/* ---- Subscription controller ---- */
const subscribe = catchAsync(async (req, res, next) => {
  const { plan } = req.body;
  if (!plan) return next(new AppError('Field "plan" is required ("premium" or "enterprise")', 400));
  const session = await createCheckoutSession(req.user, plan);
  return sendSuccess(res, 200, 'Checkout session created', { checkoutUrl: session.url });
});

const stripeWebhook = catchAsync(async (req, res, next) => {
  const signature = req.headers['stripe-signature'];
  let event;
  try {
    event = stripe.webhooks.constructEvent(req.body, signature, process.env.STRIPE_WEBHOOK_SECRET);
  } catch (err) {
    return next(new AppError(`Webhook signature verification failed: ${err.message}`, 400));
  }
  await handleStripeWebhookEvent(event);
  res.status(200).json({ received: true });
});

/* ---- Admin controller ---- */
const listUsers = catchAsync(async (req, res) => {
  const page = Math.max(1, parseInt(req.query.page, 10) || 1);
  const limit = Math.min(100, parseInt(req.query.limit, 10) || 25);
  const skip = (page - 1) * limit;

  const [users, total] = await Promise.all([
    User.find().sort({ createdAt: -1 }).skip(skip).limit(limit),
    User.countDocuments(),
  ]);

  return sendSuccess(res, 200, 'Users fetched', { users }, {
    page,
    limit,
    total,
    totalPages: Math.ceil(total / limit),
  });
});

const deleteUser = catchAsync(async (req, res, next) => {
  const user = await User.findByIdAndDelete(req.params.id);
  if (!user) return next(new AppError('User not found', 404));
  await ScanHistory.deleteMany({ user: req.params.id });
  return sendSuccess(res, 200, 'User deleted');
});

const getAnalytics = catchAsync(async (req, res) => {
  const [totalUsers, totalScans, scamDetections, planBreakdown] = await Promise.all([
    User.countDocuments(),
    ScanHistory.countDocuments(),
    ScanHistory.countDocuments({ classification: 'Likely Scam' }),
    User.aggregate([{ $group: { _id: '$plan', count: { $sum: 1 } } }]),
  ]);

  return sendSuccess(res, 200, 'Analytics fetched', { totalUsers, totalScans, scamDetections, planBreakdown });
});

const getReports = catchAsync(async (req, res) => {
  const recentScamReports = await ScanHistory.find({ classification: 'Likely Scam' })
    .sort({ createdAt: -1 })
    .limit(100)
    .populate('user', 'name email');

  return sendSuccess(res, 200, 'Reports fetched', { recentScamReports });
});

const getRevenue = catchAsync(async (req, res) => {
  const activeSubscriptions = await Subscription.find({ status: 'active' });
  const PLAN_PRICES = { premium: 19, enterprise: 99 };
  const mrr = activeSubscriptions.reduce((sum, sub) => sum + (PLAN_PRICES[sub.plan] || 0), 0);

  return sendSuccess(res, 200, 'Revenue fetched', {
    activeSubscriptions: activeSubscriptions.length,
    estimatedMonthlyRecurringRevenue: mrr,
    note: 'Estimated from local subscription records. Reconcile against Stripe Dashboard for exact figures.',
  });
});

/* ============================================================================
 * 8. ROUTERS + APP ASSEMBLY
 * ========================================================================== */

const app = express();

connectDB();

app.set('trust proxy', 1);

app.use(helmet());
app.use(cors({ origin: process.env.CLIENT_URL || '*', credentials: true }));
app.use(compression());
app.use(requestLogger);

/* ---- Auth routes ---- */
const authRouter = express.Router();

authRouter.post(
  '/register',
  authLimiter,
  validate([
    body('name').trim().notEmpty().withMessage('Name is required'),
    body('email').isEmail().withMessage('A valid email is required').normalizeEmail(),
    body('password').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  ]),
  register
);
authRouter.post(
  '/login',
  authLimiter,
  validate([
    body('email').isEmail().withMessage('A valid email is required').normalizeEmail(),
    body('password').notEmpty().withMessage('Password is required'),
  ]),
  login
);
authRouter.post('/logout', logout);
authRouter.post('/refresh', refresh);
authRouter.post(
  '/verify-email',
  validate([
    body('token').notEmpty().withMessage('Token is required'),
    body('uid').isMongoId().withMessage('Valid user ID is required'),
  ]),
  verifyEmail
);
authRouter.post(
  '/forgot-password',
  authLimiter,
  validate([body('email').isEmail().withMessage('A valid email is required').normalizeEmail()]),
  forgotPassword
);
authRouter.post(
  '/reset-password',
  authLimiter,
  validate([
    body('token').notEmpty().withMessage('Token is required'),
    body('uid').isMongoId().withMessage('Valid user ID is required'),
    body('newPassword').isLength({ min: 8 }).withMessage('Password must be at least 8 characters'),
  ]),
  resetPassword
);

/* ---- User routes ---- */
const userRouter = express.Router();
userRouter.use(authenticate);
userRouter.get('/profile', getProfile);
userRouter.put(
  '/profile',
  validate([body('name').optional().trim().notEmpty().withMessage('Name cannot be empty')]),
  updateProfile
);
userRouter.post('/avatar', upload.single('avatar'), uploadAvatar);
userRouter.delete('/account', deleteAccount);

/* ---- Scan routes (also exposes /check/phone) ---- */
const scanRouter = express.Router();
scanRouter.use(optionalAuthenticate, scanLimiter);
scanRouter.post(
  '/scan/text',
  validate([body('text').isString().trim().notEmpty().withMessage('Field "text" is required')]),
  scanText
);
scanRouter.post(
  '/scan/url',
  validate([body('url').isURL({ require_protocol: true }).withMessage('A valid http(s) URL is required')]),
  scanUrl
);
scanRouter.post(
  '/scan/email',
  validate([
    body('body').isString().trim().notEmpty().withMessage('Field "body" is required'),
    body('sender').optional().isString().trim(),
    body('subject').optional().isString().trim(),
  ]),
  scanEmail
);
scanRouter.post('/scan/image', upload.single('image'), scanImage);
scanRouter.post('/scan/qr', upload.single('image'), scanQr);
scanRouter.post(
  '/check/phone',
  validate([body('phoneNumber').isString().trim().notEmpty().withMessage('Field "phoneNumber" is required')]),
  checkPhone
);

/* ---- History routes ---- */
const historyRouter = express.Router();
historyRouter.use(authenticate);
historyRouter.get('/', getHistory);
historyRouter.delete('/:id', deleteHistoryItem);

/* ---- Dashboard route ---- */
const dashboardRouter = express.Router();
dashboardRouter.get('/', authenticate, getDashboard);

/* ---- Subscription routes ---- */
const subscriptionRouter = express.Router();
subscriptionRouter.post(
  '/',
  authenticate,
  validate([body('plan').isIn(['premium', 'enterprise']).withMessage('Plan must be "premium" or "enterprise"')]),
  subscribe
);

/* ---- Stripe webhook router (raw body only) ---- */
const webhookRouter = express.Router();
webhookRouter.post('/', express.raw({ type: 'application/json' }), stripeWebhook);

/* ---- Admin routes ---- */
const adminRouter = express.Router();
adminRouter.use(authenticate, requireAdmin);
adminRouter.get('/users', listUsers);
adminRouter.delete('/users/:id', deleteUser);
adminRouter.get('/analytics', getAnalytics);
adminRouter.get('/reports', getReports);
adminRouter.get('/revenue', getRevenue);

/* ---- Mount: Stripe webhook BEFORE the JSON body parser (needs raw body) ---- */
app.use('/api/webhook', webhookRouter);

/* ---- Standard body parsing for every other route ---- */
app.use(express.json({ limit: '2mb' }));
app.use(express.urlencoded({ extended: true, limit: '2mb' }));
app.use(cookieParser());
app.use(sanitizeInputs);

/* ---- Global API rate limiting ---- */
app.use('/api', apiLimiter);

/* ---- Health check ---- */
app.get('/api/health', (req, res) => {
  res.status(200).json({ success: true, message: 'TrustLayer API is healthy', timestamp: new Date().toISOString() });
});

/* ---- Mount remaining routers ---- */
app.use('/api/auth', authRouter);
app.use('/api/user', userRouter);
app.use('/api', scanRouter); // exposes /api/scan/* and /api/check/phone
app.use('/api/history', historyRouter);
app.use('/api/dashboard', dashboardRouter);
app.use('/api/subscribe', subscriptionRouter);
app.use('/api/admin', adminRouter);

/* ---- Static files ---- */
app.use('/public', express.static(path.join(__dirname, 'public')));

/* ---- 404 + centralized error handling (must be mounted last) ---- */
app.use(notFound);
app.use(errorHandler);

const PORT = process.env.PORT || 5000;

const server = app.listen(PORT, () => {
  console.log(`[Server] TrustLayer API running on port ${PORT} in ${process.env.NODE_ENV || 'development'} mode`);
});

process.on('SIGTERM', () => {
  console.log('[Server] SIGTERM received. Shutting down gracefully.');
  server.close(() => process.exit(0));
});

process.on('unhandledRejection', (reason) => {
  console.error('[Server] Unhandled Promise Rejection:', reason);
});

module.exports = app;
