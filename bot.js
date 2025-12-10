/**
 * PikaShort V20 GOD++++++
 * Final complete bot core (split into parts)
 *
 * Paste each part sequentially into a single file named `bot.js`
 * (or save each part and then concatenate).
 *
 * ENV variables required (set on Render / host):
 *   TELEGRAM_BOT_TOKEN   - required
 *   ADMIN_ID             - required (primary admin chat id)
 *   ADMIN_PASSWORD       - required (admin dashboard password)
 *   DASHBOARD_SECRET     - required (dashboard auth token)
 *   PORT                 - optional (default 8080)
 *   INACTIVE_DAYS        - optional (default 2)
 *   UPLOAD_MAX_MB        - optional (default 50)
 *
 * Dependencies:
 *   npm i express express-session multer axios node-telegram-bot-api mime-types bcrypt jsonwebtoken
 *
 * Note: This file is split for safe transfer. After you receive all parts,
 * combine them into one `bot.js` and run `node bot.js`.
 */

/* ================== PART 1: IMPORTS, CONFIG, PATHS, DB HELPERS ================== */

const fs = require('fs');
const path = require('path');
const express = require('express');
const session = require('express-session');
const multer = require('multer');
const axios = require('axios');
const TelegramBot = require('node-telegram-bot-api');
const mime = require('mime-types');
const bcrypt = require('bcrypt'); // used later if needed
const jwt = require('jsonwebtoken'); // placeholder for token flows

// ---------- Config from env ----------
const BOT_TOKEN = process.env.TELEGRAM_BOT_TOKEN;
const ADMIN_ID = String(process.env.ADMIN_ID || process.env.ADMIN_CHAT_ID || '');
const ADMIN_PASSWORD = String(process.env.ADMIN_PASSWORD || '');
const DASHBOARD_SECRET = process.env.DASHBOARD_SECRET || '';
const PORT = Number(process.env.PORT || 8080);
const INACTIVE_DAYS = Number(process.env.INACTIVE_DAYS || 2);
const UPLOAD_MAX_MB = Number(process.env.UPLOAD_MAX_MB || 50);

// Validate required envs early
if (!BOT_TOKEN) { console.error('❌ TELEGRAM_BOT_TOKEN missing'); process.exit(1); }
if (!ADMIN_ID)   { console.error('❌ ADMIN_ID missing'); process.exit(1); }
if (!ADMIN_PASSWORD) { console.error('❌ ADMIN_PASSWORD missing'); process.exit(1); }
if (!DASHBOARD_SECRET) { console.error('❌ DASHBOARD_SECRET missing'); process.exit(1); }

// ---------- Paths ----------
const ROOT = process.cwd();
const DB_PATH = path.join(ROOT, 'database.json');
const UPLOADS_DIR = path.join(ROOT, 'src', 'dashboard', 'uploads');
const BACKUP_DIR = path.join(ROOT, 'backups');

// ensure directories exist
function ensureDir(p) {
  try { if (!fs.existsSync(p)) fs.mkdirSync(p, { recursive: true }); } catch(e) { console.error('mkdir err', e); }
}
ensureDir(path.dirname(DB_PATH));
ensureDir(UPLOADS_DIR);
ensureDir(BACKUP_DIR);

// ---------- Initialize Telegram bot ----------
const bot = new TelegramBot(BOT_TOKEN, { polling: true });

// ---------- Simple JSON DB helpers ----------
function defaultDB() {
  return {
    tokens: {},            // chatId -> apiKey
    lastActive: {},        // chatId -> timestamp
    admins: [ADMIN_ID],    // admin ids
    roles: {},             // chatId -> role
    premium: [],           // premium users
    adsMessage: '🔥 Special Offer! Shorten links & earn more 🚀',
    headerText: '',
    footerText: '',
    inactiveMessage: "👋 Hey! It’s been a while since you used me.\nNeed to shorten links? Just send me any URL 🔗\nI'm here to help 😎",
    adStats: { totalSent:0, totalDelivered:0, totalFailed:0, history:[] },
    shortCache: {},        // chatId -> { originalUrl: shortUrl }
    lastUploads: [],       // upload entries
    uploadsCache: {},      // filename -> telegramFileId
    settings: {
      inactiveDays: INACTIVE_DAYS,
      maintenance: false,
      requireJoinChannel: null // optional channel id for join-to-use
    }
  };
}

function readDB() {
  try {
    const raw = fs.readFileSync(DB_PATH, 'utf8');
    const parsed = JSON.parse(raw || '{}');
    return Object.assign(defaultDB(), parsed);
  } catch (e) {
    const d = defaultDB();
    fs.writeFileSync(DB_PATH, JSON.stringify(d, null, 2));
    return d;
  }
}

function writeDB(db) {
  try {
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
  } catch (e) {
    console.error('writeDB error', e);
  }
}

/* ================== PART 1 UTILS ================== */

// Escape text for MarkdownV2
function escapeMdV2(text='') {
  return String(text).replace(/([_*[\]()~`>#+\-=|{}.!\\])/g, '\\$1');
}
function now() { return Date.now(); }
function sleep(ms){ return new Promise(r=>setTimeout(r, ms)); }

// validate chat id
function isValidChatId(id) {
  return /^[0-9]{5,20}$/.test(String(id));
}

/* ================== RATE LIMIT (per-user) ================== */
const RATE_WINDOW_MS = 10_000;
const RATE_MAX = 8;
const rateMap = {}; // chatId -> timestamps
function rateAllow(chatId) {
  const arr = rateMap[chatId] || [];
  const cutoff = Date.now() - RATE_WINDOW_MS;
  const keep = arr.filter(ts => ts > cutoff);
  if (keep.length >= RATE_MAX) { rateMap[chatId] = keep; return false; }
  keep.push(Date.now());
  rateMap[chatId] = keep;
  return true;
}

/* ================== BROADCAST QUEUE CLASS ================== */
class BroadcastQueue {
  constructor(concurrency=3, batchSize=25, delayMs=1200) {
    this.queue = [];
    this.running = 0;
    this.concurrency = concurrency;
    this.batchSize = batchSize;
    this.delayMs = delayMs;
  }

  push(job) {
    this.queue.push(job);
    setImmediate(()=>this._process());
  }

  size() { return this.queue.length + this.running; }

  async _process() {
    if (this.running >= this.concurrency) return;
    const job = this.queue.shift();
    if (!job) return;
    this.running++;
    try {
      if (job.type === 'text') await this._runText(job.payload);
      else if (job.type === 'media') await this._runMedia(job.payload);
    } catch(e) {
      console.error('BroadcastQueue job error', e);
    } finally {
      this.running--;
      setImmediate(()=>this._process());
    }
  }

  async _runText({ text, users }) {
    let delivered = 0, failed = 0;
    for (let i=0; i<users.length; i+=this.batchSize) {
      const batch = users.slice(i, i+this.batchSize);
      await Promise.all(batch.map(async uid => {
        try { await bot.sendMessage(uid, text, { parse_mode: 'Markdown' }); delivered++; } catch(e) { failed++; }
      }));
      await sleep(this.delayMs);
    }
    const db = readDB();
    db.adStats.totalSent += users.length;
    db.adStats.totalDelivered += delivered;
    db.adStats.totalFailed += failed;
    db.adStats.history.unshift({ id: now(), type: 'text', delivered, failed, preview: text.slice(0,200) });
    if (db.adStats.history.length > 400) db.adStats.history.pop();
    writeDB(db);
  }

  async _runMedia({ fileId, mediaType, caption, users }) {
    let delivered = 0, failed = 0;
    for (let i=0; i<users.length; i+=this.batchSize) {
      const batch = users.slice(i, i+this.batchSize);
      await Promise.all(batch.map(async uid => {
        try {
          if (mediaType === 'image') await bot.sendPhoto(uid, fileId, { caption, parse_mode: 'Markdown' });
          else if (mediaType === 'video') await bot.sendVideo(uid, fileId, { caption, parse_mode: 'Markdown' });
          else await bot.sendDocument(uid, fileId, { caption, parse_mode: 'Markdown' });
          delivered++;
        } catch(e) { failed++; }
      }));
      await sleep(this.delayMs);
    }
    const db = readDB();
    db.adStats.totalSent += users.length;
    db.adStats.totalDelivered += delivered;
    db.adStats.totalFailed += failed;
    db.adStats.history.unshift({ id: now(), type: 'media', mediaType, fileId, delivered, failed });
    if (db.adStats.history.length > 400) db.adStats.history.pop();
    writeDB(db);
  }
}

const bqueue = new BroadcastQueue(3, 25, 1200);

/* ================== SHORTENER HELPERS ================== */

// Basic live validation of smallshorturl API key
async function validateApiLive(apiKey) {
  if (!apiKey) return false;
  try {
    const test = `https://smallshorturl.myvippanel.shop/api?api=${encodeURIComponent(apiKey)}&url=${encodeURIComponent('https://google.com')}`;
    const r = await axios.get(test, { timeout: 10000 });
    const d = r.data || {};
    return !!(d.shortenedUrl || d.short || d.url || (d.data && d.data.shortenedUrl));
  } catch(e) {
    return false;
  }
}

async function shortenViaApi(apiKey, longUrl) {
  try {
    const url = `https://smallshorturl.myvippanel.shop/api?api=${encodeURIComponent(apiKey)}&url=${encodeURIComponent(longUrl)}`;
    const r = await axios.get(url, { timeout: 15000 });
    const d = r.data || {};
    return d.shortenedUrl || d.short || d.url || (d.data && d.data.shortenedUrl) || null;
  } catch(e) {
    return null;
  }
}

/* ================== MULTER UPLOAD SETUP ================== */
const storage = multer.diskStorage({
  destination: (req, file, cb) => cb(null, UPLOADS_DIR),
  filename: (req, file, cb) => cb(null, Date.now() + '-' + file.originalname.replace(/\s+/g,'_'))
});
const upload = multer({ storage, limits: { fileSize: UPLOAD_MAX_MB * 1024 * 1024 } });

/* ================== EXPRESS APP & MIDDLEWARE ================== */
const app = express();
app.use(express.json({ limit: '30mb' }));
app.use(express.urlencoded({ extended: true }));
app.use('/dashboard/static', express.static(path.join(ROOT, 'src', 'dashboard')));
app.use('/dashboard/static/uploads', express.static(UPLOADS_DIR));
app.use(session({ secret: DASHBOARD_SECRET, resave: false, saveUninitialized: false, cookie: { maxAge: 24*60*60*1000 } }));

function requireAuth(req, res, next) {
  const token = req.headers['x-auth-token'] || req.body.token || req.query.token || (req.session && req.session.token);
  if (token === DASHBOARD_SECRET) return next();
  return res.status(403).json({ ok:false, error:'unauth' });
}

/* End of Part 1 */
/* ================== PART 2: BOT COMMANDS, MESSAGE HANDLERS, ADMIN INTERACTIONS ================== */

/* ---------- Helper: format success message ---------- */
function formatShortSuccess(orig, short) {
  // Original and Short in a neat layout using MarkdownV2 (short in monospace)
  return `✨✨ Congratulations! Your URL has been successfully shortened! 🚀🔗\n\n` +
         `*Original URL:*\n${escapeMdV2(orig)}\n\n` +
         `🌐 *Shortened URL:*\n\`${escapeMdV2(short)}\``;
}

/* ---------- Bot: /start ---------- */
bot.onText(/^\/start(@\S+)?(\s+.*)?$/i, (msg) => {
  try {
    const db = readDB();
    const chatId = String(msg.chat.id);
    const username = (msg.from && (msg.from.first_name || msg.from.username)) ? (msg.from.first_name || msg.from.username) : 'User';
    db.lastActive[chatId] = now();
    writeDB(db);

    const dashboardLink = 'https://smallshorturl.myvippanel.shop/member/tools/api';
    const text =
      `👋 Hello *${escapeMdV2(username)}*! \n\n` +
      `Send your *Smallshorturl API Key* from *[Dashboard](${dashboardLink})* (use /api YOUR_API_KEY)\n\n` +
      `Once your API key is set, just send any link — I will shorten it instantly 🔗🚀`;

    bot.sendMessage(chatId, text, { parse_mode: 'MarkdownV2' }).catch(() => {});
  } catch (e) {
    console.error('/start handler error', e);
  }
});

/* ---------- Bot: /api <key> — set & validate user's API key ---------- */
bot.onText(/\/api\s+(.+)/i, async (msg, match) => {
  try {
    const chatId = String(msg.chat.id);
    const key = (match && match[1]) ? String(match[1]).trim() : '';
    if (!key) return bot.sendMessage(chatId, '❌ Please provide your API key. Usage: /api YOUR_API_KEY');

    const db = readDB();
    db.lastActive[chatId] = now();
    writeDB(db);

    if (key.length < 6) return bot.sendMessage(chatId, '❌ API key too short.');
    const ok = await validateApiLive(key);
    if (!ok) return bot.sendMessage(chatId, '❌ Invalid API. Please verify it on your Smallshorturl dashboard.');

    db.tokens[chatId] = key;
    db.shortCache = db.shortCache || {};
    db.shortCache[chatId] = db.shortCache[chatId] || {};
    writeDB(db);
    return bot.sendMessage(chatId, '✅ Your Smallshorturl API Key has been saved successfully!');
  } catch (e) {
    console.error('/api err', e);
    return bot.sendMessage(msg.chat.id, '❌ Something went wrong while saving the API.');
  }
});

/* ---------- Pending interactive map for admin actions ---------- */
const pendingMap = {}; // adminChatId -> { type: 'sendto'|'adText'|'imgBroadcast'|'vidBroadcast', meta: {...}, timeout }

/* ---------- Utility to set pending state ---------- */
function setPending(adminId, obj, timeoutMs = 2 * 60 * 1000) {
  if (pendingMap[adminId] && pendingMap[adminId].timeout) clearTimeout(pendingMap[adminId].timeout);
  const to = setTimeout(() => { delete pendingMap[adminId]; try { bot.sendMessage(adminId, '⏳ Action timed out.'); } catch {} }, timeoutMs);
  pendingMap[adminId] = Object.assign({}, obj, { timeout: to });
}

/* ---------- Bot: /sendto <chatId> (interactive) ---------- */
bot.onText(/^\/sendto\s+([0-9]{5,20})$/i, (msg, match) => {
  try {
    const admin = String(msg.chat.id);
    const target = String(match[1]);
    const db = readDB();
    if (!db.admins.includes(admin) && admin !== ADMIN_ID) return; // silent for security

    if (!isValidChatId(target)) return bot.sendMessage(admin, '❌ Invalid chat id.');

    setPending(admin, { type: 'sendto', meta: { target } });
    bot.sendMessage(admin, `✅ Send the message (text/photo/video/document) you want to forward to *${escapeMdV2(target)}* now. I will forward the next message you send (2 min).`, { parse_mode: 'MarkdownV2' });
  } catch (e) { console.error('/sendto err', e); }
});

/* ---------- Bot: /sendads (interactive or inline) ---------- */
bot.onText(/^\/sendads(?:\s+(.+))?$/i, (msg, match) => {
  try {
    const admin = String(msg.chat.id);
    const db = readDB();
    if (!db.admins.includes(admin) && admin !== ADMIN_ID) return;
    const text = (match && match[1]) ? String(match[1]).trim() : null;
    if (!text) {
      setPending(admin, { type: 'adText' });
      return bot.sendMessage(admin, '📣 Send the ad text (next message). I will broadcast to all users.', { parse_mode: 'Markdown' });
    }
    // immediate send
    const users = Object.keys(db.lastActive || {});
    bqueue.push({ type: 'text', payload: { text, users } });
    return bot.sendMessage(admin, `📢 Ad queued to ${users.length} users.`);
  } catch (e) { console.error('/sendads err', e); }
});

/* ---------- Bot: /sendimgads & /sendvideoads (interactive) ---------- */
bot.onText(/^\/sendimgads$/i, (msg) => {
  try {
    const admin = String(msg.chat.id);
    const db = readDB();
    if (!db.admins.includes(admin) && admin !== ADMIN_ID) return;
    setPending(admin, { type: 'imgBroadcast' });
    bot.sendMessage(admin, '📸 Send the image (photo) you want to broadcast (caption optional). I will forward it to all users.');
  } catch (e) { console.error('/sendimgads err', e); }
});
bot.onText(/^\/sendvideoads$/i, (msg) => {
  try {
    const admin = String(msg.chat.id);
    const db = readDB();
    if (!db.admins.includes(admin) && admin !== ADMIN_ID) return;
    setPending(admin, { type: 'vidBroadcast' });
    bot.sendMessage(admin, '🎬 Send the video you want to broadcast (caption optional). I will forward it to all users.');
  } catch (e) { console.error('/sendvideoads err', e); }
});

/* ---------- Bot: Generic message handler (URLs, pending admin actions) ---------- */
bot.on('message', async (msg) => {
  try {
    if (!msg) return;
    const chatId = String(msg.chat.id);
    const text = msg.text || msg.caption || '';

    // 1) If admin has pending action — capture it first (sendto, adText, imgBroadcast, vidBroadcast)
    if (pendingMap[chatId]) {
      const pending = pendingMap[chatId];
      // clear timeout and remove pending
      clearTimeout(pending.timeout);
      delete pendingMap[chatId];

      if (pending.type === 'sendto') {
        const target = pending.meta.target;
        try {
          if (msg.photo) {
            const fid = msg.photo[msg.photo.length - 1].file_id;
            await bot.sendPhoto(target, fid, { caption: msg.caption || '', parse_mode: 'Markdown' });
          } else if (msg.video) {
            await bot.sendVideo(target, msg.video.file_id, { caption: msg.caption || '', parse_mode: 'Markdown' });
          } else if (msg.document) {
            await bot.sendDocument(target, msg.document.file_id, { caption: msg.caption || '', parse_mode: 'Markdown' });
          } else if (msg.text) {
            await bot.sendMessage(target, msg.text, { parse_mode: 'Markdown' });
          } else {
            await bot.sendMessage(chatId, '❌ Unsupported message type for forwarding.');
            return;
          }
          await bot.sendMessage(chatId, '✅ Message forwarded successfully.');
        } catch (e) {
          console.error('sendto forward err', e);
          await bot.sendMessage(chatId, '❌ Failed to forward message.');
        }
        return;
      }

      if (pending.type === 'adText') {
        const adText = msg.text || msg.caption || '';
        const db = readDB();
        const users = Object.keys(db.lastActive || {});
        bqueue.push({ type: 'text', payload: { text: adText, users } });
        await bot.sendMessage(chatId, `📢 Ad queued to ${users.length} users.`);
        return;
      }

      if (pending.type === 'imgBroadcast' && msg.photo) {
        const fid = msg.photo[msg.photo.length - 1].file_id;
        const caption = msg.caption || '';
        const db = readDB();
        const users = Object.keys(db.lastActive || {});
        bqueue.push({ type: 'media', payload: { fileId: fid, mediaType: 'image', caption, users } });
        await bot.sendMessage(chatId, `📢 Image ad queued to ${users.length} users.`);
        return;
      }

      if (pending.type === 'vidBroadcast' && msg.video) {
        const fid = msg.video.file_id;
        const caption = msg.caption || '';
        const db = readDB();
        const users = Object.keys(db.lastActive || {});
        bqueue.push({ type: 'media', payload: { fileId: fid, mediaType: 'video', caption, users } });
        await bot.sendMessage(chatId, `📢 Video ad queued to ${users.length} users.`);
        return;
      }

      // If pending type doesn't match incoming content:
      await bot.sendMessage(chatId, '❌ The message you sent does not match the expected type. Please retry the command.');
      return;
    }

    // 2) Ignore commands here (they are handled via onText)
    if ((text || '').trim().startsWith('/')) return;

    // 3) Maintenance mode check
    const dbNow = readDB();
    if (dbNow.settings && dbNow.settings.maintenance) {
      await bot.sendMessage(chatId, '⚠️ Bot is under maintenance. Please try again later.');
      return;
    }

    // 4) Extract URLs
    const urls = (text && typeof text === 'string') ? (() => {
      const re = /(https?:\/\/[^\s'"]+|www\.[^\s'"]+|[a-z0-9\-]+\.[a-z]{2,}(\/\S*)?)/gi;
      const matches = [...text.matchAll(re)].map(m => m[0]);
      return matches.map(u => u.startsWith('www.') ? 'http://' + u : u);
    })() : [];

    if (!urls || urls.length === 0) return;

    // 5) Rate limit per user
    if (!rateAllow(chatId)) {
      await bot.sendMessage(chatId, '⚠️ You are sending messages too quickly. Please slow down.');
      return;
    }

    // 6) Update lastActive
    dbNow.lastActive[chatId] = now();
    writeDB(dbNow);

    // 7) Ensure user has API key
    const apiKey = (dbNow.tokens || {})[chatId];
    if (!apiKey) {
      await bot.sendMessage(chatId, '❌ Please set your Smallshorturl API Key first.\nUse: /api YOUR_API_KEY', { parse_mode: 'Markdown' });
      return;
    }

    // 8) Validate API live (fast)
    const valid = await validateApiLive(apiKey);
    if (!valid) {
      await bot.sendMessage(chatId, '❌ Invalid API. Please set a valid API key via /api.');
      return;
    }

    // 9) Process each URL (use per-user cache to prevent duplicate re-shorten)
    dbNow.shortCache = dbNow.shortCache || {};
    dbNow.shortCache[chatId] = dbNow.shortCache[chatId] || {};
    const parts = [];

    for (const u of urls) {
      if (dbNow.shortCache[chatId][u]) {
        parts.push(formatShortSuccess(u, dbNow.shortCache[chatId][u]));
        continue;
      }
      const short = await shortenViaApi(apiKey, u);
      if (!short) parts.push(`⚠️ Could not shorten: ${escapeMdV2(u)}`);
      else {
        dbNow.shortCache[chatId][u] = short;
        writeDB(dbNow);
        parts.push(formatShortSuccess(u, short));
      }
    }

    const finalMsg = parts.join('\n\n---\n\n');
    await bot.sendMessage(chatId, finalMsg, { parse_mode: 'MarkdownV2' });
  } catch (e) {
    console.error('general message handler err', e);
  }
});

/* End of Part 2 */
/* ================== PART 3: DASHBOARD API + AUTH + MESSAGE EDITOR + USER LISTS ================== */

/* -------------------- WEB DASHBOARD AUTH -------------------- */
/*  Frontend sends:  { chatId, password }
    Response:
      { ok: true, token: "...jwt..." }
      { ok: false, error: "Invalid credentials" }
*/

app.post('/api/login', async (req, res) => {
  try {
    const { chatId, password } = req.body || {};

    if (!chatId || !password) {
      return res.json({ ok: false, error: "Missing credentials" });
    }

    const db = readDB();
    const isMaster = String(chatId) === String(ADMIN_ID);

    if (!isMaster && !db.admins.includes(String(chatId))) {
      return res.json({ ok: false, error: "Unauthorized chat ID" });
    }

    const correctPass = process.env.ADMIN_PASSWORD || ADMIN_PASS;
    if (password !== correctPass) {
      return res.json({ ok: false, error: "Invalid password" });
    }

    const token = jwt.sign({ chatId }, JWT_SECRET, { expiresIn: '7d' });
    return res.json({ ok: true, token });

  } catch (e) {
    console.error("Login error:", e);
    return res.json({ ok: false, error: "Server error" });
  }
});


/* --- Middleware: check JWT token --- */
function requireAuth(req, res, next) {
  try {
    const auth = req.headers.authorization;
    if (!auth) return res.status(401).json({ ok: false, error: "Missing token" });

    const token = auth.split(' ')[1];
    const payload = jwt.verify(token, JWT_SECRET);

    req.adminId = String(payload.chatId);
    next();
  } catch (e) {
    return res.status(401).json({ ok: false, error: "Invalid token" });
  }
}


/* -------------------- DASHBOARD: GET ALL DATA -------------------- */
app.get('/api/dashboard', requireAuth, (req, res) => {
  try {
    const db = readDB();

    const users = Object.keys(db.lastActive);
    const inactive = users.filter(id => Number(db.lastActive[id]) < (now() - INACTIVE_DAYS * 86400000));

    return res.json({
      ok: true,
      settings: db.settings,
      defaults: db.defaults,
      stats: {
        totalUsers: users.length,
        inactiveUsers: inactive.length,
      },
      users,
      inactive
    });

  } catch (e) {
    console.error("dashboard fetch error:", e);
    res.json({ ok: false, error: "Server error" });
  }
});


/* -------------------- UPDATE DEFAULT MESSAGES --------------------
    API:
      POST /api/updatedefaults
      { welcome, inactiveMsg, successTop, successBottom, footer }

    Example:
      { welcome: "Hello!", inactiveMsg: "Long time!" }
------------------------------------------------------------------*/

app.post('/api/updatedefaults', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const data = req.body || {};

    db.defaults = db.defaults || {};

    for (const k of Object.keys(data)) {
      if (typeof data[k] === 'string') {
        db.defaults[k] = data[k];
      }
    }

    writeDB(db);
    return res.json({ ok: true, saved: true });

  } catch (e) {
    console.error("defaults update error:", e);
    res.json({ ok: false });
  }
});


/* -------------------- UPDATE SETTINGS --------------------
    POST /api/updatesettings
    Example data:
      { maintenance: true, inactiveDays: 2 }
---------------------------------------------------------- */

app.post('/api/updatesettings', requireAuth, (req, res) => {
  try {
    const data = req.body || {};
    const db = readDB();

    db.settings = db.settings || {};

    if (typeof data.maintenance === 'boolean') {
      db.settings.maintenance = data.maintenance;
    }
    if (typeof data.inactiveDays === 'number') {
      db.settings.inactiveDays = Math.max(1, data.inactiveDays);
    }

    writeDB(db);
    return res.json({ ok: true });

  } catch (e) {
    console.error("settings update error:", e);
    res.json({ ok: false });
  }
});


/* -------------------- MANUAL INACTIVE SEND --------------------
    POST /api/sendinactive
    Sends the inactive message to all inactive users
--------------------------------------------------------------- */

app.post('/api/sendinactive', requireAuth, async (req, res) => {
  try {
    const db = readDB();
    const days = db.settings.inactiveDays || INACTIVE_DAYS;

    const limit = now() - days * 86400000;

    const inactiveIds = Object.keys(db.lastActive)
      .filter(uid => Number(db.lastActive[uid]) < limit);

    if (!db.defaults.inactiveMsg) {
      db.defaults.inactiveMsg = "👋 Hey! It’s been a while.\nSend any URL to shorten!";
      writeDB(db);
    }

    const msgText = db.defaults.inactiveMsg;

    bqueue.push({
      type: 'text',
      payload: {
        text: msgText,
        users: inactiveIds
      }
    });

    return res.json({ ok: true, count: inactiveIds.length });

  } catch (e) {
    console.error("manual inactive error:", e);
    res.json({ ok: false });
  }
});


/* -------------------- DASHBOARD SENDTO (ADMIN PANEL) --------------------
    POST /api/sendto
      { targetId, contentType, text, fileId, caption }
------------------------------------------------------------------------ */

app.post('/api/sendto', requireAuth, async (req, res) => {
  try {
    const { targetId, contentType, text, fileId, caption } = req.body || {};

    if (!targetId) return res.json({ ok: false, error: "Missing targetId" });

    if (contentType === 'text' && text) {
      await bot.sendMessage(targetId, text, { parse_mode: 'Markdown' });
    }
    else if (contentType === 'image' && fileId) {
      await bot.sendPhoto(targetId, fileId, { caption: caption || '' });
    }
    else if (contentType === 'video' && fileId) {
      await bot.sendVideo(targetId, fileId, { caption: caption || '' });
    }
    else {
      return res.json({ ok: false, error: "Invalid content" });
    }

    return res.json({ ok: true });

  } catch (e) {
    console.error("dashboard sendto error:", e);
    res.json({ ok: false, error: "Failed" });
  }
});

/* ============= END OF PART 3 ============= */
/* ================== PART 4: FINAL ROUTES, UPLOADS, SENDMEDIA, METRICS, BACKUPS, SHUTDOWN ================== */

/* ----- Fix missing env aliases (safe defaults) ----- */
const JWT_SECRET = process.env.JWT_SECRET || process.env.DASHBOARD_SECRET || 'ps_jwt_secret_change_me';
const ADMIN_PASS = process.env.ADMIN_PASSWORD || ADMIN_PASSWORD || 'afiya1310';

/* ---------- Helper endpoints used by dashboard frontends (compat layer) ---------- */

// Return simple messages/defaults (used by old dashboard script)
app.get('/api/messages', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const defaults = db.defaults || {};
    return res.json({
      ok: true,
      welcome: defaults.welcome || `👋 Hello! Send your API key via /api YOUR_API_KEY`,
      api: defaults.api || `Please set your API key.`,
      invalidApi: defaults.invalidApi || `❌ Invalid API. Please provide a valid API key.`,
      inactive: defaults.inactiveMsg || db.inactiveMessage || `👋 Hey! It's been a while...`,
      shortSuccess: defaults.shortSuccess || `✨✨ Congratulations! Your URL has been successfully shortened!`
    });
  } catch (e) {
    console.error('/api/messages err', e);
    return res.json({ ok: false });
  }
});

// Save messages (compat)
app.post('/api/saveMessages', requireAuth, (req, res) => {
  try {
    const body = req.body || {};
    const db = readDB();
    db.defaults = db.defaults || {};
    if (body.welcome) db.defaults.welcome = body.welcome;
    if (body.api) db.defaults.api = body.api;
    if (body.invalidApi) db.defaults.invalidApi = body.invalidApi;
    if (body.inactive) db.defaults.inactiveMsg = body.inactive;
    if (body.shortSuccess) db.defaults.shortSuccess = body.shortSuccess;
    writeDB(db);
    return res.json({ ok: true });
  } catch (e) {
    console.error('/api/saveMessages err', e);
    return res.json({ ok: false });
  }
});

// Users list (compat)
app.get('/api/users', requireAuth, (req, res) => {
  try {
    const q = (req.query.q || '').trim();
    const db = readDB();
    let users = Object.keys(db.lastActive || {});
    if (q) users = users.filter(u => u.includes(q));
    return res.json(users);
  } catch (e) {
    console.error('/api/users err', e);
    return res.status(500).json([]);
  }
});

// Inactive list (compat)
app.get('/api/inactive', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const threshold = (db.settings && db.settings.inactiveDays) ? db.settings.inactiveDays : INACTIVE_DAYS;
    const nowTs = now();
    const list = Object.keys(db.lastActive || {}).filter(uid => nowTs - db.lastActive[uid] >= threshold * 24*60*60*1000);
    return res.json(list);
  } catch (e) {
    console.error('/api/inactive err', e);
    return res.json([]);
  }
});

// Send Ads (compat)
app.post('/api/sendAds', requireAuth, (req, res) => {
  try {
    const text = (req.body && (req.body.msg || req.body.text)) || '';
    if (!text) return res.json({ ok: false, error: 'no_text' });
    const db = readDB();
    const users = Object.keys(db.lastActive || {});
    bqueue.push({ type: 'text', payload: { text, users } });
    return res.json({ ok: true, queued: true, targetCount: users.length });
  } catch (e) {
    console.error('/api/sendAds err', e);
    return res.json({ ok: false });
  }
});

/* -------------------- UPLOADS (compat) -------------------- */
/* POST /api/upload  (form-data 'media') */
app.post('/api/upload', requireAuth, upload.single('media'), (req, res) => {
  try {
    if (!req.file) return res.status(400).json({ ok: false, error: 'no_file' });
    const db = readDB();
    const entry = {
      id: Date.now(),
      filename: req.file.filename,
      original: req.file.originalname,
      mimetype: req.file.mimetype,
      size: req.file.size,
      path: `/dashboard/static/uploads/${req.file.filename}`,
      telegramFileId: db.uploadsCache[req.file.filename] || null,
      uploadedAt: new Date().toISOString()
    };
    db.lastUploads = db.lastUploads || [];
    db.lastUploads.unshift(entry);
    if (db.lastUploads.length > 300) db.lastUploads.pop();
    writeDB(db);
    return res.json({ ok: true, file: entry });
  } catch (e) {
    console.error('/api/upload err', e);
    return res.status(500).json({ ok: false, error: 'upload_failed' });
  }
});

// GET last uploads
app.get('/api/lastuploads', requireAuth, (req, res) => {
  try {
    const db = readDB();
    return res.json({ ok: true, lastUploads: db.lastUploads || [] });
  } catch (e) {
    console.error('/api/lastuploads err', e);
    return res.json({ ok: true, lastUploads: [] });
  }
});

/* -------------------- SEND MEDIA (compat) --------------------
   POST /api/sendmedia
   body: { uploadId, fileName, fileId, caption, mediaType, target }
   If fileId supplied, uses it. Else tries to find upload and upload to telegram temporarily to get file_id.
------------------------------------------------------------------ */
app.post('/api/sendmedia', requireAuth, async (req, res) => {
  try {
    const { uploadId, fileName, fileId, caption = '', mediaType, target } = req.body || {};
    const db = readDB();
    let telegramFileId = fileId || null;
    let entry = null;

    if (!telegramFileId && (uploadId || fileName)) {
      entry = db.lastUploads.find(e => (uploadId && e.id == uploadId) || (fileName && e.filename === fileName));
      if (!entry) return res.json({ ok: false, error: 'upload_not_found' });
      const localPath = path.join(UPLOADS_DIR, entry.filename);
      if (!fs.existsSync(localPath)) return res.json({ ok: false, error: 'file_missing' });

      try {
        let resp;
        if ((mediaType && mediaType === 'video') || entry.mimetype.startsWith('video/')) {
          resp = await bot.sendVideo(ADMIN_ID, localPath, { caption: 'upload-temp' });
          telegramFileId = resp && resp.video && resp.video.file_id ? resp.video.file_id : null;
        } else {
          resp = await bot.sendPhoto(ADMIN_ID, localPath, { caption: 'upload-temp' });
          telegramFileId = resp && resp.photo && resp.photo[resp.photo.length - 1] && resp.photo[resp.photo.length - 1].file_id ? resp.photo[resp.photo.length - 1].file_id : null;
        }
        if (telegramFileId) {
          db.uploadsCache = db.uploadsCache || {};
          db.uploadsCache[entry.filename] = telegramFileId;
          entry.telegramFileId = telegramFileId;
          writeDB(db);
          try { if (resp && resp.message_id) await bot.deleteMessage(ADMIN_ID, resp.message_id).catch(()=>{}); } catch(e){}
        }
      } catch (e) {
        console.error('upload->telegram err', e);
        return res.json({ ok: false, error: 'telegram_upload_failed' });
      }
    }

    if (!telegramFileId) return res.json({ ok: false, error: 'no_file_id' });

    let users = Object.keys(db.lastActive || {});
    if (target && isValidChatId(String(target))) users = [String(target)];

    bqueue.push({ type: 'media', payload: { fileId: telegramFileId, mediaType: mediaType || (entry && entry.mimetype && entry.mimetype.startsWith('video/') ? 'video' : 'image'), caption, users } });

    return res.json({ ok: true, queued: true });
  } catch (e) {
    console.error('/api/sendmedia err', e);
    return res.status(500).json({ ok: false, error: 'server_err' });
  }
});

/* -------------------- METRICS & INFO -------------------- */
app.get('/api/metrics', requireAuth, (req, res) => {
  try {
    const db = readDB();
    return res.json({ ok: true, users: Object.keys(db.lastActive || {}).length, queueSize: bqueue.size(), adStats: db.adStats });
  } catch (e) {
    console.error('/api/metrics err', e);
    return res.json({ ok: false });
  }
});

/* -------------------- MAP /dashboard/api/* to /api/* (compat shim) -------------------- */
app.all('/dashboard/api/*', (req, res, next) => {
  // rewrite path: /dashboard/api/foo -> /api/foo
  req.url = req.url.replace('/dashboard/api', '/api');
  next();
});

/* -------------------- MANUAL-SHORTCUT: /api/dashboard (legacy) -------------------- */
app.get('/api/data', requireAuth, (req, res) => {
  try {
    const db = readDB();
    const nowTs = now();
    const threshold = (db.settings && db.settings.inactiveDays) ? db.settings.inactiveDays : INACTIVE_DAYS;
    const inactive = Object.keys(db.lastActive || {}).filter(uid => nowTs - db.lastActive[uid] >= threshold * 24*60*60*1000);
    return res.json({ ok: true, tokens: db.tokens, lastActive: db.lastActive, admins: db.admins, adsMessage: db.adsMessage, headerText: db.headerText, footerText: db.footerText, adStats: db.adStats, inactive, lastUploads: db.lastUploads || [], settings: db.settings });
  } catch (e) {
    console.error('/api/data err', e);
    return res.json({ ok: false });
  }
});

/* -------------------- INACTIVE NOTIFIER (auto every 12 hours) -------------------- */
setInterval(async () => {
  try {
    const db = readDB();
    const threshold = (db.settings && db.settings.inactiveDays) ? db.settings.inactiveDays : INACTIVE_DAYS;
    const nowTs = now();
    const toNotify = Object.keys(db.lastActive || {}).filter(uid => nowTs - db.lastActive[uid] >= threshold * 24*60*60*1000);
    for (const uid of toNotify) {
      try {
        await bot.sendMessage(uid, db.defaults && db.defaults.inactiveMsg ? db.defaults.inactiveMsg : db.inactiveMessage);
        // update lastActive to avoid spamming repeatedly
        db.lastActive[uid] = now();
      } catch (e) {
        // ignore individual send errors
      }
    }
    writeDB(db);
  } catch (e) {
    console.error('inactive notifier err', e);
  }
}, 12 * 60 * 60 * 1000); // every 12 hours

/* -------------------- DB BACKUPS ROTATION -------------------- */
setInterval(() => {
  try {
    if (!fs.existsSync(DB_PATH)) return;
    const dest = path.join(BACKUP_DIR, `backup-${Date.now()}.json`);
    fs.copyFileSync(DB_PATH, dest);
    const files = fs.readdirSync(BACKUP_DIR).filter(f => f.startsWith('backup-')).sort();
    if (files.length > 500) {
      const remove = files.slice(0, files.length - 500);
      remove.forEach(f => fs.unlinkSync(path.join(BACKUP_DIR, f)));
    }
  } catch (e) {
    console.error('db backup err', e);
  }
}, 6 * 60 * 60 * 1000); // 6 hours

/* -------------------- GRACEFUL SHUTDOWN -------------------- */
let shuttingDown = false;
async function gracefulShutdown() {
  if (shuttingDown) return;
  shuttingDown = true;
  console.log('Graceful shutdown started...');
  const start = Date.now();
  while (bqueue.size() > 0 && (Date.now() - start) < 30_000) {
    await sleep(500);
  }
  try {
    const db = readDB();
    fs.writeFileSync(DB_PATH, JSON.stringify(db, null, 2));
  } catch (e) {}
  process.exit(0);
}
process.on('SIGINT', gracefulShutdown);
process.on('SIGTERM', gracefulShutdown);

/* -------------------- SIMPLE HEALTH + SERVE DASHBOARD -------------------- */
app.get('/', (req, res) => res.send('PikaShort V20 GOD++++++ is running.'));
app.get('/dashboard', (req, res) => {
  const token = req.headers['x-auth-token'] || req.query.token || (req.session && req.session.token);
  if (token === DASHBOARD_SECRET) return res.sendFile(path.join(ROOT, 'src', 'dashboard', 'index.html'));
  return res.redirect('/login');
});
app.get('/login', (req, res) => res.sendFile(path.join(ROOT, 'src', 'dashboard', 'login.html')));

/* -------------------- START SERVER -------------------- */
app.listen(PORT, () => {
  console.log(`PikaShort V20 GOD++++++ listening on port ${PORT}`);
  console.log('Admin ID:', ADMIN_ID);
  console.log('Dash secret present:', !!DASHBOARD_SECRET);
  console.log('Inactive days:', INACTIVE_DAYS);
});

/* ================== END OF FILE (PART 4) ================== */
