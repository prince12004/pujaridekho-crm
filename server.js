require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const bcrypt = require('bcryptjs');
const path = require('path');
const crypto = require('crypto');

process.on('uncaughtException', (err) => {
  console.error('❌ Uncaught Exception:', err.message);
  process.exit(1);
});
process.on('unhandledRejection', (reason) => {
  console.error('❌ Unhandled Rejection:', reason);
  process.exit(1);
});

const app = express();
const PORT = process.env.PORT || 3000;
const MONGODB_URI = process.env.MONGODB_URI;
const JWT_SECRET = process.env.JWT_SECRET || 'pujari-dekho-jwt-secret-2024';
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'Pujaridekho';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'Pujaridekho@#2026';

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI not set in .env');
  process.exit(1);
}

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
// Default 100kb is too small once voice-note activity logs (base64 audio,
// capped client-side at ~2 minutes) start posting through /api/activity-logs.
// `verify` stashes the raw request bytes on `req.rawBody` — the Meta/WhatsApp
// webhook signature (X-Hub-Signature-256) is computed over the exact bytes
// they sent, which can differ from re-serializing the parsed JSON.
app.use(express.json({
  // 2 minutes of voice note (base64, see ActivityLog schema below) needs
  // real headroom under this — 5mb was cutting it close enough that a
  // longer/higher-bitrate recording could hit a hard 413 on every retry.
  // Stays comfortably under MongoDB's 16MB document limit.
  limit: '12mb',
  verify: (req, _res, buf) => {
    req.rawBody = buf;
  },
}));
// Admin HTML panel (login + dashboard)
app.use(express.static(path.join(__dirname, 'public')));
// Flutter web build — served at /app (run: flutter build web --base-href /app/)
const flutterBuildPath = path.join(__dirname, '..', 'build', 'web');
app.use('/app', express.static(flutterBuildPath));

// ── Auth Middleware ──────────────────────────────────────────────────────────
// Every caller (Flutter app or web dashboard) authenticates with the same
// JWT, minted by /api/auth/login — carries { role, salesPersonId?, name },
// which the per-route data scoping below relies on.
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (auth && auth.startsWith('Bearer ')) {
    try {
      req.user = jwt.verify(auth.split(' ')[1], JWT_SECRET);
      return next();
    } catch {
      return res.status(401).json({ error: 'Invalid or expired token' });
    }
  }

  res.status(401).json({ error: 'Unauthorized' });
}

// Admin-only routes (salesperson account management, deletes) layer this on
// top of requireAuth.
function requireAdmin(req, res, next) {
  if (req.user?.role !== 'admin') {
    return res.status(403).json({ error: 'Admin only' });
  }
  next();
}

// ── Mongoose Schema ──────────────────────────────────────────────────────────
const inquirySchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    clientName: { type: String, required: true },
    phone: { type: String, required: true },
    pujaName: { type: String, required: true },
    pujaDate: { type: String, default: null },
    pujaTime: { type: String, default: null },
    status: { type: String, default: 'inquiry', enum: ['inquiry', 'confirmed', 'notConverted'] },
    totalAmount: { type: Number, default: 0 },
    tokenAmount: { type: Number, default: 0 },
    tokenStatus: { type: String, default: 'pending', enum: ['pending', 'received'] },
    // Whether the FULL totalAmount (not just the token/advance) has been
    // collected from the client — a separate flag from tokenStatus since a
    // booking can have its token received while the balance is still due.
    totalAmountStatus: { type: String, default: 'pending', enum: ['pending', 'received'] },
    transactionId: { type: String, default: null },
    nextCallDate: { type: String, default: null },
    pujariName: { type: String, default: null },
    address: { type: String, default: null },
    notes: { type: String, default: null },
    source: {
      type: String,
      default: 'other',
      enum: ['website', 'whatsapp', 'instagram', 'facebook', 'other'],
    },
    assignedTo: { type: String, default: null },
    createdAt: { type: String, required: true },
    reviewed: { type: Boolean, default: false },
    // Whether Pujari Dekho is providing the puja samagri for a confirmed
    // booking, or the client is arranging their own. Only meaningful once
    // status is 'confirmed'.
    samagriIncluded: { type: Boolean, default: false },
    // Optimistic locking (see PUT /api/inquiries/:id below). Deliberately a
    // plain app-level field rather than Mongoose's built-in `versionKey`/
    // `optimisticConcurrency`, since that mechanism only guards `.save()` —
    // this route uses `findOneAndUpdate`, so the version check has to be
    // encoded into the query filter by hand instead.
    version: { type: Number, default: 0 },
    updatedAt: { type: String, default: null },
  },
  { versionKey: false }
);

// ── Indexes ──────────────────────────────────────────────────────────────────
// Every one of these fields is queried directly by at least one route below
// (GET /api/inquiries filters/sort, GET /api/stats aggregates, the
// salesperson `ownFilter` scope applied to nearly every route). Without
// them, each of those queries is a full collection scan — fine at a few
// hundred documents, unacceptable at the 100k+ this app is sized for.
//   - assignedTo: every request from a salesperson token filters on this
//     (`ownFilter`); also the admin "filter by salesperson" query param.
//   - createdAt: the sort key for every list/pagination query (newest first)
//     and the `?cursor=` keyset condition in GET /api/inquiries.
//   - status: filtered by `?status=`, by /api/stats' confirmed/inquiry
//     counts, and by the follow-up/puja-review queue queries.
//   - nextCallDate / pujaDate: range-queried by /api/stats' "due today"
//     counts (`$regex: ^<today>`, which Mongo can use an index for since the
//     pattern is left-anchored) and by the salesperson follow-up/puja views.
//   - phone / clientName: the `?search=` filter matches against both.
// Compound indexes mirror the two dominant access patterns instead of
// forcing Mongo to intersect single-field indexes at query time:
//   - { assignedTo, createdAt } — a salesperson's own feed, sorted/paginated.
//   - { assignedTo, status, createdAt } — a salesperson's feed narrowed by
//     status (e.g. their Puja Review queue: assignedTo + status=confirmed).
//   - { status, createdAt } — admin's status-filtered, sorted list.
//   - { status, pujaDate } / { status, nextCallDate } — the /api/stats "today"
//     counts, which always filter status alongside the date range.
// Note: this does add write overhead (12 indexes to maintain per insert/
// update) — an accepted, standard tradeoff for a collection this size; see
// the migration note for how these get created on an existing database.
inquirySchema.index({ assignedTo: 1 });
inquirySchema.index({ createdAt: -1 });
inquirySchema.index({ status: 1 });
inquirySchema.index({ nextCallDate: 1 });
inquirySchema.index({ pujaDate: 1 });
inquirySchema.index({ phone: 1 });
inquirySchema.index({ clientName: 1 });
inquirySchema.index({ assignedTo: 1, createdAt: -1 });
inquirySchema.index({ assignedTo: 1, status: 1, createdAt: -1 });
inquirySchema.index({ status: 1, createdAt: -1 });
inquirySchema.index({ status: 1, pujaDate: 1 });
inquirySchema.index({ status: 1, nextCallDate: 1 });

const Inquiry = mongoose.model('Inquiry', inquirySchema);

const salesPersonSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    name: { type: String, required: true },
    phone: { type: String, required: true, unique: true },
    passwordHash: { type: String, required: true },
    active: { type: Boolean, default: true },
    createdAt: { type: String, required: true },
  },
  { versionKey: false }
);

const SalesPerson = mongoose.model('SalesPerson', salesPersonSchema);

const activityLogSchema = new mongoose.Schema(
  {
    id: { type: String, required: true, unique: true },
    inquiryId: { type: String, required: true, index: true },
    salesPersonId: { type: String, required: true },
    note: { type: String, default: '' },
    // Short per-call voice note, base64-encoded — capped client-side at ~2
    // minutes, comfortably under MongoDB's 16MB document limit.
    audioBase64: { type: String, default: null },
    createdAt: { type: String, required: true },
    isConversion: { type: Boolean, default: false },
    isReassignment: { type: Boolean, default: false },
    isRejection: { type: Boolean, default: false },
  },
  { versionKey: false }
);

const ActivityLog = mongoose.model('ActivityLog', activityLogSchema);

// ── Auth Routes (public) ─────────────────────────────────────────────────────
// One login for both admin (username/password from env vars) and
// salespeople (mobile number/password, account created by admin via
// POST /api/salespeople below). `identifier` is either the admin username
// or a salesperson's phone number — the two are checked in turn.
app.post('/api/auth/login', async (req, res) => {
  try {
    const identifier = (req.body.identifier ?? req.body.username ?? '').trim();
    const { password } = req.body;

    if (identifier === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
      const token = jwt.sign({ role: 'admin', name: ADMIN_USERNAME }, JWT_SECRET, {
        expiresIn: '30d',
      });
      return res.json({ token, role: 'admin', username: ADMIN_USERNAME });
    }

    const person = await SalesPerson.findOne({ phone: identifier, active: true });
    if (person && (await bcrypt.compare(password ?? '', person.passwordHash))) {
      const token = jwt.sign(
        { role: 'salesperson', salesPersonId: person.id, name: person.name },
        JWT_SECRET,
        { expiresIn: '30d' }
      );
      return res.json({
        token,
        role: 'salesperson',
        salesPersonId: person.id,
        name: person.name,
      });
    }

    res.status(401).json({ error: 'Invalid username/mobile number or password' });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Health check (public) ─────────────────────────────────────────────────────
app.get('/api/health', (_req, res) =>
  res.json({ status: 'ok', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' })
);

// ── Social lead webhooks (public) ─────────────────────────────────────────────
// Scaffolding only — no real Meta/WhatsApp Business API credentials exist yet.
// These verify/receive endpoints are wired up so a real integration can be
// dropped in later without touching the rest of the app. Meta/WhatsApp call
// these directly with their own verify-token/signature scheme, not the app's
// JWT/APP_TOKEN, so they must stay outside the requireAuth middleware below.

// Meta (Facebook/Instagram) webhook verification handshake — called once
// when the webhook URL is registered in the Meta App dashboard.
app.get('/api/webhooks/meta', (req, res) => {
  const VERIFY_TOKEN = process.env.META_WEBHOOK_VERIFY_TOKEN || 'pd-crm-verify-placeholder';
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// Meta (Facebook/Instagram) lead/message webhook receiver.
app.post('/api/webhooks/meta', async (req, res) => {
  // TODO(real integration): verify the X-Hub-Signature-256 header against
  // META_APP_SECRET once a real Meta app exists — unimplemented for now since
  // there's no live app secret to verify against.
  // TODO(real integration): map the actual Lead Ads/Messenger/Instagram DM
  // payload shape into { clientName, phone, pujaName, source } and create an
  // Inquiry — the shape can't be finalized without a live payload sample from
  // a connected Meta App.
  console.log('[stub] Meta webhook payload:', JSON.stringify(req.body));
  res.sendStatus(200); // Meta requires a fast 200 regardless of processing outcome
});

// WhatsApp Business Cloud API webhook verification handshake — WhatsApp is
// typically registered as its own callback URL (separate from Meta/
// Messenger above), so it needs its own GET handshake too. Reuses
// META_WEBHOOK_VERIFY_TOKEN rather than adding a second token env var.
app.get('/api/webhooks/whatsapp', (req, res) => {
  const VERIFY_TOKEN = process.env.META_WEBHOOK_VERIFY_TOKEN || 'pd-crm-verify-placeholder';
  const mode = req.query['hub.mode'];
  const token = req.query['hub.verify_token'];
  const challenge = req.query['hub.challenge'];
  if (mode === 'subscribe' && token === VERIFY_TOKEN) {
    return res.status(200).send(challenge);
  }
  return res.sendStatus(403);
});

// Strips the country code WhatsApp always includes (e.g. `919812345678`) so
// lookups match the plain 10-digit numbers the rest of the app stores (see
// the salesperson form's 10-digit validator) — without this, dedup silently
// fails to find a customer who already exists from manual entry.
function normalizeIndianPhone(raw) {
  const digits = String(raw || '').replace(/\D/g, '');
  if (digits.length === 12 && digits.startsWith('91')) return digits.slice(2);
  return digits;
}

// Auto-creates a raw lead for a genuinely new WhatsApp contact, or does
// nothing if this phone already has an "open" inquiry — i.e. this is just
// that same conversation continuing (whether it's a lead nobody's assigned
// yet, or a salesperson's existing back-and-forth with an assigned lead).
// "Open" mirrors the app's own `isCompletedPuja` idea: still `inquiry`
// status, or `confirmed` with the puja date not yet passed. Only `clientName`
// (best effort) + `phone` + `source` are ever saved — the message content
// itself is never persisted, by design.
async function handleInboundWhatsAppMessage(message, contactsByWaId) {
  const phone = normalizeIndianPhone(message.from);
  if (!phone) return;

  const today = new Date().toISOString().slice(0, 10);
  const existing = await Inquiry.find({ phone }, 'status pujaDate');
  const hasOpenLead = existing.some((r) => {
    if (r.status === 'inquiry') return true;
    if (r.status === 'confirmed') return !r.pujaDate || r.pujaDate >= today;
    return false; // notConverted, or a confirmed+completed puja — closed
  });
  if (hasOpenLead) return;

  const name = contactsByWaId[message.from];
  const nowIso = new Date().toISOString();
  const doc = new Inquiry({
    id: crypto.randomUUID(),
    clientName: name && name.trim() ? name.trim() : 'WhatsApp Lead',
    phone,
    pujaName: 'Follow Up', // matches the app's kFollowUpPlaceholder — raw, uncalled lead
    status: 'inquiry',
    source: 'whatsapp',
    assignedTo: null,
    createdAt: nowIso,
    updatedAt: nowIso,
    version: 0,
  });
  await doc.save();
}

// WhatsApp Business Cloud API webhook receiver.
app.post('/api/webhooks/whatsapp', async (req, res) => {
  try {
    // Signature verification only enforced once a real WhatsApp app secret
    // is configured — matches this scaffolding's existing assumption that
    // no live credentials exist yet (see the file-level comment above).
    const secret = process.env.WHATSAPP_APP_SECRET;
    if (secret) {
      const signature = req.headers['x-hub-signature-256'];
      const expected =
        'sha256=' +
        crypto.createHmac('sha256', secret).update(req.rawBody || Buffer.alloc(0)).digest('hex');
      const sigBuf = Buffer.from(signature || '');
      const expectedBuf = Buffer.from(expected);
      if (sigBuf.length !== expectedBuf.length || !crypto.timingSafeEqual(sigBuf, expectedBuf)) {
        return res.sendStatus(403);
      }
    }

    for (const entry of req.body?.entry || []) {
      for (const change of entry.changes || []) {
        const value = change.value || {};
        // `value.statuses[]` (delivery/read receipts for messages *we*
        // sent) arrives on the same webhook — no `messages[]` there, so
        // there's nothing to do with it here.
        if (!Array.isArray(value.messages) || value.messages.length === 0) continue;

        const contactsByWaId = {};
        for (const c of value.contacts || []) {
          if (c.wa_id) contactsByWaId[c.wa_id] = c.profile?.name;
        }
        for (const message of value.messages) {
          await handleInboundWhatsAppMessage(message, contactsByWaId);
        }
      }
    }
  } catch (err) {
    console.error('WhatsApp webhook processing failed:', err.message);
    // Still fall through to a 200 below — Meta redelivers on non-200s and
    // there's nothing it can do to fix a processing bug on our side.
  }
  res.sendStatus(200); // Meta requires a fast 200 regardless of processing outcome
});

// ── All other API routes require auth ────────────────────────────────────────
app.use('/api', requireAuth);

// ── API Info ──────────────────────────────────────────────────────────────────
app.get('/api', (_req, res) => {
  res.json({ app: 'Pujari Dekho CRM API', version: '2.0.0', status: 'running' });
});

// ── Salespeople (admin only) ─────────────────────────────────────────────────
function toSalesPersonJson(doc) {
  return {
    id: doc.id,
    name: doc.name,
    phone: doc.phone,
    active: doc.active,
    createdAt: doc.createdAt,
  };
}

app.get('/api/salespeople', requireAdmin, async (_req, res) => {
  try {
    const docs = await SalesPerson.find().sort({ name: 1 });
    res.json(docs.map(toSalesPersonJson));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/salespeople', requireAdmin, async (req, res) => {
  try {
    const { id, name, phone, password } = req.body;
    if (!name || !phone || !password) {
      return res.status(400).json({ error: 'name, phone and password are required' });
    }
    const passwordHash = await bcrypt.hash(password, 10);
    const doc = new SalesPerson({
      id: id || `${Date.now()}_${Math.round(Math.random() * 999)}`,
      name,
      phone: phone.trim(),
      passwordHash,
      createdAt: req.body.createdAt || new Date().toISOString(),
    });
    await doc.save();
    res.status(201).json(toSalesPersonJson(doc));
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'A salesperson with this phone number already exists' });
    }
    res.status(400).json({ error: err.message });
  }
});

app.put('/api/salespeople/:id', requireAdmin, async (req, res) => {
  try {
    const update = {};
    if (req.body.name !== undefined) update.name = req.body.name;
    if (req.body.phone !== undefined) update.phone = req.body.phone.trim();
    if (req.body.active !== undefined) update.active = req.body.active;
    if (req.body.password) update.passwordHash = await bcrypt.hash(req.body.password, 10);

    const doc = await SalesPerson.findOneAndUpdate(
      { id: req.params.id },
      { $set: update },
      { new: true }
    );
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(toSalesPersonJson(doc));
  } catch (err) {
    if (err.code === 11000) {
      return res.status(409).json({ error: 'A salesperson with this phone number already exists' });
    }
    res.status(400).json({ error: err.message });
  }
});

// ── Per-user data scoping ─────────────────────────────────────────────────────
// Admin's token sees/touches everything; a salesperson's token only ever
// reaches records currently assigned to them.
function isAdmin(req) {
  return req.user?.role === 'admin';
}
function ownFilter(req) {
  return isAdmin(req) ? {} : { assignedTo: req.user.salesPersonId };
}

// ── Pagination helpers ────────────────────────────────────────────────────────
// Keyset ("seek") cursor pagination on (createdAt desc, id desc) — cheap at
// any offset (no OFFSET/skip scan), unlike page/skip which degrades linearly
// on large collections. `createdAt`/`id` are both plain strings (schema
// predates real Date fields), and every writer produces fixed-width
// `toIso8601String()` timestamps, so lexicographic string comparison already
// matches chronological order — no need to migrate the field to a real Date
// to get correct, index-friendly range queries.
function encodeCursor(doc) {
  return Buffer.from(JSON.stringify({ c: doc.createdAt, i: doc.id }), 'utf8').toString(
    'base64'
  );
}
function decodeCursor(raw) {
  try {
    const { c, i } = JSON.parse(Buffer.from(raw, 'base64').toString('utf8'));
    if (typeof c !== 'string' || typeof i !== 'string') return null;
    return { c, i };
  } catch {
    return null;
  }
}
function escapeRegex(s) {
  return s.replace(/[.*+?^${}()|[\]\\]/g, '\\$&');
}

/// Builds the Mongo filter shared by the list query and its `total` count —
/// everything except the cursor's "seek past this point" condition, which is
/// pagination-position-specific and must not affect `total`.
function buildInquiryFilter(req) {
  const filter = { ...ownFilter(req) };
  if (req.query.status) filter.status = req.query.status;
  // Admin-only: a salesperson's `ownFilter` above already pins assignedTo to
  // themselves — honoring their own `assignedTo` param here would let them
  // query another salesperson's leads.
  if (isAdmin(req) && req.query.assignedTo) {
    filter.assignedTo = req.query.assignedTo === 'unassigned' ? null : req.query.assignedTo;
  }
  const search = (req.query.search || '').trim();
  if (search) {
    const re = new RegExp(escapeRegex(search), 'i');
    filter.$or = [{ clientName: re }, { phone: re }];
  }
  return filter;
}

// ── GET all inquiries ─────────────────────────────────────────────────────────
// Backward compatible: a request with none of page/limit/cursor gets the
// original behavior (every matching record, bare JSON array) — the admin
// HTML dashboard (public/dashboard.html) still calls it exactly this way and
// isn't touched by this change. Any client that opts into page/limit/cursor
// gets the new paginated envelope below, capped at `limit` per request
// regardless of collection size.
app.get('/api/inquiries', async (req, res) => {
  try {
    const wantsPagination =
      req.query.page !== undefined || req.query.limit !== undefined || req.query.cursor;

    if (!wantsPagination) {
      const docs = await Inquiry.find(buildInquiryFilter(req)).sort({ createdAt: -1, id: -1 });
      return res.json(docs.map(toJson));
    }

    const limit = Math.min(Math.max(parseInt(req.query.limit, 10) || 50, 1), 200);
    const baseFilter = buildInquiryFilter(req);

    let queryFilter = baseFilter;
    let page = null;
    let skip = 0;
    const cursor = req.query.cursor ? decodeCursor(req.query.cursor) : null;

    if (cursor) {
      const cursorCond = {
        $or: [{ createdAt: { $lt: cursor.c } }, { createdAt: cursor.c, id: { $lt: cursor.i } }],
      };
      // buildInquiryFilter may already use `$or` for `search` — merge via
      // `$and` instead of a plain object spread so the two `$or` clauses
      // don't clobber each other.
      queryFilter = baseFilter.$or ? { $and: [baseFilter, cursorCond] } : { ...baseFilter, ...cursorCond };
    } else {
      page = Math.max(parseInt(req.query.page, 10) || 1, 1);
      skip = (page - 1) * limit;
    }

    const [docs, total] = await Promise.all([
      Inquiry.find(queryFilter)
        .sort({ createdAt: -1, id: -1 })
        .skip(skip)
        .limit(limit + 1), // fetch one extra to detect hasMore without a second count query
      Inquiry.countDocuments(baseFilter),
    ]);

    const hasMore = docs.length > limit;
    const pageDocs = hasMore ? docs.slice(0, limit) : docs;

    res.json({
      data: pageDocs.map(toJson),
      page,
      limit,
      total,
      hasMore,
      nextCursor: hasMore ? encodeCursor(pageDocs[pageDocs.length - 1]) : null,
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET single inquiry ────────────────────────────────────────────────────────
app.get('/api/inquiries/:id', async (req, res) => {
  try {
    const doc = await Inquiry.findOne({ id: req.params.id, ...ownFilter(req) });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(toJson(doc));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST create inquiry ───────────────────────────────────────────────────────
app.post('/api/inquiries', async (req, res) => {
  try {
    const body = { ...req.body };
    // Salesperson: server forces self-assignment regardless of what the
    // client sent, matching the app's own "new leads self-assign" rule.
    if (!isAdmin(req)) body.assignedTo = req.user.salesPersonId;
    // Client-supplied version/updatedAt (e.g. replaying an offline-queued
    // create) shouldn't seed a version other than the true starting point.
    body.version = 0;
    body.updatedAt = body.createdAt || new Date().toISOString();
    const doc = new Inquiry(body);
    await doc.save();
    res.status(201).json({ id: doc.id, version: doc.version, updatedAt: doc.updatedAt });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── PUT update inquiry ────────────────────────────────────────────────────────
// Optimistic locking: Client loads record (GET response includes `version`)
// → another user edits it (version increments) → this client saves with the
// `version` it originally loaded → the filter below no longer matches
// (current version has moved on) → 409 Conflict, telling the client to
// refresh instead of silently clobbering the other user's change.
// Backward compatible: a client that doesn't send `version` at all (the
// admin HTML dashboard, or an older app build) skips the check entirely and
// gets today's last-write-wins behavior — opting into the guard is what
// requires sending `version`.
app.put('/api/inquiries/:id', async (req, res) => {
  try {
    const body = { ...req.body };
    const clientVersion = body.version;
    delete body.version; // version only ever advances via the $inc below

    const filter = { id: req.params.id, ...ownFilter(req) };
    if (clientVersion !== undefined && clientVersion !== null) {
      filter.version = clientVersion;
    }

    // Ownership is checked against the *current* assignedTo, before this
    // update — so a salesperson can still send a lead back to admin
    // (assignedTo -> null) as long as they owned it going in.
    const doc = await Inquiry.findOneAndUpdate(
      filter,
      { $set: { ...body, updatedAt: new Date().toISOString() }, $inc: { version: 1 } },
      { new: true }
    );
    if (doc) return res.json({ updated: true, version: doc.version, updatedAt: doc.updatedAt });

    if (clientVersion !== undefined && clientVersion !== null) {
      // Filter may have failed on `version` (conflict) or on `id`/ownership
      // (not found/not owned) — tell those apart before deciding the status.
      const current = await Inquiry.findOne({ id: req.params.id, ...ownFilter(req) });
      if (current) {
        return res.status(409).json({
          error: 'This inquiry has been updated by another user.',
          current: toJson(current),
        });
      }
    }
    res.status(404).json({ error: 'Not found' });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── DELETE inquiry (admin only — no delete action exists on any
// salesperson screen in the app) ─────────────────────────────────────────────
app.delete('/api/inquiries/:id', requireAdmin, async (req, res) => {
  try {
    const result = await Inquiry.deleteOne({ id: req.params.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Activity log (call history, incl. voice notes) — append-only ────────────
function toActivityLogJson(doc) {
  return {
    id: doc.id,
    inquiryId: doc.inquiryId,
    salesPersonId: doc.salesPersonId,
    note: doc.note,
    audioBase64: doc.audioBase64,
    createdAt: doc.createdAt,
    isConversion: doc.isConversion,
    isReassignment: doc.isReassignment,
    isRejection: doc.isRejection,
  };
}

app.get('/api/activity-logs', async (req, res) => {
  try {
    const { inquiryId } = req.query;
    if (!inquiryId) return res.status(400).json({ error: 'inquiryId is required' });

    // Same ownership rule as GET /api/inquiries/:id — a salesperson can only
    // see logs for a lead currently assigned to them.
    const inquiry = await Inquiry.findOne({ id: inquiryId, ...ownFilter(req) });
    if (!inquiry) return res.status(404).json({ error: 'Not found' });

    const docs = await ActivityLog.find({ inquiryId }).sort({ createdAt: -1 });
    res.json(docs.map(toActivityLogJson));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Bulk activity-log fetch ───────────────────────────────────────────────────
// One round trip for a whole visible page of cards instead of the N+1
// `GET /activity-logs?inquiryId=` per card. Every requested id gets a key in
// the response, even if empty (unowned/nonexistent/no logs yet), so the
// client can tell "fetched, nothing there" apart from "never fetched".
const MAX_BULK_ACTIVITY_LOG_IDS = 200;
app.post('/api/activity-logs/bulk', async (req, res) => {
  try {
    const inquiryIds = req.body.inquiryIds;
    if (!Array.isArray(inquiryIds) || inquiryIds.length === 0) {
      return res.status(400).json({ error: 'inquiryIds must be a non-empty array' });
    }
    const ids = [...new Set(inquiryIds)].slice(0, MAX_BULK_ACTIVITY_LOG_IDS);

    // Same ownership rule as the single-record GET/POST above: a salesperson
    // only gets logs for inquiries currently assigned to them.
    const owned = await Inquiry.find({ id: { $in: ids }, ...ownFilter(req) }, 'id');
    const ownedIds = owned.map((d) => d.id);

    const result = {};
    for (const id of ids) result[id] = [];

    if (ownedIds.length > 0) {
      const docs = await ActivityLog.find({ inquiryId: { $in: ownedIds } }).sort({ createdAt: -1 });
      for (const doc of docs) {
        result[doc.inquiryId].push(toActivityLogJson(doc));
      }
    }

    res.json(result);
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

app.post('/api/activity-logs', async (req, res) => {
  try {
    const inquiry = await Inquiry.findOne({
      id: req.body.inquiryId,
      ...ownFilter(req),
    });
    if (!inquiry) return res.status(404).json({ error: 'Not found' });

    const body = { ...req.body };
    // Salesperson: server forces attribution to themselves, same
    // defense-in-depth as inquiry creation.
    if (!isAdmin(req)) body.salesPersonId = req.user.salesPersonId;

    const doc = new ActivityLog(body);
    await doc.save();
    res.status(201).json(toActivityLogJson(doc));
  } catch (err) {
    if (err.code === 11000) {
      // Same id posted twice (e.g. offline-queue retry) — treat as already
      // saved rather than an error.
      return res.status(200).json({ ok: true });
    }
    res.status(400).json({ error: err.message });
  }
});

// ── GET stats ─────────────────────────────────────────────────────────────────
app.get('/api/stats', async (req, res) => {
  try {
    const scope = ownFilter(req);
    const today = new Date().toISOString().slice(0, 10);
    const [totalRecords, confirmed, inquiryCount, todayPujas, todayFollowUps, tokenData, totalCollectedData, confirmedDocs] =
      await Promise.all([
        Inquiry.countDocuments(scope),
        Inquiry.countDocuments({ ...scope, status: 'confirmed' }),
        Inquiry.countDocuments({ ...scope, status: 'inquiry' }),
        Inquiry.countDocuments({ ...scope, pujaDate: { $regex: `^${today}` } }),
        Inquiry.countDocuments({ ...scope, nextCallDate: { $regex: `^${today}` } }),
        Inquiry.aggregate([
          { $match: { ...scope, tokenStatus: 'received' } },
          { $group: { _id: null, total: { $sum: '$tokenAmount' } } },
        ]),
        // Total amount fully collected — separate from tokenTotal above,
        // which only counts the token/advance portion (see
        // totalAmountStatus on the schema).
        Inquiry.aggregate([
          { $match: { ...scope, totalAmountStatus: 'received' } },
          { $group: { _id: null, total: { $sum: '$totalAmount' } } },
        ]),
        Inquiry.find(
          { ...scope, status: 'confirmed' },
          'totalAmount tokenAmount tokenStatus totalAmountStatus'
        ),
      ]);

    const tokenTotal = tokenData[0]?.total ?? 0;
    const totalCollected = totalCollectedData[0]?.total ?? 0;
    // 0 once the full amount is marked received; otherwise totalAmount minus
    // whatever token has actually been received (an unreceived token amount
    // doesn't reduce what's still owed).
    const pendingBalance = confirmedDocs.reduce((sum, d) => {
      if (d.totalAmountStatus === 'received') return sum;
      const paid = d.tokenStatus === 'received' ? d.tokenAmount : 0;
      return sum + (d.totalAmount - paid);
    }, 0);

    res.json({ totalRecords, confirmed, inquiryCount, todayPujas, todayFollowUps, tokenTotal, totalCollected, pendingBalance });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Bulk sync ─────────────────────────────────────────────────────────────────
app.post('/api/sync', async (req, res) => {
  try {
    const inquiries = req.body;
    if (!Array.isArray(inquiries)) return res.status(400).json({ error: 'Expected array' });

    let items = inquiries;
    if (!isAdmin(req)) {
      // Same ownership rule as PUT/POST above, applied per-document: an
      // update is only synced if the salesperson currently owns that
      // record; a brand-new record is force-assigned to them.
      const ids = inquiries.map((item) => item.id);
      const existing = await Inquiry.find({ id: { $in: ids } }, 'id assignedTo');
      const existingIds = new Set(existing.map((d) => d.id));
      const ownedIds = new Set(
        existing.filter((d) => d.assignedTo === req.user.salesPersonId).map((d) => d.id)
      );
      items = inquiries
        .filter((item) => !existingIds.has(item.id) || ownedIds.has(item.id))
        .map((item) =>
          existingIds.has(item.id) ? item : { ...item, assignedTo: req.user.salesPersonId }
        );
    }

    // Strip any client-supplied version/updatedAt — this bulk path doesn't do
    // per-item optimistic-lock conflict detection (unlike PUT
    // /api/inquiries/:id; there's no per-op response channel in a bulkWrite
    // to report a 409 back for one item out of the batch), but a raw `$set`
    // of a stale client version would corrupt the counter for every future
    // PUT conflict check against this record. `$inc` instead keeps it
    // monotonic no matter which path last wrote the document.
    const ops = items.map((item) => {
      const body = { ...item };
      delete body.version;
      delete body.updatedAt;
      return {
        updateOne: {
          filter: { id: item.id },
          update: { $set: { ...body, updatedAt: new Date().toISOString() }, $inc: { version: 1 } },
          upsert: true,
        },
      };
    });
    if (ops.length > 0) await Inquiry.bulkWrite(ops);
    res.json({ synced: ops.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Named HTML routes ─────────────────────────────────────────────────────────
app.get('/dashboard', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
});

// Flutter web SPA — catch-all for /app/* routes
app.get('/app/*', (_req, res) => {
  const indexPath = path.join(flutterBuildPath, 'index.html');
  if (require('fs').existsSync(indexPath)) {
    res.sendFile(indexPath);
  } else {
    res.status(404).send('Flutter web build not found. Run: flutter build web --base-href /app/');
  }
});

// ── Helper ────────────────────────────────────────────────────────────────────
function toJson(doc) {
  return {
    id: doc.id,
    clientName: doc.clientName,
    phone: doc.phone,
    pujaName: doc.pujaName,
    pujaDate: doc.pujaDate,
    pujaTime: doc.pujaTime,
    status: doc.status,
    totalAmount: doc.totalAmount,
    tokenAmount: doc.tokenAmount,
    tokenStatus: doc.tokenStatus,
    totalAmountStatus: doc.totalAmountStatus,
    transactionId: doc.transactionId,
    nextCallDate: doc.nextCallDate,
    pujariName: doc.pujariName,
    address: doc.address,
    notes: doc.notes,
    source: doc.source,
    assignedTo: doc.assignedTo,
    createdAt: doc.createdAt,
    reviewed: doc.reviewed,
    samagriIncluded: doc.samagriIncluded,
    version: doc.version,
    updatedAt: doc.updatedAt,
  };
}

// ── Connect → Start ──────────────────────────────────────────────────────────
mongoose
  .connect(MONGODB_URI)
  .then(async () => {
    console.log('✅ Connected to MongoDB Atlas');
    // Explicit (rather than relying solely on Mongoose's default autoIndex)
    // so index creation is logged and this also covers the existing
    // production database — Mongoose only creates indexes that don't
    // already exist, so this is a no-op after the first successful run.
    // On a large existing collection this can take a while in the
    // background (MongoDB 4.2+ builds indexes without blocking reads/
    // writes); safe to leave running, but for a very large collection
    // consider running it once during a low-traffic window instead of
    // relying on server startup.
    try {
      await Inquiry.createIndexes();
      console.log('✅ Inquiry indexes verified/created');
    } catch (err) {
      console.error('⚠️  Index creation failed:', err.message);
    }
    const server = app.listen(PORT, () => {
      console.log(`🚀 PujariDekho CRM running on http://localhost:${PORT}`);
    });

    server.on('error', (err) => {
      if (err.code === 'EADDRINUSE') {
        console.error(`❌ Port ${PORT} in use. Kill it: lsof -ti :${PORT} | xargs kill -9`);
      } else {
        console.error('❌ Server error:', err.message);
      }
      process.exit(1);
    });

    const shutdown = (sig) => {
      console.log(`\n[${sig}] Shutting down…`);
      server.close(() => mongoose.disconnect().then(() => process.exit(0)));
      setTimeout(() => process.exit(1), 3000).unref();
    };
    process.on('SIGTERM', () => shutdown('SIGTERM'));
    process.on('SIGINT', () => shutdown('SIGINT'));
  })
  .catch((err) => {
    console.error('❌ MongoDB connection failed:', err.message);
    process.exit(1);
  });
