require('dotenv').config();
const express = require('express');
const cors = require('cors');
const mongoose = require('mongoose');
const jwt = require('jsonwebtoken');
const path = require('path');

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
const ADMIN_USERNAME = process.env.ADMIN_USERNAME || 'admin';
const ADMIN_PASSWORD = process.env.ADMIN_PASSWORD || 'admin@123';

if (!MONGODB_URI) {
  console.error('❌ MONGODB_URI not set in .env');
  process.exit(1);
}

// ── Middleware ───────────────────────────────────────────────────────────────
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// ── Auth Middleware ──────────────────────────────────────────────────────────
function requireAuth(req, res, next) {
  const auth = req.headers.authorization;
  if (!auth || !auth.startsWith('Bearer ')) {
    return res.status(401).json({ error: 'Unauthorized' });
  }
  try {
    req.user = jwt.verify(auth.split(' ')[1], JWT_SECRET);
    next();
  } catch {
    res.status(401).json({ error: 'Invalid or expired token' });
  }
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
    status: { type: String, default: 'inquiry', enum: ['inquiry', 'confirmed'] },
    totalAmount: { type: Number, default: 0 },
    tokenAmount: { type: Number, default: 0 },
    tokenStatus: { type: String, default: 'pending', enum: ['pending', 'received'] },
    transactionId: { type: String, default: null },
    nextCallDate: { type: String, default: null },
    pujariName: { type: String, default: null },
    notes: { type: String, default: null },
    createdAt: { type: String, required: true },
  },
  { versionKey: false }
);

const Inquiry = mongoose.model('Inquiry', inquirySchema);

// ── Auth Routes (public) ─────────────────────────────────────────────────────
app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  if (username === ADMIN_USERNAME && password === ADMIN_PASSWORD) {
    const token = jwt.sign({ username }, JWT_SECRET, { expiresIn: '12h' });
    res.json({ token, username });
  } else {
    res.status(401).json({ error: 'Invalid username or password' });
  }
});

// ── Health check (public) ─────────────────────────────────────────────────────
app.get('/api/health', (_req, res) =>
  res.json({ status: 'ok', db: mongoose.connection.readyState === 1 ? 'connected' : 'disconnected' })
);

// ── All other API routes require auth ────────────────────────────────────────
app.use('/api', requireAuth);

// ── API Info ──────────────────────────────────────────────────────────────────
app.get('/api', (_req, res) => {
  res.json({ app: 'Pujari Dekho CRM API', version: '2.0.0', status: 'running' });
});

// ── GET all inquiries ─────────────────────────────────────────────────────────
app.get('/api/inquiries', async (_req, res) => {
  try {
    const docs = await Inquiry.find().sort({ createdAt: -1 });
    res.json(docs.map(toJson));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET single inquiry ────────────────────────────────────────────────────────
app.get('/api/inquiries/:id', async (req, res) => {
  try {
    const doc = await Inquiry.findOne({ id: req.params.id });
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json(toJson(doc));
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── POST create inquiry ───────────────────────────────────────────────────────
app.post('/api/inquiries', async (req, res) => {
  try {
    const doc = new Inquiry(req.body);
    await doc.save();
    res.status(201).json({ id: doc.id });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── PUT update inquiry ────────────────────────────────────────────────────────
app.put('/api/inquiries/:id', async (req, res) => {
  try {
    const doc = await Inquiry.findOneAndUpdate(
      { id: req.params.id },
      { $set: req.body },
      { new: true }
    );
    if (!doc) return res.status(404).json({ error: 'Not found' });
    res.json({ updated: true });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

// ── DELETE inquiry ────────────────────────────────────────────────────────────
app.delete('/api/inquiries/:id', async (req, res) => {
  try {
    const result = await Inquiry.deleteOne({ id: req.params.id });
    if (result.deletedCount === 0) return res.status(404).json({ error: 'Not found' });
    res.json({ deleted: true });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── GET stats ─────────────────────────────────────────────────────────────────
app.get('/api/stats', async (_req, res) => {
  try {
    const today = new Date().toISOString().slice(0, 10);
    const [totalRecords, confirmed, inquiryCount, todayPujas, todayFollowUps, tokenData, confirmedDocs] =
      await Promise.all([
        Inquiry.countDocuments(),
        Inquiry.countDocuments({ status: 'confirmed' }),
        Inquiry.countDocuments({ status: 'inquiry' }),
        Inquiry.countDocuments({ pujaDate: { $regex: `^${today}` } }),
        Inquiry.countDocuments({ nextCallDate: { $regex: `^${today}` } }),
        Inquiry.aggregate([{ $match: { tokenStatus: 'received' } }, { $group: { _id: null, total: { $sum: '$tokenAmount' } } }]),
        Inquiry.find({ status: 'confirmed' }, 'totalAmount tokenAmount tokenStatus'),
      ]);

    const tokenTotal = tokenData[0]?.total ?? 0;
    const pendingBalance = confirmedDocs.reduce((sum, d) => {
      const paid = d.tokenStatus === 'received' ? d.tokenAmount : 0;
      return sum + (d.totalAmount - paid);
    }, 0);

    res.json({ totalRecords, confirmed, inquiryCount, todayPujas, todayFollowUps, tokenTotal, pendingBalance });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Bulk sync ─────────────────────────────────────────────────────────────────
app.post('/api/sync', async (req, res) => {
  try {
    const inquiries = req.body;
    if (!Array.isArray(inquiries)) return res.status(400).json({ error: 'Expected array' });
    const ops = inquiries.map((item) => ({
      updateOne: { filter: { id: item.id }, update: { $set: item }, upsert: true },
    }));
    await Inquiry.bulkWrite(ops);
    res.json({ synced: inquiries.length });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ── Serve dashboard for any non-API route ────────────────────────────────────
app.get('/dashboard', (_req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'dashboard.html'));
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
    transactionId: doc.transactionId,
    nextCallDate: doc.nextCallDate,
    pujariName: doc.pujariName,
    notes: doc.notes,
    createdAt: doc.createdAt,
  };
}

// ── Connect → Start ──────────────────────────────────────────────────────────
mongoose
  .connect(MONGODB_URI)
  .then(() => {
    console.log('✅ Connected to MongoDB Atlas');
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
