'use strict';

const express = require('express');
const cors = require('cors');
const { MongoClient, ObjectId } = require('mongodb');
const admin = require('firebase-admin');

/* =========================================================
   ENV Helpers
   ========================================================= */
function safeStr(x) {
  return x === null || x === undefined ? '' : String(x);
}

function mustEnv(name) {
  const v = safeStr(process.env[name]).trim();
  if (!v) throw new Error(`Missing required environment variable: ${name}`);
  return v;
}

function normalizeEmail(v) {
  return safeStr(v).trim().toLowerCase();
}

function isValidEmail(v) {
  const s = normalizeEmail(v);
  return s.includes('@') && s.includes('.') && s.length >= 6;
}

function isNonEmptyString(x) {
  return typeof x === 'string' && x.trim().length > 0;
}

function toNumber(x, fallback = 0) {
  const n = Number(x);
  return Number.isFinite(n) ? n : fallback;
}

function clampIntMin(v, min = 0) {
  const n = Number(v);
  if (!Number.isFinite(n)) return min;
  return Math.max(min, Math.floor(n));
}

function parseLimit(v, max = 200) {
  const n = parseInt(String(v || '0'), 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(n, max);
}

function parseBool(v) {
  const s = safeStr(v).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'y';
}

/** Normalize status values coming from UI or API */
function normalizeStatus(input) {
  const raw = safeStr(input).trim();
  if (!raw) return '';
  let s = raw.toLowerCase();

  if (s === 'order confirmed') s = 'confirmed';
  if (s === 'order completed') s = 'completed';
  if (s === 'order cancelled' || s === 'order canceled') s = 'cancelled';

  if (s === 'confirm') s = 'confirmed';
  if (s === 'cancel' || s === 'canceled') s = 'cancelled';

  return s;
}

function isAllowedStatus(s) {
  return s === 'pending' || s === 'confirmed' || s === 'completed' || s === 'cancelled';
}

/** DuitNow reference normalization (safe) */
function normalizeDuitNowRef(v) {
  const s = safeStr(v).trim().toUpperCase();
  const cleaned = s.replace(/[^A-Z0-9/-]/g, '');
  return cleaned.slice(0, 40);
}

/* =========================================================
   Firebase Admin init (Vercel-friendly)
   ========================================================= */
let firebaseReady = false;

function initFirebaseAdmin() {
  if (firebaseReady || admin.apps.length) {
    firebaseReady = true;
    return;
  }

  // IMPORTANT: On Vercel you should use FIREBASE_SERVICE_ACCOUNT (JSON string)
  const saRaw = safeStr(process.env.FIREBASE_SERVICE_ACCOUNT).trim();

  if (!saRaw) {
    throw new Error(
      'Firebase Admin not configured. Set FIREBASE_SERVICE_ACCOUNT (JSON string).'
    );
  }

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(saRaw);
  } catch {
    throw new Error('FIREBASE_SERVICE_ACCOUNT must be valid JSON (string).');
  }

  // Fix \\n for private_key stored in env
  if (serviceAccount?.private_key && typeof serviceAccount.private_key === 'string') {
    serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
  }

  admin.initializeApp({
    credential: admin.credential.cert(serviceAccount),
  });

  firebaseReady = true;
}

/* =========================================================
   Mongo connection caching (serverless-safe)
   ========================================================= */
let cached = {
  client: null,
  db: null,
  collections: null,
  indexesEnsured: false,
  seeded: false,
};

async function getCollections() {
  if (cached.collections) return cached.collections;

  const mongoUri = mustEnv('MONGODB_URI');
  const dbName = safeStr(process.env.DB_NAME).trim() || 'Charmon';

  if (!cached.client) {
    cached.client = new MongoClient(mongoUri);
    await cached.client.connect();
    await cached.client.db().command({ ping: 1 });
  }

  cached.db = cached.client.db(dbName);

  const productsCollection = cached.db.collection('Products');
  const customerOrdersCollection = cached.db.collection('Customer_orders');
  const adminsCollection = cached.db.collection('Admins');

  cached.collections = {
    dbName,
    productsCollection,
    customerOrdersCollection,
    adminsCollection,
  };

  // Ensure indexes once
  if (!cached.indexesEnsured) {
    cached.indexesEnsured = true;
    await Promise.allSettled([
      adminsCollection.createIndex({ email: 1 }, { unique: true }),
      customerOrdersCollection.createIndex(
        { customerEmail: 1, createdAt: -1 },
        { background: true }
      ),
      productsCollection.createIndex({ category: 1 }, { background: true }),
    ]);
  }

  // Seed admin once
  if (!cached.seeded) {
    cached.seeded = true;
    const seedEmail = normalizeEmail(safeStr(process.env.SEED_ADMIN_EMAIL));
    if (seedEmail && isValidEmail(seedEmail)) {
      const now = new Date();
      await adminsCollection.updateOne(
        { email: seedEmail },
        {
          $set: { email: seedEmail, role: 'admin', updatedAt: now },
          $setOnInsert: { createdAt: now },
        },
        { upsert: true }
      );
      // eslint-disable-next-line no-console
      console.log(`✅ Admin seed ensured for: ${seedEmail}`);
    } else {
      // eslint-disable-next-line no-console
      console.log('ℹ️ SEED_ADMIN_EMAIL not set/invalid (seed skipped).');
    }
  }

  return cached.collections;
}

/* =========================================================
   Auth middleware
   ========================================================= */
async function requireAuth(req, res, next) {
  try {
    initFirebaseAdmin();

    const authHeader = safeStr(req.headers.authorization);
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    if (!token) return res.status(401).json({ message: 'Missing Authorization Bearer token.' });

    const decoded = await admin.auth().verifyIdToken(token);
    const email = normalizeEmail(decoded?.email);

    if (!email) return res.status(401).json({ message: 'Token has no email.' });

    req.user = {
      uid: safeStr(decoded?.uid),
      email,
      decoded,
    };

    return next();
  } catch (err) {
    // eslint-disable-next-line no-console
    console.error('Auth verify error:', err?.message || err);
    return res.status(401).json({ message: 'Invalid or expired token.' });
  }
}

function makeRequireAdmin(adminsCollection) {
  return async function requireAdmin(req, res, next) {
    try {
      if (!req.user?.email) return res.status(401).json({ message: 'Login required.' });

      const email = normalizeEmail(req.user.email);
      const row = await adminsCollection.findOne({ email });

      if (!row) return res.status(403).json({ message: 'Access denied. Admin only.' });

      req.user.isAdmin = true;
      return next();
    } catch (err) {
      // eslint-disable-next-line no-console
      console.error('requireAdmin error:', err?.message || err);
      return res.status(500).json({ message: 'Failed to check admin permission.' });
    }
  };
}

/* =========================================================
   Async handler helper (no try/catch spam)
   ========================================================= */
function asyncHandler(fn) {
  return function wrapped(req, res, next) {
    Promise.resolve(fn(req, res, next)).catch(next);
  };
}

/* =========================================================
   App
   ========================================================= */
const app = express();

/* ---------- CORS ---------- */
const CORS_ORIGINS = safeStr(process.env.CORS_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, cb) {
    // allow same-origin / server-to-server / curl / postman
    if (!origin) return cb(null, true);
    if (CORS_ORIGINS.includes(origin)) return cb(null, true);
    return cb(new Error(`CORS blocked for origin: ${origin}`));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  credentials: true,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

/* ---------- Body Limits ---------- */
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

/* =========================================================
   Routes
   ========================================================= */
app.get(
  '/',
  asyncHandler(async (_req, res) => {
    res.json({ ok: true, message: '✅ Creatimal server is running.' });
  })
);

/* =========================
   PRODUCTS
   ========================= */

// GET /products?category=&search=&limit=
app.get(
  '/products',
  asyncHandler(async (req, res) => {
    const { productsCollection } = await getCollections();
    const { category, search, limit } = req.query;

    const query = {};
    if (category) query.category = String(category);

    if (search) {
      const s = String(search);
      query.$or = [
        { name: { $regex: s, $options: 'i' } },
        { title: { $regex: s, $options: 'i' } },
        { brand: { $regex: s, $options: 'i' } },
      ];
    }

    const lim = parseLimit(limit, 200);
    const cursor = productsCollection.find(query).sort({ _id: -1 });
    if (lim > 0) cursor.limit(lim);

    const products = await cursor.toArray();
    res.json(products);
  })
);

// GET /products/:id
app.get(
  '/products/:id',
  asyncHandler(async (req, res) => {
    const { productsCollection } = await getCollections();
    const { id } = req.params;

    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid product id.' });

    const product = await productsCollection.findOne({ _id: new ObjectId(id) });
    if (!product) return res.status(404).json({ message: 'Product not found.' });

    res.json(product);
  })
);

// POST /products (admin only)
app.post(
  '/products',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { productsCollection, adminsCollection } = await getCollections();
    const requireAdmin = makeRequireAdmin(adminsCollection);

    // run admin check
    await new Promise((resolve, reject) =>
      requireAdmin(req, res, (err) => (err ? reject(err) : resolve()))
    );

    const product = req.body;

    if (!product || typeof product !== 'object') {
      return res.status(400).json({ message: 'Product data is required.' });
    }

    if (!isNonEmptyString(product.name)) {
      return res.status(400).json({ message: 'Product name is required.' });
    }
    if (!isNonEmptyString(product.description)) {
      return res.status(400).json({ message: 'Product description is required.' });
    }
    if (!isNonEmptyString(product.quantity)) {
      return res.status(400).json({ message: 'Product quantity is required.' });
    }

    const priceNum = toNumber(product.price, NaN);
    if (!Number.isFinite(priceNum) || priceNum <= 0) {
      return res.status(400).json({ message: 'Product price must be a number > 0.' });
    }

    if (!isNonEmptyString(product.imageUrl)) {
      return res.status(400).json({ message: 'Product imageUrl is required.' });
    }

    const now = new Date();
    const doc = { ...product, price: priceNum, createdAt: now, updatedAt: now };

    const result = await productsCollection.insertOne(doc);

    res.status(201).json({
      acknowledged: result.acknowledged,
      insertedId: result.insertedId,
    });
  })
);

// PUT /products/:id (admin only)
app.put(
  '/products/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { productsCollection, adminsCollection } = await getCollections();
    const requireAdmin = makeRequireAdmin(adminsCollection);

    await new Promise((resolve, reject) =>
      requireAdmin(req, res, (err) => (err ? reject(err) : resolve()))
    );

    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid product id.' });

    const updates = req.body;
    if (!updates || typeof updates !== 'object') {
      return res.status(400).json({ message: 'Update data is required.' });
    }

    delete updates._id;

    if (updates.price !== undefined) {
      const priceNum = toNumber(updates.price, NaN);
      if (!Number.isFinite(priceNum) || priceNum <= 0) {
        return res.status(400).json({ message: 'Product price must be a number > 0.' });
      }
      updates.price = priceNum;
    }

    const result = await productsCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { ...updates, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) return res.status(404).json({ message: 'Product not found.' });

    res.json({
      acknowledged: result.acknowledged,
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
    });
  })
);

// DELETE /products/:id (admin only)
app.delete(
  '/products/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { productsCollection, adminsCollection } = await getCollections();
    const requireAdmin = makeRequireAdmin(adminsCollection);

    await new Promise((resolve, reject) =>
      requireAdmin(req, res, (err) => (err ? reject(err) : resolve()))
    );

    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid product id.' });

    const result = await productsCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) return res.status(404).json({ message: 'Product not found.' });

    res.json({ acknowledged: result.acknowledged, deletedCount: result.deletedCount });
  })
);

/* =========================
   CUSTOMER ORDERS (SECURE)
   ========================= */

// POST /customer-orders (logged-in user creates their own order)
app.post(
  '/customer-orders',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { productsCollection, customerOrdersCollection } = await getCollections();

    const body = req.body;
    if (!body || typeof body !== 'object') {
      return res.status(400).json({ message: 'Order data is required.' });
    }

    const productIdRaw = safeStr(body.productId).trim();
    if (!ObjectId.isValid(productIdRaw)) {
      return res.status(400).json({ message: 'Invalid productId.' });
    }
    const productId = new ObjectId(productIdRaw);

    const product = await productsCollection.findOne({ _id: productId });
    if (!product) return res.status(404).json({ message: 'Product not found.' });

    const productName = safeStr(body.productName || product?.name).trim();
    const productImage = safeStr(body.productImage || product?.imageUrl).trim();

    const customerEmail = normalizeEmail(req.user.email);
    const customerPhone = safeStr(body.customerPhone).trim();
    const deliveryAddress = safeStr(body.deliveryAddress).trim();

    const orderQuantity = clampIntMin(body.orderQuantity, 1);
    if (orderQuantity < 1) return res.status(400).json({ message: 'orderQuantity must be >= 1.' });

    const perfumeQuantityMl = clampIntMin(
      body.perfumeQuantityMl ?? body.availableMl ?? product?.quantity ?? 0,
      0
    );

    const duitNowRefNo = normalizeDuitNowRef(body.duitNowRefNo);
    if (!duitNowRefNo || duitNowRefNo.length < 6) {
      return res.status(400).json({ message: 'Valid DuitNow Reference No. is required.' });
    }

    if (!productName) return res.status(400).json({ message: 'productName is required.' });
    if (!productImage) return res.status(400).json({ message: 'productImage is required.' });

    if (!customerEmail || !customerEmail.includes('@')) {
      return res.status(400).json({ message: 'Valid customer email is required.' });
    }
    if (!customerPhone || customerPhone.length < 7) {
      return res.status(400).json({ message: 'Valid customerPhone is required.' });
    }
    if (!deliveryAddress || deliveryAddress.length < 8) {
      return res.status(400).json({ message: 'Valid deliveryAddress is required.' });
    }

    // Server-side totals
    const unitPrice = Math.max(0, toNumber(product?.price, 0));
    const deliveryFee = Math.max(0, toNumber(body.deliveryFee, 0));
    const itemsTotal = Math.max(0, unitPrice * orderQuantity);
    const totalPrice = Math.max(0, itemsTotal + deliveryFee);

    const now = new Date();
    const doc = {
      productId,
      productName,
      productImage,

      status: 'pending',

      perfumeQuantityMl,
      orderQuantity,

      customerEmail,
      customerPhone,
      deliveryAddress,

      duitNowRefNo,

      unitPrice,
      itemsTotal,
      deliveryFee,
      totalPrice,

      currency: safeStr(body.currency || 'RM').trim() || 'RM',

      createdAt: now,
      updatedAt: now,
    };

    const result = await customerOrdersCollection.insertOne(doc);

    res.status(201).json({
      acknowledged: result.acknowledged,
      insertedId: result.insertedId,
      status: doc.status,
    });
  })
);

// GET /customer-orders?status=&limit=&email=&all=1
app.get(
  '/customer-orders',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { customerOrdersCollection, adminsCollection } = await getCollections();
    const { status, limit, email, all } = req.query;

    const tokenEmail = normalizeEmail(req.user.email);
    const adminRow = await adminsCollection.findOne({ email: tokenEmail });
    const isAdmin = !!adminRow;

    const wantAll = parseBool(all);

    let query = {};
    if (!isAdmin) {
      query.customerEmail = tokenEmail;
    } else {
      const wantEmail = normalizeEmail(email);
      if (wantEmail) query.customerEmail = wantEmail;
      else if (wantAll) query = {};
      else query = {}; // admin default = all
    }

    if (status) {
      const st = normalizeStatus(status);
      if (st && st !== 'all') query.status = st;
    }

    const lim = parseLimit(limit, 200);
    const cursor = customerOrdersCollection.find(query).sort({ _id: -1 });
    if (lim > 0) cursor.limit(lim);

    const orders = await cursor.toArray();
    res.json(orders);
  })
);

// GET /customer-orders/:id (customer only own; admin any)
app.get(
  '/customer-orders/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { customerOrdersCollection, adminsCollection } = await getCollections();

    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid order id.' });

    const order = await customerOrdersCollection.findOne({ _id: new ObjectId(id) });
    if (!order) return res.status(404).json({ message: 'Order not found.' });

    const tokenEmail = normalizeEmail(req.user.email);
    const ownerEmail = normalizeEmail(order?.customerEmail);

    if (ownerEmail !== tokenEmail) {
      const adminRow = await adminsCollection.findOne({ email: tokenEmail });
      if (!adminRow) return res.status(403).json({ message: 'Access denied.' });
    }

    res.json(order);
  })
);

// PATCH /customer-orders/:id (admin only) - status update
app.patch(
  '/customer-orders/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { customerOrdersCollection, adminsCollection } = await getCollections();
    const requireAdmin = makeRequireAdmin(adminsCollection);

    await new Promise((resolve, reject) =>
      requireAdmin(req, res, (err) => (err ? reject(err) : resolve()))
    );

    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid order id.' });

    const normalized = normalizeStatus(req.body?.status);
    if (!normalized) return res.status(400).json({ message: 'status is required.' });

    if (!isAllowedStatus(normalized)) {
      return res.status(400).json({
        message: 'Invalid status. Allowed: pending, confirmed, completed, cancelled.',
      });
    }

    const result = await customerOrdersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { status: normalized, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) return res.status(404).json({ message: 'Order not found.' });

    res.json({
      acknowledged: result.acknowledged,
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
      status: normalized,
    });
  })
);

// PUT /customer-orders/:id (admin only)
app.put(
  '/customer-orders/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { customerOrdersCollection, adminsCollection } = await getCollections();
    const requireAdmin = makeRequireAdmin(adminsCollection);

    await new Promise((resolve, reject) =>
      requireAdmin(req, res, (err) => (err ? reject(err) : resolve()))
    );

    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid order id.' });

    const updates = req.body;
    if (!updates || typeof updates !== 'object') {
      return res.status(400).json({ message: 'Update data is required.' });
    }

    delete updates._id;
    delete updates.createdAt;
    delete updates.customerEmail;
    delete updates.productId;

    // protect server-computed fields
    delete updates.unitPrice;
    delete updates.itemsTotal;
    delete updates.deliveryFee;
    delete updates.totalPrice;

    if (updates.status !== undefined) {
      const normalized = normalizeStatus(updates.status);
      if (!normalized || !isAllowedStatus(normalized)) {
        return res.status(400).json({
          message: 'Invalid status. Allowed: pending, confirmed, completed, cancelled.',
        });
      }
      updates.status = normalized;
    }

    if (updates.duitNowRefNo !== undefined) {
      const dn = normalizeDuitNowRef(updates.duitNowRefNo);
      if (!dn || dn.length < 6) {
        return res.status(400).json({ message: 'Invalid DuitNow Reference No.' });
      }
      updates.duitNowRefNo = dn;
    }

    const result = await customerOrdersCollection.updateOne(
      { _id: new ObjectId(id) },
      { $set: { ...updates, updatedAt: new Date() } }
    );

    if (result.matchedCount === 0) return res.status(404).json({ message: 'Order not found.' });

    res.json({
      acknowledged: result.acknowledged,
      matchedCount: result.matchedCount,
      modifiedCount: result.modifiedCount,
    });
  })
);

// DELETE /customer-orders/:id (admin only)
app.delete(
  '/customer-orders/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { customerOrdersCollection, adminsCollection } = await getCollections();
    const requireAdmin = makeRequireAdmin(adminsCollection);

    await new Promise((resolve, reject) =>
      requireAdmin(req, res, (err) => (err ? reject(err) : resolve()))
    );

    const { id } = req.params;
    if (!ObjectId.isValid(id)) return res.status(400).json({ message: 'Invalid order id.' });

    const result = await customerOrdersCollection.deleteOne({ _id: new ObjectId(id) });
    if (result.deletedCount === 0) return res.status(404).json({ message: 'Order not found.' });

    res.json({ acknowledged: result.acknowledged, deletedCount: result.deletedCount });
  })
);

/* =========================
   ADMINS
   ========================= */

// GET /admins (admin only)
app.get(
  '/admins',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { adminsCollection } = await getCollections();
    const requireAdmin = makeRequireAdmin(adminsCollection);

    await new Promise((resolve, reject) =>
      requireAdmin(req, res, (err) => (err ? reject(err) : resolve()))
    );

    const list = await adminsCollection.find({}).sort({ _id: -1 }).limit(500).toArray();
    res.json(list);
  })
);

// POST /admins (admin only) body: { email }
app.post(
  '/admins',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { adminsCollection } = await getCollections();
    const requireAdmin = makeRequireAdmin(adminsCollection);

    await new Promise((resolve, reject) =>
      requireAdmin(req, res, (err) => (err ? reject(err) : resolve()))
    );

    const email = normalizeEmail(req.body?.email);
    if (!isValidEmail(email)) return res.status(400).json({ message: 'Valid email is required.' });

    const now = new Date();
    const result = await adminsCollection.updateOne(
      { email },
      { $set: { email, role: 'admin', updatedAt: now }, $setOnInsert: { createdAt: now } },
      { upsert: true }
    );

    res.status(201).json({
      acknowledged: result.acknowledged,
      upsertedId: result.upsertedId || null,
      message: 'Admin saved.',
      email,
    });
  })
);

// DELETE /admins/:id (admin only) supports ObjectId OR email
app.delete(
  '/admins/:id',
  requireAuth,
  asyncHandler(async (req, res) => {
    const { adminsCollection } = await getCollections();
    const requireAdmin = makeRequireAdmin(adminsCollection);

    await new Promise((resolve, reject) =>
      requireAdmin(req, res, (err) => (err ? reject(err) : resolve()))
    );

    const raw = safeStr(req.params.id).trim();
    if (!raw) return res.status(400).json({ message: 'Missing admin id.' });

    const tokenEmail = normalizeEmail(req.user?.email);
    const seedNorm = normalizeEmail(safeStr(process.env.SEED_ADMIN_EMAIL));

    let query = null;
    if (ObjectId.isValid(raw)) query = { _id: new ObjectId(raw) };
    else {
      const maybeEmail = normalizeEmail(raw);
      if (!isValidEmail(maybeEmail)) {
        return res.status(400).json({ message: 'Invalid admin id (must be ObjectId or email).' });
      }
      query = { email: maybeEmail };
    }

    const target = await adminsCollection.findOne(query);
    if (!target) return res.status(404).json({ message: 'Admin not found.' });

    const targetEmail = normalizeEmail(target.email);

    if (seedNorm && targetEmail === seedNorm) {
      return res.status(403).json({ message: 'Cannot delete the seed admin.' });
    }
    if (tokenEmail && targetEmail && tokenEmail === targetEmail) {
      return res.status(403).json({ message: 'You cannot delete your own admin access.' });
    }

    const result = await adminsCollection.deleteOne({ _id: target._id });

    res.json({
      acknowledged: result.acknowledged,
      deletedCount: result.deletedCount,
      deletedEmail: targetEmail,
    });
  })
);

/* =========================
   Error handler (AFTER routes)
   ========================= */
app.use((err, _req, res, _next) => {
  const msg = safeStr(err?.message);

  if (msg.startsWith('CORS blocked for origin:')) {
    return res.status(403).json({ message: msg });
  }

  // eslint-disable-next-line no-console
  console.error('Unhandled error:', err);
  return res.status(500).json({ message: 'Server error.' });
});

module.exports = app;
