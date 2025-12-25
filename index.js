// server.js (or index.js) — FULL FIXED VERSION
// ✅ Uses your MongoDB Atlas URI: mongodb+srv://admin:admin112233@creatimal.sw15nau.mongodb.net/?appName=Creatimal
// ✅ Admin can view ALL customer orders (?all=1 OR default admin = all)
// ✅ Firebase service account private_key \\n fix
// ✅ Admin delete (by ObjectId OR email) + safety checks
// ✅ Safer CORS error handling
// ✅ FIX: Error handler registered AFTER routes (correct Express order)
// ✅ FIX: Remove duplication (single file)
// ✅ IMPROVEMENT (safe): Customer order totals computed server-side + saves DuitNow ref
'use strict';

const express = require('express');
const cors = require('cors');
require('dotenv').config();

const { MongoClient, ObjectId } = require('mongodb');
const admin = require('firebase-admin');

const app = express();

/* =========================
   CORS + Body Limits
   ========================= */
const CORS_ORIGINS = String(process.env.CORS_ORIGINS || 'http://localhost:3000')
  .split(',')
  .map((s) => s.trim())
  .filter(Boolean);

const corsOptions = {
  origin(origin, cb) {
    // allow same-origin / server-to-server / curl / postman
    if (!origin) return cb(null, true);

    if (CORS_ORIGINS.includes(origin)) return cb(null, true);

    // deny
    return cb(new Error(`CORS blocked for origin: ${origin}`));
  },
  methods: ['GET', 'POST', 'PUT', 'PATCH', 'DELETE', 'OPTIONS'],
  credentials: true,
};

app.use(cors(corsOptions));
app.options('*', cors(corsOptions));

// Base64 images can be big
app.use(express.json({ limit: '50mb' }));
app.use(express.urlencoded({ extended: true, limit: '50mb' }));

const port = Number(process.env.PORT || 5000);

/* =========================
   Helpers
   ========================= */
function mustEnv(name) {
  const v = process.env[name];
  if (!v || !String(v).trim()) {
    throw new Error(`Missing required environment variable: ${name}`);
  }
  return String(v).trim();
}

function safeStr(x) {
  return x === null || x === undefined ? '' : String(x);
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

function normalizeEmail(v) {
  return safeStr(v).trim().toLowerCase();
}

function isValidEmail(v) {
  const s = normalizeEmail(v);
  return s.includes('@') && s.includes('.') && s.length >= 6;
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

function parseLimit(v, max = 200) {
  const n = parseInt(String(v || '0'), 10);
  if (!Number.isFinite(n) || n <= 0) return 0;
  return Math.min(n, max);
}

function parseBool(v) {
  const s = safeStr(v).trim().toLowerCase();
  return s === '1' || s === 'true' || s === 'yes' || s === 'y';
}

/** DuitNow reference normalization (safe) */
function normalizeDuitNowRef(v) {
  const s = safeStr(v).trim().toUpperCase();
  const cleaned = s.replace(/[^A-Z0-9/-]/g, '');
  return cleaned.slice(0, 40);
}

/* =========================
   Mongo URI (UPDATED)
   =========================
   TIP (recommended): put this in .env as MONGODB_URI and keep secrets out of code.
*/
function buildMongoUri() {
  // Prefer env override if provided
  const envUri = safeStr(process.env.MONGODB_URI).trim();
  if (envUri) return envUri;

  // Otherwise, use your fixed URI
  return 'mongodb+srv://admin:admin112233@creatimal.sw15nau.mongodb.net/?appName=Creatimal';
}

/* =========================
   Firebase Admin (Auth)
   =========================
   Choose ONE method:
   A) GOOGLE_APPLICATION_CREDENTIALS=/path/to/serviceAccount.json
   OR
   B) FIREBASE_SERVICE_ACCOUNT='{"type":"service_account", ... }'
*/
function initFirebaseAdmin() {
  if (admin.apps.length) return;

  const hasGac = !!safeStr(process.env.GOOGLE_APPLICATION_CREDENTIALS).trim();
  const saRaw = safeStr(process.env.FIREBASE_SERVICE_ACCOUNT).trim();

  if (hasGac) {
    admin.initializeApp({ credential: admin.credential.applicationDefault() });
    console.log('✅ Firebase Admin initialized (applicationDefault).');
    return;
  }

  if (saRaw) {
    let serviceAccount;
    try {
      serviceAccount = JSON.parse(saRaw);
    } catch {
      throw new Error('FIREBASE_SERVICE_ACCOUNT must be a valid JSON string.');
    }

    // ✅ IMPORTANT FIX: .env often stores private_key with \\n
    if (serviceAccount?.private_key && typeof serviceAccount.private_key === 'string') {
      serviceAccount.private_key = serviceAccount.private_key.replace(/\\n/g, '\n');
    }

    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('✅ Firebase Admin initialized (service account JSON).');
    return;
  }

  throw new Error(
    'Firebase Admin not configured. Set GOOGLE_APPLICATION_CREDENTIALS or FIREBASE_SERVICE_ACCOUNT.'
  );
}

async function requireAuth(req, res, next) {
  try {
    const authHeader = safeStr(req.headers.authorization);
    const token = authHeader.startsWith('Bearer ') ? authHeader.slice(7).trim() : '';

    if (!token) {
      return res.status(401).json({ message: 'Missing Authorization Bearer token.' });
    }

    const decoded = await admin.auth().verifyIdToken(token);
    const email = normalizeEmail(decoded?.email);

    if (!email) {
      return res.status(401).json({ message: 'Token has no email.' });
    }

    req.user = {
      uid: safeStr(decoded?.uid),
      email,
      decoded,
    };

    return next();
  } catch (err) {
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

      if (!row) {
        return res.status(403).json({ message: 'Access denied. Admin only.' });
      }

      req.user.isAdmin = true;
      return next();
    } catch (err) {
      console.error('requireAdmin error:', err?.message || err);
      return res.status(500).json({ message: 'Failed to check admin permission.' });
    }
  };
}

/* =========================
   Mongo Setup
   ========================= */
const mongoUri = buildMongoUri();
const client = new MongoClient(mongoUri);

/* =========================
   ✅ Seed Admin Email (HARDCODED)
   ========================= */
const SEED_ADMIN_EMAIL = 'nazmul.hasan.palash2000@gmail.com';

/* =========================
   Main
   ========================= */
async function main() {
  try {
    initFirebaseAdmin();

    await client.connect();
    await client.db().command({ ping: 1 });
    console.log('✅ MongoDB connected successfully.');

    // ✅ Default DB name for your cluster (override with DB_NAME if you want)
    const dbName = safeStr(process.env.DB_NAME).trim() || 'Charmon';
    const db = client.db(dbName);

    const productsCollection = db.collection('Products');
    const customerOrdersCollection = db.collection('Customer_orders');
    const adminsCollection = db.collection('Admins');

    // Helpful indexes (safe to run many times)
    await Promise.allSettled([
      adminsCollection.createIndex({ email: 1 }, { unique: true }),
      customerOrdersCollection.createIndex({ customerEmail: 1, createdAt: -1 }, { background: true }),
      productsCollection.createIndex({ category: 1 }, { background: true }),
    ]);

    const requireAdmin = makeRequireAdmin(adminsCollection);

    // ✅ Seed first admin (hardcoded)
    const seedEmail = normalizeEmail(SEED_ADMIN_EMAIL);
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
      console.log(`✅ Admin seed ensured for: ${seedEmail}`);
    } else {
      console.warn('⚠️ SEED_ADMIN_EMAIL is not a valid email. Seed skipped.');
    }

    /* -------------------- Root -------------------- */
    app.get('/', (_req, res) => {
      res.send('✅ Creatimal server is running.');
    });

    /* =========================
       PRODUCTS
       ========================= */

    // GET /products?category=&search=&limit=
    app.get('/products', async (req, res) => {
      try {
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
        return res.json(products);
      } catch (err) {
        console.error('GET /products error:', err);
        return res.status(500).json({ message: 'Failed to fetch products.' });
      }
    });

    // GET /products/:id
    app.get('/products/:id', async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid product id.' });
        }

        const product = await productsCollection.findOne({ _id: new ObjectId(id) });
        if (!product) return res.status(404).json({ message: 'Product not found.' });

        return res.json(product);
      } catch (err) {
        console.error('GET /products/:id error:', err);
        return res.status(500).json({ message: 'Failed to fetch product.' });
      }
    });

    // POST /products (admin only)
    app.post('/products', requireAuth, requireAdmin, async (req, res) => {
      try {
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

        return res.status(201).json({
          acknowledged: result.acknowledged,
          insertedId: result.insertedId,
        });
      } catch (err) {
        console.error('POST /products error:', err);
        return res.status(500).json({ message: 'Failed to create product.' });
      }
    });

    // PUT /products/:id (admin only)
    app.put('/products/:id', requireAuth, requireAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid product id.' });
        }

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

        if (result.matchedCount === 0) {
          return res.status(404).json({ message: 'Product not found.' });
        }

        return res.json({
          acknowledged: result.acknowledged,
          matchedCount: result.matchedCount,
          modifiedCount: result.modifiedCount,
        });
      } catch (err) {
        console.error('PUT /products/:id error:', err);
        return res.status(500).json({ message: 'Failed to update product.' });
      }
    });

    // DELETE /products/:id (admin only)
    app.delete('/products/:id', requireAuth, requireAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid product id.' });
        }

        const result = await productsCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) {
          return res.status(404).json({ message: 'Product not found.' });
        }

        return res.json({
          acknowledged: result.acknowledged,
          deletedCount: result.deletedCount,
        });
      } catch (err) {
        console.error('DELETE /products/:id error:', err);
        return res.status(500).json({ message: 'Failed to delete product.' });
      }
    });

    /* =========================
       CUSTOMER ORDERS (SECURE)
       ========================= */

    // POST /customer-orders (logged-in user creates their own order)
    // ✅ Saves duitNowRefNo + itemsTotal + deliveryFee + totalPrice
    // ✅ Server computes totals using DB price (prevents fake total from client)
    app.post('/customer-orders', requireAuth, async (req, res) => {
      try {
        const body = req.body;

        if (!body || typeof body !== 'object') {
          return res.status(400).json({ message: 'Order data is required.' });
        }

        const productIdRaw = safeStr(body.productId).trim();
        if (!ObjectId.isValid(productIdRaw)) {
          return res.status(400).json({ message: 'Invalid productId.' });
        }
        const productId = new ObjectId(productIdRaw);

        // ✅ fetch product (ensure exists + use DB price)
        const product = await productsCollection.findOne({ _id: productId });
        if (!product) return res.status(404).json({ message: 'Product not found.' });

        const productName = safeStr(body.productName || product?.name).trim();
        const productImage = safeStr(body.productImage || product?.imageUrl).trim();

        const customerEmail = normalizeEmail(req.user.email);
        const customerPhone = safeStr(body.customerPhone).trim();
        const deliveryAddress = safeStr(body.deliveryAddress).trim();

        const orderQuantity = clampIntMin(body.orderQuantity, 1);

        const perfumeQuantityMl = clampIntMin(
          body.perfumeQuantityMl ?? body.availableMl ?? product?.quantity ?? 0,
          0
        );

        // DuitNow Reference No (required for your workflow)
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

        // ✅ compute pricing server-side
        const unitPrice = Math.max(0, toNumber(product?.price, 0));
        const deliveryFee = Math.max(0, toNumber(body.deliveryFee, 0)); // allow frontend to send (or 0)
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

        return res.status(201).json({
          acknowledged: result.acknowledged,
          insertedId: result.insertedId,
          status: doc.status,
        });
      } catch (err) {
        console.error('POST /customer-orders error:', err);
        return res.status(500).json({ message: 'Failed to create order.' });
      }
    });

    // ✅ GET /customer-orders?status=&limit=&email=&all=1
    app.get('/customer-orders', requireAuth, async (req, res) => {
      try {
        const { status, limit, email, all } = req.query;

        const tokenEmail = normalizeEmail(req.user.email);
        const adminRow = await adminsCollection.findOne({ email: tokenEmail });
        const isAdmin = !!adminRow;

        const wantAll = parseBool(all);

        let query = {};

        if (!isAdmin) {
          // non-admin: only own
          query.customerEmail = tokenEmail;
        } else {
          // admin: can filter by ?email= otherwise show all (default)
          const wantEmail = normalizeEmail(email);
          if (wantEmail) query.customerEmail = wantEmail;
          else if (wantAll) query = {};
          else query = {};
        }

        if (status) {
          const st = normalizeStatus(status);
          if (st && st !== 'all') query.status = st;
        }

        const lim = parseLimit(limit, 200);
        const cursor = customerOrdersCollection.find(query).sort({ _id: -1 });
        if (lim > 0) cursor.limit(lim);

        const orders = await cursor.toArray();
        return res.json(orders);
      } catch (err) {
        console.error('GET /customer-orders error:', err);
        return res.status(500).json({ message: 'Failed to fetch orders.' });
      }
    });

    // GET /customer-orders/:id (customer only own; admin any)
    app.get('/customer-orders/:id', requireAuth, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid order id.' });
        }

        const order = await customerOrdersCollection.findOne({ _id: new ObjectId(id) });
        if (!order) return res.status(404).json({ message: 'Order not found.' });

        const tokenEmail = normalizeEmail(req.user.email);
        const ownerEmail = normalizeEmail(order?.customerEmail);

        if (ownerEmail !== tokenEmail) {
          const adminRow = await adminsCollection.findOne({ email: tokenEmail });
          if (!adminRow) return res.status(403).json({ message: 'Access denied.' });
        }

        return res.json(order);
      } catch (err) {
        console.error('GET /customer-orders/:id error:', err);
        return res.status(500).json({ message: 'Failed to fetch order.' });
      }
    });

    // PATCH /customer-orders/:id (admin only) - status update
    app.patch('/customer-orders/:id', requireAuth, requireAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid order id.' });
        }

        const body = req.body || {};
        const normalized = normalizeStatus(body.status);

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

        return res.json({
          acknowledged: result.acknowledged,
          matchedCount: result.matchedCount,
          modifiedCount: result.modifiedCount,
          status: normalized,
        });
      } catch (err) {
        console.error('PATCH /customer-orders/:id error:', err);
        return res.status(500).json({ message: 'Failed to update order status.' });
      }
    });

    // PUT /customer-orders/:id (admin only)
    app.put('/customer-orders/:id', requireAuth, requireAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid order id.' });
        }

        const updates = req.body;
        if (!updates || typeof updates !== 'object') {
          return res.status(400).json({ message: 'Update data is required.' });
        }

        delete updates._id;
        delete updates.createdAt;
        delete updates.customerEmail; // never allow changing owner
        delete updates.productId;

        // protect server-computed price fields
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

        return res.json({
          acknowledged: result.acknowledged,
          matchedCount: result.matchedCount,
          modifiedCount: result.modifiedCount,
        });
      } catch (err) {
        console.error('PUT /customer-orders/:id error:', err);
        return res.status(500).json({ message: 'Failed to update order.' });
      }
    });

    // DELETE /customer-orders/:id (admin only)
    app.delete('/customer-orders/:id', requireAuth, requireAdmin, async (req, res) => {
      try {
        const { id } = req.params;
        if (!ObjectId.isValid(id)) {
          return res.status(400).json({ message: 'Invalid order id.' });
        }

        const result = await customerOrdersCollection.deleteOne({ _id: new ObjectId(id) });

        if (result.deletedCount === 0) return res.status(404).json({ message: 'Order not found.' });

        return res.json({
          acknowledged: result.acknowledged,
          deletedCount: result.deletedCount,
        });
      } catch (err) {
        console.error('DELETE /customer-orders/:id error:', err);
        return res.status(500).json({ message: 'Failed to delete order.' });
      }
    });

    /* =========================
       ADMINS (for DisplayAdmin.js)
       ========================= */

    // GET /admins (admin only)
    app.get('/admins', requireAuth, requireAdmin, async (_req, res) => {
      try {
        const list = await adminsCollection.find({}).sort({ _id: -1 }).limit(500).toArray();
        return res.json(list);
      } catch (err) {
        console.error('GET /admins error:', err);
        return res.status(500).json({ message: 'Failed to fetch admins.' });
      }
    });

    // POST /admins (admin only) body: { email }
    app.post('/admins', requireAuth, requireAdmin, async (req, res) => {
      try {
        const email = normalizeEmail(req.body?.email);
        if (!isValidEmail(email)) {
          return res.status(400).json({ message: 'Valid email is required.' });
        }

        const now = new Date();

        const result = await adminsCollection.updateOne(
          { email },
          {
            $set: { email, role: 'admin', updatedAt: now },
            $setOnInsert: { createdAt: now },
          },
          { upsert: true }
        );

        return res.status(201).json({
          acknowledged: result.acknowledged,
          upsertedId: result.upsertedId || null,
          message: 'Admin saved.',
          email,
        });
      } catch (err) {
        console.error('POST /admins error:', err);
        return res.status(500).json({ message: 'Failed to add admin.' });
      }
    });

    // ✅ DELETE /admins/:id (admin only) supports ObjectId OR email
    app.delete('/admins/:id', requireAuth, requireAdmin, async (req, res) => {
      try {
        const raw = safeStr(req.params.id).trim();
        if (!raw) return res.status(400).json({ message: 'Missing admin id.' });

        const tokenEmail = normalizeEmail(req.user?.email);
        const seedNorm = normalizeEmail(SEED_ADMIN_EMAIL);

        // Determine lookup mode
        let query = null;
        if (ObjectId.isValid(raw)) {
          query = { _id: new ObjectId(raw) };
        } else {
          const maybeEmail = normalizeEmail(raw);
          if (!isValidEmail(maybeEmail)) {
            return res.status(400).json({
              message: 'Invalid admin id (must be ObjectId or email).',
            });
          }
          query = { email: maybeEmail };
        }

        const target = await adminsCollection.findOne(query);
        if (!target) return res.status(404).json({ message: 'Admin not found.' });

        const targetEmail = normalizeEmail(target.email);

        // Protect seed admin
        if (seedNorm && targetEmail === seedNorm) {
          return res.status(403).json({ message: 'Cannot delete the seed admin.' });
        }

        // Prevent deleting yourself
        if (tokenEmail && targetEmail && tokenEmail === targetEmail) {
          return res.status(403).json({ message: 'You cannot delete your own admin access.' });
        }

        const result = await adminsCollection.deleteOne({ _id: target._id });

        return res.json({
          acknowledged: result.acknowledged,
          deletedCount: result.deletedCount,
          deletedEmail: targetEmail,
        });
      } catch (err) {
        console.error('DELETE /admins/:id error:', err);
        return res.status(500).json({ message: 'Failed to delete admin.' });
      }
    });

    /* =========================
       FIX: Error handler (CORS) AFTER routes
       ========================= */
    app.use((err, _req, res, _next) => {
      const msg = safeStr(err?.message);
      if (msg.startsWith('CORS blocked for origin:')) {
        return res.status(403).json({ message: msg });
      }
      console.error('Unhandled error:', err);
      return res.status(500).json({ message: 'Server error.' });
    });

    /* =========================
       Start server AFTER DB connect
       ========================= */
    app.listen(port, () => {
      console.log(`✅ Server listening at http://localhost:${port}`);
      if (CORS_ORIGINS.length) console.log('✅ CORS origins:', CORS_ORIGINS);
      console.log(`✅ Using DB: ${dbName}`);
      console.log(`✅ Seed admin: ${SEED_ADMIN_EMAIL}`);
    });
  } catch (err) {
    console.error('❌ Startup failed:', err?.message || err);
    process.exit(1);
  }
}

/* =========================
   Graceful shutdown
   ========================= */
async function shutdown(signal) {
  try {
    console.log(`\nReceived ${signal}. Closing MongoDB connection...`);
    await client.close();
    console.log('MongoDB connection closed.');
  } catch (e) {
    console.error('Error closing MongoDB:', e);
  } finally {
    process.exit(0);
  }
}

process.on('SIGINT', () => shutdown('SIGINT'));
process.on('SIGTERM', () => shutdown('SIGTERM'));

main();
