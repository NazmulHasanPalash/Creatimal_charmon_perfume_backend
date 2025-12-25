// admins.routes.js
'use strict';

const express = require('express');
const requireAdmin = require('./requireAdmin');
const { admin } = require('./firebase-admin');

/**
 * Factory router for /admins
 *
 * ✅ How to use in your server.js (inside main() after db is created):
 *   const createAdminsRouter = require('./admins.routes');
 *   app.use('/admins', createAdminsRouter({ db }));
 *
 * This router:
 *   - GET  /admins   (admin only)  -> list admins
 *   - POST /admins   (admin only)  -> add admin by email (also sets Firebase custom claims)
 */

// Defaults (you can change via .env)
const ADMINS_COLLECTION = process.env.ADMINS_COLLECTION || 'Admins';

function safeStr(v) {
  return v === null || v === undefined ? '' : String(v);
}

function normalizeEmail(v) {
  return safeStr(v).trim().toLowerCase();
}

function isValidEmail(v) {
  const s = normalizeEmail(v);
  return s.includes('@') && s.includes('.') && s.length >= 6;
}

function clampLimit(n, min, max) {
  const x = Number(n);
  if (!Number.isFinite(x)) return max;
  return Math.max(min, Math.min(max, Math.floor(x)));
}

module.exports = function createAdminsRouter({ db }) {
  if (!db || typeof db.collection !== 'function') {
    throw new Error('createAdminsRouter requires { db } (MongoDB database instance).');
  }

  const router = express.Router();
  const adminsCol = db.collection(ADMINS_COLLECTION);

  /**
   * GET /admins
   * Admin-only list. Supports:
   *   - ?q=searchText (email/role/uid)
   *   - ?limit=200
   */
  router.get('/', requireAdmin, async (req, res) => {
    try {
      const q = safeStr(req.query.q).trim();
      const limit = clampLimit(req.query.limit, 1, 200);

      const query = {};
      if (q) {
        const rx = new RegExp(q.replace(/[.*+?^${}()|[\]\\]/g, '\\$&'), 'i');
        query.$or = [{ email: rx }, { role: rx }, { uid: rx }];
      }

      const list = await adminsCol
        .find(query)
        .sort({ createdAt: -1 })
        .limit(limit)
        .toArray();

      return res.json(list);
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('GET /admins error:', e);
      return res.status(500).json({ message: 'Failed to load admins.' });
    }
  });

  /**
   * POST /admins
   * Admin-only add. Body:
   *   { email: "user@example.com" }
   *
   * What it does:
   *   1) Finds Firebase user by email
   *   2) Sets custom claims: { admin: true, role: "admin" }
   *   3) Upserts record into Mongo "Admins" collection
   */
  router.post('/', requireAdmin, async (req, res) => {
    try {
      const email = normalizeEmail(req.body?.email);
      if (!isValidEmail(email)) {
        return res.status(400).json({ message: 'Valid email is required.' });
      }

      // Prevent adding yourself again (optional but nice)
      const myEmail = normalizeEmail(req.user?.email);
      if (myEmail && email === myEmail) {
        return res.status(400).json({ message: 'You are already an admin.' });
      }

      // 1) Find Firebase user by email
      let fbUser;
      try {
        fbUser = await admin.auth().getUserByEmail(email);
      } catch (err) {
        // eslint-disable-next-line no-console
        console.error('Firebase getUserByEmail error:', err);
        return res
          .status(404)
          .json({ message: 'User not found in Firebase for this email.' });
      }

      const uid = safeStr(fbUser?.uid).trim();
      if (!uid) {
        return res.status(500).json({ message: 'Firebase user uid missing.' });
      }

      // 2) Set custom claims (admin)
      // NOTE: This requires Admin SDK credentials configured correctly.
      await admin.auth().setCustomUserClaims(uid, { admin: true, role: 'admin' });

      // 3) Upsert Mongo record
      const now = new Date();
      const doc = {
        uid,
        email,
        role: 'admin',
        updatedAt: now,
        createdAt: now, // only used on insert via $setOnInsert
        addedByUid: safeStr(req.user?.uid).trim() || '',
        addedByEmail: normalizeEmail(req.user?.email) || '',
      };

      const result = await adminsCol.updateOne(
        { email },
        {
          $set: {
            uid: doc.uid,
            email: doc.email,
            role: doc.role,
            updatedAt: doc.updatedAt,
            addedByUid: doc.addedByUid,
            addedByEmail: doc.addedByEmail,
          },
          $setOnInsert: { createdAt: doc.createdAt },
        },
        { upsert: true }
      );

      return res.status(201).json({
        message: 'Admin added.',
        upsertedId: result.upsertedId || null,
        matchedCount: result.matchedCount || 0,
        modifiedCount: result.modifiedCount || 0,
        email,
        uid,
        role: 'admin',
      });
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('POST /admins error:', e);
      return res.status(500).json({ message: 'Failed to add admin.' });
    }
  });

  return router;
};
