// requireAdmin.js
'use strict';

const verifyFirebaseToken = require('./verifyFirebaseToken');
const { admin } = require('./firebase-admin');

/**
 * Checks whether the authenticated user is an admin.
 *
 * Supports BOTH patterns:
 *  A) Custom claims: { admin: true } or { role: "admin" }
 *  B) Firestore lookup: users/{uid}.role === "admin"
 *
 * Usage:
 *   const requireAdmin = require('./requireAdmin');
 *   app.get('/admins', requireAdmin, handler);
 *   app.post('/admins', requireAdmin, handler);
 */

// Customize if your Firestore user collection is different
const USERS_COLLECTION = process.env.USERS_COLLECTION || 'users';

function safeStr(v) {
  return v === null || v === undefined ? '' : String(v);
}

function normalizeRole(v) {
  return safeStr(v).trim().toLowerCase();
}

function isTruthyAdminClaim(claims) {
  if (!claims || typeof claims !== 'object') return false;

  // common patterns:
  // { admin: true }
  // { role: "admin" }
  // { roles: ["admin", ...] }
  if (claims.admin === true) return true;

  const role = normalizeRole(claims.role);
  if (role === 'admin') return true;

  const roles = claims.roles;
  if (Array.isArray(roles)) {
    return roles.map(normalizeRole).includes('admin');
  }

  return false;
}

async function isAdminByFirestore(uid) {
  if (!uid) return false;

  const db = admin.firestore();
  const snap = await db.collection(USERS_COLLECTION).doc(uid).get();
  if (!snap.exists) return false;

  const data = snap.data() || {};
  const role = normalizeRole(data.role || data.userRole);
  return role === 'admin';
}

/**
 * Middleware that:
 *  1) Verifies Firebase token (req.user)
 *  2) Checks admin permission
 */
async function requireAdmin(req, res, next) {
  // Step 1: verify token and populate req.user
  verifyFirebaseToken(req, res, async function afterVerify(err) {
    // If verifyFirebaseToken ever calls next(err)
    if (err) {
      return res.status(401).json({ message: 'Unauthorized.' });
    }

    try {
      const uid = safeStr(req?.user?.uid).trim();
      if (!uid) {
        return res.status(401).json({ message: 'Unauthorized.' });
      }

      const claims = req?.user?.claims || {};
      const claimOK = isTruthyAdminClaim(claims);

      // Step 2: allow by claims, otherwise check Firestore role
      let ok = claimOK;

      if (!ok) {
        ok = await isAdminByFirestore(uid);
      }

      if (!ok) {
        return res.status(403).json({ message: 'Forbidden. Admin access required.' });
      }

      // helpful flag for handlers
      req.user.isAdmin = true;

      return next();
    } catch (e) {
      // eslint-disable-next-line no-console
      console.error('requireAdmin error:', e);
      return res.status(500).json({ message: 'Server error while checking admin permission.' });
    }
  });
}

module.exports = requireAdmin;
