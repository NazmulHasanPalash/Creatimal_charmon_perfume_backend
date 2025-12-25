// verifyFirebaseToken.js
'use strict';

const { admin } = require('./firebase-admin');

/**
 * Extract Firebase ID token from common places:
 * - Authorization: Bearer <token>
 * - cookies.idToken (if you use cookie-parser)
 * - header: x-firebase-token
 * - query: ?token=<token> (optional)
 */
function extractToken(req) {
  const authHeader = req.headers.authorization || req.headers.Authorization;
  if (typeof authHeader === 'string') {
    const m = authHeader.match(/^Bearer\s+(.+)$/i);
    if (m && m[1]) return String(m[1]).trim();
  }

  const xToken = req.headers['x-firebase-token'];
  if (typeof xToken === 'string' && xToken.trim()) return xToken.trim();

  if (req.cookies && typeof req.cookies.idToken === 'string' && req.cookies.idToken.trim()) {
    return req.cookies.idToken.trim();
  }

  if (req.query && typeof req.query.token === 'string' && req.query.token.trim()) {
    return req.query.token.trim();
  }

  return '';
}

/**
 * Middleware: verifies Firebase ID token and sets req.user
 * Usage:
 *   const verifyFirebaseToken = require('./verifyFirebaseToken');
 *   app.get('/secure', verifyFirebaseToken, (req,res)=> res.json(req.user));
 */
async function verifyFirebaseToken(req, res, next) {
  try {
    const token = extractToken(req);

    if (!token) {
      return res.status(401).json({ message: 'Missing Authorization token (Bearer).' });
    }

    if (!admin || typeof admin.auth !== 'function') {
      return res.status(500).json({ message: 'Firebase Admin SDK not initialized.' });
    }

    // true => checks for revoked tokens too
    const decoded = await admin.auth().verifyIdToken(token, true);

    req.user = {
      uid: decoded.uid,
      email: decoded.email || '',
      emailVerified: !!decoded.email_verified,
      name: decoded.name || decoded.displayName || '',
      picture: decoded.picture || '',
      claims: decoded, // full decoded claims if you need them
    };

    return next();
  } catch (err) {
    const code = (err && err.code) ? String(err.code) : '';

    if (code.includes('auth/id-token-expired')) {
      return res.status(401).json({ message: 'Token expired. Please login again.' });
    }

    if (code.includes('auth/id-token-revoked')) {
      return res.status(401).json({ message: 'Token revoked. Please login again.' });
    }

    return res.status(401).json({ message: 'Unauthorized. Invalid or expired token.' });
  }
}

module.exports = verifyFirebaseToken;
module.exports.extractToken = extractToken;
