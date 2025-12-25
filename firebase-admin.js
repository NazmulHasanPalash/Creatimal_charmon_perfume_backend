// firebase-admin.js
// ✅ Robust Firebase Admin SDK init (Local + Vercel safe)
// Local options:
//   1) GOOGLE_APPLICATION_CREDENTIALS=./serviceAccountKey.json
//   2) FIREBASE_SERVICE_ACCOUNT='{"type":"service_account",...}' (JSON string)
//   3) Auto-detect serviceAccountKey.json (LOCAL ONLY)
// Vercel:
//   ✅ Use FIREBASE_SERVICE_ACCOUNT only (recommended)
//   ❌ Do NOT rely on GOOGLE_APPLICATION_CREDENTIALS file path on Vercel

'use strict';

const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

function safeStr(v) {
  return v === null || v === undefined ? '' : String(v);
}

function fixPrivateKey(serviceAccount) {
  if (!serviceAccount || typeof serviceAccount !== 'object') return serviceAccount;

  const pk = safeStr(serviceAccount.private_key);
  if (!pk) return serviceAccount;

  // Common env issue: private_key contains literal "\\n"
  const fixed = pk.includes('\\n') ? pk.replace(/\\n/g, '\n') : pk;

  return { ...serviceAccount, private_key: fixed };
}

function validateServiceAccount(serviceAccount, sourceLabel) {
  const projectId = safeStr(serviceAccount?.project_id).trim();
  const clientEmail = safeStr(serviceAccount?.client_email).trim();
  const privateKey = safeStr(serviceAccount?.private_key).trim();

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error(
      `${sourceLabel}: service account JSON missing required fields ` +
        `(project_id, client_email, private_key).`
    );
  }
}

function loadServiceAccountFromFile(filePathRaw) {
  const raw = safeStr(filePathRaw).trim();
  if (!raw) return null;

  // If relative, resolve against current working dir (project root)
  const absPath = path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);

  if (!fs.existsSync(absPath)) {
    throw new Error(
      `Service account file not found at: ${absPath}\n` +
        `Fix: set GOOGLE_APPLICATION_CREDENTIALS to the correct path, e.g.\n` +
        `GOOGLE_APPLICATION_CREDENTIALS=./serviceAccountKey.json`
    );
  }

  const jsonText = fs.readFileSync(absPath, 'utf8');

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(jsonText);
  } catch (e) {
    throw new Error(
      `Service account file is not valid JSON: ${absPath}\n` +
        `Original error: ${e?.message || e}`
    );
  }

  serviceAccount = fixPrivateKey(serviceAccount);
  validateServiceAccount(serviceAccount, `File(${absPath})`);

  return serviceAccount;
}

function loadServiceAccountFromEnvJson(saRaw) {
  const raw = safeStr(saRaw).trim();
  if (!raw) return null;

  let serviceAccount;
  try {
    serviceAccount = JSON.parse(raw);
  } catch (e) {
    throw new Error(
      'FIREBASE_SERVICE_ACCOUNT must be a valid JSON string.\n' +
        'Tip: On Vercel, paste the JSON into the env var as ONE LINE.\n' +
        `Original error: ${e?.message || e}`
    );
  }

  serviceAccount = fixPrivateKey(serviceAccount);
  validateServiceAccount(serviceAccount, 'Env(FIREBASE_SERVICE_ACCOUNT)');

  return serviceAccount;
}

function findDefaultServiceAccountFileLocalOnly() {
  // Auto-detect common filenames (LOCAL ONLY)
  const candidates = [
    path.resolve(process.cwd(), 'serviceAccountKey.json'),
    path.resolve(process.cwd(), 'serviceAccount.json'),
    path.resolve(__dirname, 'serviceAccountKey.json'),
    path.resolve(__dirname, 'serviceAccount.json'),
  ];

  for (const p of candidates) {
    if (fs.existsSync(p)) return p;
  }
  return null;
}

function initFirebaseAdmin() {
  // Prevent "already exists" errors (dev hot reload / serverless re-use)
  if (admin.apps && admin.apps.length) return admin;

  // Optional: disable Firebase init (NOT for production)
  const disabled = safeStr(process.env.FIREBASE_DISABLED).trim().toLowerCase() === 'true';
  if (disabled) {
    console.warn('⚠️ FIREBASE_DISABLED=true → Firebase Admin will NOT be initialized.');
    return admin;
  }

  const isVercel = safeStr(process.env.VERCEL).trim() === '1' || !!process.env.VERCEL;

  const gac = safeStr(process.env.GOOGLE_APPLICATION_CREDENTIALS).trim();
  const saRaw = safeStr(process.env.FIREBASE_SERVICE_ACCOUNT).trim();

  // ✅ Vercel: MUST use env JSON (best practice)
  if (isVercel) {
    if (!saRaw) {
      throw new Error(
        'Vercel detected but FIREBASE_SERVICE_ACCOUNT is missing.\n' +
          'Fix: Add FIREBASE_SERVICE_ACCOUNT in Vercel Project → Settings → Environment Variables.'
      );
    }
    const serviceAccount = loadServiceAccountFromEnvJson(saRaw);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('✅ Firebase Admin initialized (Vercel: FIREBASE_SERVICE_ACCOUNT).');
    return admin;
  }

  // ✅ Local dev: GOOGLE_APPLICATION_CREDENTIALS file
  if (gac) {
    const serviceAccount = loadServiceAccountFromFile(gac);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('✅ Firebase Admin initialized (Local: GOOGLE_APPLICATION_CREDENTIALS file).');
    return admin;
  }

  // ✅ Any hosting: env JSON
  if (saRaw) {
    const serviceAccount = loadServiceAccountFromEnvJson(saRaw);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('✅ Firebase Admin initialized (Env: FIREBASE_SERVICE_ACCOUNT).');
    return admin;
  }

  // ✅ Local convenience: auto-detect file (LOCAL ONLY)
  const detected = findDefaultServiceAccountFileLocalOnly();
  if (detected) {
    const serviceAccount = loadServiceAccountFromFile(detected);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log(`✅ Firebase Admin initialized (Local auto-detect: ${detected}).`);
    return admin;
  }

  // Final fallback: applicationDefault (mainly for GCP environments)
  try {
    admin.initializeApp({ credential: admin.credential.applicationDefault() });
    console.log('✅ Firebase Admin initialized (applicationDefault fallback).');
    return admin;
  } catch (e) {
    throw new Error(
      'Firebase Admin not configured.\n' +
        'Set ONE of:\n' +
        '1) GOOGLE_APPLICATION_CREDENTIALS=./serviceAccountKey.json (local)\n' +
        '2) FIREBASE_SERVICE_ACCOUNT=\'{"type":"service_account",...}\' (recommended for Vercel)\n' +
        `Original error: ${e?.message || e}`
    );
  }
}

module.exports = {
  admin,
  initFirebaseAdmin,
};
