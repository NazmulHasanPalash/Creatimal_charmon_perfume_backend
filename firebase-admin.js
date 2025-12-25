// firebase-admin.js
// ✅ Robust Firebase Admin SDK init
// ✅ Works with:
//    1) GOOGLE_APPLICATION_CREDENTIALS=./serviceAccountKey.json (relative or absolute)
//    2) FIREBASE_SERVICE_ACCOUNT='{"type":"service_account",...}' (JSON string)
//    3) Auto-detect ./serviceAccountKey.json if env not set (project root or same folder)
//    4) Fixes private_key newline issues (\\n -> \n)

'use strict';

const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

function safeStr(v) {
  return v === null || v === undefined ? '' : String(v);
}

function fixPrivateKey(sa) {
  if (!sa || typeof sa !== 'object') return sa;
  const pk = safeStr(sa.private_key);
  if (!pk) return sa;

  // Common .env issue: private_key has literal "\n"
  const fixed = pk.includes('\\n') ? pk.replace(/\\n/g, '\n') : pk;

  return { ...sa, private_key: fixed };
}

function loadServiceAccountFromFile(filePathRaw) {
  const raw = safeStr(filePathRaw).trim();
  if (!raw) return null;

  // If relative, resolve against current working dir (project root)
  const absPath = path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);

  if (!fs.existsSync(absPath)) {
    throw new Error(
      `Service account file not found at: ${absPath}\n` +
        `Tip: set GOOGLE_APPLICATION_CREDENTIALS to the correct path, e.g.\n` +
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

  const projectId = safeStr(serviceAccount.project_id).trim();
  const clientEmail = safeStr(serviceAccount.client_email).trim();
  const privateKey = safeStr(serviceAccount.private_key).trim();

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error(
      `Service account JSON missing required fields (project_id, client_email, private_key): ${absPath}`
    );
  }

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
        'Tip: wrap in single quotes in .env and ensure private_key newlines are escaped.\n' +
        `Original error: ${e?.message || e}`
    );
  }

  serviceAccount = fixPrivateKey(serviceAccount);

  const projectId = safeStr(serviceAccount.project_id).trim();
  const clientEmail = safeStr(serviceAccount.client_email).trim();
  const privateKey = safeStr(serviceAccount.private_key).trim();

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error(
      'FIREBASE_SERVICE_ACCOUNT JSON missing required fields: project_id, client_email, private_key.'
    );
  }

  return serviceAccount;
}

function findDefaultServiceAccountFile() {
  // Auto-detect common filenames if env is not set
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
  // Prevent "already exists" error in dev/hot reload
  if (admin.apps && admin.apps.length) return admin;

  // Optional: allow disabling Firebase auth in dev (NOT recommended for production)
  const disabled = safeStr(process.env.FIREBASE_DISABLED).trim().toLowerCase() === 'true';
  if (disabled) {
    console.warn('⚠️ FIREBASE_DISABLED=true → Firebase Admin will NOT be initialized.');
    return admin;
  }

  const gac = safeStr(process.env.GOOGLE_APPLICATION_CREDENTIALS).trim();
  const saRaw = safeStr(process.env.FIREBASE_SERVICE_ACCOUNT).trim();

  // 1) GOOGLE_APPLICATION_CREDENTIALS path (recommended for local dev)
  if (gac) {
    const serviceAccount = loadServiceAccountFromFile(gac);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('✅ Firebase Admin initialized (GOOGLE_APPLICATION_CREDENTIALS file).');
    return admin;
  }

  // 2) FIREBASE_SERVICE_ACCOUNT JSON string (recommended for hosting env vars)
  if (saRaw) {
    const serviceAccount = loadServiceAccountFromEnvJson(saRaw);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('✅ Firebase Admin initialized (FIREBASE_SERVICE_ACCOUNT JSON).');
    return admin;
  }

  // 3) Auto-detect serviceAccountKey.json if you forgot env var
  const detected = findDefaultServiceAccountFile();
  if (detected) {
    const serviceAccount = loadServiceAccountFromFile(detected);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log(`✅ Firebase Admin initialized (auto-detected file: ${detected}).`);
    return admin;
  }

  // 4) Final fallback: applicationDefault (useful on GCP environments)
  // Note: If you are NOT on GCP and did not set creds, verifyIdToken will fail later.
  try {
    admin.initializeApp({ credential: admin.credential.applicationDefault() });
    console.log('✅ Firebase Admin initialized (applicationDefault fallback).');
    return admin;
  } catch (e) {
    // If even this fails, throw a clear error
    throw new Error(
      'Firebase Admin not configured.\n' +
        'Set ONE of the following:\n' +
        '1) GOOGLE_APPLICATION_CREDENTIALS=./serviceAccountKey.json\n' +
        `2) FIREBASE_SERVICE_ACCOUNT='{"type":"service_account",...}'\n` +
        'Or put serviceAccountKey.json in your project root.\n' +
        `Original error: ${e?.message || e}`
    );
  }
}

module.exports = {
  admin,
  initFirebaseAdmin,
};
