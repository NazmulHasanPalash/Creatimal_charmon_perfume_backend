'use strict';

const admin = require('firebase-admin');
const fs = require('fs');
const path = require('path');

function safeStr(v) {
  return v === null || v === undefined ? '' : String(v);
}

function isPlainObject(v) {
  return v !== null && typeof v === 'object' && !Array.isArray(v);
}

function fixPrivateKey(serviceAccount) {
  if (!isPlainObject(serviceAccount)) return serviceAccount;

  const pk = safeStr(serviceAccount.private_key);
  if (!pk) return serviceAccount;

  // Fix env formatting: "\\n" -> "\n"
  return {
    ...serviceAccount,
    private_key: pk.replace(/\\n/g, '\n'),
  };
}

function validateServiceAccount(serviceAccount, sourceLabel) {
  if (!isPlainObject(serviceAccount)) {
    throw new Error(`${sourceLabel}: service account must be a JSON object.`);
  }

  const projectId = safeStr(serviceAccount.project_id).trim();
  const clientEmail = safeStr(serviceAccount.client_email).trim();
  const privateKey = safeStr(serviceAccount.private_key).trim();

  if (!projectId || !clientEmail || !privateKey) {
    throw new Error(
      `${sourceLabel}: service account JSON missing required fields (project_id, client_email, private_key).`
    );
  }
}

function loadServiceAccountFromFile(filePathRaw) {
  const raw = safeStr(filePathRaw).trim();
  if (!raw) return null;

  const absPath = path.isAbsolute(raw) ? raw : path.resolve(process.cwd(), raw);

  if (!fs.existsSync(absPath)) {
    throw new Error(
      `Service account file not found at: ${absPath}\n` +
        `Fix: set GOOGLE_APPLICATION_CREDENTIALS correctly, e.g.\n` +
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

function isVercelRuntime() {
  // Vercel typically sets VERCEL="1"
  return !!process.env.VERCEL || !!process.env.VERCEL_ENV || !!process.env.VERCEL_URL;
}

function initFirebaseAdmin() {
  // Prevent re-init in serverless warm instances / dev reload
  if (admin.apps && admin.apps.length) return admin;

  // Optional dev bypass (do NOT use in production)
  const disabled = safeStr(process.env.FIREBASE_DISABLED).trim().toLowerCase() === 'true';
  if (disabled) {
    console.warn('⚠️ FIREBASE_DISABLED=true → Firebase Admin will NOT be initialized.');
    return admin;
  }

  const onVercel = isVercelRuntime();
  const saRaw = safeStr(process.env.FIREBASE_SERVICE_ACCOUNT).trim();
  const gac = safeStr(process.env.GOOGLE_APPLICATION_CREDENTIALS).trim();

  // ✅ Vercel: MUST use env JSON
  if (onVercel) {
    if (!saRaw) {
      throw new Error(
        'Vercel detected but FIREBASE_SERVICE_ACCOUNT is missing.\n' +
          'Fix: Add FIREBASE_SERVICE_ACCOUNT in Vercel → Project → Settings → Environment Variables.'
      );
    }

    const serviceAccount = loadServiceAccountFromEnvJson(saRaw);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('✅ Firebase Admin initialized (Vercel: FIREBASE_SERVICE_ACCOUNT).');
    return admin;
  }

  // ✅ Local: file path
  if (gac) {
    const serviceAccount = loadServiceAccountFromFile(gac);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('✅ Firebase Admin initialized (Local: GOOGLE_APPLICATION_CREDENTIALS file).');
    return admin;
  }

  // ✅ Local/hosting: env JSON
  if (saRaw) {
    const serviceAccount = loadServiceAccountFromEnvJson(saRaw);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log('✅ Firebase Admin initialized (Env: FIREBASE_SERVICE_ACCOUNT).');
    return admin;
  }

  // ✅ Local convenience: auto-detect file
  const detected = findDefaultServiceAccountFileLocalOnly();
  if (detected) {
    const serviceAccount = loadServiceAccountFromFile(detected);
    admin.initializeApp({ credential: admin.credential.cert(serviceAccount) });
    console.log(`✅ Firebase Admin initialized (Local auto-detect: ${detected}).`);
    return admin;
  }

  // Fallback (mostly for GCP)
  try {
    admin.initializeApp({ credential: admin.credential.applicationDefault() });
    console.log('✅ Firebase Admin initialized (applicationDefault fallback).');
    return admin;
  } catch (e) {
    throw new Error(
      'Firebase Admin not configured.\n' +
        'Set ONE of:\n' +
        '1) GOOGLE_APPLICATION_CREDENTIALS=./serviceAccountKey.json (local)\n' +
        '2) FIREBASE_SERVICE_ACCOUNT=\'{"type":"service_account",...}\' (required on Vercel)\n' +
        `Original error: ${e?.message || e}`
    );
  }
}

module.exports = { admin, initFirebaseAdmin };
