const express = require('express');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');

const app = express();

// ------------------------------------------------------------------
// Enterprise structured logging
// LOG_LEVEL=debug|info|warn|error (default info). LOG_FILE appends JSONL.
// All logs go to stdout (Coolify picks them up); audit events also go to
// DATA_DIR/logs/audit.log for compliance. Secrets are never logged.
// ------------------------------------------------------------------
const LOG_LEVEL = (process.env.LOG_LEVEL || 'info').toLowerCase();
const LOG_LEVELS = { debug: 10, info: 20, warn: 30, error: 40 };
const LOG_FILE = process.env.LOG_FILE || '';
function maskSecrets(obj) {
  try {
    const s = JSON.stringify(obj);
    return s.replace(/(cert_[a-f0-9]{8})[a-f0-9]+/gi, '$1…')
      .replace(/("password"\s*:\s*")[^"]*(")/gi, '$1***$2')
      .replace(/(-----BEGIN [^-]+-----)[\s\S]*?(-----END [^-]+-----)/g, '$1 ***REDACTED*** $2');
  } catch (e) { return '[unserializable]'; }
}
function log(level, msg, meta) {
  if ((LOG_LEVELS[level] ?? 20) < (LOG_LEVELS[LOG_LEVEL] ?? 20)) return;
  const entry = { ts: new Date().toISOString(), level, msg };
  if (meta !== undefined) {
    try { entry.meta = JSON.parse(maskSecrets(meta)); }
    catch (e) { entry.meta = String(meta).slice(0, 2000); }
  }
  const line = JSON.stringify(entry);
  if (level === 'error' || level === 'warn') console.error(line);
  else console.log(line);
  if (LOG_FILE) { try { fs.appendFileSync(LOG_FILE, line + '\n'); } catch (e) {} }
}
const logger = {
  debug: (m, x) => log('debug', m, x),
  info: (m, x) => log('info', m, x),
  warn: (m, x) => log('warn', m, x),
  error: (m, x) => log('error', m, x),
};
function audit(event, details, req) {
  const entry = {
    ts: new Date().toISOString(), event,
    ip: req ? (req.ip || req.headers['x-forwarded-for'] || '') : '',
    actor: req && req.apiToken ? req.apiToken.name : (req && req.adminUser ? req.adminUser : 'admin-ui/session'),
    details: details || {}
  };
  const line = JSON.stringify(entry);
  console.log(JSON.stringify({ ts: entry.ts, level: 'audit', msg: event, meta: { ip: entry.ip, actor: entry.actor } }));
  try {
    const auditDir = path.join(DATA_DIR, 'logs');
    if (!fs.existsSync(auditDir)) fs.mkdirSync(auditDir, { recursive: true });
    fs.appendFileSync(path.join(auditDir, 'audit.log'), line + '\n');
  } catch (e) {}
}
// Request id + access log (method, path, status, ms) — no bodies/tokens logged.
app.use((req, res, next) => {
  req.id = crypto.randomBytes(8).toString('hex');
  const start = Date.now();
  res.on('finish', () => {
    const ms = Date.now() - start;
    const level = res.statusCode >= 500 ? 'error' : res.statusCode >= 400 ? 'warn' : 'debug';
    log(level, 'http', { reqId: req.id, method: req.method, path: req.url.split('?')[0], status: res.statusCode, ms });
  });
  next();
});
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ type: ['text/*', 'application/pkcs10', 'application/x-pem-file'], limit: '10mb' }));

const PORT = parseInt(process.env.PORT || '9000', 10);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
// BASE_URL is an optional override. When unset, the public URL is AUTO-DETECTED
// per request from X-Forwarded-Proto/Host (Coolify/Traefik) + BASE_PATH, so domain
// changes never require a redeploy for ACME/CRL/installer URLs.
const BASE_URL_FROM_ENV = !!(process.env.BASE_URL && process.env.BASE_URL.trim());
// BASE_PATH: sub-path when hosted behind a path-based reverse proxy (Coolify).
// e.g. BASE_PATH=/cert-signer when UI is at https://backend.rajlabs.in/cert-signer
// Can also be auto-detected: set BASE_PATH=auto to derive it from the first
// request's path prefix. Frontend probes both injected value and location.
const BASE_PATH_RAW = (process.env.BASE_PATH || '').trim().replace(/\/$/, '');
let BASE_PATH = BASE_PATH_RAW === 'auto' ? '' : BASE_PATH_RAW;
function getPublicBase(req) {
  if (BASE_URL_FROM_ENV) return BASE_URL;
  try {
    const proto = String(req.headers['x-forwarded-proto'] || req.protocol || 'http').split(',')[0].trim() || 'http';
    const host = String(req.headers['x-forwarded-host'] || req.headers['host'] || `localhost:${PORT}`).split(',')[0].trim();
    const cleanHost = host.replace(/\/$/, '');
    // If BASE_PATH=auto, learn it from the incoming URL's first segment
    if (BASE_PATH_RAW === 'auto' && !BASE_PATH) {
      const m = String(req.url || '').match(/^\/([^\/?#]+)(\/|$)/);
      if (m && /^(api|acme|certs|crl|health|install-trust-)/.test(m[1]) === false) {
        // Looks like a sub-path deployment; remember it for this process
        BASE_PATH = '/' + m[1];
        logger.info('server.basepath_autodetected', { basePath: BASE_PATH });
      }
    }
    return `${proto}://${cleanHost}${BASE_PATH || ''}`.replace(/\/$/, '');
  } catch (e) { return BASE_URL; }
}
app.set('trust proxy', 1);
// Minimal CORS so a FreeRADIUS/backend dashboard on another origin can probe status.
app.use((req, res, next) => {
  res.setHeader('Access-Control-Allow-Origin', process.env.CORS_ORIGIN || '*');
  res.setHeader('Access-Control-Allow-Headers', 'Content-Type, Authorization, x-api-key');
  res.setHeader('Access-Control-Allow-Methods', 'GET,POST,DELETE,OPTIONS');
  if (req.method === 'OPTIONS') return res.status(204).end();
  next();
});
// Strip BASE_PATH prefix when the proxy forwards the full path (Coolify default).
app.use((req, res, next) => {
  if (BASE_PATH && (req.url === BASE_PATH || req.url.startsWith(BASE_PATH + '/'))) {
    req.url = req.url.slice(BASE_PATH.length) || '/';
  }
  next();
});

// Standard error envelope so API consumers (FreeRADIUS UI, scripts) can
// render friendly messages. Codes: CA_NOT_AVAILABLE, VALIDATION_ERROR,
// NOT_FOUND, UNAUTHORIZED, FORBIDDEN_REVOKED_KEY, INTERNAL_ERROR, PARSE_ERROR
function sendError(res, httpStatus, code, message, hint) {
  const body = { success: false, code, error: message };
  if (hint) body.hint = hint;
  return res.status(httpStatus).json(body);
}
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CERTS_DIR = path.join(DATA_DIR, 'issued-certs');
const CRL_DIR = path.join(DATA_DIR, 'crl');
const DB_FILE = path.join(DATA_DIR, 'database.json');
const CREDENTIALS_FILE = path.join(DATA_DIR, 'admin_credentials.txt');

[DATA_DIR, CERTS_DIR, CRL_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// AES-256-GCM Encryption for Intermediate Private Keys in DB/Disk
const MASTER_KEY_FILE = path.join(DATA_DIR, 'master_encryption.key');
function getMasterKey() {
  if (process.env.ENCRYPTION_KEY) {
    return crypto.createHash('sha256').update(process.env.ENCRYPTION_KEY).digest();
  }
  if (!fs.existsSync(MASTER_KEY_FILE)) {
    const key = crypto.randomBytes(32);
    fs.writeFileSync(MASTER_KEY_FILE, key, { mode: 0o600 });
    return key;
  }
  return fs.readFileSync(MASTER_KEY_FILE);
}
const MASTER_ENCRYPTION_KEY = getMasterKey();

function encryptData(text) {
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv('aes-256-gcm', MASTER_ENCRYPTION_KEY, iv);
  let encrypted = cipher.update(text, 'utf8', 'hex');
  encrypted += cipher.final('hex');
  const authTag = cipher.getAuthTag().toString('hex');
  return `${iv.toString('hex')}:${authTag}:${encrypted}`;
}

function decryptData(cipherText) {
  const parts = cipherText.split(':');
  if (parts.length !== 3) return cipherText; // Return raw if unencrypted
  const iv = Buffer.from(parts[0], 'hex');
  const authTag = Buffer.from(parts[1], 'hex');
  const encrypted = parts[2];
  const decipher = crypto.createDecipheriv('aes-256-gcm', MASTER_ENCRYPTION_KEY, iv);
  decipher.setAuthTag(authTag);
  let decrypted = decipher.update(encrypted, 'hex', 'utf8');
  decrypted += decipher.final('utf8');
  return decrypted;
}

// ------------------------------------------------------------------
// Database Layer: PostgreSQL with automatic in-built SQLite fallback
// ------------------------------------------------------------------
const SQLITE_FILE = path.join(DATA_DIR, 'pki_vault.sqlite');
let sqliteDb = null;
let pgPool = null;
let activeDatabaseType = 'Inbuilt SQLite';

try {
  const sqlite3 = require('sqlite3').verbose();
  sqliteDb = new sqlite3.Database(SQLITE_FILE);
  sqliteDb.serialize(() => {
    sqliteDb.run(`CREATE TABLE IF NOT EXISTS system_config (key TEXT PRIMARY KEY, value TEXT NOT NULL)`);
    sqliteDb.run(`CREATE TABLE IF NOT EXISTS intermediate_cas (id TEXT PRIMARY KEY, name TEXT UNIQUE NOT NULL, description TEXT, cert_pem TEXT NOT NULL, encrypted_key_pem TEXT NOT NULL, root_cert_pem TEXT NOT NULL, is_active INTEGER DEFAULT 0, created_at TEXT)`);
    sqliteDb.run(`CREATE TABLE IF NOT EXISTS api_tokens (id TEXT PRIMARY KEY, name TEXT NOT NULL, token TEXT UNIQUE NOT NULL, created_at TEXT)`);
    sqliteDb.run(`CREATE TABLE IF NOT EXISTS issued_certs (id TEXT PRIMARY KEY, serial TEXT NOT NULL, ca_name TEXT NOT NULL, san_domains TEXT, status TEXT DEFAULT 'valid', issued_at TEXT)`);
  });
  logger.info('database.sqlite.init', { file: SQLITE_FILE });
} catch (err) {
  logger.warn('database.sqlite.fallback_to_json', { error: err.message });
}

if (process.env.DATABASE_URL) {
  pgPool = new Pool({ connectionString: process.env.DATABASE_URL });
  initPostgres().then(() => {
    activeDatabaseType = 'PostgreSQL';
    logger.info('database.postgres.connected', {});
  }).catch(err => {
    logger.error('database.postgres.failed_fallback_sqlite', { error: err.message });
  });
}

async function initPostgres() {
  if (!pgPool) return;
  await pgPool.query(`
    CREATE TABLE IF NOT EXISTS system_config (
      key VARCHAR(50) PRIMARY KEY,
      value TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS intermediate_cas (
      id VARCHAR(50) PRIMARY KEY,
      name VARCHAR(100) UNIQUE NOT NULL,
      description TEXT,
      cert_pem TEXT NOT NULL,
      encrypted_key_pem TEXT NOT NULL,
      root_cert_pem TEXT NOT NULL,
      is_active BOOLEAN DEFAULT false,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS api_tokens (
      id VARCHAR(50) PRIMARY KEY,
      name VARCHAR(100) NOT NULL,
      token VARCHAR(100) UNIQUE NOT NULL,
      created_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
    CREATE TABLE IF NOT EXISTS issued_certs (
      id VARCHAR(50) PRIMARY KEY,
      serial VARCHAR(50) NOT NULL,
      intermediate_name VARCHAR(100) NOT NULL,
      san_domains TEXT[],
      status VARCHAR(20) DEFAULT 'valid',
      issued_at TIMESTAMP DEFAULT CURRENT_TIMESTAMP
    );
  `);
}

function getLocalDB() {
  if (!fs.existsSync(DB_FILE)) {
    fs.writeFileSync(DB_FILE, JSON.stringify({
      config: {},
      intermediateCAs: [],
      apiTokens: [],
      certificates: [],
      serial: 2000
    }, null, 2));
  }
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveLocalDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
  // Sync to SQLite asynchronously for durability
  if (sqliteDb) {
    sqliteDb.serialize(() => {
      sqliteDb.run(`INSERT OR REPLACE INTO system_config (key, value) VALUES ('db_snapshot', ?)`, [JSON.stringify(data)]);
    });
  }
}

// ------------------------------------------------------------------
// Admin Credentials Auto-Generation
// ------------------------------------------------------------------
function initAdminAuth() {
  const db = getLocalDB();
  db.config.adminUser = process.env.ADMIN_USER || db.config.adminUser || 'admin';

  if (process.env.ADMIN_PASSWORD) {
    // User explicitly provided ADMIN_PASSWORD in environment (e.g. in Docker / Coolify)
    const salt = bcrypt.genSaltSync(10);
    db.config.adminPasswordHash = bcrypt.hashSync(process.env.ADMIN_PASSWORD, salt);
    if (!db.config.hasCompletedSetup) {
      db.config.isFirstRun = true;
      db.config.temporaryInitialPassword = process.env.ADMIN_PASSWORD;
    }
    saveLocalDB(db);
    logger.info('auth.admin_password_from_env', { user: db.config.adminUser });
  } else if (!db.config.adminPasswordHash) {
    // No password provided; auto-generate a cryptographically strong initial password
    const generatedPassword = crypto.randomBytes(18).toString('base64url');
    const salt = bcrypt.genSaltSync(10);
    db.config.adminPasswordHash = bcrypt.hashSync(generatedPassword, salt);
    db.config.isFirstRun = true;
    db.config.temporaryInitialPassword = generatedPassword;
    saveLocalDB(db);

    const credNotice = `==========================================================\n ENTERPRISE CERTIFICATE SIGNER - ADMIN CREDENTIALS\n==========================================================\n Generated User     : ${db.config.adminUser}\n Generated Password : ${generatedPassword}\n Login UI URL       : ${BASE_URL}/login\n Saved at (Docker)  : ${CREDENTIALS_FILE}\n==========================================================\n`;
    fs.writeFileSync(CREDENTIALS_FILE, credNotice);
    logger.info('auth.admin_autogenerated', { user: db.config.adminUser, credentialsFile: CREDENTIALS_FILE });
    if (LOG_LEVEL === 'debug') console.log(credNotice);
  }
}
initAdminAuth();

// Simple Session Token Map
const activeSessions = new Set();

function findApiTokenRecord(db, apiKey) {
  const keyBuf = Buffer.from(String(apiKey));
  return (db.apiTokens || []).find(t => {
    if (t.revoked) return false;
    if (t.expiresAt && new Date(t.expiresAt).getTime() < Date.now()) return false;
    try {
      const tokBuf = Buffer.from(String(t.token));
      return keyBuf.length === tokBuf.length && crypto.timingSafeEqual(keyBuf, tokBuf);
    } catch (e) { return false; }
  }) || null;
}

function recordTokenUsage(tokenId, commonName) {
  try {
    const db = getLocalDB();
    const t = (db.apiTokens || []).find(x => x.id === tokenId);
    if (!t) return;
    t.usageCount = (t.usageCount || 0) + 1;
    t.lastUsedAt = new Date().toISOString();
    if (commonName) t.lastUsedCN = commonName;
    saveLocalDB(db);
  } catch (e) { /* usage accounting must never break signing */ }
}

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const apiKey = req.headers['x-api-key'] || '';

  // Check Bearer session token from UI login
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    if (activeSessions.has(token)) return next();
  }

  // Check API Token using timing-safe comparison to prevent timing attacks
  try {
    const db = getLocalDB();
    if (apiKey) {
      const match = findApiTokenRecord(db, apiKey);
      if (match) {
        req.apiToken = { id: match.id, name: match.name };
        return next();
      }
      // Legacy global AUTH_TOKEN env fallback (no usage tracking)
      if (process.env.AUTH_TOKEN) {
        const keyBuf = Buffer.from(String(apiKey));
        const envBuf = Buffer.from(String(process.env.AUTH_TOKEN));
        if (keyBuf.length === envBuf.length && crypto.timingSafeEqual(keyBuf, envBuf)) {
          req.apiToken = { id: 'env:AUTH_TOKEN', name: 'ENV AUTH_TOKEN' };
          return next();
        }
      }
    }
  } catch (e) { /* fall through to 401 */ }

  return sendError(res, 401, 'UNAUTHORIZED', 'Unauthorized. Please login or provide a valid x-api-key token.',
    'Login via POST /api/auth/login, or pass a non-revoked API key in x-api-key header.');
}

// ------------------------------------------------------------------
// Certificate Signing Engine
// ------------------------------------------------------------------
// Purpose → intermediate CA routing. Request can name a CA explicitly
// (intermediateId/ca), give a purpose/profile (server|wifi|iot|radius…),
// or leave it empty for active → int-server → first healthy CA.
const CA_PURPOSE_MAP = {
  'server': ['int-server'], 'web': ['int-server'], 'tls': ['int-server'], 'acme': ['int-server'],
  'wifi': ['int-wifi'], 'radius': ['int-wifi'], '8021x': ['int-wifi'], '802.1x': ['int-wifi'], 'eap': ['int-wifi'], 'wireless': ['int-wifi'],
  'iot': ['int-iot'], 'device': ['int-iot'], 'mqtt': ['int-iot'], 'embedded': ['int-iot']
};
function resolveSigningCA(db, hint) {
  const cas = db.intermediateCAs || [];
  const usable = (c) => !!(c && c.certPem && c.encryptedKeyPem);
  const h = String(hint && (hint.ca || hint.intermediateId || hint.intermediateName || hint.purpose || hint.profile || '')).toLowerCase().trim();
  // 1. Explicit CA name wins (if it exists and has a key)
  if (h) {
    const exact = cas.find(c => c.name.toLowerCase() === h && usable(c));
    if (exact) return { ca: exact, reason: `explicit:${exact.name}` };
    // 2. Purpose/profile mapping (wifi/radius→int-wifi, iot/device→int-iot, server/web→int-server)
    const candidates = CA_PURPOSE_MAP[h] || [];
    for (const name of candidates) {
      const match = cas.find(c => c.name.toLowerCase() === name && usable(c));
      if (match) return { ca: match, reason: `purpose:${h}→${match.name}` };
    }
    // Unknown hint: fall through to defaults (never hard-fail on a typo)
  }
  // 3. Active CA, 4. int-server default, 5. first usable CA
  const active = cas.find(c => c.isActive && usable(c));
  if (active) return { ca: active, reason: h ? `fallback:active:${active.name}` : 'default:active' };
  const server = cas.find(c => c.name.toLowerCase() === 'int-server' && usable(c));
  if (server) return { ca: server, reason: h ? `fallback:int-server` : 'default:int-server' };
  const first = cas.find(usable);
  if (first) return { ca: first, reason: h ? `fallback:first:${first.name}` : 'default:first' };
  return { ca: null, reason: 'none:empty' };
}
async function signLeafCertificate(csrPem, sanDomains = [], days = 90, issuedVia, publicBase, caHint) {
  const db = getLocalDB();
  const { ca: activeCA, reason: selectionReason } = resolveSigningCA(db, caHint);
  if (!activeCA) {
    const err = new Error('CA_NOT_AVAILABLE: No Signing CA set up yet. Open Admin UI → 🧙 Setup Wizard (or Intermediate CAs) and generate/import at least one Signing CA (e.g. int-server for web/TLS, int-wifi for RADIUS/802.1X, int-iot for devices), then retry.');
    err.code = 'CA_NOT_AVAILABLE';
    err.httpStatus = 503;
    err.details = { hint: caHint || null, expectedCAs: ['int-server', 'int-wifi', 'int-iot'], setupUrl: '/onboarding' };
    throw err;
  }
  let decryptedKey;
  try {
    decryptedKey = decryptData(activeCA.encryptedKeyPem);
  } catch (e) {
    const err = new Error('CA_NOT_AVAILABLE: Active intermediate CA private key cannot be decrypted. Re-import the CA.');
    err.code = 'CA_NOT_AVAILABLE';
    err.httpStatus = 503;
    throw err;
  }
  if (!decryptedKey || !decryptedKey.includes('PRIVATE KEY')) {
    const err = new Error('CA_NOT_AVAILABLE: Active intermediate CA has no usable private key.');
    err.code = 'CA_NOT_AVAILABLE';
    err.httpStatus = 503;
    throw err;
  }

  const certId = uuidv4();
  const serialNum = db.serial++;
  saveLocalDB(db);

  const serial = serialNum.toString(16).padStart(4, '0');
  const tempCsr = path.join('/tmp', `${certId}.csr`);
  const tempCert = path.join('/tmp', `${certId}.crt`);
  const tempExt = path.join('/tmp', `${certId}.ext`);
  const tempCaCert = path.join('/tmp', `${certId}-ca.crt`);
  const tempCaKey = path.join('/tmp', `${certId}-ca.key`);

  fs.writeFileSync(tempCsr, csrPem);
  fs.writeFileSync(tempCaCert, activeCA.certPem);
  fs.writeFileSync(tempCaKey, decryptedKey, { mode: 0o600 });

  const crlFallbackBases = [
    publicBase || BASE_URL,
    'http://certs.rajlabs.in',
    'http://crl.rajlabs.in',
    'http://pki.rajlabs.in'
  ].filter((v, i, a) => a.indexOf(v) === i);

  const crlUrls = crlFallbackBases.map(u => `URI:${u}/crl/${activeCA.name}.crl`).join(', ');
  const ocspUrls = crlFallbackBases.map(u => `OCSP;URI:${u}/ocsp`).join(', ');
  const caIssuerUrls = crlFallbackBases.map(u => `caIssuers;URI:${u}/api/v1/ca/${activeCA.name}/cert`).join(', ');

  let extContent = [
    'basicConstraints = CA:FALSE',
    'keyUsage = digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth, clientAuth',
    'subjectKeyIdentifier = hash',
    'authorityKeyIdentifier = keyid,issuer',
    `crlDistributionPoints = ${crlUrls}`,
    `authorityInfoAccess = ${ocspUrls}, ${caIssuerUrls}`
  ];

  if (sanDomains.length > 0) {
    const sans = sanDomains.map((d, i) => `DNS.${i + 1} = ${d}`).join('\n');
    extContent.push(`subjectAltName = @alt_names\n[alt_names]\n${sans}`);
  }

  fs.writeFileSync(tempExt, extContent.join('\n'));

  // Execute openssl using execFileSync with explicit argument array (immune to shell injection)
  try {
    execFileSync('openssl', [
      'x509',
      '-req',
      '-in', tempCsr,
      '-CA', tempCaCert,
      '-CAkey', tempCaKey,
      '-set_serial', `0x${serial}`,
      '-out', tempCert,
      '-days', Math.max(1, Math.min(825, parseInt(days, 10) || 90)).toString(),
      '-sha256',
      '-extfile', tempExt
    ], { stdio: 'pipe' });
  } catch (e) {
    [tempCsr, tempCert, tempExt, tempCaCert, tempCaKey].forEach(f => { try { fs.unlinkSync(f); } catch (_) {} });
    // Roll back serial reservation bookkeeping is noisy; keep monotonic serials.
    const err = new Error('SIGNING_FAILED: OpenSSL could not sign the CSR. Verify the CSR is a valid PEM PKCS#10 request.');
    err.code = 'SIGNING_FAILED';
    err.httpStatus = 422;
    throw err;
  }

  const issuedCert = fs.readFileSync(tempCert, 'utf8');
  const fullChain = `${issuedCert.trim()}\n${activeCA.certPem.trim()}\n${activeCA.rootCertPem.trim()}`.trim();

  fs.writeFileSync(path.join(CERTS_DIR, `${certId}.crt`), issuedCert);
  fs.writeFileSync(path.join(CERTS_DIR, `${certId}-chain.crt`), fullChain);

  // Clean temp files securely
  [tempCsr, tempCert, tempExt, tempCaCert, tempCaKey].forEach(f => {
    try { fs.unlinkSync(f); } catch (e) {}
  });

  const primaryCN = (sanDomains && sanDomains[0]) || '';
  db.certificates.unshift({
    id: certId,
    serial,
    caName: activeCA.name,
    commonName: primaryCN,
    sanDomains,
    issuedAt: new Date().toISOString(),
    status: 'valid',
    issuedViaTokenId: (issuedVia && issuedVia.id) || null,
    issuedViaTokenName: (issuedVia && issuedVia.name) || null
  });
  saveLocalDB(db);
  if (issuedVia && issuedVia.id && !String(issuedVia.id).startsWith('env:') && issuedVia.id !== 'admin-ui') {
    recordTokenUsage(issuedVia.id, primaryCN);
  }

  return { certId, serial, certificate: issuedCert, fullChain, caName: activeCA.name, selectionReason };
}

// ------------------------------------------------------------------
// Web UI & Authentication Endpoints
// ------------------------------------------------------------------
// Serve static assets, but inject runtime base-path into index.html so the
// SPA works behind Coolify path-based routing (e.g. /cert-signer).
app.use(express.static(path.join(__dirname, 'public'), { index: false }));
// /onboarding is an alias for the setup wizard (same SPA; frontend force-opens it).
app.get(['/', '/index.html', '/onboarding'], (req, res) => {
  try {
    let html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    const inject = `<script>window.__PKI_BASE_PATH__=${JSON.stringify(BASE_PATH || '')};window.__PKI_BASE_URL__=${JSON.stringify(BASE_URL)};</script>`;
    html = html.replace('</head>', `  ${inject}\n</head>`);
    res.setHeader('Content-Type', 'text/html');
    return res.send(html);
  } catch (e) {
    return res.status(500).send('UI unavailable');
  }
});

app.get('/api/auth/setup-status', (req, res) => {
  const db = getLocalDB();
  const payload = {
    isFirstRun: !!db.config.isFirstRun,
    basePath: BASE_PATH || '',
    baseUrl: BASE_URL,
    adminUser: db.config.adminUser || process.env.ADMIN_USER || 'admin'
  };
  if (db.config.isFirstRun) {
    payload.initialPassword = db.config.temporaryInitialPassword || null;
  }
  res.json(payload);
});

app.post('/api/auth/complete-setup', (req, res) => {
  const db = getLocalDB();
  db.config.isFirstRun = false;
  db.config.hasCompletedSetup = true;
  delete db.config.temporaryInitialPassword;
  saveLocalDB(db);
  res.json({ success: true });
});

// ------------------------------------------------------------------
// 1-Click Onboarding PKI Wizard Generator
// Generates Root CA & Intermediate CA in memory, saves intermediate to DB,
// hands Root CA Private Key to user for download, then IMMEDIATELY wipes root key!
// ------------------------------------------------------------------
app.post('/api/auth/onboarding-generate-pki', (req, res) => {
  const db = getLocalDB();
  const orgName = (req.body.orgName || 'Enterprise').replace(/[^a-zA-Z0-9\s.\-_]/g, '');
  const country = (req.body.country || 'US').replace(/[^a-zA-Z]/g, '').substring(0, 2).toUpperCase();
  const state = (req.body.state || 'California').replace(/[^a-zA-Z0-9\s.\-_]/g, '');
  const city = (req.body.city || 'San Francisco').replace(/[^a-zA-Z0-9\s.\-_]/g, '');
  const intermediateName = (req.body.intermediateName || 'int-server').toLowerCase().replace(/[^a-z0-9\-_]/g, '');

  const opId = uuidv4();
  const rootKeyFile = path.join('/tmp', `${opId}-root.key`);
  const rootCertFile = path.join('/tmp', `${opId}-root.crt`);
  const intKeyFile = path.join('/tmp', `${opId}-int.key`);
  const intCsrFile = path.join('/tmp', `${opId}-int.csr`);
  const intCertFile = path.join('/tmp', `${opId}-int.crt`);
  const extFile = path.join('/tmp', `${opId}-ext.cnf`);

  try {
    // 1. Generate Root CA (4096-bit RSA, 20 Years)
    execFileSync('openssl', ['genrsa', '-out', rootKeyFile, '4096'], { stdio: 'pipe' });
    const rootSubj = `/C=${country}/ST=${state}/L=${city}/O=${orgName}/OU=${orgName} Root Authority/CN=${orgName} Root CA`;
    execFileSync('openssl', ['req', '-new', '-x509', '-days', '7300', '-sha256', '-key', rootKeyFile, '-out', rootCertFile, '-subj', rootSubj], { stdio: 'pipe' });

    // 2. Generate Intermediate CA (4096-bit RSA, 10 Years)
    execFileSync('openssl', ['genrsa', '-out', intKeyFile, '4096'], { stdio: 'pipe' });
    const intSubj = `/C=${country}/ST=${state}/L=${city}/O=${orgName}/OU=${orgName} Infrastructure/CN=${orgName} Intermediate CA`;
    execFileSync('openssl', ['req', '-new', '-sha256', '-key', intKeyFile, '-out', intCsrFile, '-subj', intSubj], { stdio: 'pipe' });

    // 3. Sign Intermediate with Root CA
    fs.writeFileSync(extFile, "basicConstraints = critical, CA:true, pathlen:0\nkeyUsage = critical, digitalSignature, cRLSign, keyCertSign\nsubjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always,issuer\n");
    execFileSync('openssl', ['x509', '-req', '-in', intCsrFile, '-CA', rootCertFile, '-CAkey', rootKeyFile, '-CAcreateserial', '-out', intCertFile, '-days', '3650', '-sha256', '-extfile', extFile], { stdio: 'pipe' });

    // Read generated files
    const rootKeyPem = fs.readFileSync(rootKeyFile, 'utf8');
    const rootCertPem = fs.readFileSync(rootCertFile, 'utf8');
    const intKeyPem = fs.readFileSync(intKeyFile, 'utf8');
    const intCertPem = fs.readFileSync(intCertFile, 'utf8');

    // 4. SECURELY DESTROY ROOT PRIVATE KEY FROM CONTAINER DISK IMMEDIATELY!
    try {
      fs.unlinkSync(rootKeyFile);
      fs.unlinkSync(rootCertFile);
      fs.unlinkSync(intKeyFile);
      fs.unlinkSync(intCsrFile);
      fs.unlinkSync(intCertFile);
      fs.unlinkSync(extFile);
      fs.unlinkSync(path.join('/tmp', `${opId}-root.srl`));
    } catch (e) {}

    // 5. Automatically store Intermediate CA in DB (Encrypted at rest with AES-256)
    db.intermediateCAs.forEach(c => c.isActive = false);
    const newCA = {
      id: uuidv4(),
      name: intermediateName,
      description: `${orgName} Primary Signer`,
      certPem: intCertPem.trim(),
      encryptedKeyPem: encryptData(intKeyPem.trim()), // Encrypted in DB!
      rootCertPem: rootCertPem.trim(),
      isActive: true,
      createdAt: new Date().toISOString()
    };
    db.intermediateCAs.push(newCA);

    // Save profile defaults
    db.config.profile = { orgName, country, state, city, defaultDays: 90, domainSuffix: `${orgName.toLowerCase().replace(/\s+/g, '')}.local` };
    saveLocalDB(db);

    // 6. Send all files to user browser for immediate download
    res.json({
      success: true,
      rootCertPem,
      rootKeyPem, // Delivered ONCE for user download, NOT preserved on server!
      intCertPem,
      intKeyPem,
      caChainPem: `${intCertPem.trim()}\n${rootCertPem.trim()}\n`,
      caName: intermediateName
    });
  } catch (err) {
    [rootKeyFile, rootCertFile, intKeyFile, intCsrFile, intCertFile, extFile].forEach(f => {
      try { fs.unlinkSync(f); } catch (e) {}
    });
    res.status(500).json({ error: 'Failed to generate PKI: ' + err.message });
  }
});

const loginAttempts = new Map(); // ip -> {count, resetAt}
function loginRateLimited(ip) {
  const now = Date.now();
  const cur = loginAttempts.get(ip) || { count: 0, resetAt: now + 60000 };
  if (now > cur.resetAt) { cur.count = 0; cur.resetAt = now + 60000; }
  cur.count += 1;
  loginAttempts.set(ip, cur);
  return cur.count > 20;
}

app.post('/api/auth/login', (req, res) => {
  try {
    if (loginRateLimited(req.ip)) {
      return sendError(res, 429, 'RATE_LIMITED', 'Too many login attempts. Try again in a minute.');
    }
    const { username, password } = req.body || {};
    const db = getLocalDB();
    const expectedUser = db.config.adminUser || process.env.ADMIN_USER || 'admin';
    const hash = db.config.adminPasswordHash;
    if (!username || !password) {
      return sendError(res, 400, 'VALIDATION_ERROR', 'username and password are required.');
    }
    if (!hash) {
      return sendError(res, 503, 'AUTH_NOT_INITIALIZED', 'Admin credentials not initialized yet. Restart the container once.',
        'If ADMIN_PASSWORD is set in Coolify, restart the service so initAdminAuth can run.');
    }
    let ok = false;
    try { ok = (username === expectedUser) && bcrypt.compareSync(String(password), hash); }
    catch (e) { ok = false; }
    if (ok) {
      const sessionToken = uuidv4();
      activeSessions.add(sessionToken);
      // Cap session map to avoid unbounded growth
      if (activeSessions.size > 500) { const first = activeSessions.values().next().value; activeSessions.delete(first); }
      audit('auth.login_ok', { user: expectedUser }, req);
      logger.info('auth.login_ok', { user: expectedUser });
      return res.json({ success: true, token: sessionToken, username: expectedUser });
    }
    audit('auth.login_failed', { user: username }, req);
    logger.warn('auth.login_failed', { user: username });
    return sendError(res, 401, 'INVALID_CREDENTIALS', 'Invalid admin username or password.',
      'ADMIN_USER defaults to "admin". ADMIN_PASSWORD env (Coolify) overrides the stored hash on every boot.');
  } catch (e) {
    return sendError(res, 500, 'INTERNAL_ERROR', 'Login failed: ' + e.message);
  }
});

app.get('/api/auth/me', authMiddleware, (req, res) => {
  const db = getLocalDB();
  res.json({ success: true, username: db.config.adminUser || 'admin', basePath: BASE_PATH || '', baseUrl: BASE_URL });
});

app.post('/api/auth/logout', (req, res) => {
  const h = req.headers['authorization'] || '';
  if (h.startsWith('Bearer ')) activeSessions.delete(h.substring(7));
  res.json({ success: true });
});

// Intermediate CAs Management
app.get('/api/admin/intermediate-cas', authMiddleware, (req, res) => {
  const db = getLocalDB();
  const safeList = db.intermediateCAs.map(ca => ({
    id: ca.id,
    name: ca.name,
    description: ca.description,
    certPem: ca.certPem,
    rootCertPem: ca.rootCertPem,
    isActive: ca.isActive,
    hasKey: !!ca.encryptedKeyPem
  }));
  res.json(safeList);
});

app.post('/api/admin/intermediate-cas', authMiddleware, (req, res) => {
  const { name, description, certPem, keyPem, rootCertPem, setActive } = req.body || {};
  if (!name || !certPem || !keyPem || !rootCertPem) {
    return sendError(res, 400, 'VALIDATION_ERROR', 'name, certPem, keyPem, and rootCertPem are required.');
  }
  if (!String(certPem).includes('BEGIN CERTIFICATE') || !String(keyPem).includes('PRIVATE KEY')) {
    return sendError(res, 400, 'VALIDATION_ERROR', 'certPem must be a PEM certificate and keyPem a PEM private key.');
  }

  const db = getLocalDB();
  if (setActive) {
    db.intermediateCAs.forEach(c => c.isActive = false);
  }

  const newCA = {
    id: uuidv4(),
    name: name.trim().toLowerCase().replace(/\s+/g, '-'),
    description: description || '',
    certPem: certPem.trim(),
    encryptedKeyPem: encryptData(keyPem.trim()), // Stored encrypted!
    rootCertPem: rootCertPem.trim(),
    isActive: !!setActive || db.intermediateCAs.length === 0,
    createdAt: new Date().toISOString()
  };

  db.intermediateCAs.push(newCA);
  saveLocalDB(db);
  audit('ca.imported', { id: newCA.id, name: newCA.name, active: newCA.isActive }, req);
  logger.info('ca.imported', { name: newCA.name });
  res.json({ success: true, ca: { id: newCA.id, name: newCA.name, isActive: newCA.isActive } });
});

app.post('/api/admin/intermediate-cas/:id/activate', authMiddleware, (req, res) => {
  const db = getLocalDB();
  const target = (db.intermediateCAs || []).find(c => c.id === req.params.id);
  if (!target) return sendError(res, 404, 'NOT_FOUND', 'CA not found.');

  db.intermediateCAs.forEach(c => c.isActive = false);
  target.isActive = true;
  saveLocalDB(db);
  audit('ca.activated', { id: target.id, name: target.name }, req);
  logger.info('ca.activated', { name: target.name });
  res.json({ success: true, code: 'ACTIVATED', message: `Activated ${target.name}` });
});

app.delete('/api/admin/intermediate-cas/:id', authMiddleware, (req, res) => {
  const db = getLocalDB();
  const target = (db.intermediateCAs || []).find(c => c.id === req.params.id);
  if (!target) return sendError(res, 404, 'NOT_FOUND', 'CA not found.');
  const issued = (db.certificates || []).filter(c => c.caName === target.name).length;
  if (target.isActive && (db.intermediateCAs || []).length > 1) {
    return sendError(res, 400, 'VALIDATION_ERROR', `Cannot delete the active CA (${target.name}). Activate another CA first.`);
  }
  db.intermediateCAs = db.intermediateCAs.filter(c => c.id !== req.params.id);
  // If we deleted the last CA, certs remain for audit but signing returns CA_NOT_AVAILABLE.
  saveLocalDB(db);
  audit('ca.deleted', { id: target.id, name: target.name, certsIssued: issued }, req);
  logger.warn('ca.deleted', { name: target.name, certsIssued: issued });
  res.json({ success: true, code: 'DELETED', message: `Deleted ${target.name}.`, certsAffected: issued });
});

// API Tokens Management (with usage analytics, revoke, expiry, bulk actions)
function tokenUsageStats(db, tokenId) {
  const certs = (db.certificates || []).filter(c => c.issuedViaTokenId === tokenId);
  return {
    certsIssued: certs.length,
    lastCN: certs.length ? (certs[0].commonName || (certs[0].sanDomains || [])[0] || null) : null,
    lastIssuedAt: certs.length ? certs[0].issuedAt : null
  };
}
function sanitizeToken(db, t) {
  const stats = tokenUsageStats(db, t.id);
  const usageCount = t.usageCount ?? stats.certsIssued;
  const expired = !!(t.expiresAt && new Date(t.expiresAt).getTime() < Date.now());
  return {
    id: t.id, name: t.name, token: t.token,
    createdAt: t.createdAt, expiresAt: t.expiresAt || null,
    revoked: !!t.revoked, revokedAt: t.revokedAt || null,
    expired, status: t.revoked ? 'revoked' : (expired ? 'expired' : 'active'),
    scopes: t.scopes || ['sign', 'revoke'],
    usageCount, lastUsedAt: t.lastUsedAt || stats.lastIssuedAt,
    lastUsedCN: t.lastUsedCN || stats.lastCN,
    certsIssued: stats.certsIssued
  };
}
app.get('/api/admin/tokens', authMiddleware, (req, res) => {
  const db = getLocalDB();
  res.json((db.apiTokens || []).map(t => sanitizeToken(db, t)));
});

app.post('/api/admin/tokens', authMiddleware, (req, res) => {
  const { name, expiresAt, scopes } = req.body || {};
  if (name && String(name).length > 100) return sendError(res, 400, 'VALIDATION_ERROR', 'Token name too long (max 100 chars).');
  const db = getLocalDB();
  const newToken = {
    id: uuidv4(),
    name: (name || 'API Token').trim().slice(0, 100),
    token: `cert_${crypto.randomBytes(24).toString('hex')}`,
    scopes: Array.isArray(scopes) && scopes.length ? scopes.filter(s => ['sign', 'revoke'].includes(s)) : ['sign', 'revoke'],
    expiresAt: expiresAt || null,
    revoked: false, usageCount: 0, lastUsedAt: null, lastUsedCN: null,
    createdAt: new Date().toISOString()
  };
  db.apiTokens.push(newToken);
  saveLocalDB(db);
  audit('token.created', { id: newToken.id, name: newToken.name }, req);
  logger.info('token.created', { id: newToken.id, name: newToken.name });
  res.json({ success: true, token: sanitizeToken(db, newToken) });
});

// Per-token usage detail: which certs were issued with this key
app.get('/api/admin/tokens/:id/usage', authMiddleware, (req, res) => {
  const db = getLocalDB();
  const t = (db.apiTokens || []).find(x => x.id === req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'API token not found.');
  const certs = (db.certificates || []).filter(c => c.issuedViaTokenId === t.id);
  res.json({ success: true, token: sanitizeToken(db, t), certificates: certs });
});

// Revoke (soft, reversible) — preferred over delete for audit trail
app.post('/api/admin/tokens/:id/revoke', authMiddleware, (req, res) => {
  const db = getLocalDB();
  const t = (db.apiTokens || []).find(x => x.id === req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'API token not found.');
  t.revoked = true; t.revokedAt = new Date().toISOString();
  saveLocalDB(db);
  audit('token.revoked', { id: t.id, name: t.name }, req);
  logger.warn('token.revoked', { id: t.id, name: t.name });
  res.json({ success: true, token: sanitizeToken(db, t) });
});

app.post('/api/admin/tokens/:id/restore', authMiddleware, (req, res) => {
  const db = getLocalDB();
  const t = (db.apiTokens || []).find(x => x.id === req.params.id);
  if (!t) return sendError(res, 404, 'NOT_FOUND', 'API token not found.');
  t.revoked = false; delete t.revokedAt;
  saveLocalDB(db);
  audit('token.restored', { id: t.id, name: t.name }, req);
  res.json({ success: true, token: sanitizeToken(db, t) });
});

app.delete('/api/admin/tokens/:id', authMiddleware, (req, res) => {
  const db = getLocalDB();
  const exists = (db.apiTokens || []).some(t => t.id === req.params.id);
  if (!exists) return sendError(res, 404, 'NOT_FOUND', 'API token not found.');
  db.apiTokens = db.apiTokens.filter(t => t.id !== req.params.id);
  saveLocalDB(db);
  audit('token.deleted', { id: req.params.id }, req);
  res.json({ success: true });
});

// Bulk actions: { ids: [...] } revoke / restore / delete
app.post('/api/admin/tokens/bulk', authMiddleware, (req, res) => {
  const { ids, action } = req.body || {};
  if (!Array.isArray(ids) || !ids.length) return sendError(res, 400, 'VALIDATION_ERROR', 'ids[] array is required.');
  if (!['revoke', 'restore', 'delete'].includes(action)) return sendError(res, 400, 'VALIDATION_ERROR', 'action must be revoke|restore|delete.');
  const db = getLocalDB();
  let affected = 0;
  if (action === 'delete') {
    const before = db.apiTokens.length;
    db.apiTokens = db.apiTokens.filter(t => !ids.includes(t.id));
    affected = before - db.apiTokens.length;
  } else {
    (db.apiTokens || []).forEach(t => {
      if (ids.includes(t.id)) {
        if (action === 'revoke' && !t.revoked) { t.revoked = true; t.revokedAt = new Date().toISOString(); affected++; }
        if (action === 'restore' && t.revoked) { t.revoked = false; delete t.revokedAt; affected++; }
      }
    });
  }
  saveLocalDB(db);
  audit('token.bulk', { action, affected }, req);
  logger.info('token.bulk', { action, affected });
  res.json({ success: true, action, affected });
});

// User Organization & Default PKI Profile
app.get('/api/admin/profile', authMiddleware, (req, res) => {
  const db = getLocalDB();
  res.json(db.config.profile || {
    orgName: 'MyCompany',
    country: 'US',
    state: 'California',
    city: 'San Francisco',
    defaultDays: 90,
    domainSuffix: 'example.com'
  });
});

app.post('/api/admin/profile', authMiddleware, (req, res) => {
  const db = getLocalDB();
  db.config.profile = {
    orgName: req.body.orgName || 'MyCompany',
    country: req.body.country || 'US',
    state: req.body.state || 'California',
    city: req.body.city || 'San Francisco',
    defaultDays: parseInt(req.body.defaultDays || '90', 10),
    domainSuffix: req.body.domainSuffix || 'example.com'
  };
  saveLocalDB(db);
  res.json({ success: true, profile: db.config.profile });
});

// Issued Certificates
app.get('/api/admin/certificates', authMiddleware, (req, res) => {
  const db = getLocalDB();
  res.json(db.certificates || []);
});

// Direct UI Certificate Generator (Create Key + CSR + Sign in one go)
app.post('/api/admin/generate-cert', authMiddleware, async (req, res) => {
  const { commonName, sans, days } = req.body || {};
  if (!commonName) return sendError(res, 400, 'VALIDATION_ERROR', 'commonName is required.');
  const opId = uuidv4();
  const tempKey = path.join('/tmp', `${opId}.key`);
  const tempCsr = path.join('/tmp', `${opId}.csr`);
  try {
    const cleanCN = String(commonName).replace(/[^a-zA-Z0-9.\-_]/g, '').slice(0, 253);
    if (!cleanCN) return sendError(res, 400, 'VALIDATION_ERROR', 'Invalid commonName format.');
    const daysNum = Math.max(1, Math.min(825, parseInt(days, 10) || 90));

    execFileSync('openssl', ['genrsa', '-out', tempKey, '2048'], { stdio: 'pipe' });
    execFileSync('openssl', ['req', '-new', '-key', tempKey, '-out', tempCsr, '-subj', `/CN=${cleanCN}`], { stdio: 'pipe' });

    const csrPem = fs.readFileSync(tempCsr, 'utf8');
    const privateKey = fs.readFileSync(tempKey, 'utf8');

    const sanList = String(sans || '').split(',').map(s => s.trim().replace(/[^a-zA-Z0-9.\-_:*]/g, '')).filter(Boolean).slice(0, 50);
    if (!sanList.includes(cleanCN)) sanList.unshift(cleanCN);

    const caHint = { ca: req.body.ca || req.body.intermediateId, purpose: req.body.purpose || req.body.profile };
    const result = await signLeafCertificate(csrPem, sanList, daysNum, { id: 'admin-ui', name: 'Admin UI' }, getPublicBase(req), caHint);

    try { fs.unlinkSync(tempKey); fs.unlinkSync(tempCsr); } catch (e) {}
    audit('cert.issued', { serial: result.serial, cn: cleanCN, via: 'admin-ui' }, req);
    logger.info('cert.issued', { serial: result.serial, cn: cleanCN, via: 'admin-ui' });

    res.json({
      success: true,
      serial: result.serial,
      privateKey,
      certificate: result.certificate,
      fullChain: result.fullChain,
      caName: result.caName,
      caSelection: result.selectionReason
    });
  } catch (err) {
    try { fs.unlinkSync(tempKey); fs.unlinkSync(tempCsr); } catch (e) {}
    logger.error('cert.issue_failed', { error: err.message, code: err.code });
    if (err.code === 'CA_NOT_AVAILABLE') {
      return res.status(503).json({ success: false, code: 'CA_NOT_AVAILABLE', error: err.message,
        hint: 'Set up at least one Signing CA first: 🧙 Setup Wizard (1-click) or Intermediate CAs → Import.',
        setupUrl: '/onboarding', expectedCAs: ['int-server', 'int-wifi', 'int-iot'] });
    }
    return sendError(res, err.httpStatus || 500, err.code || 'INTERNAL_ERROR', err.message);
  }
});

// ------------------------------------------------------------------
// ACME & Public REST Sign APIs
// ------------------------------------------------------------------
app.post('/api/v1/sign', authMiddleware, async (req, res) => {
  const { csr, san, days, intermediateId, ca, purpose, profile } = req.body || {};
  if (!csr || typeof csr !== 'string' || !csr.includes('BEGIN CERTIFICATE REQUEST')) {
    return sendError(res, 400, 'VALIDATION_ERROR', 'Missing or invalid csr in request body (expected PEM PKCS#10).');
  }
  try {
    const sanList = Array.isArray(san) ? san : (typeof san === 'string' ? san.split(',').map(s => s.trim()).filter(Boolean) : []);
    const caHint = { ca: ca || intermediateId, purpose: purpose || profile };
    const result = await signLeafCertificate(csr, sanList.slice(0, 50), days || 90, req.apiToken || { id: 'admin-ui', name: 'Admin UI' }, getPublicBase(req), caHint);
    const leafCN = (sanList[0] || 'csr-cn');
    audit('cert.issued', { serial: result.serial, cn: leafCN, via: req.apiToken ? req.apiToken.name : 'admin-ui' }, req);
    logger.info('cert.issued', { serial: result.serial, via: req.apiToken ? req.apiToken.name : 'admin-ui' });
    res.json({
      success: true,
      certificate: result.certificate,
      chain: result.fullChain,
      fullChain: result.fullChain,
      serialNumber: result.serial,
      serial: result.serial,
      caName: result.caName,
      caSelection: result.selectionReason,
      expiresAt: new Date(Date.now() + (parseInt(days, 10) || 90) * 86400000).toISOString()
    });
  } catch (err) {
    logger.error('cert.sign_failed', { error: err.message, code: err.code });
    if (err.code === 'CA_NOT_AVAILABLE') {
      return res.status(503).json({ success: false, code: 'CA_NOT_AVAILABLE', error: err.message,
        hint: 'Set up at least one Signing CA: Admin UI → 🧙 Setup Wizard (1-click) or Intermediate CAs → Import. Suggested: int-server (web/TLS), int-wifi (RADIUS/802.1X), int-iot (devices).',
        setupUrl: '/onboarding', expectedCAs: ['int-server', 'int-wifi', 'int-iot'], caHint: { ca: ca || intermediateId || null, purpose: purpose || profile || null } });
    }
    return sendError(res, err.httpStatus || 500, err.code || 'INTERNAL_ERROR', err.message);
  }
});

// Certificate & CSR Inspector Endpoint
app.post('/api/admin/parse-cert', (req, res) => {
  let { content, type } = req.body;
  if (!content) return res.status(400).json({ error: 'Missing content to inspect' });

  const tempId = uuidv4();
  const tempFile = path.join('/tmp', `${tempId}.tmp`);

  try {
    // If base64 DER, convert to Buffer
    if (content.startsWith('data:') && content.includes('base64,')) {
      content = Buffer.from(content.split('base64,')[1], 'base64');
      fs.writeFileSync(tempFile, content);
    } else {
      fs.writeFileSync(tempFile, content.trim());
    }

    let parsed = {};
    if (content.toString().includes('CERTIFICATE REQUEST') || type === 'csr') {
      // Parse CSR
      const textOut = execFileSync('openssl', ['req', '-in', tempFile, '-noout', '-text'], { stdio: 'pipe' }).toString();
      const subjOut = execFileSync('openssl', ['req', '-in', tempFile, '-noout', '-subject'], { stdio: 'pipe' }).toString();
      parsed = {
        kind: 'Certificate Signing Request (CSR)',
        subject: subjOut.trim().replace(/^subject=/, ''),
        fullText: textOut
      };
    } else {
      // Parse Certificate (supports PEM or DER)
      let textOut;
      try {
        textOut = execFileSync('openssl', ['x509', '-in', tempFile, '-noout', '-text'], { stdio: 'pipe' }).toString();
      } catch (pemErr) {
        textOut = execFileSync('openssl', ['x509', '-in', tempFile, '-inform', 'DER', '-noout', '-text'], { stdio: 'pipe' }).toString();
      }

      // Extract subject, issuer, dates, serial, and SANs
      const subjectMatch = textOut.match(/Subject:\s*([^\n]+)/);
      const issuerMatch = textOut.match(/Issuer:\s*([^\n]+)/);
      const notBeforeMatch = textOut.match(/Not Before:\s*([^\n]+)/);
      const notAfterMatch = textOut.match(/Not After\s*:\s*([^\n]+)/);
      const serialMatch = textOut.match(/Serial Number:\s*([^\n]+)/);
      const sanMatch = textOut.match(/X509v3 Subject Alternative Name:[^\n]*\n\s*([^\n]+)/);
      const isCaMatch = textOut.match(/CA:(TRUE|FALSE)/i);

      parsed = {
        kind: 'X.509 Public Certificate',
        subject: subjectMatch ? subjectMatch[1].trim() : 'Unknown',
        issuer: issuerMatch ? issuerMatch[1].trim() : 'Unknown',
        serial: serialMatch ? serialMatch[1].trim() : 'Unknown',
        validFrom: notBeforeMatch ? notBeforeMatch[1].trim() : 'Unknown',
        validTo: notAfterMatch ? notAfterMatch[1].trim() : 'Unknown',
        sans: sanMatch ? sanMatch[1].trim() : 'None',
        isCA: isCaMatch ? isCaMatch[1].toUpperCase() === 'TRUE' : false,
        fullText: textOut
      };
    }

    try { fs.unlinkSync(tempFile); } catch (e) {}
    res.json({ success: true, ...parsed });
  } catch (err) {
    try { fs.unlinkSync(tempFile); } catch (e) {}
    res.status(400).json({ error: 'Could not parse certificate/CSR: ' + err.message });
  }
});

function regenerateCrl(db, activeCA) {
  const crlFile = path.join(CRL_DIR, `${activeCA.name}.crl`);
  const caIndex = path.join(DATA_DIR, 'index.txt');
  const caSerial = path.join(DATA_DIR, 'crlnumber');
  const cnfFile = path.join(DATA_DIR, 'crl_openssl.cnf');
  const tempCaCert = path.join('/tmp', `crl-${activeCA.id}.crt`);
  const tempCaKey = path.join('/tmp', `crl-${activeCA.id}.key`);
  if (!fs.existsSync(caIndex)) fs.writeFileSync(caIndex, '');
  if (!fs.existsSync(caSerial)) fs.writeFileSync(caSerial, '1000\n');
  fs.writeFileSync(tempCaCert, activeCA.certPem);
  fs.writeFileSync(tempCaKey, decryptData(activeCA.encryptedKeyPem), { mode: 0o600 });
  fs.writeFileSync(cnfFile, `[ ca ]\ndefault_ca = CA_default\n[ CA_default ]\ndatabase = ${caIndex}\ncrlnumber = ${caSerial}\ndefault_md = sha256\ndefault_crl_days = 30\n`);
  execFileSync('openssl', ['ca', '-gencrl', '-keyfile', tempCaKey, '-cert', tempCaCert, '-config', cnfFile, '-out', crlFile], { stdio: 'pipe' });
  try { fs.unlinkSync(tempCaCert); fs.unlinkSync(tempCaKey); } catch (e) {}
  return crlFile;
}

app.post('/api/v1/revoke', authMiddleware, async (req, res) => {
  const { serial, reason } = req.body || {};
  if (!serial) return sendError(res, 400, 'VALIDATION_ERROR', 'Serial is required.');

  // Sanitize serial (hex only)
  const cleanSerial = String(serial).replace(/[^a-fA-F0-9]/g, '');
  if (!cleanSerial) return sendError(res, 400, 'VALIDATION_ERROR', 'Invalid serial format.');
  const db = getLocalDB();
  const cert = (db.certificates || []).find(c => String(c.serial).toLowerCase() === cleanSerial.toLowerCase());

  if (!cert) return sendError(res, 404, 'NOT_FOUND', `Certificate serial 0x${cleanSerial} not found in database.`);
  if (cert.status === 'revoked') return res.json({ success: true, code: 'ALREADY_REVOKED', message: `Certificate 0x${cleanSerial} was already revoked.` });

  cert.status = 'revoked';
  cert.revokedAt = new Date().toISOString();
  cert.revokeReason = String(reason || 'unspecified').replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 64);
  saveLocalDB(db);

  // Generate updated CRL
  const activeCA = (db.intermediateCAs || []).find(ca => ca.isActive) || (db.intermediateCAs || [])[0];
  let crlOk = false;
  if (activeCA) {
    try {
      regenerateCrl(db, activeCA);
      crlOk = true;
    } catch (crlErr) {
      logger.warn('crl.regen_failed', { error: crlErr.message });
    }
  }

  audit('cert.revoked', { serial: cleanSerial, reason: cert.revokeReason, crlOk }, req);
  logger.warn('cert.revoked', { serial: cleanSerial, reason: cert.revokeReason });
  res.json({ success: true, code: 'REVOKED', message: `Certificate 0x${cleanSerial} revoked and CRL updated.`, crlRegenerated: crlOk });
});

// Bulk certificate revoke: { serials: [...], reason }
app.post('/api/v1/revoke-bulk', authMiddleware, async (req, res) => {
  const { serials, reason } = req.body || {};
  if (!Array.isArray(serials) || !serials.length) return sendError(res, 400, 'VALIDATION_ERROR', 'serials[] array is required.');
  if (serials.length > 200) return sendError(res, 400, 'VALIDATION_ERROR', 'Max 200 serials per bulk request.');
  const db = getLocalDB();
  const cleanReason = String(reason || 'unspecified').replace(/[^a-zA-Z0-9_\-]/g, '').slice(0, 64);
  let revoked = 0; const notFound = []; const already = [];
  serials.forEach(s => {
    const clean = String(s).replace(/[^a-fA-F0-9]/g, '').toLowerCase();
    const cert = (db.certificates || []).find(c => String(c.serial).toLowerCase() === clean);
    if (!cert) { notFound.push(String(s)); return; }
    if (cert.status === 'revoked') { already.push(clean); return; }
    cert.status = 'revoked'; cert.revokedAt = new Date().toISOString(); cert.revokeReason = cleanReason;
    revoked++;
  });
  saveLocalDB(db);
  const activeCA = (db.intermediateCAs || []).find(ca => ca.isActive) || (db.intermediateCAs || [])[0];
  let crlOk = false;
  if (activeCA && revoked > 0) { try { regenerateCrl(db, activeCA); crlOk = true; } catch (e) { logger.warn('crl.regen_failed', { error: e.message }); } }
  audit('cert.bulk_revoked', { revoked, notFound: notFound.length, already: already.length }, req);
  logger.warn('cert.bulk_revoked', { revoked });
  res.json({ success: true, code: 'BULK_REVOKED', revoked, alreadyRevoked: already, notFound, crlRegenerated: crlOk });
});

app.get('/acme/directory', (req, res) => {
  const base = getPublicBase(req); // env override or auto-detected per request
  res.json({
    "newNonce": `${base}/acme/new-nonce`,
    "newAccount": `${base}/acme/new-account`,
    "newOrder": `${base}/acme/new-order`,
    "revokeCert": `${base}/acme/revoke-cert`,
    "keyChange": `${base}/acme/key-change`,
    "meta": { "termsOfService": `${base}/terms`, "website": "https://Enterprise.local" }
  });
});

app.head('/acme/new-nonce', (req, res) => {
  res.setHeader('Replay-Nonce', uuidv4());
  res.setHeader('Cache-Control', 'no-store');
  res.status(200).end();
});

app.get('/acme/new-nonce', (req, res) => {
  res.setHeader('Replay-Nonce', uuidv4());
  res.setHeader('Cache-Control', 'no-store');
  res.status(204).end();
});

app.post('/acme/new-account', (req, res) => {
  const accountId = uuidv4();
  const base = getPublicBase(req);
  res.setHeader('Replay-Nonce', uuidv4());
  res.setHeader('Location', `${base}/acme/acct/${accountId}`);
  res.status(201).json({ status: 'valid', orders: `${base}/acme/acct/${accountId}/orders` });
});

app.post('/acme/new-order', (req, res) => {
  const orderId = uuidv4();
  const authzId = uuidv4();
  const base = getPublicBase(req);
  res.setHeader('Replay-Nonce', uuidv4());
  res.setHeader('Location', `${base}/acme/order/${orderId}`);
  res.status(201).json({
    status: 'ready',
    expires: new Date(Date.now() + 86400000).toISOString(),
    identifiers: req.body.identifiers || [],
    authorizations: [`${base}/acme/authz/${authzId}`],
    finalize: `${base}/acme/order/${orderId}/finalize`
  });
});

app.post('/acme/order/:orderId/finalize', async (req, res) => {
  try {
    let csrRaw = req.body.csr || req.body;
    let csrPem = csrRaw;
    if (!csrPem.includes('-----BEGIN CERTIFICATE REQUEST-----')) {
      const buffer = Buffer.from(csrRaw, 'base64');
      csrPem = `-----BEGIN CERTIFICATE REQUEST-----\n${buffer.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE REQUEST-----`;
    }
    const { certId } = await signLeafCertificate(csrPem, ['localhost'], 90, { id: 'acme', name: 'ACME' }, getPublicBase(req), { purpose: 'acme' });
    res.setHeader('Replay-Nonce', uuidv4());
    res.json({ status: 'valid', certificate: `${getPublicBase(req)}/acme/cert/${certId}` });
  } catch (err) {
    res.status(400).json({ error: err.message });
  }
});

app.get('/acme/cert/:certId', (req, res) => {
  const chainPath = path.join(CERTS_DIR, `${req.params.certId}-chain.crt`);
  if (!fs.existsSync(chainPath)) return res.status(404).send('Not found');
  res.setHeader('Content-Type', 'application/pem-certificate-chain');
  res.send(fs.readFileSync(chainPath, 'utf8'));
});

// Client Installers (host auto-detected so moved domains keep working)
app.get('/install-trust-windows.ps1', (req, res) => {
  const hostUrl = getPublicBase(req);
  res.setHeader('Content-Type', 'text/plain');
  res.send(`$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')
if (-not $isAdmin) { Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -Command \\"irm ${hostUrl}/install-trust-windows.ps1 | iex\\"") -Verb RunAs; exit }
$t = [System.IO.Path]::GetTempPath(); $r = Join-Path $t 'r.crt'; $i = Join-Path $t 'i.crt'
Invoke-WebRequest -Uri '${hostUrl}/certs/root-ca.crt' -OutFile $r -UseBasicParsing
Invoke-WebRequest -Uri '${hostUrl}/certs/intermediate-ca.crt' -OutFile $i -UseBasicParsing
$rs = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine'); $rs.Open('ReadWrite'); $rs.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($r))); $rs.Close()
$is = New-Object System.Security.Cryptography.X509Certificates.X509Store('CertificateAuthority', 'LocalMachine'); $is.Open('ReadWrite'); $is.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($i))); $is.Close()
Write-Host '[SUCCESS] Enterprise Trust Chain Installed!' -ForegroundColor Green
`);
});

app.get('/install-trust-linux.sh', (req, res) => {
  const hostUrl = getPublicBase(req);
  res.setHeader('Content-Type', 'text/plain');
  res.send(`#!/bin/bash
set -e
if [ "$EUID" -ne 0 ]; then echo "Run as root"; exit 1; fi
d=$(mktemp -d); trap 'rm -rf "$d"' EXIT
curl -fsSL "${hostUrl}/certs/root-ca.crt" -o "$d/root.crt"
curl -fsSL "${hostUrl}/certs/intermediate-ca.crt" -o "$d/int.crt"
if [ -d "/usr/local/share/ca-certificates" ]; then
  cp "$d/root.crt" "$d/int.crt" /usr/local/share/ca-certificates/; update-ca-certificates
elif [ -d "/etc/pki/ca-trust/source/anchors" ]; then
  cp "$d/root.crt" "$d/int.crt" /etc/pki/ca-trust/source/anchors/; update-ca-trust extract
fi
echo "[SUCCESS] Enterprise Trust Chain Installed!"
`);
});

app.get('/certs/root-ca.crt', (req, res) => {
  const db = getLocalDB();
  const ca = db.intermediateCAs.find(c => c.isActive) || db.intermediateCAs[0];
  if (ca && ca.rootCertPem) {
    if (req.query.download === '1') {
      res.setHeader('Content-Disposition', 'attachment; filename="root-ca.crt"');
    }
    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
    return res.send(ca.rootCertPem);
  }
  res.status(404).send('Root cert not found');
});

app.get('/certs/intermediate-ca.crt', (req, res) => {
  const db = getLocalDB();
  const ca = db.intermediateCAs.find(c => c.isActive) || db.intermediateCAs[0];
  if (ca && ca.certPem) {
    if (req.query.download === '1') {
      res.setHeader('Content-Disposition', 'attachment; filename="intermediate-ca.crt"');
    }
    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
    return res.send(ca.certPem);
  }
  res.status(404).send('Intermediate cert not found');
});

app.get('/certs/ca-chain.crt', (req, res) => {
  const db = getLocalDB();
  const ca = db.intermediateCAs.find(c => c.isActive) || db.intermediateCAs[0];
  if (ca && ca.certPem && ca.rootCertPem) {
    if (req.query.download === '1') {
      res.setHeader('Content-Disposition', 'attachment; filename="ca-chain.crt"');
    }
    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
    return res.send(`${ca.certPem.trim()}\n${ca.rootCertPem.trim()}\n`);
  }
  res.status(404).send('CA Chain not available');
});

// Public CA cert fetch for FreeRADIUS/backend integration: GET /api/v1/ca/:name/cert
app.get('/api/v1/ca/:name/cert', (req, res) => {
  const db = getLocalDB();
  const ca = (db.intermediateCAs || []).find(c => c.name === req.params.name)
    || (db.intermediateCAs || []).find(c => c.isActive);
  if (!ca) return sendError(res, 503, 'CA_NOT_AVAILABLE', 'No CA available.',
    'Import or generate an Intermediate CA in Admin UI > Intermediate CAs.');
  res.setHeader('Content-Type', 'application/x-x509-ca-cert');
  res.send(`${ca.certPem.trim()}\n${ca.rootCertPem.trim()}\n`);
});

// Serve CRLs (DER-ish PEM) with correct content type
app.get('/crl/:caName.crl', (req, res) => {
  const f = path.join(CRL_DIR, `${req.params.caName}.crl`);
  if (!fs.existsSync(f)) return sendError(res, 404, 'NOT_FOUND', `CRL for ${req.params.caName} not found yet. Revoke a cert or wait for generation.`);
  res.setHeader('Content-Type', 'application/pkix-crl');
  res.send(fs.readFileSync(f));
});

// Liveness (Coolify healthcheck) — never requires auth, never touches DB hard
app.get('/health', (req, res) => {
  res.json({ status: 'ok', uptimeSec: Math.floor(process.uptime()), time: new Date().toISOString() });
});

// Readiness / integration status for FreeRADIUS admin tab (public, no secrets).
// backend.rajlabs.in "Certificates" tab should poll this every 30s.
app.get('/api/v1/status', (req, res) => {
  let db;
  try { db = getLocalDB(); }
  catch (e) { return sendError(res, 500, 'INTERNAL_ERROR', 'Database unreadable: ' + e.message); }
  const cas = db.intermediateCAs || [];
  const active = cas.find(c => c.isActive) || cas[0] || null;
  const certs = db.certificates || [];
  const revoked = certs.filter(c => c.status === 'revoked').length;
  const crlFile = active ? path.join(CRL_DIR, `${active.name}.crl`) : null;
  const code = active ? 'READY' : 'CA_NOT_AVAILABLE';
  res.json({
    success: true, code,
    status: active ? 'ready' : 'degraded',
    message: active ? `Signer ready (active CA: ${active.name}).` : 'CA_NOT_AVAILABLE: No Intermediate CA configured.',
    basePath: BASE_PATH || '', baseUrl: BASE_URL,
    activeCA: active ? active.name : null,
    intermediateCAsCount: cas.length,
    certificates: { total: certs.length, revoked, valid: certs.length - revoked },
    crl: active ? { name: `${active.name}.crl`, exists: !!(crlFile && fs.existsSync(crlFile)) } : null,
    acme: { directory: `${getPublicBase(req)}/acme/directory` },
    api: { sign: '/api/v1/sign', revoke: '/api/v1/revoke', revokeBulk: '/api/v1/revoke-bulk', caCert: '/api/v1/ca/:name/cert' },
    database: activeDatabaseType,
    time: new Date().toISOString()
  });
});

// Audit log viewer (admin). Query: ?event=token.created&?q=radius&?limit=100&?offset=0
app.get('/api/admin/audit', authMiddleware, (req, res) => {
  try {
    const logFile = path.join(DATA_DIR, 'logs', 'audit.log');
    if (!fs.existsSync(logFile)) return res.json({ success: true, total: 0, entries: [] });
    const lines = fs.readFileSync(logFile, 'utf8').split('\n').filter(Boolean);
    const entries = [];
    for (const line of lines) {
      try { entries.push(JSON.parse(line)); } catch (e) { /* skip corrupt line */ }
    }
    entries.reverse(); // newest first
    const { event, q } = req.query || {};
    let filtered = entries;
    if (event) filtered = filtered.filter(e => e.event === event);
    if (q) {
      const needle = String(q).toLowerCase();
      filtered = filtered.filter(e => JSON.stringify(e).toLowerCase().includes(needle));
    }
    const limit = Math.max(1, Math.min(500, parseInt(req.query.limit, 10) || 100));
    const offset = Math.max(0, parseInt(req.query.offset, 10) || 0);
    const page = filtered.slice(offset, offset + limit);
    const eventCounts = {};
    for (const e of entries) eventCounts[e.event] = (eventCounts[e.event] || 0) + 1;
    res.json({ success: true, total: filtered.length, limit, offset, entries: page, eventCounts });
  } catch (e) {
    logger.error('audit.read_failed', { error: e.message });
    return sendError(res, 500, 'INTERNAL_ERROR', 'Could not read audit log: ' + e.message);
  }
});

// Authenticated deep-health for admin Status tab (openssl present, key decrypt ok)
app.get('/api/admin/health-detail', authMiddleware, (req, res) => {
  const db = getLocalDB();
  const cas = db.intermediateCAs || [];
  const active = cas.find(c => c.isActive) || cas[0] || null;
  let openssl = 'unknown'; let keyOk = false; let keyError = null;
  try { openssl = execFileSync('openssl', ['version'], { stdio: 'pipe' }).toString().trim(); }
  catch (e) { openssl = 'missing: ' + e.message; }
  if (active) {
    try { const k = decryptData(active.encryptedKeyPem); keyOk = !!(k && k.includes('PRIVATE KEY')); }
    catch (e) { keyError = e.message; }
  }
  res.json({
    success: true,
    openssl, keyDecryptOk: keyOk, keyError,
    node: process.version, uptimeSec: Math.floor(process.uptime()),
    dataDir: DATA_DIR, basePath: BASE_PATH || '', baseUrl: BASE_URL,
    database: activeDatabaseType, postgresConfigured: !!process.env.DATABASE_URL,
    logLevel: LOG_LEVEL
  });
});

// SPA fallback (must not swallow API/ACME/certs/crl/health routes)
app.get('*', (req, res, next) => {
  if (/^\/(api|acme|certs|crl|health|install-trust-)/.test(req.url.split('?')[0])) return next();
  try {
    let html = fs.readFileSync(path.join(__dirname, 'public', 'index.html'), 'utf8');
    const inject = `<script>window.__PKI_BASE_PATH__=${JSON.stringify(BASE_PATH || '')};window.__PKI_BASE_URL__=${JSON.stringify(BASE_URL)};</script>`;
    html = html.replace('</head>', `  ${inject}\n</head>`);
    res.setHeader('Content-Type', 'text/html');
    return res.send(html);
  } catch (e) { return res.status(500).send('UI unavailable'); }
});

app.listen(PORT, '0.0.0.0', () => {
  logger.info('server.start', { port: PORT, baseUrl: BASE_URL, basePath: BASE_PATH || '/', dataDir: DATA_DIR, logLevel: LOG_LEVEL });
  logger.info('server.ready', { health: '/health', status: '/api/v1/status', ui: '/' });
});
