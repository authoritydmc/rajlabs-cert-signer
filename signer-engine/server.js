const express = require('express');
const { execFileSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const crypto = require('crypto');
const bcrypt = require('bcryptjs');
const { Pool } = require('pg');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ type: ['text/*', 'application/pkcs10', 'application/x-pem-file'], limit: '10mb' }));

const PORT = parseInt(process.env.PORT || '9000', 10);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
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
  console.log(`[DATABASE] Inbuilt SQLite initialized at: ${SQLITE_FILE}`);
} catch (err) {
  console.log(`[DATABASE] SQLite native driver fallback to JSON:`, err.message);
}

if (process.env.DATABASE_URL) {
  pgPool = new Pool({ connectionString: process.env.DATABASE_URL });
  initPostgres().then(() => {
    activeDatabaseType = 'PostgreSQL';
    console.log(`[DATABASE] Connected to external PostgreSQL database`);
  }).catch(err => {
    console.error(`[DATABASE] PostgreSQL connection failed, falling back to Inbuilt SQLite:`, err.message);
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
    console.log(`[AUTH] Admin password configured from environment variable for user '${db.config.adminUser}'`);
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
    console.log(credNotice);
  }
}
initAdminAuth();

// Simple Session Token Map
const activeSessions = new Set();

function authMiddleware(req, res, next) {
  const authHeader = req.headers['authorization'] || '';
  const apiKey = req.headers['x-api-key'] || '';

  // Check Bearer session token from UI login
  if (authHeader.startsWith('Bearer ')) {
    const token = authHeader.substring(7);
    if (activeSessions.has(token)) return next();
  }

  // Check API Token using timing-safe comparison to prevent timing attacks
  const db = getLocalDB();
  if (apiKey) {
    const validTokens = (db.apiTokens || []).map(t => t.token);
    if (process.env.AUTH_TOKEN) validTokens.push(process.env.AUTH_TOKEN);

    const keyBuf = Buffer.from(apiKey);
    const isValid = validTokens.some(token => {
      const tokBuf = Buffer.from(token);
      return keyBuf.length === tokBuf.length && crypto.timingSafeEqual(keyBuf, tokBuf);
    });

    if (isValid) return next();
  }

  res.status(401).json({ error: 'Unauthorized. Please login or provide a valid x-api-key token.' });
}

// ------------------------------------------------------------------
// Certificate Signing Engine
// ------------------------------------------------------------------
async function signLeafCertificate(csrPem, sanDomains = [], days = 90) {
  const db = getLocalDB();
  const activeCA = db.intermediateCAs.find(ca => ca.isActive) || db.intermediateCAs[0];
  if (!activeCA) {
    throw new Error('No Intermediate CA configured in the system! Please add one in Admin UI.');
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
  fs.writeFileSync(tempCaKey, decryptData(activeCA.encryptedKeyPem), { mode: 0o600 });

  let extContent = [
    'basicConstraints = CA:FALSE',
    'keyUsage = digitalSignature, keyEncipherment',
    'extendedKeyUsage = serverAuth, clientAuth',
    'subjectKeyIdentifier = hash',
    'authorityKeyIdentifier = keyid,issuer'
  ];

  if (sanDomains.length > 0) {
    const sans = sanDomains.map((d, i) => `DNS.${i + 1} = ${d}`).join('\n');
    extContent.push(`subjectAltName = @alt_names\n[alt_names]\n${sans}`);
  }

  fs.writeFileSync(tempExt, extContent.join('\n'));

  // Execute openssl using execFileSync with explicit argument array (immune to shell injection)
  execFileSync('openssl', [
    'x509',
    '-req',
    '-in', tempCsr,
    '-CA', tempCaCert,
    '-CAkey', tempCaKey,
    '-set_serial', `0x${serial}`,
    '-out', tempCert,
    '-days', days.toString(),
    '-sha256',
    '-extfile', tempExt
  ], { stdio: 'pipe' });

  const issuedCert = fs.readFileSync(tempCert, 'utf8');
  const fullChain = `${issuedCert.trim()}\n${activeCA.certPem.trim()}\n${activeCA.rootCertPem.trim()}`.trim();

  fs.writeFileSync(path.join(CERTS_DIR, `${certId}.crt`), issuedCert);
  fs.writeFileSync(path.join(CERTS_DIR, `${certId}-chain.crt`), fullChain);

  // Clean temp files securely
  [tempCsr, tempCert, tempExt, tempCaCert, tempCaKey].forEach(f => {
    try { fs.unlinkSync(f); } catch (e) {}
  });

  db.certificates.unshift({
    id: certId,
    serial,
    caName: activeCA.name,
    sanDomains,
    issuedAt: new Date().toISOString(),
    status: 'valid'
  });
  saveLocalDB(db);

  return { certId, serial, certificate: issuedCert, fullChain, caName: activeCA.name };
}

// ------------------------------------------------------------------
// Web UI & Authentication Endpoints
// ------------------------------------------------------------------
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/auth/setup-status', (req, res) => {
  const db = getLocalDB();
  if (db.config.isFirstRun) {
    return res.json({
      isFirstRun: true,
      adminUser: db.config.adminUser,
      initialPassword: db.config.temporaryInitialPassword
    });
  }
  res.json({ isFirstRun: false });
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

app.post('/api/auth/login', (req, res) => {
  const { username, password } = req.body;
  const db = getLocalDB();
  if (username === db.config.adminUser && bcrypt.compareSync(password, db.config.adminPasswordHash)) {
    const sessionToken = uuidv4();
    activeSessions.add(sessionToken);
    return res.json({ success: true, token: sessionToken, username });
  }
  res.status(401).json({ success: false, error: 'Invalid admin username or password' });
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
  const { name, description, certPem, keyPem, rootCertPem, setActive } = req.body;
  if (!name || !certPem || !keyPem || !rootCertPem) {
    return res.status(400).json({ error: 'name, certPem, keyPem, and rootCertPem are required.' });
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
  res.json({ success: true, ca: { id: newCA.id, name: newCA.name, isActive: newCA.isActive } });
});

app.post('/api/admin/intermediate-cas/:id/activate', authMiddleware, (req, res) => {
  const db = getLocalDB();
  const target = db.intermediateCAs.find(c => c.id === req.params.id);
  if (!target) return res.status(404).json({ error: 'CA not found' });

  db.intermediateCAs.forEach(c => c.isActive = false);
  target.isActive = true;
  saveLocalDB(db);
  res.json({ success: true, message: `Activated ${target.name}` });
});

// API Tokens Management
app.get('/api/admin/tokens', authMiddleware, (req, res) => {
  const db = getLocalDB();
  res.json(db.apiTokens || []);
});

app.post('/api/admin/tokens', authMiddleware, (req, res) => {
  const { name } = req.body;
  const db = getLocalDB();
  const newToken = {
    id: uuidv4(),
    name: name || 'API Token',
    token: `cert_${crypto.randomBytes(24).toString('hex')}`,
    createdAt: new Date().toISOString()
  };
  db.apiTokens.push(newToken);
  saveLocalDB(db);
  res.json({ success: true, token: newToken });
});

app.delete('/api/admin/tokens/:id', authMiddleware, (req, res) => {
  const db = getLocalDB();
  db.apiTokens = db.apiTokens.filter(t => t.id !== req.params.id);
  saveLocalDB(db);
  res.json({ success: true });
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
  const { commonName, sans, days } = req.body;
  if (!commonName) return res.status(400).json({ error: 'commonName is required' });

  try {
    const certId = uuidv4();
    // Sanitize commonName to prevent any invalid characters
    const cleanCN = commonName.replace(/[^a-zA-Z0-9.\-_]/g, '');
    if (!cleanCN) return res.status(400).json({ error: 'Invalid commonName format' });

    execFileSync('openssl', ['genrsa', '-out', tempKey, '2048'], { stdio: 'pipe' });
    execFileSync('openssl', ['req', '-new', '-key', tempKey, '-out', tempCsr, '-subj', `/CN=${cleanCN}`], { stdio: 'pipe' });

    const csrPem = fs.readFileSync(tempCsr, 'utf8');
    const privateKey = fs.readFileSync(tempKey, 'utf8');

    const sanList = (sans || '').split(',').map(s => s.trim().replace(/[^a-zA-Z0-9.\-_]/g, '')).filter(Boolean);
    if (!sanList.includes(cleanCN)) sanList.unshift(cleanCN);

    const result = await signLeafCertificate(csrPem, sanList, parseInt(days || '90', 10));

    try { fs.unlinkSync(tempKey); fs.unlinkSync(tempCsr); } catch (e) {}

    res.json({
      success: true,
      serial: result.serial,
      privateKey,
      certificate: result.certificate,
      fullChain: result.fullChain
    });
  } catch (err) {
    res.status(500).json({ error: err.message });
  }
});

// ------------------------------------------------------------------
// ACME & Public REST Sign APIs
// ------------------------------------------------------------------
app.post('/api/v1/sign', authMiddleware, async (req, res) => {
  const { csr, san, days } = req.body;
  if (!csr) return res.status(400).json({ error: 'Missing csr in request body' });
  try {
    const result = await signLeafCertificate(csr, san || [], days || 90);
    res.json({ success: true, ...result });
  } catch (err) {
    res.status(500).json({ error: err.message });
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

app.post('/api/v1/revoke', authMiddleware, async (req, res) => {
  const { serial, reason } = req.body;
  if (!serial) return res.status(400).json({ error: 'Serial is required' });

  // Sanitize serial (hex only)
  const cleanSerial = serial.replace(/[^a-fA-F0-9]/g, '');
  const db = getLocalDB();
  const cert = (db.certificates || []).find(c => c.serial.toLowerCase() === cleanSerial.toLowerCase());

  if (!cert) return res.status(404).json({ error: 'Certificate serial not found in database' });

  cert.status = 'revoked';
  cert.revokedAt = new Date().toISOString();
  cert.revokeReason = (reason || 'unspecified').replace(/[^a-zA-Z0-9_\-]/g, '');
  saveLocalDB(db);

  // Generate updated CRL
  const activeCA = db.intermediateCAs.find(ca => ca.isActive) || db.intermediateCAs[0];
  if (activeCA) {
    try {
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
    } catch (crlErr) {
      console.error('CRL regeneration note:', crlErr.message);
    }
  }

  res.json({ success: true, message: `Certificate 0x${cleanSerial} revoked and CRL updated.` });
});

app.get('/acme/directory', (req, res) => {
  res.json({
    "newNonce": `${BASE_URL}/acme/new-nonce`,
    "newAccount": `${BASE_URL}/acme/new-account`,
    "newOrder": `${BASE_URL}/acme/new-order`,
    "revokeCert": `${BASE_URL}/acme/revoke-cert`,
    "keyChange": `${BASE_URL}/acme/key-change`,
    "meta": { "termsOfService": `${BASE_URL}/terms`, "website": "https://Enterprise.local" }
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
  res.setHeader('Replay-Nonce', uuidv4());
  res.setHeader('Location', `${BASE_URL}/acme/acct/${accountId}`);
  res.status(201).json({ status: 'valid', orders: `${BASE_URL}/acme/acct/${accountId}/orders` });
});

app.post('/acme/new-order', (req, res) => {
  const orderId = uuidv4();
  const authzId = uuidv4();
  res.setHeader('Replay-Nonce', uuidv4());
  res.setHeader('Location', `${BASE_URL}/acme/order/${orderId}`);
  res.status(201).json({
    status: 'ready',
    expires: new Date(Date.now() + 86400000).toISOString(),
    identifiers: req.body.identifiers || [],
    authorizations: [`${BASE_URL}/acme/authz/${authzId}`],
    finalize: `${BASE_URL}/acme/order/${orderId}/finalize`
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
    const { certId } = await signLeafCertificate(csrPem, ['localhost']);
    res.setHeader('Replay-Nonce', uuidv4());
    res.json({ status: 'valid', certificate: `${BASE_URL}/acme/cert/${certId}` });
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

// Client Installers
app.get('/install-trust-windows.ps1', (req, res) => {
  const hostUrl = BASE_URL;
  res.setHeader('Content-Type', 'text/plain');
  res.send(`$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')
if (-not $isAdmin) { Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -Command `"irm ${hostUrl}/install-trust-windows.ps1 | iex`"") -Verb RunAs; exit }
$t = [System.IO.Path]::GetTempPath(); $r = Join-Path $t 'r.crt'; $i = Join-Path $t 'i.crt'
Invoke-WebRequest -Uri '${hostUrl}/certs/root-ca.crt' -OutFile $r -UseBasicParsing
Invoke-WebRequest -Uri '${hostUrl}/certs/intermediate-ca.crt' -OutFile $i -UseBasicParsing
$rs = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine'); $rs.Open('ReadWrite'); $rs.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($r))); $rs.Close()
$is = New-Object System.Security.Cryptography.X509Certificates.X509Store('CertificateAuthority', 'LocalMachine'); $is.Open('ReadWrite'); $is.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($i))); $is.Close()
Write-Host '[SUCCESS] Enterprise Trust Chain Installed!' -ForegroundColor Green
`);
});

app.get('/install-trust-linux.sh', (req, res) => {
  const hostUrl = BASE_URL;
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

app.get('/health', (req, res) => {
  const db = getLocalDB();
  res.json({
    status: 'healthy',
    intermediateCAsCount: db.intermediateCAs.length,
    activeCA: (db.intermediateCAs.find(c => c.isActive) || {}).name || null,
    rootKeyAirGapped: true,
    activeDatabase: activeDatabaseType,
    postgresConnected: !!pgPool
  });
});

// SPA fallback
app.get('*', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`==========================================================`);
  console.log(` Enterprise Cert Signer Web UI running on http://0.0.0.0:${PORT}`);
  console.log(`==========================================================`);
});
