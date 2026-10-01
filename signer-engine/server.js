const express = require('express');
const { execSync } = require('child_process');
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
const MASTER_ENCRYPTION_KEY = process.env.ENCRYPTION_KEY || crypto.createHash('sha256').update(process.env.ADMIN_PASSWORD || 'Enterprise-default-master-key-seed').digest();

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
// PostgreSQL or Embedded JSON Database Layer
// ------------------------------------------------------------------
let pgPool = null;
if (process.env.DATABASE_URL) {
  pgPool = new Pool({ connectionString: process.env.DATABASE_URL });
  initPostgres().catch(console.error);
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
}

// ------------------------------------------------------------------
// Admin Credentials Auto-Generation
// ------------------------------------------------------------------
function initAdminAuth() {
  const db = getLocalDB();
  if (!db.config.adminPasswordHash) {
    const generatedPassword = process.env.ADMIN_PASSWORD || crypto.randomBytes(18).toString('base64url');
    const salt = bcrypt.genSaltSync(10);
    db.config.adminUser = process.env.ADMIN_USER || 'admin';
    db.config.adminPasswordHash = bcrypt.hashSync(generatedPassword, salt);
    db.config.isFirstRun = true;
    db.config.temporaryInitialPassword = generatedPassword;
    saveLocalDB(db);

    const credNotice = `==========================================================\n Enterprise CERTIFICATE SIGNER - ADMIN CREDENTIALS\n==========================================================\n Generated User     : ${db.config.adminUser}\n Generated Password : ${generatedPassword}\n Login UI URL       : ${BASE_URL}/login\n Saved at (Docker)  : ${CREDENTIALS_FILE}\n==========================================================\n`;
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

  // Check API Token
  const db = getLocalDB();
  if (apiKey && (db.apiTokens.some(t => t.token === apiKey) || apiKey === process.env.AUTH_TOKEN)) {
    return next();
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

  const cmd = `openssl x509 -req -in "${tempCsr}" -CA "${tempCaCert}" -CAkey "${tempCaKey}" -set_serial 0x${serial} -out "${tempCert}" -days ${days} -sha256 -extfile "${tempExt}"`;
  execSync(cmd, { stdio: 'pipe' });

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
  delete db.config.temporaryInitialPassword;
  saveLocalDB(db);
  res.json({ success: true });
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
    const tempKey = path.join('/tmp', `${certId}.key`);
    const tempCsr = path.join('/tmp', `${certId}.csr`);

    execSync(`openssl genrsa -out "${tempKey}" 2048`);
    execSync(`openssl req -new -key "${tempKey}" -out "${tempCsr}" -subj "/CN=${commonName}"`);

    const csrPem = fs.readFileSync(tempCsr, 'utf8');
    const privateKey = fs.readFileSync(tempKey, 'utf8');

    const sanList = (sans || '').split(',').map(s => s.trim()).filter(Boolean);
    if (!sanList.includes(commonName)) sanList.unshift(commonName);

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
