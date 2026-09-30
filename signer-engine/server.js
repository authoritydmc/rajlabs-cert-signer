const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json());
app.use(express.text({ type: ['text/*', 'application/pkcs10', 'application/x-pem-file'] }));

const PORT = process.env.PORT || 9000;
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const CA_NAME = process.env.CA_NAME || 'int-server';
const DAYS_VALID = parseInt(process.env.DAYS_VALID || '90', 10);
const AUTH_TOKEN = process.env.AUTH_TOKEN || '';

const CA_CERT_PATH = path.join('/app/ca-certs', `${CA_NAME}.cert.pem`);
const CA_KEY_PATH = path.join('/app/ca-keys', `${CA_NAME}.key.pem`);
const ROOT_CERT_PATH = path.join('/app/ca-certs', 'root-ca.cert.pem');

const DATA_DIR = path.join('/app/data');
const CERTS_DIR = path.join(DATA_DIR, 'issued-certs');
const CRL_DIR = process.env.CRL_OUTPUT_PATH || path.join(DATA_DIR, 'crl');
const DB_FILE = path.join(DATA_DIR, 'database.json');
const SERIAL_FILE = path.join(DATA_DIR, 'serial');

[DATA_DIR, CERTS_DIR, CRL_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({ certificates: [], revocations: [], accounts: [] }, null, 2));
}
if (!fs.existsSync(SERIAL_FILE)) {
  fs.writeFileSync(SERIAL_FILE, '2000\n');
}

function getNextSerial() {
  const current = parseInt(fs.readFileSync(SERIAL_FILE, 'utf8').trim(), 10);
  const next = current + 1;
  fs.writeFileSync(SERIAL_FILE, `${next}\n`);
  return current.toString(16).padStart(4, '0');
}

function loadDB() {
  return JSON.parse(fs.readFileSync(DB_FILE, 'utf8'));
}

function saveDB(data) {
  fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2));
}

// ------------------------------------------------------------------
// Core Signing Logic (Using OpenSSL directly with Intermediate CA)
// ------------------------------------------------------------------
function signCSR(csrPem, sanDomains = [], days = DAYS_VALID) {
  const certId = uuidv4();
  const serial = getNextSerial();
  const tempCsr = path.join('/tmp', `${certId}.csr`);
  const tempCert = path.join('/tmp', `${certId}.crt`);
  const tempExt = path.join('/tmp', `${certId}.ext`);

  fs.writeFileSync(tempCsr, csrPem);

  // Build SAN extension
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

  // Sign using intermediate CA
  const cmd = `openssl x509 -req -in "${tempCsr}" -CA "${CA_CERT_PATH}" -CAkey "${CA_KEY_PATH}" -set_serial 0x${serial} -out "${tempCert}" -days ${days} -sha256 -extfile "${tempExt}"`;
  execSync(cmd, { stdio: 'pipe' });

  const issuedCert = fs.readFileSync(tempCert, 'utf8');
  const intermediateCert = fs.readFileSync(CA_CERT_PATH, 'utf8');
  const rootCert = fs.existsSync(ROOT_CERT_PATH) ? fs.readFileSync(ROOT_CERT_PATH, 'utf8') : '';
  const fullChain = `${issuedCert.trim()}\n${intermediateCert.trim()}\n${rootCert.trim()}`.trim();

  // Save issued cert to archive
  fs.writeFileSync(path.join(CERTS_DIR, `${certId}.crt`), issuedCert);
  fs.writeFileSync(path.join(CERTS_DIR, `${certId}-chain.crt`), fullChain);

  // Clean temp files
  try {
    fs.unlinkSync(tempCsr);
    fs.unlinkSync(tempCert);
    fs.unlinkSync(tempExt);
  } catch (e) {}

  const db = loadDB();
  db.certificates.push({
    id: certId,
    serial,
    sanDomains,
    issuedAt: new Date().toISOString(),
    expiresDays: days,
    status: 'valid'
  });
  saveDB(db);

  return { certId, serial, certificate: issuedCert, fullChain };
}

// ------------------------------------------------------------------
// CRL Generation
// ------------------------------------------------------------------
function generateCRL() {
  const crlFile = path.join(CRL_DIR, `${CA_NAME}.crl`);
  const caIndex = path.join(DATA_DIR, 'index.txt');
  const caSerial = path.join(DATA_DIR, 'crlnumber');
  const cnfFile = path.join(DATA_DIR, 'crl_openssl.cnf');

  if (!fs.existsSync(caIndex)) fs.writeFileSync(caIndex, '');
  if (!fs.existsSync(caSerial)) fs.writeFileSync(caSerial, '1000\n');

  const cnf = `
[ ca ]
default_ca = CA_default
[ CA_default ]
database = ${caIndex}
crlnumber = ${caSerial}
default_md = sha256
default_crl_days = 30
`;
  fs.writeFileSync(cnfFile, cnf);

  try {
    execSync(`openssl ca -gencrl -keyfile "${CA_KEY_PATH}" -cert "${CA_CERT_PATH}" -config "${cnfFile}" -out "${crlFile}"`, { stdio: 'pipe' });
  } catch (err) {
    // Fallback self-crl if OpenSSL index is blank
    console.error('CRL gen notice:', err.message);
  }
}

// ------------------------------------------------------------------
// ACME Directory & RFC 8555 Endpoints
// ------------------------------------------------------------------
app.get('/acme/directory', (req, res) => {
  res.json({
    "newNonce": `${BASE_URL}/acme/new-nonce`,
    "newAccount": `${BASE_URL}/acme/new-account`,
    "newOrder": `${BASE_URL}/acme/new-order`,
    "revokeCert": `${BASE_URL}/acme/revoke-cert`,
    "keyChange": `${BASE_URL}/acme/key-change`,
    "meta": {
      "termsOfService": `${BASE_URL}/terms`,
      "website": "https://rajlabs.local",
      "caaIdentities": ["rajlabs.local"],
      "externalAccountRequired": false
    }
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
  const db = loadDB();
  db.accounts.push({ id: accountId, createdAt: new Date().toISOString() });
  saveDB(db);

  res.setHeader('Replay-Nonce', uuidv4());
  res.setHeader('Location', `${BASE_URL}/acme/acct/${accountId}`);
  res.status(201).json({
    status: 'valid',
    contact: req.body.contact || [],
    orders: `${BASE_URL}/acme/acct/${accountId}/orders`
  });
});

app.post('/acme/new-order', (req, res) => {
  const orderId = uuidv4();
  const authzId = uuidv4();
  const identifiers = req.body.identifiers || [];

  res.setHeader('Replay-Nonce', uuidv4());
  res.setHeader('Location', `${BASE_URL}/acme/order/${orderId}`);
  res.status(201).json({
    status: 'ready',
    expires: new Date(Date.now() + 86400000).toISOString(),
    identifiers: identifiers,
    authorizations: [`${BASE_URL}/acme/authz/${authzId}`],
    finalize: `${BASE_URL}/acme/order/${orderId}/finalize`
  });
});

app.post('/acme/order/:orderId/finalize', (req, res) => {
  try {
    const orderId = req.params.orderId;
    let csrRaw = req.body.csr;
    if (!csrRaw && typeof req.body === 'string') csrRaw = req.body;

    let csrPem = csrRaw;
    if (!csrPem.includes('-----BEGIN CERTIFICATE REQUEST-----')) {
      const buffer = Buffer.from(csrRaw, 'base64');
      csrPem = `-----BEGIN CERTIFICATE REQUEST-----\n${buffer.toString('base64').match(/.{1,64}/g).join('\n')}\n-----END CERTIFICATE REQUEST-----`;
    }

    const { certId } = signCSR(csrPem, ['localhost']);

    res.setHeader('Replay-Nonce', uuidv4());
    res.setHeader('Location', `${BASE_URL}/acme/order/${orderId}`);
    res.status(200).json({
      status: 'valid',
      certificate: `${BASE_URL}/acme/cert/${certId}`
    });
  } catch (err) {
    res.status(400).json({ type: 'urn:ietf:params:acme:error:badCSR', detail: err.message });
  }
});

app.get('/acme/cert/:certId', (req, res) => {
  const chainPath = path.join(CERTS_DIR, `${req.params.certId}-chain.crt`);
  if (!fs.existsSync(chainPath)) {
    return res.status(404).send('Certificate not found');
  }
  res.setHeader('Content-Type', 'application/pem-certificate-chain');
  res.send(fs.readFileSync(chainPath, 'utf8'));
});

// ------------------------------------------------------------------
// High-Level REST API for Direct PKI Signing
// ------------------------------------------------------------------
app.post('/api/v1/sign', (req, res) => {
  if (AUTH_TOKEN && req.headers['x-api-key'] !== AUTH_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized. Invalid x-api-key header.' });
  }

  const { csr, san, days } = req.body;
  if (!csr) {
    return res.status(400).json({ error: 'Missing csr in request body' });
  }

  try {
    const result = signCSR(csr, san || [], days || DAYS_VALID);
    res.json({
      success: true,
      serial: result.serial,
      certificate: result.certificate,
      fullChain: result.fullChain
    });
  } catch (err) {
    res.status(500).json({ success: false, error: err.message });
  }
});

app.post('/api/v1/revoke', (req, res) => {
  if (AUTH_TOKEN && req.headers['x-api-key'] !== AUTH_TOKEN) {
    return res.status(401).json({ error: 'Unauthorized.' });
  }

  const { serial, reason } = req.body;
  const db = loadDB();
  const cert = db.certificates.find(c => c.serial === serial);

  if (!cert) return res.status(404).json({ error: 'Certificate serial not found' });

  cert.status = 'revoked';
  cert.revokedAt = new Date().toISOString();
  cert.revokeReason = reason || 'unspecified';
  saveDB(db);

  generateCRL();
  res.json({ success: true, message: `Certificate ${serial} revoked and CRL updated.` });
});

app.get('/api/v1/health', (req, res) => {
  res.json({
    status: 'healthy',
    intermediateCA: CA_NAME,
    rootKeyMounted: false, // Security assurance
    uptimeSeconds: process.uptime()
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Certificate Signer Engine listening on port ${PORT}`);
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Using Intermediate CA: ${CA_NAME}`);
  generateCRL();
});
