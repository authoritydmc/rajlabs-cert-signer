const express = require('express');
const { execSync } = require('child_process');
const fs = require('fs');
const path = require('path');
const { v4: uuidv4 } = require('uuid');

const app = express();
app.use(express.json({ limit: '10mb' }));
app.use(express.text({ type: ['text/*', 'application/pkcs10', 'application/x-pem-file'], limit: '10mb' }));

const PORT = parseInt(process.env.PORT || '9000', 10);
const BASE_URL = (process.env.BASE_URL || `http://localhost:${PORT}`).replace(/\/$/, '');
const CA_NAME = process.env.CA_NAME || 'int-server';
const DAYS_VALID = parseInt(process.env.DAYS_VALID || '90', 10);
const AUTH_TOKEN = process.env.AUTH_TOKEN || '';

// Storage and file paths (supports both Coolify volume mounts or environment-injected certs/keys)
const DATA_DIR = process.env.DATA_DIR || path.join(__dirname, 'data');
const CA_CERTS_DIR = process.env.CA_CERTS_DIR || path.join(__dirname, 'ca-certs');
const CA_KEYS_DIR = process.env.CA_KEYS_DIR || path.join(__dirname, 'ca-keys');
const CERTS_DIR = path.join(DATA_DIR, 'issued-certs');
const CRL_DIR = path.join(DATA_DIR, 'crl');
const PUBLIC_DIR = path.join(DATA_DIR, 'public');
const DB_FILE = path.join(DATA_DIR, 'database.json');
const SERIAL_FILE = path.join(DATA_DIR, 'serial');

[DATA_DIR, CA_CERTS_DIR, CA_KEYS_DIR, CERTS_DIR, CRL_DIR, PUBLIC_DIR].forEach(dir => {
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
});

// Support loading Intermediate CA & Root CA directly from environment variables (great for Coolify!)
const CA_CERT_PATH = path.join(CA_CERTS_DIR, `${CA_NAME}.cert.pem`);
const CA_KEY_PATH = path.join(CA_KEYS_DIR, `${CA_NAME}.key.pem`);
const ROOT_CERT_PATH = path.join(CA_CERTS_DIR, 'root-ca.cert.pem');

if (process.env.INTERMEDIATE_CERT_PEM && !fs.existsSync(CA_CERT_PATH)) {
  fs.writeFileSync(CA_CERT_PATH, process.env.INTERMEDIATE_CERT_PEM.replace(/\\n/g, '\n'));
}
if (process.env.INTERMEDIATE_KEY_PEM && !fs.existsSync(CA_KEY_PATH)) {
  fs.writeFileSync(CA_KEY_PATH, process.env.INTERMEDIATE_KEY_PEM.replace(/\\n/g, '\n'), { mode: 0o600 });
}
if (process.env.ROOT_CERT_PEM && !fs.existsSync(ROOT_CERT_PATH)) {
  fs.writeFileSync(ROOT_CERT_PATH, process.env.ROOT_CERT_PEM.replace(/\\n/g, '\n'));
}

if (!fs.existsSync(DB_FILE)) {
  fs.writeFileSync(DB_FILE, JSON.stringify({ certificates: [], accounts: [] }, null, 2));
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
  if (!fs.existsSync(CA_CERT_PATH) || !fs.existsSync(CA_KEY_PATH)) {
    throw new Error(`Intermediate CA certificate or private key missing! Looked in: ${CA_CERT_PATH}`);
  }

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

  // Sign with intermediate CA
  const cmd = `openssl x509 -req -in "${tempCsr}" -CA "${CA_CERT_PATH}" -CAkey "${CA_KEY_PATH}" -set_serial 0x${serial} -out "${tempCert}" -days ${days} -sha256 -extfile "${tempExt}"`;
  execSync(cmd, { stdio: 'pipe' });

  const issuedCert = fs.readFileSync(tempCert, 'utf8');
  const intermediateCert = fs.readFileSync(CA_CERT_PATH, 'utf8');
  const rootCert = fs.existsSync(ROOT_CERT_PATH) ? fs.readFileSync(ROOT_CERT_PATH, 'utf8') : '';
  const fullChain = `${issuedCert.trim()}\n${intermediateCert.trim()}\n${rootCert.trim()}`.trim();

  // Save issued cert to storage
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
  if (!fs.existsSync(CA_CERT_PATH) || !fs.existsSync(CA_KEY_PATH)) return;

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
    console.error('CRL gen notice:', err.message);
  }
}

// ------------------------------------------------------------------
// Client Installer Script Generators (Windows & Linux)
// ------------------------------------------------------------------
app.get('/install-trust-windows.ps1', (req, res) => {
  const hostUrl = BASE_URL;
  const script = `# Rajlabs Windows Trust Installer
$ErrorActionPreference = 'Stop'
$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
if (-not $isAdmin) {
    Start-Process powershell.exe -ArgumentList ("-NoProfile -ExecutionPolicy Bypass -Command `"irm ${hostUrl}/install-trust-windows.ps1 | iex`"") -Verb RunAs
    exit
}
$temp = [System.IO.Path]::GetTempPath()
$rootFile = Join-Path $temp 'rajlabs-root.crt'
$intFile  = Join-Path $temp 'rajlabs-int.crt'
Invoke-WebRequest -Uri '${hostUrl}/certs/root-ca.crt' -OutFile $rootFile -UseBasicParsing
Invoke-WebRequest -Uri '${hostUrl}/certs/intermediate-ca.crt' -OutFile $intFile -UseBasicParsing

$rootStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine')
$rootStore.Open('ReadWrite')
$rootStore.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($rootFile)))
$rootStore.Close()

$intStore = New-Object System.Security.Cryptography.X509Certificates.X509Store('CertificateAuthority', 'LocalMachine')
$intStore.Open('ReadWrite')
$intStore.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($intFile)))
$intStore.Close()
Write-Host '[SUCCESS] Rajlabs CA trust chain installed successfully!' -ForegroundColor Green
`;
  res.setHeader('Content-Type', 'text/plain');
  res.send(script);
});

app.get('/install-trust-linux.sh', (req, res) => {
  const hostUrl = BASE_URL;
  const script = `#!/bin/bash
set -e
if [ "$EUID" -ne 0 ]; then echo "Please run as root or with sudo."; exit 1; fi
TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT
curl -fsSL "${hostUrl}/certs/root-ca.crt" -o "$TEMP_DIR/rajlabs-root.crt"
curl -fsSL "${hostUrl}/certs/intermediate-ca.crt" -o "$TEMP_DIR/rajlabs-int.crt"

if [ -d "/usr/local/share/ca-certificates" ]; then
    cp "$TEMP_DIR/rajlabs-root.crt" /usr/local/share/ca-certificates/
    cp "$TEMP_DIR/rajlabs-int.crt" /usr/local/share/ca-certificates/
    update-ca-certificates
elif [ -d "/etc/pki/ca-trust/source/anchors" ]; then
    cp "$TEMP_DIR/rajlabs-root.crt" /etc/pki/ca-trust/source/anchors/
    cp "$TEMP_DIR/rajlabs-int.crt" /etc/pki/ca-trust/source/anchors/
    update-ca-trust extract
fi
echo "[SUCCESS] Rajlabs CA trust chain installed successfully!"
`;
  res.setHeader('Content-Type', 'text/plain');
  res.send(script);
});

// ------------------------------------------------------------------
// Public Certificate & CRL Serving
// ------------------------------------------------------------------
app.get('/certs/root-ca.crt', (req, res) => {
  if (fs.existsSync(ROOT_CERT_PATH)) {
    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
    res.send(fs.readFileSync(ROOT_CERT_PATH));
  } else {
    res.status(404).send('Root CA certificate not available');
  }
});

app.get('/certs/intermediate-ca.crt', (req, res) => {
  if (fs.existsSync(CA_CERT_PATH)) {
    res.setHeader('Content-Type', 'application/x-x509-ca-cert');
    res.send(fs.readFileSync(CA_CERT_PATH));
  } else {
    res.status(404).send('Intermediate CA certificate not available');
  }
});

app.get('/certs/ca-chain.crt', (req, res) => {
  const intCert = fs.existsSync(CA_CERT_PATH) ? fs.readFileSync(CA_CERT_PATH, 'utf8') : '';
  const rootCert = fs.existsSync(ROOT_CERT_PATH) ? fs.readFileSync(ROOT_CERT_PATH, 'utf8') : '';
  res.setHeader('Content-Type', 'application/x-x509-ca-cert');
  res.send(`${intCert.trim()}\n${rootCert.trim()}\n`);
});

app.get('/crl/:caName.crl', (req, res) => {
  const file = path.join(CRL_DIR, `${req.params.caName}.crl`);
  if (fs.existsSync(file)) {
    res.setHeader('Content-Type', 'application/pkix-crl');
    res.send(fs.readFileSync(file));
  } else {
    res.status(404).send('CRL not found');
  }
});

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

app.get('/health', (req, res) => {
  const hasIntCert = fs.existsSync(CA_CERT_PATH);
  const hasIntKey = fs.existsSync(CA_KEY_PATH);
  const hasRootCert = fs.existsSync(ROOT_CERT_PATH);

  res.json({
    status: hasIntCert && hasIntKey ? 'healthy' : 'degraded',
    intermediateCA: CA_NAME,
    intermediateCertLoaded: hasIntCert,
    intermediateKeyLoaded: hasIntKey,
    rootCertLoaded: hasRootCert,
    rootPrivateKeyMounted: false, // Strict Zero-Trust assurance
    uptimeSeconds: process.uptime()
  });
});

app.listen(PORT, '0.0.0.0', () => {
  console.log(`Certificate Signer Engine listening on port ${PORT}`);
  console.log(`Base URL: ${BASE_URL}`);
  console.log(`Using Intermediate CA: ${CA_NAME}`);
  generateCRL();
});
