# Rajlabs Enterprise PKI Certificate Signer & Dashboard

A modern, containerized, **UI-based Certificate Authority & ACME Signer** designed for enterprise environments, **Coolify**, and Docker deployments.

---

## 🛡️ Security Architecture: Air-Gapped Root CA Isolation

This solution enforces the gold standard in Zero-Trust PKI:
- **Root CA Private Key is NEVER loaded into Docker, Coolify, or this repository.**
- Your Root CA stays completely **offline** (e.g. in a cold-storage encrypted vault).
- The web UI lets administrators import **Intermediate CAs** (`int-server`, `int-wifi`, `int-iot`), whose private keys are **encrypted at rest using AES-256-GCM**.
- Leaf certificates, ACME clients (Certbot, Traefik), and microservices are signed strictly by the active intermediate CA.

```
[ Air-Gapped Offline Root CA ] (Kept in physical vault / offline USB)
            │
            ▼ (Signed offline once every 5–10 years)
[ Intermediate CA (Server / WiFi / IoT) ]
            │
            ▼ (Imported via Admin Web UI)
┌─────────────────────────────────────────────────────────────────┐
│               Rajlabs Cert Signer Container (Coolify)           │
│                                                                 │
│  ┌───────────────────────┐   ┌───────────────────────────────┐  │
│  │ Web Admin UI (:9000)  │   │  ACME & REST Engine (:9000)   │  │
│  │ ├─ AES-256 DB Vault   │   │  ├─ RFC 8555 /acme/directory  │  │
│  │ ├─ Token Management   │   │  ├─ POST /api/v1/sign         │  │
│  │ ├─ 1-Click Cert Issue │   │  ├─ Full CA Chain Bundler     │  │
│  │ └─ Postgres / Embedded│   │  └─ Auto-Generated CRLs       │  │
│  └───────────────────────┘   └───────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## ✨ Features

- 🖥️ **Full Web UI Dashboard**: Manage multiple intermediate CAs, issue leaf certificates, and view certificate histories.
- 🔐 **Auto-Generated Secure Admin Password**: Automatically generates a cryptographically random admin password on initial start and saves it securely to `/app/data/admin_credentials.txt` (and container logs).
- 🗄️ **Flexible Storage**: Works zero-config with embedded file storage or scales with external **PostgreSQL**.
- 🔑 **API Token System**: Create and revoke scoped API keys directly in the UI for automated ACME clients, CI/CD pipelines, and microservices.
- 📜 **Automatic Full-Chain Bundling**: End devices never suffer from "missing intermediate chain" errors because the engine automatically concatenates the leaf + intermediate + root public certificates.
- 💻 **1-Command Client Trust Installers**:
  - **Windows (PowerShell)**: `irm http://<host>:9000/install-trust-windows.ps1 | iex`
  - **Linux (Bash)**: `curl -fsSL http://<host>:9000/install-trust-linux.sh | sudo bash`

---

## 🚀 Deployment Guide (Coolify)

### Step 1: Deploy with Coolify
1. In your Coolify dashboard, select **+ New Resource** → **Application** → **From Git Repository**.
2. Repository URL: `https://github.com/authoritydmc/rajlabs-cert-signer`.
3. Select **Build Pack**: **`Dockerfile`**.
4. Set **Port**: `9000`.
5. Under **Storage**, add a persistent volume:
   - **Mount Path**: `/app/data`
6. (Optional) Set an external PostgreSQL database in **Environment Variables**:
   - `DATABASE_URL=postgres://user:pass@your-db:5432/pki`
7. Click **Deploy**!

### Step 2: Retrieve Admin Password
When the container boots for the first time, check the **Coolify Deployment Logs** or open the terminal inside `/app/data/admin_credentials.txt`:
```
==========================================================
 RAJLABS CERTIFICATE SIGNER - ADMIN CREDENTIALS
==========================================================
 Generated User     : admin
 Generated Password : <random-secure-password>
 Login UI URL       : http://your-coolify-domain:9000
 Saved at (Docker)  : /app/data/admin_credentials.txt
==========================================================
```

### Step 3: Login to Dashboard
Open your domain, enter `admin` and your generated password, and access the PKI dashboard.

---

## 🛡️ Step-by-Step: Generating an Offline Root CA & Intermediate Signers

Follow this guide on a **secure, air-gapped machine** to create your Root CA and export intermediate signers into the Web UI:

### 1. Create Offline Root CA (Air-gapped machine)
```bash
# 1. Generate private key
openssl genrsa -out root-ca.key.pem 4096

# 2. Generate 20-year Root CA Certificate
openssl req -new -x509 -days 7300 -sha256 -key root-ca.key.pem -out root-ca.cert.pem \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=Rajlabs/OU=Rajlabs Root CA/CN=Rajlabs Root CA"
```
> ⚠️ **CRITICAL**: Store `root-ca.key.pem` on an offline USB or secure vault. **NEVER copy it to any server or Docker host!**

### 2. Generate Intermediate CA Signer (e.g. Server Intermediate)
```bash
# 1. Generate Intermediate private key
openssl genrsa -out int-server.key.pem 4096

# 2. Generate CSR
openssl req -new -sha256 -key int-server.key.pem -out int-server.csr.pem \
  -subj "/C=IN/ST=Karnataka/L=Bengaluru/O=Rajlabs/OU=Rajlabs Server Infrastructure/CN=Rajlabs Server Intermediate CA"
```

### 3. Sign Intermediate with Root CA (Offline)
Create a temporary extension file `int_ext.cnf`:
```ini
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
```

Sign the intermediate CSR:
```bash
openssl x509 -req -in int-server.csr.pem -CA root-ca.cert.pem -CAkey root-ca.key.pem \
  -CAcreateserial -out int-server.cert.pem -days 3650 -sha256 -extfile int_ext.cnf
```

### 4. Import Intermediate CA via Web UI
1. Log into your Rajlabs PKI Signer dashboard.
2. Go to the **Intermediate CAs** tab and click **+ Import Intermediate CA**.
3. Paste:
   - **Public Root Certificate**: `root-ca.cert.pem`
   - **Intermediate Certificate**: `int-server.cert.pem`
   - **Intermediate Private Key**: `int-server.key.pem`
4. Click **Save & Encrypt**. The private key will be encrypted at rest using **AES-256-GCM** inside the database.

---

## 🔑 Automated ACME & API Token Usage

### Generating API Tokens in UI
1. Navigate to **API Tokens** in the dashboard.
2. Click **+ Generate New Token** (e.g. `ingress-certbot-token`).
3. Copy the token: `rajlabs_3a9f...`

### Issuing Certificates via REST API
```bash
curl -X POST http://<ca-server>:9000/api/v1/sign \
  -H "Content-Type: application/json" \
  -H "x-api-key: rajlabs_3a9f..." \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "san": ["web.rajlabs.local", "api.rajlabs.local"],
    "days": 90
  }'
```

### Automated ACME (Certbot)
```bash
certbot certonly --standalone \
  --server http://<ca-server>:9000/acme/directory \
  -d myapp.rajlabs.local
```
