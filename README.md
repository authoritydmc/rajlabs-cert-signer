# Enterprise PKI Certificate Signer & Dashboard

A containerized, **UI-based Certificate Authority, ACME Signer, and Certificate Inspector** designed for modern infrastructure, **Coolify**, and Docker deployments.

[![Live Demo](https://img.shields.io/badge/Live%20Demo-GitHub%20Pages-06b6d4?style=flat&logo=github)](https://authoritydmc.github.io/rajlabs-cert-signer/)
[![Docker Ready](https://img.shields.io/badge/Docker-Ready-2496ED?style=flat&logo=docker)](Dockerfile)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

---

## 📑 Table of Contents
1. [Zero-Trust Security Architecture](#-zero-trust-security-architecture)
2. [Quick Reference for AI Agents & Developers](#-quick-reference-for-ai-agents--developers)
3. [Key Features](#-key-features)
4. [Onboarding & Setup Modes](#-onboarding--setup-modes)
   - [Mode A: 1-Click Automated In-Browser Setup](#mode-a-1-click-automated-in-browser-setup)
   - [Mode B: Offline Air-Gapped Scripts](#mode-b-mode-b-offline-air-gapped-scripts)
5. [Docker & Coolify Deployment Guide](#-docker--coolify-deployment-guide)
6. [REST API Specification](#-rest-api-specification)
7. [Automated ACME RFC 8555 Setup (Certbot, Traefik, Caddy)](#-automated-acme-rfc-8555-setup)
8. [Certificate & CSR Inspector Tool](#-certificate--csr-inspector-tool)
9. [1-Line Client Device Trust Installers](#-1-line-client-device-trust-installers)
10. [Database Schema & Encryption at Rest](#-database-schema--encryption-at-rest)

---

## 🛡️ Zero-Trust Security Architecture

This system enforces strict Zero-Trust PKI principles:
- **Root CA Private Key is NEVER loaded into Docker, Coolify, or this repository.**
- Your Root CA stays completely **offline** in cold storage (hardware vault, offline USB, or physical safe).
- Intermediate CAs (`int-server`, `int-wifi`, `int-iot`) perform all signing operations. Their private keys are stored **encrypted at rest using AES-256-GCM**.
- Leaf certificates, ACME clients (Certbot, Traefik), and microservices are signed strictly by the active intermediate CA.

```
┌─────────────────────────────────────────────────────────────────┐
│        AIR-GAPPED OFFLINE ROOT CA (Physical Vault / USB)        │
│  - 4096-bit RSA / 20-Year Lifetime                              │
│  - Never touches the container filesystem                       │
└────────────────────────────────┬────────────────────────────────┘
                                 │ Signed once every 5–10 years
                                 ▼
┌─────────────────────────────────────────────────────────────────┐
│              Enterprise Cert Signer Container (Coolify)         │
│                                                                 │
│  ┌───────────────────────┐   ┌───────────────────────────────┐  │
│  │ Web Admin UI (:9000)  │   │  ACME & REST Engine (:9000)   │  │
│  │ ├─ AES-256 DB Vault   │   │  ├─ RFC 8555 /acme/directory  │  │
│  │ ├─ Token Management   │   │  ├─ POST /api/v1/sign         │  │
│  │ ├─ Cert/CSR Inspector │   │  ├─ Full CA Chain Bundler     │  │
│  │ └─ SQLite / Postgres  │   │  └─ Real-Time PKIX CRL Engine │  │
│  └───────────────────────┘   └───────────────────────────────┘  │
└─────────────────────────────────────────────────────────────────┘
```

---

## 🤖 Quick Reference for AI Agents & Developers

If you are an AI assistant, automation bot, or developer integrating with this repository, keep these rules and endpoints in mind:

- **Signer Engine Location**: `/signer-engine` (Node.js native backend + OpenSSL engine).
- **Default Port**: `9000` (HTTP).
- **Default Database**: SQLite at `/app/data/pki_vault.sqlite`. Seamlessly switches to PostgreSQL if `DATABASE_URL` is set.
- **Admin Password Configuration**:
  - Set via env: `ADMIN_PASSWORD=YourStrongPasswordHere` (recommended for headless deployments).
  - If unset, a random password is generated and saved to `/app/data/admin_credentials.txt`.
- **API Token Header**: Pass API tokens using `x-api-key: <token>` or `Authorization: Bearer <token>`.
- **Root Key Sanitization**: Never write or commit any `.key` or `.key.pem` files.
- **Safety Overwrites**: Offline scripts require `-ForceOverwrite` or `--force-overwrite` to overwrite existing Root CAs.

---

## ✨ Key Features

- 🖥️ **Tailwind Modern Web UI**: Responsive dark-mode dashboard with real-time stats, intermediate CA management, certificate viewer, and tutorials.
- ⚡ **1-Click Onboarding Generator**: Issue both Root CA and Intermediate CA directly in memory on first boot without command-line dependencies.
- 🔍 **Interactive Certificate & CSR Inspector**: Drag & drop or paste any PEM/CRT/CSR file to view Subject, Issuer, SAN badges, validity meters, key usage, and raw dumps.
- 🗄️ **Zero-Config Dual-Database Engine**:
  - Built-in SQLite database requiring zero setup.
  - Full PostgreSQL support for high-availability enterprise clusters via `DATABASE_URL`.
- 🔑 **API Token Management**: Provision scoped API keys with 1 click for CI/CD pipelines, Kubernetes cert-manager, or Traefik.
- 📜 **Automated Full-Chain Assembly**: Emits `ca-chain.crt` bundling `[Leaf + Intermediate + Root]` to eliminate client-side `SEC_ERROR_UNKNOWN_ISSUER` errors.
- 🔄 **Real-Time CRL Generation**: Automated `openssl ca -gencrl` on revocations, served with standard `application/pkix-crl` headers at `/crl/<ca-name>.crl`.

---

## 🚀 Onboarding & Setup Modes

### Mode A: 1-Click Automated In-Browser Setup

Ideal for immediate Docker / Coolify deployments:
1. Boot the container and access `http://<your-host>:9000`.
2. On first run, the interactive onboarding modal opens automatically.
3. Select **⚡ 1-Click Generate PKI Now**.
4. Enter your Organization Name (e.g. `MyCompany`), Country, and Intermediate Signer Name.
5. Click **Generate PKI & Auto-Configure Signer**:
   - The engine generates a 4096-bit RSA Root CA and Intermediate CA in memory.
   - The Intermediate CA private key is **automatically encrypted using AES-256-GCM** and saved into the database.
   - The **Root CA private key is delivered to your browser for a one-time download**.
   - **The server immediately and permanently shreds the Root CA private key from memory and disk.**
6. Save your downloaded `root-ca.key.pem` to an offline flash drive or cold vault.

---

### Mode B: Offline Air-Gapped Scripts

For organizations requiring physical air-gap boundaries:

#### 1. Run the safe generator script on an offline machine:
- **Windows (PowerShell)**:
  ```powershell
  .\scripts\generate-offline-ca.ps1 -OrgName "MyCompany" -IntermediateName "int-server"
  ```
- **Linux / macOS (Bash)**:
  ```bash
  chmod +x ./scripts/generate-offline-ca.sh
  ./scripts/generate-offline-ca.sh "MyCompany" "US" "California" "San Francisco" "int-server"
  ```

#### 2. Inspect generated folders:
| Directory | Contents | Security Action |
|---|---|---|
| `upload-to-web-ui/` | `root-ca.cert.pem`<br>`int-server.cert.pem`<br>`int-server.key.pem` | **Upload to Web UI via Dashboard** |
| `offline-root-ca-vault/` | `root-ca.key.pem` | **NEVER UPLOAD! Store in safe cold storage** |

*Note: Both directories and all `.key` files are strictly git-ignored.*

---

## 🐳 Docker & Coolify Deployment Guide

### Deploying via Docker CLI
```bash
docker run -d \
  --name cert-signer \
  -p 9000:9000 \
  -v $(pwd)/pki-data:/app/data \
  -e ADMIN_PASSWORD="MyCustomStrongPassword" \
  authoritydmc/rajlabs-cert-signer:latest
```

### Deploying via Docker Compose
```yaml
version: '3.8'

services:
  cert-signer:
    image: authoritydmc/rajlabs-cert-signer:latest
    build: .
    ports:
      - "9000:9000"
    environment:
      - ADMIN_PASSWORD=MyCustomStrongPassword
      # Optional external database:
      # - DATABASE_URL=postgres://pkiuser:pkipass@postgres:5432/pkidb
    volumes:
      - cert-data:/app/data
    restart: unless-stopped

volumes:
  cert-data:
```

### Deploying with Coolify
1. In Coolify, click **+ New Resource** → **Application** → **From Git Repository**.
2. Point to `https://github.com/authoritydmc/rajlabs-cert-signer`.
3. Set **Build Pack** to `Dockerfile`.
4. Set **Port** to `9000`.
5. Under **Storage**, add a persistent volume:
   - **Mount Path**: `/app/data`
6. Under **Environment Variables**, optionally set:
   - `ADMIN_PASSWORD=<YourSecurePassword>`
   - `DATABASE_URL=postgres://...` (Optional, defaults to SQLite)
7. Click **Deploy**.

---

## 📡 REST API Specification

### Authentication
Authenticate API calls using one of the following headers:
- `x-api-key: cert_xxxxxxxx...`
- `Authorization: Bearer <jwt-token>` (for Admin UI sessions)

### 1. Issue / Sign Certificate
`POST /api/v1/sign`

**Request Body:**
```json
{
  "csr": "-----BEGIN CERTIFICATE REQUEST-----\nMIICvDCCAaQCAQAwdzELMAkGA1UEBhMCVVMx...",
  "san": ["api.example.internal", "10.0.0.5"],
  "days": 90,
  "intermediateId": "int-server"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "certificate": "-----BEGIN CERTIFICATE-----\nMIIEczCCA1ugAwIBAgIU...",
  "chain": "-----BEGIN CERTIFICATE-----\n[Intermediate CA PEM]\n-----BEGIN CERTIFICATE-----\n[Root CA PEM]\n",
  "fullChain": "-----BEGIN CERTIFICATE-----\n[Leaf PEM]\n[Intermediate PEM]\n[Root PEM]\n",
  "serialNumber": "1004",
  "expiresAt": "2027-01-01T00:00:00.000Z"
}
```

---

### 2. Revoke Certificate
`POST /api/v1/revoke`

**Request Body:**
```json
{
  "serial": "1004",
  "reason": "keyCompromise"
}
```

**Response (200 OK):**
```json
{
  "success": true,
  "message": "Certificate 1004 revoked successfully and CRL regenerated."
}
```

---

### 3. Parse / Inspect Certificate or CSR
`POST /api/admin/parse-cert`

**Request Body:**
```json
{
  "pem": "-----BEGIN CERTIFICATE-----\n..."
}
```

**Response (200 OK):**
```json
{
  "type": "Certificate",
  "subject": "CN = web.mycompany.internal, O = MyCompany",
  "issuer": "CN = MyCompany Intermediate CA",
  "validFrom": "Oct 1 18:00:00 2026 GMT",
  "validTo": "Jan 1 18:00:00 2027 GMT",
  "san": ["web.mycompany.internal", "IP:10.0.0.15"],
  "fingerprint": "SHA256 Fingerprint=8A:4F:92:...",
  "keyUsage": "Digital Signature, Key Encipherment",
  "extendedKeyUsage": "TLS Web Server Authentication, TLS Web Client Authentication"
}
```

---

### 4. Download Certificate Revocation List (CRL)
`GET /crl/:caName.crl`
- **Response Headers**: `Content-Type: application/pkix-crl`
- **Body**: Binary DER CRL file queryable by firewalls, reverse proxies, and operating systems.

---

## 🔄 Automated ACME RFC 8555 Setup

The engine serves an RFC 8555 compliant ACME directory endpoint at `/acme/directory`.

### Certbot Example
```bash
certbot certonly --standalone \
  --server http://<ca-server>:9000/acme/directory \
  --email admin@mycompany.internal \
  --agree-tos \
  --no-eff-email \
  -d app.mycompany.internal
```

### Traefik Configuration (`traefik.yml`)
```yaml
certificatesResolvers:
  internalCa:
    acme:
      email: admin@mycompany.internal
      caServer: http://<ca-server>:9000/acme/directory
      storage: /etc/traefik/acme.json
      httpChallenge:
        entryPoint: web
```

---

## 🔍 Certificate & CSR Inspector Tool

The web dashboard includes a built-in inspector accessible at the **Certificate Viewer** tab or live at [GitHub Pages Demo](https://authoritydmc.github.io/rajlabs-cert-signer/):

- **Drag-and-drop or paste**: Accepts `.crt`, `.pem`, `.cer`, `.csr`, or `.der` files.
- **Subject Alternative Names (SAN)**: Auto-extracts DNS domains, IPv4/IPv6 addresses, and emails into clickable badges.
- **Validity & Expiry Bars**: Visual meter showing days elapsed vs. days remaining.
- **Key Usage Badges**: Identifies Server Auth, Client Auth, Code Signing, and Digital Signatures.
- **Raw OpenSSL Output**: Includes a full dump tab for troubleshooting complex X.509 extensions.

---

## 💻 1-Line Client Device Trust Installers

Once your Root CA is active, install the trust certificate across client machines using simple 1-line commands:

### Windows (PowerShell as Administrator)
```powershell
irm http://<ca-server>:9000/install-trust-windows.ps1 | iex
```
*Installs the Root CA into `Cert:\LocalMachine\Root` and intermediate certs into `Cert:\LocalMachine\CA`.*

### Linux / Ubuntu / Debian / RHEL (Bash as Root)
```bash
curl -fsSL http://<ca-server>:9000/install-trust-linux.sh | sudo bash
```
*Copies certificates to `/usr/local/share/ca-certificates/` and runs `update-ca-certificates`.*

### Manual Download
Download `root-ca.crt` or `ca-chain.crt` directly from the dashboard:
- Public Root Certificate: `http://<ca-server>:9000/download/root-ca.crt`
- Full Chain Bundle: `http://<ca-server>:9000/download/ca-chain.crt`

---

## 🗄️ Database Schema & Encryption at Rest

When intermediate CAs are imported or generated, their private keys are encrypted before hitting storage:
- **Cipher**: AES-256-GCM
- **Key Derivation**: SHA-256 digest of container vault secret (`VAULT_SECRET_KEY` or auto-generated machine secret).
- **IV & Auth Tag**: Unique 16-byte IV and 16-byte authentication tag per record.

### Inbuilt SQLite Architecture
```sql
CREATE TABLE intermediate_cas (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  description TEXT,
  cert_pem TEXT NOT NULL,
  encrypted_key_pem TEXT NOT NULL,
  root_cert_pem TEXT NOT NULL,
  is_active INTEGER DEFAULT 0,
  created_at TEXT NOT NULL
);

CREATE TABLE api_tokens (
  id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  token TEXT NOT NULL,
  created_at TEXT NOT NULL
);

CREATE TABLE issued_certs (
  serial TEXT PRIMARY KEY,
  common_name TEXT NOT NULL,
  san TEXT NOT NULL,
  intermediate_id TEXT NOT NULL,
  cert_pem TEXT NOT NULL,
  full_chain_pem TEXT NOT NULL,
  revoked INTEGER DEFAULT 0,
  revoked_at TEXT,
  revocation_reason TEXT,
  created_at TEXT NOT NULL,
  expires_at TEXT NOT NULL
);
```

---

## 🧙 Setup Wizard (always available)

- First boot shows the wizard automatically (`isFirstRun` from `GET /api/auth/setup-status`).
- After setup, reopen anytime via sidebar **🧙 Setup Wizard** or route **`GET /onboarding`**.
- 1-click generates Root + Intermediate in memory, stores the intermediate
  AES-256-GCM encrypted, hands you the Root key **once**, then shreds it.

## 🎯 Purpose-Based CA Routing

`POST /api/v1/sign` (and UI Issue tab) accept `ca`/`intermediateId` plus
`purpose`/`profile`:

| Purpose | CA |
|---|---|
| `server`, `web`, `tls`, `acme` | `int-server` |
| `wifi`, `radius`, `8021x`, `eap`, `wireless` | `int-wifi` |
| `iot`, `device`, `mqtt`, `embedded` | `int-iot` |

Resolution: explicit name → purpose map → active CA → `int-server` → first
usable. Responses include `caName` + `caSelection` (e.g. `purpose:wifi→int-wifi`).
Empty system → `503 CA_NOT_AVAILABLE` with setup instructions + `setupUrl: /onboarding`.

## 🔑 API Tokens (usage-tracked, bulk)

- Per-key **certs issued / uses / last used CN+time**, status (`active`/`revoked`/`expired`), scopes, optional expiry.
- Actions: revoke (reversible, audit-kept) / restore / delete, single + **bulk** (`POST /api/admin/tokens/bulk`).
- Per-token drilldown: `GET /api/admin/tokens/:id/usage` lists certs issued with that key.
- Certs record `issuedViaTokenId/Name`; bulk cert revoke: `POST /api/v1/revoke-bulk` (max 200).

## 💓 Status Contract (FreeRADIUS / backend tab)

- Public, unauthenticated: `GET /api/v1/status` → `{ code: READY|CA_NOT_AVAILABLE, activeCA, certificates{total,valid,revoked}, crl{exists}, acme{directory}, database }`.
- Liveness (Coolify healthcheck): `GET /health` → `{ status: ok }`.
- Authenticated deep health: `GET /api/admin/health-detail` (openssl, key-decrypt, uptime).
- Full spec: [`docs/freeradius-backend-integration.md`](docs/freeradius-backend-integration.md).

## 🌐 Path-Based (Coolify) Hosting

- Set `BASE_PATH=/cert-signer` (or `auto`) when the UI lives at `https://backend.rajlabs.in/cert-signer`.
- Leave `BASE_URL` **unset** to auto-detect per request (domain moves need no redeploy); set it only to pin ACME/CRL/installer URLs.
- UI prefixes every API/asset call with the detected base — this fixes logins previously hitting `backend.rajlabs.in/api/auth/login` instead of `backend.rajlabs.in/cert-signer/api/auth/login`.

## 📝 Enterprise Logging

- Structured JSONL to stdout (`LOG_LEVEL=debug|info|warn|error`), request ids + latency, secrets redacted.
- Audit trail (`auth.login_ok/failed`, `cert.issued/revoked`, `token.*`, `ca.*`) → stdout (`level: audit`) + `DATA_DIR/logs/audit.log`.

---

## 📄 License
This project is licensed under the [MIT License](LICENSE).
