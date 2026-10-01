# Enterprise PKI Certificate Signer & Dashboard

A containerized, **UI-based Certificate Authority & ACME Signer** designed for enterprise environments, **Coolify**, and Docker deployments.

---

## 🛡️ Zero-Trust Security Architecture: Air-Gapped Root CA Isolation

This solution enforces the gold standard in Zero-Trust PKI:
- **Root CA Private Key is NEVER loaded into Docker, Coolify, or this repository.**
- Your Root CA stays completely **offline** (e.g. in a cold-storage encrypted vault or offline computer).
- The web UI lets administrators import **Intermediate CAs** (`int-server`, `int-wifi`, `int-iot`), whose private keys are **encrypted at rest using AES-256-GCM**.
- Leaf certificates, ACME clients (Certbot, Traefik), and microservices are signed strictly by the active intermediate CA.

```
[ Air-Gapped Offline Root CA ] (Kept in physical vault / offline machine)
            │
            ▼ (Signed offline once every 5–10 years)
[ Intermediate CA (Server / WiFi / IoT) ]
            │
            ▼ (Imported via Admin Web UI)
┌─────────────────────────────────────────────────────────────────┐
│              Enterprise Cert Signer Container (Coolify)         │
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
- 🔐 **Dual Authentication Modes**:
  - Provide your own custom password via the `ADMIN_PASSWORD` environment variable (ideal for Docker / Coolify).
  - Or let the container auto-generate a secure random password on first run and display it on-screen and in `/app/data/admin_credentials.txt`.
- 🗄️ **Zero-Config Inbuilt SQLite Database**: By default, uses native SQLite (`pki_vault.sqlite`) stored in your persistent `/app/data` volume. Seamlessly switches to external **PostgreSQL** if `DATABASE_URL` is configured.
- 🔑 **API Token System**: Create and revoke scoped API keys directly in the UI for automated ACME clients, CI/CD pipelines, and microservices.
- 📜 **Automatic Full-Chain Bundling**: End devices never suffer from "missing intermediate chain" errors because the engine automatically concatenates the leaf + intermediate + root public certificates.
- 💻 **1-Command Client Trust Installers**:
  - **Windows (PowerShell as Admin)**: `irm http://<host>:9000/install-trust-windows.ps1 | iex`
  - **Linux (Bash)**: `curl -fsSL http://<host>:9000/install-trust-linux.sh | sudo bash`

---

## ⚡ 1-Command Helper Scripts (Generate Root & Intermediate CAs)

We provide automated helper scripts that handle all OpenSSL commands, directory packaging, and security boundaries:

### On Windows (PowerShell):
```powershell
.\scripts\generate-offline-ca.ps1 -OrgName "MyCompany" -IntermediateName "int-server"
```

### On Linux / macOS (Bash):
```bash
chmod +x ./scripts/generate-offline-ca.sh
./scripts/generate-offline-ca.sh "MyCompany" "US" "California" "San Francisco" "int-server"
```

### 📦 What the script produces:

| Folder | Contents | Action |
|---|---|---|
| `upload-to-web-ui/` | `root-ca.cert.pem`, `int-server.cert.pem`, `int-server.key.pem` | **UPLOAD TO WEB UI** |
| `offline-root-ca-vault/` | `root-ca.key.pem` | **NEVER UPLOAD! KEEP OFFLINE** |

Both `offline-root-ca-vault/` and `upload-to-web-ui/` are automatically git-ignored to prevent accidental commits.

---

## 🚀 Deployment Guide (Coolify)

### Step 1: Deploy with Coolify
1. In your Coolify dashboard, select **+ New Resource** → **Application** → **From Git Repository**.
2. Repository URL: your git repository.
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
 ENTERPRISE CERTIFICATE SIGNER - ADMIN CREDENTIALS
==========================================================
 Generated User     : admin
 Generated Password : <random-secure-password>
 Login UI URL       : http://your-coolify-domain:9000
 Saved at (Docker)  : /app/data/admin_credentials.txt
==========================================================
```

### Step 3: Login & Import Intermediate Signer
1. Log into your dashboard with `admin` and your generated password.
2. Go to **Intermediate CAs** → **+ Import Intermediate CA**.
3. Paste the files from your `upload-to-web-ui/` folder:
   - `root-ca.cert.pem`
   - `int-server.cert.pem`
   - `int-server.key.pem`
4. Click **Save & Encrypt**. Your private key is now encrypted at rest using **AES-256-GCM**.

---

## 🔑 Automated ACME & API Token Usage

### Generating API Tokens in UI
1. Navigate to **API Tokens** in the dashboard.
2. Click **+ Generate New Token** (e.g. `ingress-certbot-token`).
3. Copy the token: `cert_3a9f...`

### Issuing Certificates via REST API
```bash
curl -X POST http://<ca-server>:9000/api/v1/sign \
  -H "Content-Type: application/json" \
  -H "x-api-key: cert_3a9f..." \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "san": ["web.example.com", "api.example.com"],
    "days": 90
  }'
```

### Automated ACME (Certbot / Traefik / Caddy)
```bash
certbot certonly --standalone \
  --server http://<ca-server>:9000/acme/directory \
  -d myapp.example.com
```
