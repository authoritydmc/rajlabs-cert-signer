# Rajlabs Docker Certificate Signer (ACME, REST API & CRL Server)

A custom, high-performance containerized Certificate Authority and signing service built with **OpenSSL**, **Node.js/Express**, and **NGINX**.

## 🛡️ Security Architecture: Isolated Intermediate CA

- **Root CA Private Key is NEVER loaded into Docker or this repository.**
- Only the **Intermediate CA private key** (e.g. `int-server.key.pem`) and the **Public Root Certificate** (trust anchor) are imported.
- All leaf certificates and ACME orders are signed directly by the intermediate CA.

```
[ Root CA (Air-gapped / Offline) ]
             |
             v  (Signed offline)
[ Intermediate CA (Server / WiFi / IoT) ]
             |
             +---> [ Custom Signer Engine (Docker) ]
                         |
                         +---> ACME RFC 8555 Engine (/acme/directory)
                         +---> REST API (/api/v1/sign, /api/v1/revoke)
                         +---> Automatic CRL Generation
                         +---> CRL & Bundle Distribution (NGINX on :8080)
```

---

## 🚀 Key Features

1. **ACME RFC 8555 Directory**:
   - Automated certificate issuance for web servers, ingress, certbot, and internal microservices.
   - Endpoint: `http://<host>:9000/acme/directory`
2. **REST API for Direct PKI Signing**:
   - `POST /api/v1/sign`: Submit CSR, SAN domains, and validity duration to get signed certificates and bundled chains.
   - `POST /api/v1/revoke`: Revoke certificates and automatically re-generate the CRL.
   - `GET /api/v1/health`: Real-time health check and intermediate CA verification.
3. **CRL & Public Certificate Distribution**:
   - Serves intermediate and root CRLs (`.crl`) with proper RFC MIME headers.
   - Serves full CA chains (`ca-chain.crt`) over HTTP on port `8080`.

---

## 📋 Quick Start

### 1. Import Intermediate CA
Mount the desired Intermediate CA into the signer without touching the Root CA:
```powershell
.\import-intermediate.ps1 -TargetIntermediate "int-server"
```

### 2. Start the Signer Services
```bash
docker compose up -d --build
```

### 3. Verify Endpoints
- **ACME Directory**: `http://localhost:9000/acme/directory`
- **REST Sign API**: `http://localhost:9000/api/v1/sign`
- **CRL Web Distribution**: `http://localhost:8080/crl/`
- **Public Certificate Chains**: `http://localhost:8080/certs/ca-chain.crt`
- **Health Check**: `http://localhost:9000/api/v1/health`

---

## 📝 API Usage Example

### Issue Certificate via REST API:
```bash
curl -X POST http://localhost:9000/api/v1/sign \
  -H "Content-Type: application/json" \
  -H "x-api-key: rajlabs-secure-api-key-9988" \
  -d '{
    "csr": "-----BEGIN CERTIFICATE REQUEST-----\n...",
    "san": ["web.rajlabs.local", "api.rajlabs.local"],
    "days": 90
  }'
```
