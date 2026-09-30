# Rajlabs Docker Certificate Signer (ACME & CRL Server)

A Docker-based, production-ready enterprise certificate signing authority powered by **Step-CA** and **NGINX**.

## 🛡️ Security Architecture: Air-Gapped Root CA Isolation

This project adheres to strict Zero-Trust PKI guidelines:
- **Root CA Private Key is NEVER loaded into Docker or this repository.**
- Only the **Intermediate CA private key** (e.g. `int-server.key.pem`) and the **Public Root Certificate** (trust anchor) are imported.
- Even if the Docker host or container is compromised, the **Root CA remains 100% secure**.

```
[ Root CA (Air-gapped / Offline) ]
             |
             v  (One-time signed)
[ Intermediate CA (Server/WiFi/IoT) ]
             |
             +---> [ Step-CA Docker Container ]
                         |
                         +---> ACME Protocol (Certbot / Traefik / Caddy)
                         +---> REST API / step CLI
                         +---> CRL & Certificate Distribution (NGINX)
```

---

## 🚀 Features

- **ACME Protocol (RFC 8555)**: Automated SSL certificate issuance for Web servers, Traefik, Certbot, Kubernetes, etc.
- **CRL & Bundle Distribution**: High-performance NGINX serving CRLs and full CA certificate chains.
- **Isolated Intermediate Model**: Root CA remains strictly offline.
- **Docker Compose**: One-command initialization and launch.

---

## 📋 Quick Start

### 1. Import Intermediate CA
Run the automated import script from PowerShell:
```powershell
.\import-intermediate.ps1 -TargetIntermediate "int-server"
```
*(Options: `int-server`, `int-wifi`, `int-iot`)*

This script:
1. Copies the selected intermediate CA cert and private key into `mounted-ca/`.
2. Copies only the **public** root certificate for trust chain verification.
3. Publishes public certificates and CRLs to `crl-web/public/`.
4. Leaves the root private key completely untouched.

### 2. Start the Signer Services
```bash
docker compose up -d
```

### 3. Verification & Endpoints
- **ACME Directory**: `https://localhost:9000/acme/acme/directory`
- **CRL Distribution**: `http://localhost:8080/crl/root-ca.crl`
- **Public Certificate Chains**: `http://localhost:8080/certs/ca-chain.crt`
- **Health Check**: `http://localhost:8080/health`

---

## 🔐 Automated Issuance with Certbot

To issue a certificate automatically using the ACME endpoint:

```bash
certbot certonly --standalone \
  --server https://ca.rajlabs.local:9000/acme/acme/directory \
  -d myapp.rajlabs.local
```
