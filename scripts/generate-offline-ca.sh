#!/bin/bash
# ==============================================================================
# Interactive Offline Root CA & Intermediate Signer Generator (Linux / macOS)
# ==============================================================================

set -e

ORG_NAME="${1:-Enterprise}"
COUNTRY="${2:-US}"
STATE="${3:-California}"
CITY="${4:-San Francisco}"
INTERMEDIATE_NAME="${5:-int-server}"

echo "=========================================================="
echo "  Zero-Trust Offline PKI Generator (OpenSSL)              "
echo "=========================================================="

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
VAULT_DIR="$SCRIPT_DIR/offline-root-ca-vault"
EXPORT_DIR="$SCRIPT_DIR/upload-to-web-ui"

mkdir -p "$VAULT_DIR" "$EXPORT_DIR"

ROOT_KEY="$VAULT_DIR/root-ca.key.pem"
ROOT_CERT="$VAULT_DIR/root-ca.cert.pem"

# 1. Root CA
if [ -f "$ROOT_KEY" ] && [ -f "$ROOT_CERT" ]; then
    echo "[1/3] Existing Root CA found in vault. Preserving existing Root CA."
else
    echo "[1/3] Generating Air-Gapped Root CA (RSA 4096, 20 Years)..."
    openssl genrsa -out "$ROOT_KEY" 4096
    openssl req -new -x509 -days 7300 -sha256 -key "$ROOT_KEY" -out "$ROOT_CERT" \
      -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG_NAME/OU=$ORG_NAME Root Authority/CN=$ORG_NAME Root CA"
    echo "      [OK] Root CA generated."
fi

# 2. Intermediate CA
echo "[2/3] Generating Intermediate Signer: $INTERMEDIATE_NAME..."
INT_KEY="$EXPORT_DIR/$INTERMEDIATE_NAME.key.pem"
INT_CSR="$VAULT_DIR/$INTERMEDIATE_NAME.csr.pem"
INT_CERT="$EXPORT_DIR/$INTERMEDIATE_NAME.cert.pem"
EXT_FILE="$VAULT_DIR/int_ext.cnf"

openssl genrsa -out "$INT_KEY" 4096
openssl req -new -sha256 -key "$INT_KEY" -out "$INT_CSR" \
  -subj "/C=$COUNTRY/ST=$STATE/L=$CITY/O=$ORG_NAME/OU=$ORG_NAME Infrastructure/CN=$ORG_NAME Intermediate CA"

# 3. Sign with Root CA
echo "[3/3] Signing Intermediate CA with Root CA..."
cat << 'EOF' > "$EXT_FILE"
basicConstraints = critical, CA:true, pathlen:0
keyUsage = critical, digitalSignature, cRLSign, keyCertSign
subjectKeyIdentifier = hash
authorityKeyIdentifier = keyid:always,issuer
EOF

openssl x509 -req -in "$INT_CSR" -CA "$ROOT_CERT" -CAkey "$ROOT_KEY" \
  -CAcreateserial -out "$INT_CERT" -days 3650 -sha256 -extfile "$EXT_FILE"

cp "$ROOT_CERT" "$EXPORT_DIR/root-ca.cert.pem"

cat << EOF > "$EXPORT_DIR/WHAT_TO_DO_NEXT.txt"
================================================================================
  FILES READY TO UPLOAD TO YOUR WEB UI DASHBOARD
================================================================================

Folder: upload-to-web-ui/

1. root-ca.cert.pem       --> Paste into: 'Public Root CA Certificate (PEM)'
2. $INTERMEDIATE_NAME.cert.pem   --> Paste into: 'Intermediate Certificate (PEM)'
3. $INTERMEDIATE_NAME.key.pem    --> Paste into: 'Intermediate Private Key (PEM)'

================================================================================
  SECURITY ADVISORY - WHAT NEVER TO UPLOAD
================================================================================

Folder: offline-root-ca-vault/
File  : root-ca.key.pem (Root CA Private Key)

DO NOT UPLOAD 'root-ca.key.pem' TO DOCKER, COOLIFY, OR ANY SERVER.
Keep the 'offline-root-ca-vault/' folder on an encrypted offline drive or cold storage.
================================================================================
EOF

echo "=========================================================="
echo "  SUCCESS! CA GENERATION COMPLETE                         "
echo "=========================================================="
echo "Files to upload to Web UI: $EXPORT_DIR"
echo "Root private key is offline: $VAULT_DIR (NEVER UPLOAD!)"
echo "=========================================================="
