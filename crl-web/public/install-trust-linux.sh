#!/bin/bash
# ==============================================================================
# Rajlabs CA Trust Chain Installer for Linux (Ubuntu, Debian, RHEL, CentOS, Alpine)
# Downloads and installs both Root and Intermediate CAs into the system trust store.
# ==============================================================================

set -e

CA_SERVER_URL="${1:-http://localhost:8080}"

echo "=========================================================="
echo "  Rajlabs CA Trust Chain Installer (Linux)                "
echo "=========================================================="

if [ "$EUID" -ne 0 ]; then
  echo "Please run as root or with sudo."
  exit 1
fi

TEMP_DIR=$(mktemp -d)
trap 'rm -rf "$TEMP_DIR"' EXIT

echo "Downloading CA chain from $CA_SERVER_URL..."
curl -fsSL "$CA_SERVER_URL/certs/root-ca.crt" -o "$TEMP_DIR/rajlabs-root-ca.crt"
curl -fsSL "$CA_SERVER_URL/certs/int-server.crt" -o "$TEMP_DIR/rajlabs-int-ca.crt"

# Detect OS and install
if [ -d "/usr/local/share/ca-certificates" ]; then
    # Debian / Ubuntu
    echo "Detected Debian/Ubuntu system..."
    cp "$TEMP_DIR/rajlabs-root-ca.crt" /usr/local/share/ca-certificates/rajlabs-root-ca.crt
    cp "$TEMP_DIR/rajlabs-int-ca.crt" /usr/local/share/ca-certificates/rajlabs-int-ca.crt
    update-ca-certificates

elif [ -d "/etc/pki/ca-trust/source/anchors" ]; then
    # RHEL / CentOS / Fedora / Rocky Linux
    echo "Detected RHEL/Fedora/CentOS system..."
    cp "$TEMP_DIR/rajlabs-root-ca.crt" /etc/pki/ca-trust/source/anchors/rajlabs-root-ca.crt
    cp "$TEMP_DIR/rajlabs-int-ca.crt" /etc/pki/ca-trust/source/anchors/rajlabs-int-ca.crt
    update-ca-trust extract

elif [ -d "/usr/local/share/ca-certificates" ] || [ -f "/etc/alpine-release" ]; then
    # Alpine Linux
    echo "Detected Alpine Linux..."
    mkdir -p /usr/local/share/ca-certificates
    cp "$TEMP_DIR/rajlabs-root-ca.crt" /usr/local/share/ca-certificates/
    cp "$TEMP_DIR/rajlabs-int-ca.crt" /usr/local/share/ca-certificates/
    update-ca-certificates
else
    echo "Unsupported or custom Linux distribution. Please manually trust the files in $TEMP_DIR"
    exit 1
fi

echo "=========================================================="
echo "[SUCCESS] Rajlabs Root and Intermediate CAs installed!"
echo "Curl, Python, Docker, and system browsers will now trust all issued certs."
echo "=========================================================="
