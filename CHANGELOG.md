# Changelog

All notable changes to `rajlabs-cert-signer` will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

---

## [2.1.0] - 2026-10-02

### Added
- **Interactive Duration Selectors & Realtime Converters**:
  - Reusable `DaysSelector` component offering standard PKI presets (ACME 90d, short-lived 30d, 1y, 2y, 10y, 20y).
  - Real-time human-readable conversational duration feedback (e.g., `⏱️ 10 years (3,650 days)`).
  - Live calendar expiration calculator displaying estimated date (e.g., `📅 Exp: Oct 2, 2036`).
- **Global Country Selector**:
  - `CountrySelect` component preloaded with standard ISO 3166-1 alpha-2 country codes and custom ISO code input.
- **Enterprise Certificate Templates & Purpose Routing**:
  - Added full suite of enterprise presets in the Issue tab:
    - `🌐 Web / HTTPS Server` (ServerAuth, 90d default)
    - `🔒 Mutual TLS / Client Auth` (ClientAuth, 90d default)
    - `📶 WiFi & RADIUS 802.1X` (EAP-TLS, 365d default)
    - `🤖 IoT & Fleet Devices` (MQTT / Edge, 730d default)
    - `☸️ Kubernetes & Service Mesh` (etcd / Webhook / gRPC, 180d default)
    - `🛡️ VPN Gateways & Tunnels` (OpenVPN / IPsec, 365d default)
    - `💻 Code Signing & Artifacts` (CodeSign, 365d default)
    - `🛠️ Custom / Advanced`
- **In-App Release Notes & Changelog Modal**:
  - Embedded version badge (`v2.1.0`) and full changelog viewer in the web dashboard.
- **Automated Comprehensive Test Suite**:
  - End-to-end pytest suite in `tests/test_pki.py` verifying all 9 core functional areas:
    - AIA & CRL Distribution Point URL generators
    - Admin login, session validation & onboarding hierarchy provisioning
    - Intermediate CA import, activation, and delete protections
    - 1-step keypair generation and certificate signing
    - REST `/api/v1/sign` with CSR and OpenSSL X.509 extension inspection
    - Certificate revocation, bulk revocation, and CRL generation
    - API token lifecycle, `x-api-key` authentication, usage tracking, revocation & restoration
    - Organization profile and default validity configuration
    - Public status, trust bundles, ACME directory, and installer scripts
- **Automated GitHub Actions CI Workflow**:
  - Multi-job CI running the complete backend test suite and frontend build across Linux and container targets.

### Enhanced
- **Sleek Dark Theme Scrollbars**:
  - Added custom scrollbar styles across WebKit/Blink (Chrome, Edge, Safari) and Gecko (Firefox) with subtle track backgrounds and cyan glow hover accents.
- **Empty-State UI & Status Diagnostics**:
  - Clear empty-state callouts with 1-click Setup Wizard launchers when no intermediate CAs are configured.
  - Active signer indicator with status validation on the Overview dashboard.

### Fixed
- **OpenSSL Binary Discovery**:
  - Enhanced binary resolution supporting host, Git, and custom paths across Linux and Windows environments.
- **API Response Contract Consistency**:
  - Standardized token deletion response contract handling.

---

## [2.0.0] - 2026-10-01

### Added
- **FastAPI Backend Engine**:
  - High-performance Python backend replacing the Node signer service.
  - Dual-backend storage engine: zero-config `database.json` and PostgreSQL.
  - Multi-intermediate CA purpose routing (`server` → `int-server`, `wifi` → `int-wifi`, `iot` → `int-iot`).
  - AES-256-GCM encrypted private key storage at rest.
  - Granular API tokens with usage accounting and per-key cert metrics.

---

## [1.0.0] - 2026-09-30

### Added
- **Initial Enterprise PKI Platform**:
  - Offline Root CA hierarchy and single intermediate CA signer.
  - ACME v2 protocol engine for automated client certificate renewals.
  - Public trust center and automated OS trust installer scripts.
