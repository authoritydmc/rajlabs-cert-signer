export const APP_VERSION = "2.1.0";
export const APP_RELEASE_DATE = "2026-10-02";

export const CHANGELOG_ENTRIES = [
  {
    version: "2.1.0",
    date: "2026-10-02",
    title: "UI Redesign, Smart Duration Calculators & Comprehensive Test Suite",
    current: true,
    highlights: [
      "Dropdown duration selectors with smart PKI standard presets (ACME 90d, short-lived 30d, 1y, 2y, 10y, 20y)",
      "Real-time human-readable duration conversion and estimated calendar expiration calculation",
      "ISO 3166-1 country dropdown selector with custom country code support",
      "Full suite of enterprise certificate presets: Web Server TLS, Client mTLS, WiFi RADIUS, IoT MQTT, Kubernetes gRPC, VPN Gateways, Code Signing",
      "Custom dark-theme scrollbars matching the cyan/slate dashboard theme across all browsers",
      "Automated GitHub Actions CI workflows with 100% test coverage across all PKI, token, auth, and revocation endpoints",
      "Dynamic empty-state indicators and active signer health checks on Overview and Intermediate CAs dashboard",
    ],
    sections: [
      {
        type: "Added",
        badgeColor: "emerald",
        items: [
          "Interactive DaysSelector component with instant duration calculation (e.g. ≈ 10 years · Exp. Oct 2, 2036).",
          "CountrySelect component pre-loaded with standard global ISO country codes.",
          "Extended certificate templates: mTLS ClientAuth, Kubernetes service mesh & webhooks, VPN tunnels, and Code Signing.",
          "Automated full-coverage pytest suite in tests/test_pki.py and multi-job GitHub CI pipeline.",
          "Web-based Release Notes & Changelog modal directly inside the dashboard.",
        ],
      },
      {
        type: "Enhanced",
        badgeColor: "cyan",
        items: [
          "Redesigned Setup Wizard (Step 1 & Step 2) with clear hierarchy and RSA key strength selectors.",
          "Custom dark-theme scrollbars across WebKit and Gecko browsers.",
          "Enhanced Intermediate CAs management with empty-state callouts and 1-click bootstrap triggers.",
        ],
      },
      {
        type: "Fixed",
        badgeColor: "amber",
        items: [
          "Fixed OpenSSL discovery on host and container environments with cross-platform fallback paths.",
          "Resolved active signer display edge cases when no intermediate CA is configured.",
          "Fixed token deletion response contract handling.",
        ],
      },
    ],
  },
  {
    version: "2.0.0",
    date: "2026-10-01",
    title: "FastAPI Backend Engine, Multi-Intermediate Routing & Token Accounting",
    highlights: [
      "High-performance FastAPI Python backend engine replacing legacy Node service",
      "Multi-intermediate CA purpose routing (server → int-server, wifi → int-wifi, iot → int-iot)",
      "AES-256-GCM encrypted key storage at rest with zero-trust Root CA shredding",
      "API token usage tracking, per-key metrics, and granular sign/revoke scopes",
    ],
    sections: [
      {
        type: "Added",
        badgeColor: "emerald",
        items: [
          "Dual-backend storage architecture supporting zero-config JSON file storage and PostgreSQL.",
          "RFC 5280 CRL distribution points and Authority Information Access (AIA) extensions in leaf certs.",
          "Onboarding setup wizard for automated Root and intermediate hierarchy provisioning.",
        ],
      },
      {
        type: "Security",
        badgeColor: "purple",
        items: [
          "Root private keys are strictly air-gapped and destroyed from the server after onboarding generation.",
          "Intermediate CA private keys are encrypted with AES-256-GCM before persistent storage.",
        ],
      },
    ],
  },
  {
    version: "1.0.0",
    date: "2026-09-30",
    title: "Initial Enterprise PKI Platform Release",
    highlights: [
      "Core offline Root CA and single intermediate certificate authority architecture",
      "ACME v2 protocol engine for automated Certbot / Traefik / Caddy renewals",
      "Public trust center and 1-command installer scripts for Windows and Linux",
    ],
    sections: [
      {
        type: "Added",
        badgeColor: "emerald",
        items: [
          "Initial certificate signing and revocation engine.",
          "Web UI dashboard with trust downloads and certificate viewer.",
          "Automated PowerShell and Bash trust bundle installation scripts.",
        ],
      },
    ],
  },
];
