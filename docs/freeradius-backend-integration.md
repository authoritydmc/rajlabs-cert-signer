# FreeRADIUS / backend.rajlabs.in ↔ Cert Signer Integration

Single contract so the backend admin "Certificates" tab always shows the same
state as the signer UI's **💓 Connection Status** tab.

## 1. Config (backend env)

```env
CERT_SIGNER_BASE_URL=https://backend.rajlabs.in/cert-signer   # or https://certs.rajlabs.in (root hosting)
CERT_SIGNER_API_KEY=cert_<key from signer UI → API Tokens>    # per-integration key (revocable, usage-tracked)
```

Use a dedicated API key per consumer (FreeRADIUS, Traefik, CI). The signer UI →
API Tokens shows per-key **certs issued / uses / last used**, plus revoke,
restore, delete, and **bulk** revoke/restore/delete.

## 2. Health tab polling (every 30s, no auth)

```js
const r = await fetch(`${process.env.CERT_SIGNER_BASE_URL}/api/v1/status`);
const s = await r.json();
// s.code === 'READY' → green. Else show s.code + s.message.
// s.code === 'CA_NOT_AVAILABLE' → "No Signing CA set up yet…" + link to signer /onboarding
// Fields: status, activeCA, intermediateCAsCount,
//   certificates: { total, valid, revoked },
//   crl: { name, exists }, acme: { directory }, database, basePath, baseUrl, time
```

Render `s.message` verbatim — it already contains the actionable fix
(e.g. which CA to set up). Also surface `s.code` as a badge so support can
search logs (`CA_NOT_AVAILABLE`, `READY`).

Deep health (admin only, Bearer session): `GET /api/admin/health-detail` →
openssl version, key-decrypt check, uptime, db type, log level.

## 3. Issue a certificate (mTLS / RADIUS server cert)

```js
const r = await fetch(`${BASE}/api/v1/sign`, {
  method: 'POST',
  headers: { 'Content-Type': 'application/json', 'x-api-key': process.env.CERT_SIGNER_API_KEY },
  body: JSON.stringify({
    csr: csrPem,                 // PEM PKCS#10, required
    san: ['radius.rajlabs.in'],  // array or comma string
    days: 90,
    purpose: 'radius'            // optional routing hint (see §5)
    // ca: 'int-wifi'            // optional explicit override
  })
});
const d = await r.json();
if (!d.success) {
  // d.code ∈ CA_NOT_AVAILABLE | VALIDATION_ERROR | UNAUTHORIZED | SIGNING_FAILED | INTERNAL_ERROR
  // d.hint has the fix; d.setupUrl === '/onboarding' when a CA must be set up.
  showError(`[${d.code}] ${d.error}`, d.hint);
}
// d.certificate, d.fullChain/chain, d.serialNumber/serial, d.caName, d.caSelection, d.expiresAt
```

## 4. Lifecycle: detail, download, renew, revoke (admin Bearer)

```js
// Filtered inventory (server-side): ?status=valid|revoked|renewed|expired
//   &ca=int-wifi &q=text &expiringDays=30 &limit=&offset=
// → { success, total, entries: [{ serial, commonName, sanDomains, caName,
//     caSelection, daysRemaining, expired, expiresAt, sha256Fingerprint,
//     status, issuedViaTokenName, issuedAt, supersededBy, hasLeafFile, hasChainFile }] }
GET /api/admin/certificates?…

// Detail incl. live openssl text + file presence
GET /api/admin/certificates/:serial
// → { success, certificate: { …, opensslText } }

// PEM download (audited as cert.downloaded)
GET /api/admin/certificates/:serial/download?kind=leaf|chain

// Renew: fresh key + serial, same SANs + same CA; old → status renewed
// (superseded, NOT CRL-listed). Returns new privateKey — show once!
POST /api/admin/certificates/:serial/renew  { days }
```

## 5. Revoke (single + bulk, e.g. offboarded APs)

```js
await fetch(`${BASE}/api/v1/revoke`, { method: 'POST', headers,
  body: JSON.stringify({ serial: '0x…' /* hex */, reason: 'keyCompromise' }) });
// → { success, code: 'REVOKED' | 'ALREADY_REVOKED', crlRegenerated }

await fetch(`${BASE}/api/v1/revoke-bulk`, { method: 'POST', headers,
  body: JSON.stringify({ serials: ['…', '…'], reason: 'cessationOfOperation' }) });
// → { success, code: 'BULK_REVOKED', revoked, alreadyRevoked, notFound, crlRegenerated }
```

## 6. CA routing (purpose-based)

`POST /api/v1/sign` and `/api/admin/generate-cert` accept:

| Field | Meaning |
|---|---|
| `ca` / `intermediateId` | explicit CA name (`int-server`, `int-wifi`, `int-iot`) |
| `purpose` / `profile` | `server`/`web`/`tls`/`acme` → `int-server`; `wifi`/`radius`/`8021x`/`eap` → `int-wifi`; `iot`/`device`/`mqtt` → `int-iot` |

Resolution: explicit → purpose map → active CA → `int-server` → first usable.
Response echoes `caName` + `caSelection` (e.g. `purpose:wifi→int-wifi`).
FreeRADIUS should pass `purpose: 'radius'` and display `caSelection` in its UI.

## 7. Error envelope (all APIs)

```json
{ "success": false, "code": "CA_NOT_AVAILABLE", "error": "…actionable message…",
  "hint": "…fix…", "setupUrl": "/onboarding", "expectedCAs": ["int-server","int-wifi","int-iot"] }
```

Codes: `CA_NOT_AVAILABLE` (503, nothing to sign with), `VALIDATION_ERROR` (400),
`UNAUTHORIZED` (401, bad/revoked key), `NOT_FOUND` (404), `RATE_LIMITED` (429),
`SIGNING_FAILED` (422, bad CSR), `ALREADY_REVOKED`/`REVOKED`/`BULK_REVOKED`,
`INTERNAL_ERROR` (500), `PARSE_ERROR`.

## 8. Coolify path-routing note (why logins failed before)

The signer UI must call the signer API under the **same sub-path**
(`$BASE/api/…`, never bare `/api/…`). The rebuilt UI auto-detects `BASE_PATH`
(server-injected `window.__PKI_BASE_PATH__`, `/api/auth/setup-status: basePath`,
location fallback). Backend code must likewise prefix with
`CERT_SIGNER_BASE_URL` (which includes `/cert-signer`), never hardcode
`backend.rajlabs.in/api/…`.
