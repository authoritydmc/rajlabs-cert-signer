"""Public endpoints: health, status, trust downloads, CRL, installers, ACME, audit."""
import time
import uuid

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse, Response

from .. import config, store
from ..auth import caller
from ..errors import err
from ..store import active_database_label

router = APIRouter()
_started = time.time()


@router.get("/health")
def health():
    return {"status": "ok", "uptimeSec": int(time.time() - _started),
            "time": __import__("datetime").datetime.now(__import__("datetime").timezone.utc).isoformat()}


@router.get("/api/v1/status")
def status(request: Request):
    from ..routers.auth import _public_base
    try:
        db = store.load()
    except Exception as e:
        return err(500, "INTERNAL_ERROR", "Database unreadable: " + str(e)[:300])
    cas = db.get("intermediateCAs", []) or []
    active = next((c for c in cas if c.get("isActive")), cas[0] if cas else None)
    certs = db.get("certificates", []) or []
    revoked = sum(1 for c in certs if c.get("status") == "revoked")
    base = _public_base(request)
    if not active:
        return {"success": True, "code": "CA_NOT_AVAILABLE", "status": "degraded",
                "message": "CA_NOT_AVAILABLE: No Intermediate CA configured.",
                "basePath": config.BASE_PATH, "baseUrl": base, "activeCA": None,
                "intermediateCAsCount": len(cas),
                "certificates": {"total": len(certs), "revoked": revoked, "valid": len(certs) - revoked},
                "crl": None, "acme": {"directory": f"{base}/acme/directory"},
                "api": {"sign": "/api/v1/sign", "revoke": "/api/v1/revoke",
                        "revokeBulk": "/api/v1/revoke-bulk", "caCert": "/api/v1/ca/:name/cert"},
                "database": active_database_label(), "time": health()["time"]}
    crl_f = config.CRL_DIR / f"{active['name']}.crl"
    return {"success": True, "code": "READY", "status": "ready",
            "message": f"Signer ready (active CA: {active['name']}).",
            "basePath": config.BASE_PATH, "baseUrl": base, "activeCA": active["name"],
            "intermediateCAsCount": len(cas),
            "certificates": {"total": len(certs), "revoked": revoked, "valid": len(certs) - revoked},
            "crl": {"name": f"{active['name']}.crl", "exists": crl_f.exists()},
            "acme": {"directory": f"{base}/acme/directory"},
            "api": {"sign": "/api/v1/sign", "revoke": "/api/v1/revoke",
                    "revokeBulk": "/api/v1/revoke-bulk", "caCert": "/api/v1/ca/:name/cert"},
            "database": active_database_label(), "time": health()["time"]}


@router.get("/api/admin/health-detail")
def health_detail(request: Request, _=Depends(caller)):
    from ..routers.auth import _public_base
    from ..pki import run
    from .. import vault
    db = store.load()
    cas = db.get("intermediateCAs", []) or []
    active = next((c for c in cas if c.get("isActive")), cas[0] if cas else None)
    try:
        openssl = run("version").strip()
    except Exception as e:
        openssl = "missing: " + str(e)[:200]
    key_ok, key_err = False, None
    if active:
        try:
            key_ok = "PRIVATE KEY" in vault.decrypt(active["encryptedKeyPem"])
        except Exception as e:
            key_err = str(e)[:300]
    import sys
    return {"success": True, "openssl": openssl, "keyDecryptOk": key_ok, "keyError": key_err,
            "python": sys.version.split()[0], "uptimeSec": int(time.time() - _started),
            "dataDir": str(config.DATA_DIR), "basePath": config.BASE_PATH,
            "baseUrl": _public_base(request), "database": active_database_label(),
            "databaseBackend": store.backend_name,
            "postgresConfigured": bool(config.DATABASE_URL), "logLevel": config.LOG_LEVEL}


def _active_ca():
    db = store.load()
    cas = db.get("intermediateCAs", []) or []
    return db, next((c for c in cas if c.get("isActive")), cas[0] if cas else None)


def _pem_to_der(pem_str: str) -> bytes:
    from cryptography import x509
    from cryptography.hazmat.primitives import serialization
    cert = x509.load_pem_x509_certificate(pem_str.encode("utf-8"))
    return cert.public_bytes(serialization.Encoding.DER)


def _sha256_fingerprint(pem_str: str) -> str:
    from cryptography import x509
    from cryptography.hazmat.primitives import hashes
    cert = x509.load_pem_x509_certificate(pem_str.encode("utf-8"))
    fp = cert.fingerprint(hashes.SHA256()).hex().upper()
    return ":".join(fp[i:i+2] for i in range(0, len(fp), 2))


def _make_p7b(chain_pem: str) -> bytes:
    from .. import pki
    op = uuid.uuid4().hex
    in_f = str(pki.TMP / f"{op}-p7.pem")
    out_f = str(pki.TMP / f"{op}-p7.p7b")
    try:
        from pathlib import Path
        Path(in_f).write_text(chain_pem, encoding="utf-8")
        pki.run("crl2pkcs7", "-nocrl", "-certfile", in_f, "-out", out_f, "-outform", "DER")
        return Path(out_f).read_bytes()
    finally:
        pki._clean(in_f, out_f)


def _make_mobileconfig(root_pem: str, org_name: str = "Enterprise PKI") -> str:
    import base64
    der_bytes = _pem_to_der(root_pem)
    b64_cert = base64.b64encode(der_bytes).decode("ascii")
    payload_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{org_name}-root-ca"))
    profile_uuid = str(uuid.uuid5(uuid.NAMESPACE_DNS, f"{org_name}-profile"))

    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
    <key>PayloadContent</key>
    <array>
        <dict>
            <key>PayloadCertificateFileName</key>
            <string>root-ca.cer</string>
            <key>PayloadContent</key>
            <data>
{b64_cert}
            </data>
            <key>PayloadDescription</key>
            <string>Installs {org_name} Root CA certificate into Trusted Root Store</string>
            <key>PayloadDisplayName</key>
            <string>{org_name} Root CA</string>
            <key>PayloadIdentifier</key>
            <string>in.rajlabs.pki.root.{payload_uuid}</string>
            <key>PayloadType</key>
            <string>com.apple.security.root</string>
            <key>PayloadUUID</key>
            <string>{payload_uuid}</string>
            <key>PayloadVersion</key>
            <integer>1</integer>
        </dict>
    </array>
    <key>PayloadDescription</key>
    <string>Configures trust for {org_name} internal services and TLS certificates.</string>
    <key>PayloadDisplayName</key>
    <string>{org_name} Root CA Trust Profile</string>
    <key>PayloadIdentifier</key>
    <string>in.rajlabs.pki.profile.{profile_uuid}</string>
    <key>PayloadOrganization</key>
    <string>{org_name}</string>
    <key>PayloadRemovalDisallowed</key>
    <false/>
    <key>PayloadType</key>
    <string>Configuration</string>
    <key>PayloadUUID</key>
    <string>{profile_uuid}</string>
    <key>PayloadVersion</key>
    <integer>1</integer>
</dict>
</plist>
"""


# ---- Root CA Downloads ----
@router.get("/certs/root-ca.crt")
@router.get("/certs/root-ca.pem")
def dl_root(request: Request):
    _, ca = _active_ca()
    if not ca or not ca.get("rootCertPem"):
        return err(404, "NOT_FOUND", "Root cert not found.")
    headers = {"Content-Type": "application/x-x509-ca-cert"}
    if request.query_params.get("download") == "1" or request.url.path.endswith(".crt"):
        headers["Content-Disposition"] = 'attachment; filename="root-ca.crt"'
    return Response(content=ca["rootCertPem"], media_type="application/x-x509-ca-cert", headers=headers)


@router.get("/certs/root-ca.der")
@router.get("/certs/root-ca.cer")
def dl_root_der(request: Request):
    _, ca = _active_ca()
    if not ca or not ca.get("rootCertPem"):
        return err(404, "NOT_FOUND", "Root cert not found.")
    try:
        der = _pem_to_der(ca["rootCertPem"])
    except Exception as e:
        return err(500, "CONVERSION_ERROR", f"Failed to encode DER certificate: {e}")
    ext = "cer" if request.url.path.endswith(".cer") else "der"
    headers = {"Content-Disposition": f'attachment; filename="root-ca.{ext}"'}
    return Response(content=der, media_type="application/pkix-cert", headers=headers)


@router.get("/certs/root-ca.mobileconfig")
def dl_root_mobileconfig():
    db, ca = _active_ca()
    if not ca or not ca.get("rootCertPem"):
        return err(404, "NOT_FOUND", "Root cert not found.")
    org_name = db.get("config", {}).get("profile", {}).get("orgName") or "Enterprise PKI"
    try:
        mc = _make_mobileconfig(ca["rootCertPem"], org_name)
    except Exception as e:
        return err(500, "CONVERSION_ERROR", f"Failed to generate Apple mobileconfig: {e}")
    headers = {"Content-Disposition": 'attachment; filename="root-ca-trust.mobileconfig"'}
    return Response(content=mc, media_type="application/x-apple-aspen-config", headers=headers)


# ---- Intermediate CA Downloads ----
@router.get("/certs/intermediate-ca.crt")
@router.get("/certs/intermediate-ca.pem")
def dl_int(request: Request):
    _, ca = _active_ca()
    if not ca or not ca.get("certPem"):
        return err(404, "NOT_FOUND", "Intermediate cert not found.")
    headers = {"Content-Type": "application/x-x509-ca-cert"}
    if request.query_params.get("download") == "1" or request.url.path.endswith(".crt"):
        headers["Content-Disposition"] = 'attachment; filename="intermediate-ca.crt"'
    return Response(content=ca["certPem"], media_type="application/x-x509-ca-cert", headers=headers)


@router.get("/certs/intermediate-ca.der")
@router.get("/certs/intermediate-ca.cer")
def dl_int_der(request: Request):
    _, ca = _active_ca()
    if not ca or not ca.get("certPem"):
        return err(404, "NOT_FOUND", "Intermediate cert not found.")
    try:
        der = _pem_to_der(ca["certPem"])
    except Exception as e:
        return err(500, "CONVERSION_ERROR", f"Failed to encode DER certificate: {e}")
    ext = "cer" if request.url.path.endswith(".cer") else "der"
    headers = {"Content-Disposition": f'attachment; filename="intermediate-ca.{ext}"'}
    return Response(content=der, media_type="application/pkix-cert", headers=headers)


# Specific CA cert downloads by name (e.g. /api/v1/ca/int-server/cert, .der, .cer)
@router.get("/api/v1/ca/{ca_name}/cert")
@router.get("/api/v1/ca/{ca_name}/cert.pem")
@router.get("/api/v1/ca/{ca_name}/cert.crt")
def dl_ca_by_name(ca_name: str, request: Request):
    db = store.load()
    name_clean = ca_name.strip().lower()
    target = next((c for c in db.get("intermediateCAs", []) if c.get("name", "").lower() == name_clean), None)
    if not target or not target.get("certPem"):
        return err(404, "NOT_FOUND", f"Intermediate CA '{ca_name}' not found.")
    headers = {"Content-Type": "application/x-x509-ca-cert"}
    if request.query_params.get("download") == "1":
        headers["Content-Disposition"] = f'attachment; filename="{target["name"]}.crt"'
    return Response(content=target["certPem"], media_type="application/x-x509-ca-cert", headers=headers)


@router.get("/api/v1/ca/{ca_name}/cert.der")
@router.get("/api/v1/ca/{ca_name}/cert.cer")
def dl_ca_by_name_der(ca_name: str, request: Request):
    db = store.load()
    name_clean = ca_name.strip().lower()
    target = next((c for c in db.get("intermediateCAs", []) if c.get("name", "").lower() == name_clean), None)
    if not target or not target.get("certPem"):
        return err(404, "NOT_FOUND", f"Intermediate CA '{ca_name}' not found.")
    try:
        der = _pem_to_der(target["certPem"])
    except Exception as e:
        return err(500, "CONVERSION_ERROR", f"Failed to encode DER certificate: {e}")
    ext = "cer" if request.url.path.endswith(".cer") else "der"
    headers = {"Content-Disposition": f'attachment; filename="{target["name"]}.{ext}"'}
    return Response(content=der, media_type="application/pkix-cert", headers=headers)


# ---- Full CA Chain Downloads ----
@router.get("/certs/ca-chain.crt")
@router.get("/certs/ca-chain.pem")
@router.get("/certs/ca.crt")
@router.get("/certs/ca.pem")
@router.get("/ca.crt")
@router.get("/ca.pem")
def dl_chain(request: Request):
    _, ca = _active_ca()
    if not ca or not (ca.get("certPem") and ca.get("rootCertPem")):
        return err(404, "NOT_FOUND", "CA Chain not available.")
    chain_pem = f"{ca['certPem'].strip()}\n{ca['rootCertPem'].strip()}\n"
    headers = {"Content-Type": "application/x-x509-ca-cert"}
    if request.query_params.get("download") == "1" or request.url.path.endswith(".crt") or request.url.path.endswith(".pem"):
        headers["Content-Disposition"] = 'attachment; filename="ca-chain.crt"'
    return Response(content=chain_pem, media_type="application/x-x509-ca-cert", headers=headers)


@router.get("/certs/ca-chain.p7b")
@router.get("/certs/ca-chain.p7c")
def dl_chain_p7b(request: Request):
    _, ca = _active_ca()
    if not ca or not (ca.get("certPem") and ca.get("rootCertPem")):
        return err(404, "NOT_FOUND", "CA Chain not available.")
    chain_pem = f"{ca['certPem'].strip()}\n{ca['rootCertPem'].strip()}\n"
    try:
        p7b = _make_p7b(chain_pem)
    except Exception as e:
        return err(500, "CONVERSION_ERROR", f"Failed to generate PKCS#7 certificate chain: {e}")
    ext = "p7c" if request.url.path.endswith(".p7c") else "p7b"
    headers = {"Content-Disposition": f'attachment; filename="ca-chain.{ext}"'}
    return Response(content=p7b, media_type="application/x-pkcs7-certificates", headers=headers)


# ---- Public Trust Summary Endpoint (for unauthenticated client portal) ----
@router.get("/api/v1/trust-summary")
def trust_summary(request: Request):
    from ..routers.auth import _public_base
    base = _public_base(request)
    db, active = _active_ca()
    cas = db.get("intermediateCAs", []) or []
    org_profile = db.get("config", {}).get("profile", {})
    org_name = org_profile.get("orgName") or "Enterprise PKI"

    root_info = None
    if active and active.get("rootCertPem"):
        try:
            fp = _sha256_fingerprint(active["rootCertPem"])
        except Exception:
            fp = None
        root_info = {
            "fingerprintSha256": fp,
            "downloads": {
                "pem": f"{base}/certs/root-ca.crt",
                "der": f"{base}/certs/root-ca.der",
                "cer": f"{base}/certs/root-ca.cer",
                "mobileconfig": f"{base}/certs/root-ca.mobileconfig",
            },
        }

    ca_list = []
    for c in cas:
        fp_ca = None
        if c.get("certPem"):
            try:
                fp_ca = _sha256_fingerprint(c["certPem"])
            except Exception:
                pass
        ca_list.append({
            "name": c.get("name"),
            "description": c.get("description", ""),
            "isActive": bool(c.get("isActive")),
            "fingerprintSha256": fp_ca,
            "downloads": {
                "pem": f"{base}/api/v1/ca/{c.get('name')}/cert",
                "der": f"{base}/api/v1/ca/{c.get('name')}/cert.der",
                "cer": f"{base}/api/v1/ca/{c.get('name')}/cert.cer",
            },
        })

    chain_info = {
        "downloads": {
            "pem": f"{base}/certs/ca-chain.crt",
            "p7b": f"{base}/certs/ca-chain.p7b",
        }
    } if active else None

    return {
        "success": True,
        "orgName": org_name,
        "activeCA": active["name"] if active else None,
        "intermediateCAsCount": len(cas),
        "rootCA": root_info,
        "intermediateCAs": ca_list,
        "chain": chain_info,
        "installers": {
            "windows": f"irm {base}/install-trust-windows.ps1 | iex",
            "linux": f"curl -fsSL {base}/install-trust-linux.sh | sudo bash",
        },
    }


# ---- CRL Endpoints ----
@router.get("/crl/{ca_name}.crl")
@router.get("/{ca_name}.crl")
def dl_crl(ca_name: str):
    clean_name = ca_name.replace(".crl", "")
    f = config.CRL_DIR / f"{clean_name}.crl"
    if not f.exists():
        # Check active CA if generic
        if clean_name in ("crl", "root-ca", "ca"):
            _, active = _active_ca()
            if active and (config.CRL_DIR / f"{active['name']}.crl").exists():
                f = config.CRL_DIR / f"{active['name']}.crl"
    if not f.exists():
        return err(404, "NOT_FOUND",
                   f"CRL for {ca_name} not found yet. Revoke a cert or wait for generation.")
    return Response(content=f.read_bytes(), media_type="application/pkix-crl")


@router.get("/crl.pem")
@router.get("/crl.crl")
@router.get("/crl")
def dl_active_crl():
    _, ca = _active_ca()
    if not ca:
        return err(404, "NOT_FOUND", "No active CA found.")
    return dl_crl(ca["name"])


@router.get("/ocsp")
@router.post("/ocsp")
def ocsp_endpoint():
    # Return standard OCSP responder notice
    return Response(content=b"Rajlabs OCSP Responder (RFC 6960)", media_type="text/plain")



@router.get("/install-trust-windows.ps1")
def installer_win(request: Request):
    from ..routers.auth import _public_base
    base = _public_base(request)
    return PlainTextResponse(
        "$isAdmin = ([Security.Principal.WindowsPrincipal][Security.Principal.WindowsIdentity]::GetCurrent()).IsInRole('Administrator')\n"
        f"if (-not $isAdmin) {{ Start-Process powershell.exe -ArgumentList (\"-NoProfile -ExecutionPolicy Bypass -Command \\\"irm {base}/install-trust-windows.ps1 | iex\\\"\") -Verb RunAs; exit }}\n"
        "$t = [System.IO.Path]::GetTempPath(); $r = Join-Path $t 'r.crt'; $i = Join-Path $t 'i.crt'\n"
        f"Invoke-WebRequest -Uri '{base}/certs/root-ca.crt' -OutFile $r -UseBasicParsing\n"
        f"Invoke-WebRequest -Uri '{base}/certs/intermediate-ca.crt' -OutFile $i -UseBasicParsing\n"
        "$rs = New-Object System.Security.Cryptography.X509Certificates.X509Store('Root', 'LocalMachine'); $rs.Open('ReadWrite'); $rs.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($r))); $rs.Close()\n"
        "$is = New-Object System.Security.Cryptography.X509Certificates.X509Store('CertificateAuthority', 'LocalMachine'); $is.Open('ReadWrite'); $is.Add((New-Object System.Security.Cryptography.X509Certificates.X509Certificate2($i))); $is.Close()\n"
        "Write-Host '[SUCCESS] Enterprise Trust Chain Installed!' -ForegroundColor Green\n")


@router.get("/install-trust-linux.sh")
def installer_linux(request: Request):
    from ..routers.auth import _public_base
    base = _public_base(request)
    return PlainTextResponse(
        "#!/bin/bash\nset -e\nif [ \"$EUID\" -ne 0 ]; then echo \"Run as root\"; exit 1; fi\n"
        "d=$(mktemp -d); trap 'rm -rf \"$d\"' EXIT\n"
        f"curl -fsSL \"{base}/certs/root-ca.crt\" -o \"$d/root.crt\"\n"
        f"curl -fsSL \"{base}/certs/intermediate-ca.crt\" -o \"$d/int.crt\"\n"
        "if [ -d \"/usr/local/share/ca-certificates\" ]; then\n"
        "  cp \"$d/root.crt\" \"$d/int.crt\" /usr/local/share/ca-certificates/; update-ca-certificates\n"
        "elif [ -d \"/etc/pki/ca-trust/source/anchors\" ]; then\n"
        "  cp \"$d/root.crt\" \"$d/int.crt\" /etc/pki/ca-trust/source/anchors/; update-ca-trust extract\nfi\n"
        "echo \"[SUCCESS] Enterprise Trust Chain Installed!\"\n")


# ---- ACME (directory + account/order stubs, openssl-backed finalize) ----
@router.get("/acme/directory")
def acme_dir(request: Request):
    from ..routers.auth import _public_base
    base = _public_base(request)
    return {"newNonce": f"{base}/acme/new-nonce", "newAccount": f"{base}/acme/new-account",
            "newOrder": f"{base}/acme/new-order", "revokeCert": f"{base}/acme/revoke-cert",
            "keyChange": f"{base}/acme/key-change",
            "meta": {"termsOfService": f"{base}/terms", "website": "https://Enterprise.local"}}


def _nonce_response():
    from fastapi.responses import Response as _R
    return _R(status_code=204, headers={"Replay-Nonce": uuid.uuid4().hex, "Cache-Control": "no-store"})


@router.get("/acme/new-nonce", operation_id="acme_new_nonce")
def acme_nonce():
    return _nonce_response()


@router.head("/acme/new-nonce", operation_id="acme_new_nonce_head")
def acme_nonce_head():
    return _nonce_response()


@router.post("/acme/new-account")
def acme_account(request: Request):
    from ..routers.auth import _public_base
    base = _public_base(request)
    acc = uuid.uuid4().hex
    from fastapi.responses import JSONResponse as _J
    return _J(status_code=201, content={"status": "valid", "orders": f"{base}/acme/acct/{acc}/orders"},
              headers={"Replay-Nonce": uuid.uuid4().hex, "Location": f"{base}/acme/acct/{acc}"})


@router.post("/acme/new-order")
async def acme_order(request: Request):
    from ..routers.auth import _public_base
    base = _public_base(request)
    try:
        body = await request.json()
    except Exception:
        body = {}
    oid, aid = uuid.uuid4().hex, uuid.uuid4().hex
    from fastapi.responses import JSONResponse as _J
    from datetime import datetime, timedelta, timezone as _tz
    return _J(status_code=201, content={
        "status": "ready", "expires": (datetime.now(_tz.utc) + timedelta(days=1)).isoformat(),
        "identifiers": body.get("identifiers", []) if isinstance(body, dict) else [],
        "authorizations": [f"{base}/acme/authz/{aid}"], "finalize": f"{base}/acme/order/{oid}/finalize"},
        headers={"Replay-Nonce": uuid.uuid4().hex, "Location": f"{base}/acme/order/{oid}"})


@router.post("/acme/order/{order_id}/finalize")
async def acme_finalize(order_id: str, request: Request):
    import base64
    from ..routers.auth import _public_base
    from ..errors import ApiError as _AE
    from ..pki import sign_leaf as _sign
    try:
        body = await request.json()
    except Exception:
        body = {}
    csr_raw = (body.get("csr") if isinstance(body, dict) else body) or ""
    csr_pem = str(csr_raw)
    if "BEGIN CERTIFICATE REQUEST" not in csr_pem:
        try:
            der = base64.b64decode(csr_pem)
            b64 = base64.b64encode(der).decode()
            csr_pem = "-----BEGIN CERTIFICATE REQUEST-----\n" + "\n".join(
                b64[i:i + 64] for i in range(0, len(b64), 64)) + "\n-----END CERTIFICATE REQUEST-----"
        except Exception:
            return err(400, "VALIDATION_ERROR", "Invalid CSR in finalize request.")
    try:
        result = _sign(csr_pem, ["localhost"], 90, {"id": "acme", "name": "ACME"},
                       _public_base(request), {"purpose": "acme"})
    except _AE as e:
        if e.code == "CA_NOT_AVAILABLE":
            from ..errors import ca_not_available
            return ca_not_available({"purpose": "acme"})
        return err(e.status, e.code, e.message, e.hint)
    from fastapi.responses import JSONResponse as _J
    return _J(content={"status": "valid",
                       "certificate": f"{_public_base(request)}/acme/cert/{result['certId']}"},
              headers={"Replay-Nonce": uuid.uuid4().hex})


@router.get("/acme/cert/{cert_id}")
def acme_cert(cert_id: str):
    f = config.CERTS_DIR / f"{cert_id}-chain.crt"
    if not f.exists() or ".." in cert_id or "/" in cert_id:
        return err(404, "NOT_FOUND", "Certificate not found.")
    return Response(content=f.read_text(encoding="utf-8"),
                    media_type="application/pem-certificate-chain")


# ---- Audit viewer (table backend when SQL is active, else the log file) ----
@router.get("/api/admin/audit")
def audit_list(request: Request, _=Depends(caller)):
    q = dict(request.query_params)
    try:
        lim = max(1, min(500, int(q.get("limit") or 100)))
    except (TypeError, ValueError):
        lim = 100
    try:
        off = max(0, int(q.get("offset") or 0))
    except (TypeError, ValueError):
        off = 0
    total, entries, counts = store.audit_read(q.get("event"), q.get("q"), lim, off)
    return {"success": True, "total": total, "limit": lim, "offset": off,
            "entries": entries, "eventCounts": counts}
