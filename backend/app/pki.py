"""OpenSSL-backed PKI operations (subprocess, arg arrays - no shell)."""
import os
import re
import shutil
import subprocess
import tempfile
import uuid
from datetime import datetime, timezone
from pathlib import Path

from . import config, store, vault
from .errors import ApiError
from .logging_util import logger

OPENSSL = shutil.which("openssl") or "openssl"
TMP = Path(tempfile.gettempdir())


def run(*args: str) -> str:
    p = subprocess.run([OPENSSL, *args], capture_output=True, text=True)
    if p.returncode != 0:
        raise RuntimeError((p.stderr or p.stdout or "openssl failed").strip()[:2000])
    return p.stdout


def _clean(*paths):
    for p in paths:
        try:
            os.unlink(p)
        except Exception:
            pass


def resolve_ca(db: dict, hint: dict | None):
    """explicit name -> purpose map -> active -> int-server -> first usable."""
    cas = db.get("intermediateCAs", []) or []
    usable = lambda c: bool(c and c.get("certPem") and c.get("encryptedKeyPem"))
    h = ""
    if hint:
        h = str(hint.get("ca") or hint.get("intermediateId")
                or hint.get("intermediateName") or hint.get("purpose")
                or hint.get("profile") or "").lower().strip()
    if h:
        exact = next((c for c in cas if c.get("name", "").lower() == h and usable(c)), None)
        if exact:
            return exact, f"explicit:{exact['name']}"
        for name in config.CA_PURPOSE_MAP.get(h, []):
            m = next((c for c in cas if c.get("name", "").lower() == name and usable(c)), None)
            if m:
                return m, f"purpose:{h}\u2192{m['name']}"
    active = next((c for c in cas if c.get("isActive") and usable(c)), None)
    if active:
        return active, ("fallback:active:" + active["name"] if h else "default:active")
    server = next((c for c in cas if c.get("name", "").lower() == "int-server" and usable(c)), None)
    if server:
        return server, ("fallback:int-server" if h else "default:int-server")
    first = next((c for c in cas if usable(c)), None)
    if first:
        return first, ("fallback:first:" + first["name"] if h else "default:first")
    return None, "none:empty"


def _key_ok(ca: dict) -> str:
    try:
        key = vault.decrypt(ca["encryptedKeyPem"])
    except Exception:
        raise ApiError(503, "CA_NOT_AVAILABLE",
                       "CA_NOT_AVAILABLE: Active intermediate CA private key cannot be decrypted. Re-import the CA.")
    if not key or "PRIVATE KEY" not in key:
        raise ApiError(503, "CA_NOT_AVAILABLE",
                       "CA_NOT_AVAILABLE: Active intermediate CA has no usable private key.")
    return key


def sign_leaf(csr_pem: str, san_domains=None, days=90, issued_via=None,
              public_base=None, ca_hint=None) -> dict:
    san_domains = list(san_domains or [])
    db = store.load()
    ca, reason = resolve_ca(db, ca_hint)
    if not ca:
        raise ApiError(503, "CA_NOT_AVAILABLE",
                       "CA_NOT_AVAILABLE: No Signing CA set up yet. Open Admin UI "
                       "\u2192 \U0001f9d9 Setup Wizard (or Intermediate CAs) and generate/import "
                       "at least one Signing CA (e.g. int-server for web/TLS, int-wifi for "
                       "RADIUS/802.1X, int-iot for devices), then retry.",
                       "Set up at least one Signing CA first: \U0001f9d9 Setup Wizard (1-click) "
                       "or Intermediate CAs \u2192 Import.")
    key = _key_ok(ca)

    cert_id = uuid.uuid4().hex
    serial_num = int(db.get("serial", 2000))
    db["serial"] = serial_num + 1
    store.save(db)
    serial = format(serial_num, "x").zfill(4)

    t = lambda n: str(TMP / f"{cert_id}.{n}")
    csr_f, cert_f, ext_f, ca_f, key_f = t("csr"), t("crt"), t("ext"), t("ca.crt"), t("ca.key")
    try:
        Path(csr_f).write_text(csr_pem, encoding="utf-8")
        Path(ca_f).write_text(ca["certPem"], encoding="utf-8")
        Path(key_f).write_text(key, encoding="utf-8")
        os.chmod(key_f, 0o600)
        bases = [b for b in [public_base or config.BASE_URL, "http://certs.rajlabs.in",
                             "http://crl.rajlabs.in", "http://pki.rajlabs.in"] if b]
        bases = list(dict.fromkeys(bases))
        ext = [
            "basicConstraints = CA:FALSE",
            "keyUsage = digitalSignature, keyEncipherment",
            "extendedKeyUsage = serverAuth, clientAuth",
            "subjectKeyIdentifier = hash",
            "authorityKeyIdentifier = keyid,issuer",
            "crlDistributionPoints = " + ", ".join(f"URI:{u}/crl/{ca['name']}.crl" for u in bases),
            "authorityInfoAccess = " + ", ".join(f"OCSP;URI:{u}/ocsp" for u in bases)
            + ", " + ", ".join(f"caIssuers;URI:{u}/api/v1/ca/{ca['name']}/cert" for u in bases),
        ]
        if san_domains:
            sans = "\n".join(f"DNS.{i + 1} = {d}" for i, d in enumerate(san_domains))
            ext.append(f"subjectAltName = @alt_names\n[alt_names]\n{sans}")
        Path(ext_f).write_text("\n".join(ext), encoding="utf-8")
        days_num = max(1, min(825, int(days or 90)))
        try:
            run("x509", "-req", "-in", csr_f, "-CA", ca_f, "-CAkey", key_f,
                "-set_serial", f"0x{serial}", "-out", cert_f,
                "-days", str(days_num), "-sha256", "-extfile", ext_f)
        except RuntimeError as e:
            raise ApiError(422, "SIGNING_FAILED",
                           "SIGNING_FAILED: OpenSSL could not sign the CSR. "
                           "Verify the CSR is a valid PEM PKCS#10 request.") from e
        issued = Path(cert_f).read_text(encoding="utf-8")
        full_chain = f"{issued.strip()}\n{ca['certPem'].strip()}\n{ca['rootCertPem'].strip()}".strip()
        (config.CERTS_DIR / f"{cert_id}.crt").write_text(issued, encoding="utf-8")
        (config.CERTS_DIR / f"{cert_id}-chain.crt").write_text(full_chain, encoding="utf-8")

        expires_at = datetime.fromtimestamp(
            __import__("time").time() + days_num * 86400, timezone.utc).isoformat()
        fingerprint = None
        try:
            m = re.search(r"notAfter=(.*)", run("x509", "-in", cert_f, "-noout", "-enddate"))
            if m:
                expires_at = datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z") \
                    .replace(tzinfo=timezone.utc).isoformat()
            fpm = re.search(r"=(.*)", run("x509", "-in", cert_f, "-noout", "-fingerprint", "-sha256"))
            if fpm:
                fingerprint = fpm.group(1).strip()
        except Exception as e:
            logger.warn("cert.meta_read_failed", {"serial": serial})
    finally:
        _clean(csr_f, cert_f, ext_f, ca_f, key_f)

    cn = san_domains[0] if san_domains else ""
    db2 = store.load()
    db2.get("certificates", []).insert(0, {
        "id": cert_id, "serial": serial, "caName": ca["name"], "caSelection": reason,
        "commonName": cn, "sanDomains": san_domains, "days": days_num,
        "issuedAt": datetime.now(timezone.utc).isoformat(), "expiresAt": expires_at,
        "sha256Fingerprint": fingerprint, "status": "valid",
        "issuedViaTokenId": (issued_via or {}).get("id"),
        "issuedViaTokenName": (issued_via or {}).get("name"),
    })
    store.save(db2)
    if issued_via and issued_via.get("id") not in (None, "admin-ui", "env:AUTH_TOKEN") \
            and not str(issued_via.get("id", "")).startswith("env:"):
        from .auth import record_usage
        record_usage(issued_via["id"], cn)
    return {"certId": cert_id, "serial": serial, "certificate": issued,
            "fullChain": full_chain, "caName": ca["name"], "selectionReason": reason}


def cert_enddate(leaf_path: str) -> str | None:
    try:
        m = re.search(r"notAfter=(.*)", run("x509", "-in", str(leaf_path), "-noout", "-enddate"))
        if m:
            return datetime.strptime(m.group(1).strip(), "%b %d %H:%M:%S %Y %Z") \
                .replace(tzinfo=timezone.utc).isoformat()
    except Exception:
        pass
    return None


def cert_fingerprint(leaf_path: str) -> str | None:
    try:
        m = re.search(r"=(.*)", run("x509", "-in", str(leaf_path), "-noout", "-fingerprint", "-sha256"))
        return m.group(1).strip() if m else None
    except Exception:
        return None


def cert_text(leaf_path: str, limit=12000) -> str | None:
    try:
        return run("x509", "-in", str(leaf_path), "-noout", "-text")[:limit]
    except Exception:
        return None


def regenerate_crl(ca: dict) -> Path:
    """Best-effort CRL rebuild. Raises RuntimeError on failure (caller logs)."""
    crl_file = config.CRL_DIR / f"{ca['name']}.crl"
    idx = config.DATA_DIR / "index.txt"
    crl_num = config.DATA_DIR / "crlnumber"
    serial_f = config.DATA_DIR / "serial"
    cnf = config.DATA_DIR / "crl_openssl.cnf"
    if not idx.exists():
        idx.write_text("", encoding="utf-8")
    if not crl_num.exists():
        crl_num.write_text("1000\n", encoding="utf-8")
    if not serial_f.exists():
        serial_f.write_text("1000\n", encoding="utf-8")
    ca_crt = TMP / f"crl-{ca['id']}.crt"
    ca_key = TMP / f"crl-{ca['id']}.key"
    ca_crt.write_text(ca["certPem"], encoding="utf-8")
    ca_key.write_text(vault.decrypt(ca["encryptedKeyPem"]), encoding="utf-8")
    os.chmod(ca_key, 0o600)
    fx = lambda p: str(p).replace("\\", "/")
    cnf.write_text("\n".join([
        "[ ca ]", "default_ca = CA_default", "[ CA_default ]",
        f"database = {fx(idx)}", f"crlnumber = {fx(crl_num)}", f"serial = {fx(serial_f)}",
        f"new_certs_dir = {fx(config.DATA_DIR)}", f"certificate = {fx(ca_crt)}",
        f"private_key = {fx(ca_key)}",
        "default_md = sha256", "default_days = 365", "default_crl_days = 30",
        "policy = policy_any", "[ policy_any ]", "commonName = supplied",
    ]), encoding="utf-8")
    try:
        run("ca", "-gencrl", "-keyfile", str(ca_key), "-cert", str(ca_crt),
            "-config", str(cnf), "-out", str(crl_file))
    finally:
        _clean(str(ca_crt), str(ca_key))
    return crl_file
