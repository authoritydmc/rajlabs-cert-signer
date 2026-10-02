"""Intermediate CA management."""
import uuid
import subprocess
import shutil
import tempfile
import os
import re
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from .. import store, vault
from ..auth import caller
from ..errors import err
from ..logging_util import audit, logger
from ..pki import OPENSSL

router = APIRouter()


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _parse_cert_pem(pem: str) -> dict:
    """Parse an X.509 certificate PEM using OpenSSL and return structured fields."""
    if not pem or not OPENSSL:
        return {}
    try:
        with tempfile.NamedTemporaryFile(suffix=".pem", delete=False, mode="w") as f:
            f.write(pem.strip())
            tmp = f.name

        def run(*args):
            return subprocess.run([OPENSSL, *args], capture_output=True, text=True, timeout=10)

        # Subject fields
        subj_out = run("x509", "-in", tmp, "-noout", "-subject", "-nameopt", "RFC2253").stdout.strip()
        # Dates
        dates_out = run("x509", "-in", tmp, "-noout", "-startdate", "-enddate").stdout.strip()
        # Serial
        serial_out = run("x509", "-in", tmp, "-noout", "-serial").stdout.strip()
        # Text for extensions
        text_out = run("x509", "-in", tmp, "-noout", "-text").stdout

        os.unlink(tmp)

        result = {}

        # Parse subject: subject=CN=..., O=..., C=...
        subj_str = subj_out.replace("subject=", "").strip()
        result["subject"] = {}
        for part in subj_str.split(","):
            part = part.strip()
            if "=" in part:
                k, v = part.split("=", 1)
                result["subject"][k.strip()] = v.strip()

        # Parse dates: notBefore=..., notAfter=...
        for line in dates_out.splitlines():
            if line.startswith("notBefore="):
                raw = line.replace("notBefore=", "").strip()
                try:
                    dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
                    result["not_before"] = dt.replace(tzinfo=timezone.utc).isoformat()
                except Exception:
                    result["not_before"] = raw
            elif line.startswith("notAfter="):
                raw = line.replace("notAfter=", "").strip()
                try:
                    dt = datetime.strptime(raw, "%b %d %H:%M:%S %Y %Z")
                    result["not_after"] = dt.replace(tzinfo=timezone.utc).isoformat()
                except Exception:
                    result["not_after"] = raw

        # Serial
        serial_line = serial_out.replace("serial=", "").strip()
        result["serial"] = serial_line

        # Parse text for extended fields
        if text_out:
            # Key type / size
            pub_match = re.search(r"Public Key Algorithm: (\S+)", text_out)
            if pub_match:
                result["key_type"] = pub_match.group(1)
            rsa_match = re.search(r"RSA Public-Key: \((\d+) bit\)", text_out) or \
                        re.search(r"Public-Key: \((\d+) bit\)", text_out)
            if rsa_match:
                result["key_bits"] = int(rsa_match.group(1))
            sig_match = re.search(r"Signature Algorithm: (\S+)", text_out)
            if sig_match:
                result["sig_alg"] = sig_match.group(1)

            # CA:TRUE
            result["is_ca"] = "CA:TRUE" in text_out

            # PathLen
            path_match = re.search(r"pathlen:(\d+)", text_out)
            result["path_len"] = int(path_match.group(1)) if path_match else None

            # Key Usage
            ku_match = re.search(r"X509v3 Key Usage:.*?\n\s+(.+)", text_out)
            if ku_match:
                result["key_usage"] = [x.strip() for x in ku_match.group(1).split(",")]
            else:
                result["key_usage"] = []

            # Extended Key Usage
            eku_match = re.search(r"Extended Key Usage:.*?\n\s+(.+)", text_out)
            if eku_match:
                result["ext_key_usage"] = [x.strip() for x in eku_match.group(1).split(",")]
            else:
                result["ext_key_usage"] = []

            # SANs
            san_match = re.search(r"Subject Alternative Name:\s*\n\s+(.+)", text_out)
            if san_match:
                result["sans"] = [s.strip() for s in san_match.group(1).split(",")]
            else:
                result["sans"] = []

            # CRL URLs
            crl_urls = re.findall(r"URI:([^\s,]+crl[^\s,]*)", text_out, re.IGNORECASE)
            result["crl_urls"] = list(set(crl_urls))

            # OCSP URLs
            ocsp_urls = re.findall(r"OCSP - URI:([^\s]+)", text_out, re.IGNORECASE)
            result["ocsp_urls"] = list(set(ocsp_urls))

        return result
    except Exception as ex:
        logger.error("cert.inspect.error", {"error": str(ex)})
        return {}


@router.get("/api/admin/intermediate-cas")
def list_cas(_=Depends(caller)):
    db = store.load()
    return [{"id": c.get("id"), "name": c.get("name"), "description": c.get("description"),
             "certPem": c.get("certPem"), "rootCertPem": c.get("rootCertPem"),
             "isActive": bool(c.get("isActive")), "hasKey": bool(c.get("encryptedKeyPem"))}
            for c in db.get("intermediateCAs", [])]


@router.get("/api/admin/intermediate-cas/{ca_id}/inspect")
def inspect_ca(ca_id: str, _=Depends(caller)):
    """Return parsed X.509 fields for a given intermediate CA certificate."""
    db = store.load()
    ca = next((c for c in db.get("intermediateCAs", []) if c.get("id") == ca_id), None)
    if not ca:
        return err(404, "NOT_FOUND", "CA not found.")
    cert_pem = ca.get("certPem") or ""
    if not cert_pem:
        return err(400, "NO_CERT", "CA has no certificate stored.")
    parsed = _parse_cert_pem(cert_pem)
    parsed["ca_name"] = ca.get("name")
    parsed["has_key"] = bool(ca.get("encryptedKeyPem"))
    parsed["is_active"] = bool(ca.get("isActive"))
    return parsed


@router.post("/api/admin/intermediate-cas")
def import_ca(body: dict, request: Request, _=Depends(caller)):
    body = body or {}
    name = body.get("name") or ""
    cert, key, root = body.get("certPem") or "", body.get("keyPem") or "", body.get("rootCertPem") or ""
    if not (name and cert and key and root):
        return err(400, "VALIDATION_ERROR", "name, certPem, keyPem, and rootCertPem are required.")
    if "BEGIN CERTIFICATE" not in cert or "PRIVATE KEY" not in key:
        return err(400, "VALIDATION_ERROR", "certPem must be a PEM certificate and keyPem a PEM private key.")
    db = store.load()
    if body.get("setActive"):
        for c in db.get("intermediateCAs", []):
            c["isActive"] = False
    entry = {"id": uuid.uuid4().hex, "name": name.strip().lower().replace(" ", "-")[:64],
             "description": (body.get("description") or "")[:200],
             "certPem": cert.strip(), "encryptedKeyPem": vault.encrypt(key.strip()),
             "rootCertPem": root.strip(),
             "isActive": bool(body.get("setActive")) or not db.get("intermediateCAs"),
             "createdAt": _iso_now()}
    db["intermediateCAs"].append(entry)
    store.save(db)
    audit("ca.imported", {"id": entry["id"], "name": entry["name"], "active": entry["isActive"]}, request)
    logger.info("ca.imported", {"name": entry["name"]})
    return {"success": True, "ca": {"id": entry["id"], "name": entry["name"], "isActive": entry["isActive"]}}


@router.post("/api/admin/intermediate-cas/{ca_id}/activate")
def activate_ca(ca_id: str, request: Request, _=Depends(caller)):
    db = store.load()
    target = next((c for c in db.get("intermediateCAs", []) if c.get("id") == ca_id), None)
    if not target:
        return err(404, "NOT_FOUND", "CA not found.")
    for c in db.get("intermediateCAs", []):
        c["isActive"] = False
    target["isActive"] = True
    store.save(db)
    audit("ca.activated", {"id": target["id"], "name": target["name"]}, request)
    logger.info("ca.activated", {"name": target["name"]})
    return {"success": True, "code": "ACTIVATED", "message": f"Activated {target['name']}"}


@router.delete("/api/admin/intermediate-cas/{ca_id}")
def delete_ca(ca_id: str, request: Request, _=Depends(caller)):
    db = store.load()
    target = next((c for c in db.get("intermediateCAs", []) if c.get("id") == ca_id), None)
    if not target:
        return err(404, "NOT_FOUND", "CA not found.")
    if target.get("isActive") and len(db.get("intermediateCAs", [])) > 1:
        return err(400, "VALIDATION_ERROR",
                   f"Cannot delete the active CA ({target['name']}). Activate another CA first.")
    issued = sum(1 for c in db.get("certificates", []) if c.get("caName") == target["name"])
    db["intermediateCAs"] = [c for c in db.get("intermediateCAs", []) if c.get("id") != ca_id]
    store.save(db)
    audit("ca.deleted", {"id": target["id"], "name": target["name"], "certsIssued": issued}, request)
    logger.warn("ca.deleted", {"name": target["name"], "certsIssued": issued})
    return {"success": True, "code": "DELETED", "message": f"Deleted {target['name']}.", "certsAffected": issued}
