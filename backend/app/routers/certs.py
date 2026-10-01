"""Certificate lifecycle: issue, inventory, detail, download, renew, profile, inspect."""
import re
import uuid
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request
from fastapi.responses import PlainTextResponse

from .. import config, store
from ..auth import caller
from ..errors import ApiError, err
from ..logging_util import audit, logger
from ..pki import TMP, _clean, cert_fingerprint, cert_text, run, sign_leaf

router = APIRouter()


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _clean_cn(v: str) -> str:
    return re.sub(r"[^a-zA-Z0-9.\-_]", "", v or "")[:253]


def enrich(db: dict, c: dict) -> dict:
    out = dict(c)
    if not out.get("expiresAt"):
        leaf = config.CERTS_DIR / f"{out.get('id')}.crt"
        exp = None
        if leaf.exists():
            from ..pki import cert_enddate
            exp = cert_enddate(str(leaf))
        if exp:
            out["expiresAt"] = exp
        elif out.get("issuedAt"):
            try:
                out["expiresAt"] = (datetime.fromisoformat(str(out["issuedAt"]).replace("Z", "+00:00"))
                                    + timedelta(days=90)).isoformat()
                out["expiresAtEstimated"] = True
            except Exception:
                pass
    if not out.get("sha256Fingerprint"):
        leaf = config.CERTS_DIR / f"{out.get('id')}.crt"
        if leaf.exists():
            out["sha256Fingerprint"] = cert_fingerprint(str(leaf))
    ms_left = None
    if out.get("expiresAt"):
        try:
            ms_left = (datetime.fromisoformat(str(out["expiresAt"]).replace("Z", "+00:00"))
                       - datetime.now(timezone.utc)).total_seconds() * 1000
        except Exception:
            pass
    out["daysRemaining"] = None if ms_left is None else int(-(-ms_left // 86400000)) if ms_left > 0 else int(ms_left // 86400000)
    out["expired"] = ms_left is not None and ms_left <= 0 and out.get("status") == "valid"
    out["hasLeafFile"] = (config.CERTS_DIR / f"{out.get('id')}.crt").exists()
    out["hasChainFile"] = (config.CERTS_DIR / f"{out.get('id')}-chain.crt").exists()
    return out


@router.post("/api/admin/generate-cert")
async def generate_cert(body: dict, request: Request, _=Depends(caller)):
    from ..routers.auth import _public_base
    body = body or {}
    if not body.get("commonName"):
        return err(400, "VALIDATION_ERROR", "commonName is required.")
    clean_cn = _clean_cn(str(body["commonName"]))
    if not clean_cn:
        return err(400, "VALIDATION_ERROR", "Invalid commonName format.")
    try:
        days_num = max(1, min(825, int(body.get("days") or 90)))
    except (TypeError, ValueError):
        return err(400, "VALIDATION_ERROR", "days must be a number.")
    op = uuid.uuid4().hex
    key_f, csr_f = str(TMP / f"{op}.key"), str(TMP / f"{op}.csr")
    try:
        run("genrsa", "-out", key_f, "2048")
        run("req", "-new", "-key", key_f, "-out", csr_f, "-subj", f"/CN={clean_cn}")
        with open(csr_f, encoding="utf-8") as f:
            csr_pem = f.read()
        with open(key_f, encoding="utf-8") as f:
            priv = f.read()
        sans = [_clean_cn(s) for s in str(body.get("sans") or "").split(",")]
        sans = [s for s in sans if s][:50]
        if clean_cn not in sans:
            sans.insert(0, clean_cn)
        hint = {"ca": body.get("ca") or body.get("intermediateId"),
                "purpose": body.get("purpose") or body.get("profile")}
        result = sign_leaf(csr_pem, sans, days_num, {"id": "admin-ui", "name": "Admin UI"},
                           _public_base(request), hint)
        _clean(key_f, csr_f)
        audit("cert.issued", {"serial": result["serial"], "cn": clean_cn, "via": "admin-ui"}, request)
        logger.info("cert.issued", {"serial": result["serial"], "cn": clean_cn, "via": "admin-ui"})
        return {"success": True, "serial": result["serial"], "privateKey": priv,
                "certificate": result["certificate"], "fullChain": result["fullChain"],
                "caName": result["caName"], "caSelection": result["selectionReason"]}
    except ApiError as e:
        _clean(key_f, csr_f)
        logger.error("cert.issue_failed", {"error": e.message, "code": e.code})
        if e.code == "CA_NOT_AVAILABLE":
            from ..errors import ca_not_available
            return ca_not_available()
        return err(e.status, e.code, e.message, e.hint)
    except RuntimeError as e:
        _clean(key_f, csr_f)
        return err(500, "INTERNAL_ERROR", str(e)[:500])


@router.get("/api/admin/certificates")
def list_certs(request: Request, _=Depends(caller)):
    db = store.load()
    q = dict(request.query_params)
    if not q:
        return db.get("certificates", [])  # legacy shape
    items = [enrich(db, c) for c in db.get("certificates", [])]
    if q.get("ca"):
        items = [c for c in items if (c.get("caName") or "").lower() == q["ca"].lower()]
    if q.get("q"):
        needle = q["q"].lower()
        items = [c for c in items if needle in
                 f"{c.get('serial')} {' '.join(c.get('sanDomains') or [])} {c.get('commonName') or ''} "
                 f"{c.get('caName') or ''} {c.get('issuedViaTokenName') or ''} {c.get('sha256Fingerprint') or ''}".lower()]
    if q.get("status") == "expired":
        items = [c for c in items if c.get("expired")]
    elif q.get("status"):
        items = [c for c in items if c.get("status") == q["status"]]
    if q.get("expiringDays"):
        try:
            n = max(1, int(q["expiringDays"]))
        except (TypeError, ValueError):
            n = 30
        items = [c for c in items if c.get("status") == "valid" and c.get("daysRemaining") is not None
                 and 0 <= c["daysRemaining"] <= n]
    try:
        lim = max(1, min(500, int(q.get("limit") or 200)))
    except (TypeError, ValueError):
        lim = 200
    try:
        off = max(0, int(q.get("offset") or 0))
    except (TypeError, ValueError):
        off = 0
    return {"success": True, "total": len(items), "limit": lim, "offset": off,
            "entries": items[off:off + lim],
            "filterOptions": {
                "cas": sorted({c.get("caName") for c in db.get("certificates", []) if c.get("caName")}),
                "issuers": sorted({c.get("issuedViaTokenName") for c in db.get("certificates", []) if c.get("issuedViaTokenName")})},
            }


@router.get("/api/admin/certificates/{serial}")
def cert_detail(serial: str, _=Depends(caller)):
    db = store.load()
    clean = re.sub(r"[^a-fA-F0-9]", "", serial).lower()
    cert = next((c for c in db.get("certificates", []) if str(c.get("serial")).lower() == clean), None)
    if not cert:
        return err(404, "NOT_FOUND", f"Certificate 0x{clean} not found.")
    out = enrich(db, cert)
    leaf = config.CERTS_DIR / f"{cert.get('id')}.crt"
    out["opensslText"] = cert_text(str(leaf)) if leaf.exists() else None
    return {"success": True, "certificate": out}


@router.get("/api/admin/certificates/{serial}/download")
def cert_download(serial: str, request: Request, _=Depends(caller)):
    from fastapi.responses import Response
    db = store.load()
    clean = re.sub(r"[^a-fA-F0-9]", "", serial).lower()
    cert = next((c for c in db.get("certificates", []) if str(c.get("serial")).lower() == clean), None)
    if not cert:
        return err(404, "NOT_FOUND", f"Certificate 0x{clean} not found.")
    kind = "chain" if request.query_params.get("kind") == "chain" else "leaf"
    f = config.CERTS_DIR / (f"{cert.get('id')}-chain.crt" if kind == "chain" else f"{cert.get('id')}.crt")
    if not f.exists():
        return err(404, "NOT_FOUND", f"Stored {kind} PEM for 0x{clean} is missing from the data volume.")
    audit("cert.downloaded", {"serial": clean, "kind": kind}, request)
    return Response(content=f.read_text(encoding="utf-8"), media_type="application/x-pem-file",
                    headers={"Content-Disposition": f'attachment; filename="{clean}-{kind}.pem"'})


@router.post("/api/admin/certificates/{serial}/renew")
async def cert_renew(serial: str, body: dict, request: Request, _=Depends(caller)):
    from ..routers.auth import _public_base
    body = body or {}
    db = store.load()
    clean = re.sub(r"[^a-fA-F0-9]", "", serial).lower()
    cert = next((c for c in db.get("certificates", []) if str(c.get("serial")).lower() == clean), None)
    if not cert:
        return err(404, "NOT_FOUND", f"Certificate 0x{clean} not found.")
    if cert.get("status") == "revoked":
        return err(400, "VALIDATION_ERROR",
                   f"Certificate 0x{clean} is revoked and cannot be renewed. Issue a fresh certificate instead.")
    if cert.get("status") == "renewed":
        return err(400, "VALIDATION_ERROR",
                   f"Certificate 0x{clean} was already renewed (see serial 0x{cert.get('supersededBy') or '?'}).")
    try:
        days_num = max(1, min(825, int(body.get("days") or cert.get("days") or 90)))
    except (TypeError, ValueError):
        return err(400, "VALIDATION_ERROR", "days must be a number.")
    op = uuid.uuid4().hex
    key_f, csr_f = str(TMP / f"{op}.key"), str(TMP / f"{op}.csr")
    try:
        cn = _clean_cn(cert.get("commonName") or (cert.get("sanDomains") or ["renewed"])[0]) or "renewed"
        run("genrsa", "-out", key_f, "2048")
        run("req", "-new", "-key", key_f, "-out", csr_f, "-subj", f"/CN={cn}")
        with open(csr_f, encoding="utf-8") as f:
            csr_pem = f.read()
        with open(key_f, encoding="utf-8") as f:
            priv = f.read()
        result = sign_leaf(csr_pem, cert.get("sanDomains") or [cn], days_num,
                           {"id": "admin-ui", "name": "Admin UI"},
                           _public_base(request), {"ca": cert.get("caName")})
        _clean(key_f, csr_f)
        db2 = store.load()  # re-read: signing saved the new cert; old objects are stale
        old = next((c for c in db2.get("certificates", []) if str(c.get("serial")).lower() == clean), None)
        if old:
            old["status"] = "renewed"
            old["renewedAt"] = _iso_now()
            old["supersededBy"] = result["serial"]
            store.save(db2)
        audit("cert.renewed", {"oldSerial": clean, "newSerial": result["serial"], "cn": cn}, request)
        logger.info("cert.renewed", {"oldSerial": clean, "newSerial": result["serial"]})
        return {"success": True, "code": "RENEWED", "oldSerial": clean, "newSerial": result["serial"],
                "serial": result["serial"], "privateKey": priv, "certificate": result["certificate"],
                "fullChain": result["fullChain"], "caName": result["caName"],
                "caSelection": result["selectionReason"],
                "expiresAt": (datetime.now(timezone.utc) + timedelta(days=days_num)).isoformat()}
    except ApiError as e:
        _clean(key_f, csr_f)
        logger.error("cert.renew_failed", {"serial": clean, "error": e.message, "code": e.code})
        if e.code == "CA_NOT_AVAILABLE":
            return err(503, "CA_NOT_AVAILABLE", e.message,
                       "The original signing CA is gone. Import it again or renew into another CA via Issue tab.",
                       setupUrl="/onboarding")
        return err(e.status, e.code, e.message, e.hint)
    except RuntimeError as e:
        _clean(key_f, csr_f)
        return err(500, "INTERNAL_ERROR", str(e)[:500])


@router.get("/api/admin/profile")
def get_profile(_=Depends(caller)):
    db = store.load()
    return db.get("config", {}).get("profile") or {"orgName": "MyCompany", "country": "US",
            "state": "California", "city": "San Francisco", "defaultDays": 90, "domainSuffix": "example.com"}


@router.post("/api/admin/profile")
def save_profile(body: dict, _=Depends(caller)):
    body = body or {}
    try:
        days = int(body.get("defaultDays") or 90)
    except (TypeError, ValueError):
        days = 90
    db = store.load()
    db["config"]["profile"] = {"orgName": body.get("orgName") or "MyCompany",
                               "country": body.get("country") or "US",
                               "state": body.get("state") or "California",
                               "city": body.get("city") or "San Francisco",
                               "defaultDays": days, "domainSuffix": body.get("domainSuffix") or "example.com"}
    store.save(db)
    return {"success": True, "profile": db["config"]["profile"]}


@router.post("/api/admin/parse-cert")
async def parse_cert(request: Request):
    import base64
    try:
        body = await request.json()
    except Exception:
        return err(400, "VALIDATION_ERROR", "Invalid JSON body.")
    content = body.get("content")
    if not content:
        # legacy Node field name from the old UI
        content = body.get("pem")
    if not content:
        return err(400, "VALIDATION_ERROR", "Missing content to inspect.")
    op = uuid.uuid4().hex
    tmp = str(TMP / f"{op}.tmp")
    try:
        data = content
        if isinstance(data, str) and data.startswith("data:") and "base64," in data:
            with open(tmp, "wb") as f:
                f.write(base64.b64decode(data.split("base64,", 1)[1]))
        else:
            with open(tmp, "w", encoding="utf-8") as f:
                f.write(str(data).strip())
        import re as _re
        text_content = str(data)[:4000] if isinstance(data, str) else ""
        if "CERTIFICATE REQUEST" in text_content or body.get("type") == "csr":
            text_out = run("req", "-in", tmp, "-noout", "-text")
            subj_out = run("req", "-in", tmp, "-noout", "-subject")
            return {"success": True, "kind": "Certificate Signing Request (CSR)",
                    "subject": subj_out.strip().replace("subject=", "", 1), "fullText": text_out}
        try:
            text_out = run("x509", "-in", tmp, "-noout", "-text")
        except RuntimeError:
            text_out = run("x509", "-in", tmp, "-inform", "DER", "-noout", "-text")
        grab = lambda p: (_re.search(p, text_out).group(1).strip() if _re.search(p, text_out) else "Unknown")
        san_m = _re.search(r"X509v3 Subject Alternative Name:[^\n]*\n\s*([^\n]+)", text_out)
        ca_m = _re.search(r"CA:(TRUE|FALSE)", text_out, _re.I)
        return {"success": True, "kind": "X.509 Public Certificate",
                "subject": grab(r"Subject:\s*([^\n]+)"), "issuer": grab(r"Issuer:\s*([^\n]+)"),
                "serial": grab(r"Serial Number:\s*([^\n]+)"),
                "validFrom": grab(r"Not Before:\s*([^\n]+)"), "validTo": grab(r"Not After\s*:?\s*([^\n]+)"),
                "sans": san_m.group(1).strip() if san_m else "None",
                "isCA": (ca_m.group(1).upper() == "TRUE") if ca_m else False, "fullText": text_out}
    except RuntimeError as e:
        return err(400, "PARSE_ERROR", "Could not parse certificate/CSR: " + str(e)[:500])
    finally:
        _clean(tmp)
