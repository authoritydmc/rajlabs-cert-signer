"""Public REST signing API: /api/v1/sign, /revoke, /revoke-bulk, /ca/:name/cert."""
import re
from datetime import datetime, timedelta, timezone

from fastapi import APIRouter, Depends, Request

from .. import config, store
from ..auth import caller
from ..errors import ApiError, ca_not_available, err
from ..logging_util import audit, logger
from ..pki import regenerate_crl, sign_leaf

router = APIRouter()


@router.post("/api/v1/sign")
async def sign(body: dict, request: Request, _=Depends(caller)):
    from ..routers.auth import _public_base
    body = body or {}
    csr = body.get("csr")
    if not isinstance(csr, str) or "BEGIN CERTIFICATE REQUEST" not in csr:
        return err(400, "VALIDATION_ERROR",
                   "Missing or invalid csr in request body (expected PEM PKCS#10).")
    san = body.get("san") or []
    san_list = list(san) if isinstance(san, list) else [s.strip() for s in str(san).split(",") if s.strip()]
    hint = {"ca": body.get("ca") or body.get("intermediateId"),
            "purpose": body.get("purpose") or body.get("profile")}
    try:
        token = getattr(request.state, "api_token", None) or {"id": "admin-ui", "name": "Admin UI"}
        result = sign_leaf(csr, san_list[:50], body.get("days") or 90, token, _public_base(request), hint)
        try:
            days_n = int(body.get("days") or 90)
        except (TypeError, ValueError):
            days_n = 90
        audit("cert.issued", {"serial": result["serial"], "cn": san_list[0] if san_list else "",
                              "via": token.get("name")}, request)
        logger.info("cert.issued", {"serial": result["serial"], "via": token.get("name")})
        return {"success": True, "certificate": result["certificate"],
                "chain": result["fullChain"], "fullChain": result["fullChain"],
                "serialNumber": result["serial"], "serial": result["serial"],
                "caName": result["caName"], "caSelection": result["selectionReason"],
                "expiresAt": (datetime.now(timezone.utc) + timedelta(days=days_n)).isoformat()}
    except ApiError as e:
        logger.error("cert.sign_failed", {"error": e.message, "code": e.code})
        if e.code == "CA_NOT_AVAILABLE":
            resp = ca_not_available(hint)
            return resp
        return err(e.status, e.code, e.message, e.hint)


def _do_revoke(db: dict, clean: str, reason: str):
    cert = next((c for c in db.get("certificates", []) if str(c.get("serial")).lower() == clean), None)
    if not cert:
        return None, "missing"
    if cert.get("status") == "revoked":
        return cert, "already"
    cert["status"] = "revoked"
    cert["revokedAt"] = datetime.now(timezone.utc).isoformat()
    cert["revokeReason"] = re.sub(r"[^a-zA-Z0-9_\-]", "", reason or "unspecified")[:64]
    return cert, "revoked"


def _regen(db: dict):
    cas = db.get("intermediateCAs", []) or []
    active = next((c for c in cas if c.get("isActive")), cas[0] if cas else None)
    if not active:
        return False
    try:
        regenerate_crl(active)
        return True
    except Exception as e:
        logger.warn("crl.regen_failed", {"error": str(e)[:500]})
        return False


@router.post("/api/v1/revoke")
async def revoke(body: dict, request: Request, _=Depends(caller)):
    body = body or {}
    if not body.get("serial"):
        return err(400, "VALIDATION_ERROR", "Serial is required.")
    clean = re.sub(r"[^a-fA-F0-9]", "", str(body["serial"])).lower()
    if not clean:
        return err(400, "VALIDATION_ERROR", "Invalid serial format.")
    db = store.load()
    cert, outcome = _do_revoke(db, clean, body.get("reason"))
    if outcome == "missing":
        return err(404, "NOT_FOUND", f"Certificate serial 0x{clean} not found in database.")
    if outcome == "already":
        return {"success": True, "code": "ALREADY_REVOKED",
                "message": f"Certificate 0x{clean} was already revoked."}
    store.save(db)
    crl_ok = _regen(db)
    audit("cert.revoked", {"serial": clean, "reason": cert.get("revokeReason"), "crlOk": crl_ok}, request)
    logger.warn("cert.revoked", {"serial": clean, "reason": cert.get("revokeReason")})
    return {"success": True, "code": "REVOKED",
            "message": f"Certificate 0x{clean} revoked and CRL updated.", "crlRegenerated": crl_ok}


@router.post("/api/v1/revoke-bulk")
async def revoke_bulk(body: dict, request: Request, _=Depends(caller)):
    body = body or {}
    serials = body.get("serials")
    if not isinstance(serials, list) or not serials:
        return err(400, "VALIDATION_ERROR", "serials[] array is required.")
    if len(serials) > 200:
        return err(400, "VALIDATION_ERROR", "Max 200 serials per bulk request.")
    db = store.load()
    revoked, already, missing = 0, [], []
    for s in serials:
        clean = re.sub(r"[^a-fA-F0-9]", "", str(s)).lower()
        _, outcome = _do_revoke(db, clean, body.get("reason"))
        if outcome == "revoked":
            revoked += 1
        elif outcome == "already":
            already.append(clean)
        else:
            missing.append(str(s))
    store.save(db)
    crl_ok = _regen(db) if revoked else False
    audit("cert.bulk_revoked", {"revoked": revoked, "notFound": len(missing), "already": len(already)}, request)
    logger.warn("cert.bulk_revoked", {"revoked": revoked})
    return {"success": True, "code": "BULK_REVOKED", "revoked": revoked,
            "alreadyRevoked": already, "notFound": missing, "crlRegenerated": crl_ok}


@router.delete("/api/v1/certificates/{serial}")
@router.delete("/api/admin/certificates/{serial}")
async def revoke_by_delete(serial: str, request: Request, _=Depends(caller)):
    """RESTful revoke: DELETE marks the cert revoked and regenerates the CRL.

    Soft-delete by design — the record is kept (status=revoked) so the
    serial stays listed in the CRL. Reason via ?reason= query param
    (optional JSON body {reason} also accepted). Idempotent: re-deleting
    an already-revoked cert returns ALREADY_REVOKED.
    """
    reason = request.query_params.get("reason") or "unspecified"
    try:
        body = await request.json()
        if isinstance(body, dict) and body.get("reason"):
            reason = body["reason"]
    except Exception:
        pass
    clean = re.sub(r"[^a-fA-F0-9]", "", str(serial or "")).lower()
    if not clean:
        return err(400, "VALIDATION_ERROR", "Invalid serial format.")
    db = store.load()
    cert, outcome = _do_revoke(db, clean, reason)
    if outcome == "missing":
        return err(404, "NOT_FOUND", f"Certificate serial 0x{clean} not found in database.")
    if outcome == "already":
        return {"success": True, "code": "ALREADY_REVOKED",
                "message": f"Certificate 0x{clean} was already revoked."}
    store.save(db)
    crl_ok = _regen(db)
    audit("cert.revoked", {"serial": clean, "reason": cert.get("revokeReason"),
                           "crlOk": crl_ok, "via": "delete"}, request)
    logger.warn("cert.revoked", {"serial": clean, "reason": cert.get("revokeReason")})
    return {"success": True, "code": "REVOKED",
            "message": f"Certificate 0x{clean} revoked and CRL updated.", "crlRegenerated": crl_ok}


@router.get("/api/v1/ca/{name}/cert")
def ca_cert(name: str):
    db = store.load()
    cas = db.get("intermediateCAs", []) or []
    ca = next((c for c in cas if c.get("name") == name), None) or \
        next((c for c in cas if c.get("isActive")), cas[0] if cas else None)
    if not ca:
        return ca_not_available(None)
    from fastapi.responses import PlainTextResponse
    return PlainTextResponse(f"{ca['certPem'].strip()}\n{ca['rootCertPem'].strip()}\n",
                             media_type="application/x-x509-ca-cert")
