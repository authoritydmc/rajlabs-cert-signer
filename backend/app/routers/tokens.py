"""API token management: usage analytics, revoke/restore/delete, bulk."""
import secrets
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from .. import store
from ..auth import caller
from ..errors import err
from ..logging_util import audit, logger

router = APIRouter()


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


def _stats(db: dict, token_id: str):
    certs = [c for c in db.get("certificates", []) if c.get("issuedViaTokenId") == token_id]
    first = certs[0] if certs else None
    return {"count": len(certs),
            "last_cn": (first or {}).get("commonName") if first else None,
            "last_at": (first or {}).get("issuedAt") if first else None}


def sanitize(db: dict, t: dict):
    s = _stats(db, t.get("id", ""))
    expired = False
    if t.get("expiresAt"):
        try:
            exp = datetime.fromisoformat(str(t["expiresAt"]).replace("Z", "+00:00"))
            expired = exp.timestamp() < datetime.now(timezone.utc).timestamp()
        except Exception:
            pass
    status = "revoked" if t.get("revoked") else ("expired" if expired else "active")
    return {"id": t.get("id"), "name": t.get("name"), "token": t.get("token"),
            "createdAt": t.get("createdAt"), "expiresAt": t.get("expiresAt"),
            "revoked": bool(t.get("revoked")), "revokedAt": t.get("revokedAt"),
            "expired": expired, "status": status,
            "scopes": t.get("scopes") or ["sign", "revoke"],
            "usageCount": t.get("usageCount", s["count"]),
            "lastUsedAt": t.get("lastUsedAt") or s["last_at"],
            "lastUsedCN": t.get("lastUsedCN") or s["last_cn"],
            "certsIssued": s["count"]}


@router.get("/api/admin/tokens")
def list_tokens(_=Depends(caller)):
    db = store.load()
    return [sanitize(db, t) for t in db.get("apiTokens", [])]


@router.post("/api/admin/tokens")
def create_token(body: dict, request: Request, _=Depends(caller)):
    body = body or {}
    name = str(body.get("name") or "API Token").strip()[:100]
    if len(str(body.get("name") or "")) > 100:
        return err(400, "VALIDATION_ERROR", "Token name too long (max 100 chars).")
    scopes = [s for s in (body.get("scopes") or ["sign", "revoke"]) if s in ("sign", "revoke")] or ["sign", "revoke"]
    t = {"id": uuid.uuid4().hex, "name": name or "API Token",
         "token": "cert_" + secrets.token_hex(24), "scopes": scopes,
         "expiresAt": body.get("expiresAt"), "revoked": False,
         "usageCount": 0, "lastUsedAt": None, "lastUsedCN": None,
         "createdAt": _iso_now()}
    db = store.load()
    db["apiTokens"].append(t)
    store.save(db)
    audit("token.created", {"id": t["id"], "name": t["name"]}, request)
    logger.info("token.created", {"id": t["id"], "name": t["name"]})
    return {"success": True, "token": sanitize(db, t)}


@router.get("/api/admin/tokens/{token_id}/usage")
def token_usage(token_id: str, _=Depends(caller)):
    db = store.load()
    t = next((x for x in db.get("apiTokens", []) if x.get("id") == token_id), None)
    if not t:
        return err(404, "NOT_FOUND", "API token not found.")
    certs = [c for c in db.get("certificates", []) if c.get("issuedViaTokenId") == token_id]
    return {"success": True, "token": sanitize(db, t), "certificates": certs}


@router.post("/api/admin/tokens/{token_id}/revoke")
def revoke_token(token_id: str, request: Request, _=Depends(caller)):
    db = store.load()
    t = next((x for x in db.get("apiTokens", []) if x.get("id") == token_id), None)
    if not t:
        return err(404, "NOT_FOUND", "API token not found.")
    t["revoked"] = True
    t["revokedAt"] = _iso_now()
    store.save(db)
    audit("token.revoked", {"id": t["id"], "name": t["name"]}, request)
    logger.warn("token.revoked", {"id": t["id"], "name": t["name"]})
    return {"success": True, "token": sanitize(db, t)}


@router.post("/api/admin/tokens/{token_id}/restore")
def restore_token(token_id: str, request: Request, _=Depends(caller)):
    db = store.load()
    t = next((x for x in db.get("apiTokens", []) if x.get("id") == token_id), None)
    if not t:
        return err(404, "NOT_FOUND", "API token not found.")
    t["revoked"] = False
    t.pop("revokedAt", None)
    store.save(db)
    audit("token.restored", {"id": t["id"], "name": t["name"]}, request)
    return {"success": True, "token": sanitize(db, t)}


@router.delete("/api/admin/tokens/{token_id}")
def delete_token(token_id: str, request: Request, _=Depends(caller)):
    db = store.load()
    if not any(x.get("id") == token_id for x in db.get("apiTokens", [])):
        return err(404, "NOT_FOUND", "API token not found.")
    db["apiTokens"] = [x for x in db.get("apiTokens", []) if x.get("id") != token_id]
    store.save(db)
    audit("token.deleted", {"id": token_id}, request)
    return {"success": True}


@router.post("/api/admin/tokens/bulk")
def bulk_tokens(body: dict, request: Request, _=Depends(caller)):
    body = body or {}
    ids, action = body.get("ids"), body.get("action")
    if not isinstance(ids, list) or not ids:
        return err(400, "VALIDATION_ERROR", "ids[] array is required.")
    if action not in ("revoke", "restore", "delete"):
        return err(400, "VALIDATION_ERROR", "action must be revoke|restore|delete.")
    db = store.load()
    affected = 0
    if action == "delete":
        before = len(db.get("apiTokens", []))
        db["apiTokens"] = [x for x in db.get("apiTokens", []) if x.get("id") not in ids]
        affected = before - len(db.get("apiTokens", []))
    else:
        for t in db.get("apiTokens", []):
            if t.get("id") in ids:
                if action == "revoke" and not t.get("revoked"):
                    t["revoked"] = True
                    t["revokedAt"] = _iso_now()
                    affected += 1
                elif action == "restore" and t.get("revoked"):
                    t["revoked"] = False
                    t.pop("revokedAt", None)
                    affected += 1
    store.save(db)
    audit("token.bulk", {"action": action, "affected": affected}, request)
    logger.info("token.bulk", {"action": action, "affected": affected})
    return {"success": True, "action": action, "affected": affected}


@router.get("/api/v1/tokens/verify")
@router.post("/api/v1/tokens/verify")
def verify_token_endpoint(request: Request, _=Depends(caller)):
    """Verify an API token or session is valid and return token metadata and scopes."""
    token_meta = getattr(request.state, "api_token", None) or {"id": "session", "name": "Admin Session"}
    return {
        "success": True,
        "valid": True,
        "mode": "token" if token_meta.get("id") != "session" else "session",
        "tokenId": token_meta.get("id"),
        "tokenName": token_meta.get("name"),
        "time": _iso_now()
    }

