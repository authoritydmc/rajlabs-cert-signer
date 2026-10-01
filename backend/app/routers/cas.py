"""Intermediate CA management."""
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from .. import store, vault
from ..auth import caller
from ..errors import err
from ..logging_util import audit, logger

router = APIRouter()


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


@router.get("/api/admin/intermediate-cas")
def list_cas(_=Depends(caller)):
    db = store.load()
    return [{"id": c.get("id"), "name": c.get("name"), "description": c.get("description"),
             "certPem": c.get("certPem"), "rootCertPem": c.get("rootCertPem"),
             "isActive": bool(c.get("isActive")), "hasKey": bool(c.get("encryptedKeyPem"))}
            for c in db.get("intermediateCAs", [])]


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
