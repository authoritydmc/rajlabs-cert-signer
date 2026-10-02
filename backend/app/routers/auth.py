"""Auth + first-run onboarding wizard (multi-intermediate generation)."""
import re
import uuid
from datetime import datetime, timezone

from fastapi import APIRouter, Depends, Request

from .. import config, store, vault
from .. import store as _store
from ..auth import caller, hash_password, new_session, rate_limited, verify_password
from ..errors import ApiError, err
from ..logging_util import audit, logger
from ..pki import TMP, _clean, run

router = APIRouter()


def _iso_now():
    return datetime.now(timezone.utc).isoformat()


@router.get("/api/auth/setup-status")
def setup_status(request: Request):
    db = store.load()
    payload = {"isFirstRun": bool(db.get("config", {}).get("isFirstRun")),
               "basePath": config.BASE_PATH, "baseUrl": _public_base(request),
               "adminUser": db.get("config", {}).get("adminUser") or config.ADMIN_USER}
    if db.get("config", {}).get("isFirstRun"):
        payload["initialPassword"] = db["config"].get("temporaryInitialPassword")
    return payload


def _public_base(request: Request) -> str:
    if config.BASE_URL_FROM_ENV:
        return config.BASE_URL
    proto = (request.headers.get("x-forwarded-proto") or request.url.scheme or "http").split(",")[0].strip()
    host = (request.headers.get("x-forwarded-host") or request.headers.get("host") or f"localhost:{config.PORT}").split(",")[0].strip()
    return f"{proto}://{host}{config.BASE_PATH}".rstrip("/") or config.BASE_URL


@router.post("/api/auth/complete-setup")
def complete_setup():
    db = store.load()
    db["config"]["isFirstRun"] = False
    db["config"]["hasCompletedSetup"] = True
    db["config"].pop("temporaryInitialPassword", None)
    store.save(db)
    return {"success": True}


def _clean_name(v: str, pattern: str, default: str, lower=False, maxlen=64) -> str:
    s = re.sub(pattern, "", v or "")
    if lower:
        s = s.lower()
    return (s.strip() or default)[:maxlen]


@router.post("/api/auth/onboarding-generate-pki")
def onboarding_generate_pki(body: dict, request: Request):
    """Generate Root once + N intermediates. Returns root key ONCE + per-CA bundles."""
    body = body or {}
    db = store.load()
    org = _clean_name(body.get("orgName"), r"[^a-zA-Z0-9\s.\-_]", "Enterprise")
    country = re.sub(r"[^a-zA-Z]", "", body.get("country") or "US")[:2].upper() or "US"
    state = _clean_name(body.get("state"), r"[^a-zA-Z0-9\s.\-_]", "California")
    city = _clean_name(body.get("city"), r"[^a-zA-Z0-9\s.\-_]", "San Francisco")
    key_bits = str(body.get("keySize") or body.get("keyBits") or "4096")
    if key_bits not in ("2048", "3072", "4096"):
        return err(400, "VALIDATION_ERROR", "keySize must be one of 2048, 3072, 4096.")
    try:
        root_days = max(365, min(10950, int(body.get("rootDays") or 7300)))
        int_days = max(365, min(5475, int(body.get("intDays") or body.get("intermediateDays") or 3650)))
    except (TypeError, ValueError):
        return err(400, "VALIDATION_ERROR", "rootDays / intDays must be numbers.")

    # Intermediate list: explicit array wins, else legacy single field.
    raw_list = body.get("intermediates") or ([body.get("intermediateName")] if body.get("intermediateName") else None) \
        or ["int-server"]
    names = []
    for n in raw_list:
        c = re.sub(r"[^a-z0-9\-_]", "", str(n or "").lower()).strip()
        if c and c not in names:
            names.append(c)
    names = names[:5]
    if not names:
        return err(400, "VALIDATION_ERROR", "At least one intermediate CA name is required.")

    op = uuid.uuid4().hex
    root_key, root_crt = str(TMP / f"{op}-root.key"), str(TMP / f"{op}-root.crt")
    ext_f = str(TMP / f"{op}-ext.cnf")
    made = [root_key, root_crt, ext_f]
    try:
        run("genrsa", "-out", root_key, key_bits)
        run("req", "-new", "-x509", "-days", str(root_days), "-sha256",
            "-key", root_key, "-out", root_crt,
            "-subj", f"/C={country}/ST={state}/L={city}/O={org}/OU={org} Root Authority/CN={org} Root CA")
        with open(root_key, encoding="utf-8") as f:
            root_key_pem = f.read()
        with open(root_crt, encoding="utf-8") as f:
            root_cert_pem = f.read()
        with open(ext_f, "w", encoding="utf-8") as f:
            f.write("basicConstraints = critical, CA:true, pathlen:0\n"
                    "keyUsage = critical, digitalSignature, cRLSign, keyCertSign\n"
                    "subjectKeyIdentifier = hash\nauthorityKeyIdentifier = keyid:always,issuer\n")

        results = []
        for idx, name in enumerate(names):
            ik, ic, icrt = (str(TMP / f"{op}-{idx}.key"), str(TMP / f"{op}-{idx}.csr"),
                            str(TMP / f"{op}-{idx}.crt"))
            made += [ik, ic, icrt]
            run("genrsa", "-out", ik, key_bits)
            run("req", "-new", "-sha256", "-key", ik, "-out", ic,
                "-subj", f"/C={country}/ST={state}/L={city}/O={org}/OU={org} Infrastructure/CN={org} {name} CA")
            run("x509", "-req", "-in", ic, "-CA", root_crt, "-CAkey", root_key,
                "-CAcreateserial", "-out", icrt, "-days", str(int_days), "-sha256", "-extfile", ext_f)
            with open(ik, encoding="utf-8") as f:
                int_key = f.read()
            with open(icrt, encoding="utf-8") as f:
                int_cert = f.read()
            results.append({"name": name, "certPem": int_cert, "keyPem": int_key})
        made.append(str(TMP / f"{op}-root.srl"))
    except RuntimeError as e:
        _clean(*made)
        msg = str(e)
        logger.error("pki.generate_failed", {"error": msg})
        return err(500, "INTERNAL_ERROR", "Failed to generate PKI. Please try again or contact your administrator.",
                   "Certificate engine temporarily unavailable. Please try again or contact your administrator.")
    finally:
        _clean(*made)  # root key shredded from disk; only the response carries it

    db = store.load()
    for c in db.get("intermediateCAs", []):
        c["isActive"] = False
    stored = []
    for i, r in enumerate(results):
        entry = {"id": uuid.uuid4().hex, "name": r["name"],
                 "description": f"{org} {'Primary' if i == 0 else 'Secondary'} Signer",
                 "certPem": r["certPem"].strip(),
                 "encryptedKeyPem": vault.encrypt(r["keyPem"].strip()),
                 "rootCertPem": root_cert_pem.strip(),
                 "isActive": i == 0, "createdAt": _iso_now()}
        db["intermediateCAs"].append(entry)
        stored.append({"id": entry["id"], "name": entry["name"],
                       "certPem": r["certPem"], "keyPem": r["keyPem"],
                       "chainPem": f"{r['certPem'].strip()}\n{root_cert_pem.strip()}\n"})
    db["config"]["profile"] = {"orgName": org, "country": country, "state": state, "city": city,
                               "defaultDays": 90,
                               "domainSuffix": f"{re.sub(r'\s+', '', org.lower())}.local"}
    store.save(db)
    audit("pki.onboarded", {"org": org, "cas": names, "keyBits": key_bits}, request)
    logger.info("pki.onboarded", {"org": org, "cas": names})
    # Generate initial CRL for the first (active) CA so status shows "Active" immediately
    first_entry = next((c for c in db.get("intermediateCAs", []) if c.get("isActive")), None)
    if first_entry and first_entry.get("encryptedKeyPem"):
        try:
            from ..pki import regenerate_crl
            regenerate_crl(first_entry)
            logger.info("crl.initial_generated", {"ca": first_entry["name"]})
        except Exception as crl_err:
            logger.warn("crl.initial_failed", {"error": str(crl_err)[:300]})
    first = stored[0]
    return {"success": True, "rootCertPem": root_cert_pem, "rootKeyPem": root_key_pem,
            "intCertPem": first["certPem"], "intKeyPem": first["keyPem"],
            "caChainPem": first["chainPem"], "caName": first["name"],
            "intermediates": stored, "keyBits": key_bits,
            "rootDays": root_days, "intDays": int_days}


@router.post("/api/auth/login")
def login(body: dict, request: Request):
    if rate_limited(request.client.host if request.client else "unknown"):
        return err(429, "RATE_LIMITED", "Too many login attempts. Try again in a minute.")
    body = body or {}
    username, password = body.get("username"), body.get("password")
    if not username or not password:
        return err(400, "VALIDATION_ERROR", "username and password are required.")
    db = store.load()
    expected = db.get("config", {}).get("adminUser") or config.ADMIN_USER
    hashed = db.get("config", {}).get("adminPasswordHash")
    if not hashed:
        return err(503, "AUTH_NOT_INITIALIZED",
                   "Admin credentials are not initialized yet. Please contact your administrator.",
                   "If you manage this service, set the admin password in your hosting environment and restart the service.")
    if username == expected and verify_password(str(password), hashed):
        tok = new_session()
        audit("auth.login_ok", {"user": expected}, request)
        logger.info("auth.login_ok", {"user": expected})
        return {"success": True, "token": tok, "username": expected}
    audit("auth.login_failed", {"user": username}, request)
    logger.warn("auth.login_failed", {"user": username})
    return err(401, "INVALID_CREDENTIALS", "Invalid admin username or password.",
               "Please verify your credentials or contact your administrator.")


@router.get("/api/auth/me")
def me(request: Request, _=Depends(caller)):
    db = store.load()
    return {"success": True, "username": db.get("config", {}).get("adminUser") or "admin",
            "basePath": config.BASE_PATH, "baseUrl": _public_base(request)}


@router.post("/api/auth/logout")
def logout(request: Request):
    authz = request.headers.get("authorization", "")
    if authz.startswith("Bearer "):
        _store.session_del(authz[7:])
    return {"success": True}


def init_admin_auth():
    from ..auth import hash_password as _hp
    db = store.load()
    db["config"]["adminUser"] = config.ADMIN_USER or db["config"].get("adminUser") or "admin"
    if config.ADMIN_PASSWORD:
        db["config"]["adminPasswordHash"] = _hp(config.ADMIN_PASSWORD)
        if not db["config"].get("hasCompletedSetup"):
            db["config"]["isFirstRun"] = True
            db["config"]["temporaryInitialPassword"] = config.ADMIN_PASSWORD
        store.save(db)
        logger.info("auth.admin_password_from_env", {"user": db["config"]["adminUser"]})
    elif not db["config"].get("adminPasswordHash"):
        import secrets
        pw = secrets.token_urlsafe(24)
        db["config"]["adminPasswordHash"] = _hp(pw)
        db["config"]["isFirstRun"] = True
        db["config"]["temporaryInitialPassword"] = pw
        store.save(db)
        notice = ("=" * 58 + "\n ENTERPRISE CERTIFICATE SIGNER - ADMIN CREDENTIALS\n" + "=" * 58 +
                  f"\n User: {db['config']['adminUser']}\n Password: {pw}\n Saved: {config.CREDENTIALS_FILE}\n" + "=" * 58 + "\n")
        try:
            config.CREDENTIALS_FILE.write_text(notice, encoding="utf-8")
        except Exception:
            pass
        logger.info("auth.admin_autogenerated", {"user": db["config"]["adminUser"]})
