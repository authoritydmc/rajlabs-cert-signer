"""Enterprise PKI Certificate Signer - FastAPI backend (same API contract as v1 Node engine)."""
import time
import uuid
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, JSONResponse, FileResponse
from fastapi.staticfiles import StaticFiles

from . import config
from .errors import ApiError
from .logging_util import logger
from .routers import auth as auth_router
from .routers import cas as cas_router
from .routers import certs as certs_router
from .routers import public as public_router
from .routers import sign as sign_router
from .routers import tokens as tokens_router
from .routers.auth import init_admin_auth

app = FastAPI(title="Enterprise PKI Certificate Signer", version="2.0.0",
              docs_url="/docs", redoc_url="/redoc")


@app.exception_handler(ApiError)
async def _api_error(request: Request, exc: ApiError):
    body = {"success": False, "code": exc.code, "error": exc.message}
    if exc.hint:
        body["hint"] = exc.hint
    body.update(exc.extra or {})
    return JSONResponse(status_code=exc.status, content=body)


@app.middleware("http")
async def _middleware(request: Request, call_next):
    # Strip BASE_PATH so /cert-signer/api/... routes like /api/...
    if config.BASE_PATH:
        if request.url.path == config.BASE_PATH or request.url.path.startswith(config.BASE_PATH + "/"):
            scope = request.scope
            stripped = scope["path"][len(config.BASE_PATH):] or "/"
            scope["path"] = stripped
            # Starlette caches route path in root_path-aware manner; raw_path too
            if scope.get("raw_path"):
                scope["raw_path"] = scope["raw_path"][len(config.BASE_PATH.encode()):] or b"/"
    request.state.req_id = uuid.uuid4().hex[:16]
    start = time.time()
    try:
        resp = await call_next(request)
    except ApiError as e:
        resp = await _api_error(request, e)
    ms = int((time.time() - start) * 1000)
    lvl = "error" if resp.status_code >= 500 else ("warn" if resp.status_code >= 400 else "debug")
    getattr(logger, lvl)("http", {"reqId": request.state.req_id, "method": request.method,
                                  "path": request.url.path, "status": resp.status_code, "ms": ms})
    return resp


# CORS for backend.rajlabs.in admin tab polling /api/v1/status.
@app.middleware("http")
async def _cors(request: Request, call_next):
    if request.method == "OPTIONS":
        return JSONResponse(status_code=204, content=None, headers={
            "Access-Control-Allow-Origin": config.CORS_ORIGIN,
            "Access-Control-Allow-Headers": "Content-Type, Authorization, x-api-key",
            "Access-Control-Allow-Methods": "GET,POST,DELETE,OPTIONS"})
    resp = await call_next(request)
    resp.headers["Access-Control-Allow-Origin"] = config.CORS_ORIGIN
    return resp


for _r in (auth_router.router, cas_router.router, certs_router.router,
           sign_router.router, public_router.router, tokens_router.router):
    app.include_router(_r)

STATIC_DIR = Path(__file__).resolve().parent / "static"
STATIC_DIR.mkdir(parents=True, exist_ok=True)

if (STATIC_DIR / "assets").exists() or (STATIC_DIR / "index.html").exists():
    app.mount("/assets", StaticFiles(directory=str(STATIC_DIR / "assets"))
              if (STATIC_DIR / "assets").exists() else StaticFiles(directory=str(STATIC_DIR)),
              name="assets")


def _spa_html() -> str:
    idx = STATIC_DIR / "index.html"
    if not idx.exists():
        return ("<html><body style='background:#020617;color:#e2e8f0;font-family:sans-serif'>"
                "<h2>Enterprise PKI Signer API</h2><p>UI bundle not built yet. "
                "API is live: <a href='/docs'>/docs</a> - <a href='/api/v1/status'>/api/v1/status</a></p>"
                "</body></html>")
    html = idx.read_text(encoding="utf-8")
    import json as _json
    # <base> keeps relative asset URLs working from any route (/onboarding,
    # /cert-signer/onboarding, ...). Trailing slash is required.
    base_href = (config.BASE_PATH or "/").rstrip("/") + "/"
    inject = (f"<base href=\"{base_href}\">"
              f"<script>window.__PKI_BASE_PATH__={_json.dumps(config.BASE_PATH)};"
              f"window.__PKI_BASE_URL__={_json.dumps(config.BASE_URL)};</script>")
    return html.replace("</head>", f"  {inject}\n</head>")


@app.get("/favicon.ico", include_in_schema=False)
@app.get("/favicon.svg", include_in_schema=False)
async def _favicon():
    for name in ("favicon.svg", "favicon.ico"):
        p = STATIC_DIR / name
        if p.exists():
            mt = "image/svg+xml" if name.endswith(".svg") else "image/x-icon"
            return FileResponse(p, media_type=mt)
    return JSONResponse(status_code=404, content={"detail": "Favicon not found"})


@app.get("/", include_in_schema=False)
@app.get("/index.html", include_in_schema=False)
@app.get("/onboarding", include_in_schema=False)
async def _index():
    return HTMLResponse(_spa_html())


@app.get("/{full_path:path}", include_in_schema=False)
async def _spa_fallback(full_path: str):
    first_seg = full_path.split("?")[0].split("/")[0]
    if first_seg in ("api", "acme", "certs", "crl", "health", "docs", "ocsp",
                     "redoc", "openapi.json", "assets", "onboarding",
                     "install-trust-windows.ps1", "install-trust-linux.sh") or \
       full_path.endswith((".crl", ".crt", ".pem", ".key", ".sh", ".ps1")):
        return JSONResponse(status_code=404, content={"success": False, "code": "NOT_FOUND",
                                                      "error": "Not found."})
    return HTMLResponse(_spa_html())



_REQUIRED_PREFIXES = ("/api/auth/login", "/api/admin/tokens", "/api/admin/intermediate-cas",
                      "/api/admin/certificates", "/api/v1/sign", "/api/v1/revoke", "/api/v1/status", "/health")


def _registered_paths() -> set:
    # app.openapi() forces expansion of lazy _IncludedRouter wrappers (FastAPI >= 0.135).
    try:
        return set(app.openapi().get("paths", {}).keys())
    except Exception as e:
        logger.warn("server.openapi_probe_failed", {"error": str(e)[:200]})
        return {getattr(r, "path", "") for r in app.routes if getattr(r, "path", None)}


@app.on_event("startup")
def _startup():
    paths = _registered_paths()
    missing = [p for p in _REQUIRED_PREFIXES if p not in paths]
    if missing:
        logger.error("server.routes_missing", {"missing": missing})
        raise RuntimeError(f"Missing required routes: {missing} - a router was not included!")
    logger.info("server.routes_ok", {"count": len(paths)})
    init_admin_auth()
    logger.info("server.start", {"port": config.PORT, "baseUrl": config.BASE_URL,
                                 "basePath": config.BASE_PATH or "/", "dataDir": str(config.DATA_DIR),
                                 "logLevel": config.LOG_LEVEL})
    logger.info("server.ready", {"health": "/health", "status": "/api/v1/status", "ui": "/"})
    # Bootstrap CRL for the active CA so the status endpoint never shows "missing"
    # right after a fresh PKI generation. Runs in a thread so it doesn't block startup.
    import threading
    def _bootstrap_crl():
        try:
            from . import store as _store
            from .pki import regenerate_crl
            db = _store.load()
            active = next((c for c in db.get("intermediateCAs", []) if c.get("isActive")), None)
            if active and active.get("encryptedKeyPem"):
                crl_f = config.CRL_DIR / f"{active['name']}.crl"
                if not crl_f.exists():
                    regenerate_crl(active)
                    logger.info("crl.bootstrapped", {"ca": active["name"]})
        except Exception as exc:
            logger.warn("crl.bootstrap_failed", {"error": str(exc)[:300]})
    threading.Thread(target=_bootstrap_crl, daemon=True).start()


def run():
    import uvicorn
    uvicorn.run("app.main:app", host="0.0.0.0", port=config.PORT, workers=1)
