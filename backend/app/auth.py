"""Session + API-key authentication (same semantics as the Node engine)."""
import hmac
import time
import uuid
from collections import defaultdict

import bcrypt as _bcrypt

from fastapi import Depends, Request

from . import config, store
from .errors import ApiError

sessions: set[str] = set()
_login_hits: dict[str, list[float]] = defaultdict(list)


def rate_limited(ip: str, limit: int = 20, window: int = 60) -> bool:
    now = time.time()
    hits = [t for t in _login_hits[ip] if now - t < window]
    hits.append(now)
    _login_hits[ip] = hits
    return len(hits) > limit


def verify_password(plain: str, hashed: str) -> bool:
    try:
        return _bcrypt.checkpw(plain.encode(), hashed.encode())
    except Exception:
        return False


def hash_password(plain: str) -> str:
    return _bcrypt.hashpw(plain.encode(), _bcrypt.gensalt()).decode()


def find_token(db: dict, api_key: str):
    if not api_key:
        return None
    now = time.time() * 1000
    for t in db.get("apiTokens", []):
        if t.get("revoked"):
            continue
        exp = t.get("expiresAt")
        if exp:
            try:
                from datetime import datetime
                exp_dt = datetime.fromisoformat(str(exp).replace("Z", "+00:00"))
                if exp_dt.timestamp() * 1000 < now:
                    continue
            except Exception:
                pass
        if hmac.compare_digest(str(t.get("token", "")), str(api_key)):
            return t
    return None


def record_usage(token_id: str, cn: str | None = None):
    try:
        db = store.load()
        for t in db.get("apiTokens", []):
            if t.get("id") == token_id:
                t["usageCount"] = (t.get("usageCount") or 0) + 1
                from datetime import datetime, timezone
                t["lastUsedAt"] = datetime.now(timezone.utc).isoformat()
                if cn:
                    t["lastUsedCN"] = cn
                break
        store.save(db)
    except Exception:
        pass  # usage accounting must never break signing


async def caller(request: Request):
    """Dependency: Bearer session OR x-api-key. Sets request.state.api_token."""
    authz = request.headers.get("authorization", "")
    if authz.startswith("Bearer "):
        if authz[7:] in sessions:
            request.state.api_token = None
            return {"type": "session"}
    api_key = request.headers.get("x-api-key", "")
    if api_key:
        db = store.load()
        match = find_token(db, api_key)
        if match:
            request.state.api_token = {"id": match["id"], "name": match.get("name", "")}
            return {"type": "token", **request.state.api_token}
        if config.AUTH_TOKEN and hmac.compare_digest(str(api_key), config.AUTH_TOKEN):
            request.state.api_token = {"id": "env:AUTH_TOKEN", "name": "ENV AUTH_TOKEN"}
            return {"type": "env-token", **request.state.api_token}
    request.state.api_token = None
    raise ApiError(401, "UNAUTHORIZED",
                   "Unauthorized. Please login or provide a valid x-api-key token.",
                   "Login via POST /api/auth/login, or pass a non-revoked API key in x-api-key header.")


def new_session() -> str:
    tok = uuid.uuid4().hex
    sessions.add(tok)
    if len(sessions) > 500:
        sessions.pop()
    return tok
