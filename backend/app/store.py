"""Document store with two backends behind one interface.

- **json** (default, zero-config): single ``database.json`` — same schema as v1.
- **sql** (when ``DATABASE_URL`` is set): real relational tables (Postgres in
  production via ``postgres://…``, SQLite file for tests via ``sqlite://…``).
  Same dict shape in/out, so routers are backend-agnostic.

Backend is chosen once at import. If the SQL database is unreachable at
startup we log loudly and STICK to JSON for the process lifetime (never flip
mid-run — that would split-brain the data). ``/api/admin/health-detail``
and ``/api/v1/status`` always report which backend is active.
"""
import json
import os
import tempfile
import threading
import time

from . import config

_lock = threading.RLock()  # re-entrant: load() may call save() for first-boot init

_DEFAULTS = {"config": {}, "intermediateCAs": [], "apiTokens": [],
             "certificates": [], "serial": 2000}

backend_name = "json"
_pg = None  # set to _SqlBackend instance when active


# --------------------------------------------------------------------------
# JSON backend (zero-config)
# --------------------------------------------------------------------------
def _json_load() -> dict:
    with _lock:
        if not config.DB_FILE.exists():
            _json_save(_DEFAULTS)
            return json.loads(json.dumps(_DEFAULTS))
        try:
            data = json.loads(config.DB_FILE.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        for k, v in _DEFAULTS.items():
            data.setdefault(k, v if not isinstance(v, (dict, list)) else json.loads(json.dumps(v)))
        return data


def _json_save(data: dict) -> None:
    with _lock:
        fd, tmp = tempfile.mkstemp(dir=str(config.DATA_DIR), suffix=".tmp")
        try:
            with os.fdopen(fd, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
            os.replace(tmp, config.DB_FILE)
        except BaseException:
            try:
                os.unlink(tmp)
            except Exception:
                pass
            raise


# --------------------------------------------------------------------------
# SQL backend (Postgres / SQLite) — SQLAlchemy Core, portable column types
# --------------------------------------------------------------------------
def _sql_url() -> str:
    raw = (config.DATABASE_URL or os.getenv("POSTGRES_URL") or os.getenv("POSTGRESQL_URL") or "").strip()
    if not raw:
        pg_host = os.getenv("POSTGRES_HOST")
        pg_db = os.getenv("POSTGRES_DB")
        if pg_host and pg_db:
            user = os.getenv("POSTGRES_USER", "postgres")
            pw = os.getenv("POSTGRES_PASSWORD", "")
            port = os.getenv("POSTGRES_PORT", "5432")
            raw = f"postgresql://{user}:{pw}@{pg_host}:{port}/{pg_db}"
        else:
            # Fallback to sqlite if postgres is not provided via environment
            sqlite_file = os.getenv("SQLITE_PATH") or (config.DATA_DIR / "cert_signer.db")
            raw = f"sqlite:///{sqlite_file}"

    if raw.startswith("postgres://"):
        raw = "postgresql+psycopg://" + raw[len("postgres://"):]
    elif raw.startswith("postgresql://") and "+" not in raw.split("://")[0]:
        raw = "postgresql+psycopg://" + raw[len("postgresql://"):]
    return raw


class _SqlBackend:
    def __init__(self, url: str):
        from sqlalchemy import (Boolean, Column, Integer, MetaData, String, Table, Text,
                                create_engine, delete, insert, select)
        self._sa = __import__("sqlalchemy")
        scheme = url.split("://")[0]
        kwargs = {"pool_pre_ping": True}
        if scheme.startswith("sqlite"):
            kwargs["connect_args"] = {"check_same_thread": False, "timeout": 30}
        else:
            kwargs.update(pool_size=5, max_overflow=10, pool_recycle=300)
        self.engine = create_engine(url, future=True, **kwargs)
        md = MetaData()
        self.kv = Table("kv_config", md, Column("key", String(64), primary_key=True),
                        Column("value", Text, nullable=False))
        self.cas = Table("intermediate_cas", md,
                         Column("id", String(64), primary_key=True),
                         Column("name", String(64), nullable=False, unique=True),
                         Column("description", Text, default=""),
                         Column("cert_pem", Text, nullable=False),
                         Column("encrypted_key_pem", Text, nullable=False),
                         Column("root_cert_pem", Text, nullable=False),
                         Column("is_active", Boolean, default=False),
                         Column("created_at", String(64), default=""))
        self.toks = Table("api_tokens", md,
                          Column("id", String(64), primary_key=True),
                          Column("name", String(128), nullable=False),
                          Column("token", String(256), nullable=False, unique=True),
                          Column("scopes", Text, default='["sign", "revoke"]'),
                          Column("expires_at", String(64), nullable=True),
                          Column("revoked", Boolean, default=False),
                          Column("revoked_at", String(64), nullable=True),
                          Column("usage_count", Integer, default=0),
                          Column("last_used_at", String(64), nullable=True),
                          Column("last_used_cn", String(256), nullable=True),
                          Column("created_at", String(64), default=""))
        self.certs = Table("certificates", md,
                           Column("id", String(64), primary_key=True),
                           Column("serial", String(64), nullable=False, unique=True),
                           Column("ca_name", String(64), default=""),
                           Column("ca_selection", String(128), default=""),
                           Column("common_name", String(256), default=""),
                           Column("san_domains", Text, default="[]"),
                           Column("days", Integer, default=90),
                           Column("issued_at", String(64), default=""),
                           Column("expires_at", String(64), nullable=True),
                           Column("fingerprint", String(128), nullable=True),
                           Column("status", String(32), default="valid"),
                           Column("revoked_at", String(64), nullable=True),
                           Column("revoke_reason", String(64), nullable=True),
                           Column("renewed_at", String(64), nullable=True),
                           Column("superseded_by", String(64), nullable=True),
                           Column("via_token_id", String(64), nullable=True),
                           Column("via_token_name", String(256), nullable=True))
        self.audit = Table("audit_log", md,
                           Column("id", Integer, primary_key=True, autoincrement=True),
                           Column("ts", String(64), nullable=False),
                           Column("event", String(64), nullable=False),
                           Column("ip", String(128), default=""),
                           Column("actor", String(256), default=""),
                           Column("details", Text, default="{}"))
        self.sessions = Table("sessions", md,
                              Column("token", String(128), primary_key=True),
                              Column("created_at", String(64), nullable=False))
        md.create_all(self.engine)
        self._t = {"delete": delete, "insert": insert, "select": select}

    # -- document mapping -------------------------------------------------
    def load(self) -> dict:
        from sqlalchemy import select as _select
        doc = {"config": {}, "intermediateCAs": [], "apiTokens": [],
               "certificates": [], "serial": 2000}
        with self.engine.begin() as c:
            for k in ("config", "serial"):
                row = c.execute(_select(self.kv.c.value).where(self.kv.c.key == k)).first()
                if row:
                    try:
                        doc[k] = json.loads(row[0])
                    except Exception:
                        pass
            doc["intermediateCAs"] = [{
                "id": r.id, "name": r.name, "description": r.description or "",
                "certPem": r.cert_pem, "encryptedKeyPem": r.encrypted_key_pem,
                "rootCertPem": r.root_cert_pem, "isActive": bool(r.is_active),
                "createdAt": r.created_at or ""} for r in
                c.execute(_select(self.cas)).mappings()]
            doc["apiTokens"] = [{
                "id": r.id, "name": r.name, "token": r.token,
                "scopes": _jload(r.scopes, ["sign", "revoke"]), "expiresAt": r.expires_at,
                "revoked": bool(r.revoked), "revokedAt": r.revoked_at,
                "usageCount": r.usage_count or 0, "lastUsedAt": r.last_used_at,
                "lastUsedCN": r.last_used_cn, "createdAt": r.created_at or ""} for r in
                c.execute(_select(self.toks)).mappings()]
            doc["certificates"] = [{
                "id": r.id, "serial": r.serial, "caName": r.ca_name or "",
                "caSelection": r.ca_selection or "", "commonName": r.common_name or "",
                "sanDomains": _jload(r.san_domains, []), "days": r.days or 90,
                "issuedAt": r.issued_at or "", "expiresAt": r.expires_at,
                "sha256Fingerprint": r.fingerprint, "status": r.status or "valid",
                "revokedAt": r.revoked_at, "revokeReason": r.revoke_reason,
                "renewedAt": r.renewed_at, "supersededBy": r.superseded_by,
                "issuedViaTokenId": r.via_token_id, "issuedViaTokenName": r.via_token_name}
                for r in c.execute(_select(self.certs)).mappings()]
        # drop None-valued optional keys for shape parity with the JSON store
        for cert in doc["certificates"]:
            for k in ("expiresAt", "sha256Fingerprint", "revokedAt", "revokeReason",
                      "renewedAt", "supersededBy", "issuedViaTokenId", "issuedViaTokenName"):
                if cert.get(k) is None:
                    cert.pop(k, None)
        for tok in doc["apiTokens"]:
            for k in ("expiresAt", "revokedAt", "lastUsedAt", "lastUsedCN"):
                if tok.get(k) is None:
                    tok.pop(k, None)
        return doc

    def save(self, doc: dict) -> None:
        from sqlalchemy import delete as _delete, insert as _insert
        with self.engine.begin() as c:
            for table in (self.certs, self.toks, self.cas):
                c.execute(_delete(table))
            for r in doc.get("intermediateCAs", []):
                c.execute(_insert(self.cas).values(
                    id=r.get("id"), name=r.get("name"), description=r.get("description") or "",
                    cert_pem=r.get("certPem"), encrypted_key_pem=r.get("encryptedKeyPem"),
                    root_cert_pem=r.get("rootCertPem"), is_active=bool(r.get("isActive")),
                    created_at=r.get("createdAt") or ""))
            for t in doc.get("apiTokens", []):
                c.execute(_insert(self.toks).values(
                    id=t.get("id"), name=t.get("name"), token=t.get("token"),
                    scopes=json.dumps(t.get("scopes") or ["sign", "revoke"]),
                    expires_at=t.get("expiresAt"), revoked=bool(t.get("revoked")),
                    revoked_at=t.get("revokedAt"), usage_count=t.get("usageCount") or 0,
                    last_used_at=t.get("lastUsedAt"), last_used_cn=t.get("lastUsedCN"),
                    created_at=t.get("createdAt") or ""))
            for r in doc.get("certificates", []):
                c.execute(_insert(self.certs).values(
                    id=r.get("id"), serial=r.get("serial"), ca_name=r.get("caName") or "",
                    ca_selection=r.get("caSelection") or "", common_name=r.get("commonName") or "",
                    san_domains=json.dumps(r.get("sanDomains") or []), days=r.get("days") or 90,
                    issued_at=r.get("issuedAt") or "", expires_at=r.get("expiresAt"),
                    fingerprint=r.get("sha256Fingerprint"), status=r.get("status") or "valid",
                    revoked_at=r.get("revokedAt"), revoke_reason=r.get("revokeReason"),
                    renewed_at=r.get("renewedAt"), superseded_by=r.get("supersededBy"),
                    via_token_id=r.get("issuedViaTokenId"), via_token_name=r.get("issuedViaTokenName")))
            for k in ("config", "serial"):
                c.execute(_delete(self.kv).where(self.kv.c.key == k))
                c.execute(_insert(self.kv).values(key=k, value=json.dumps(doc.get(k))))
            # cap sessions table growth on every write path
            c.execute(_delete(self.sessions).where(
                self.sessions.c.created_at < _cutoff_days(30)))

    # -- sessions ------------------------------------------------------------
    def session_add(self, tok: str, created_at: str) -> None:
        from sqlalchemy import delete as _delete, func, insert as _insert, select as _select
        with self.engine.begin() as c:
            c.execute(_insert(self.sessions).values(token=tok, created_at=created_at))
            n = c.execute(_select(func.count()).select_from(self.sessions)).scalar() or 0
            if n > 500:
                oldest = c.execute(_select(self.sessions.c.token).order_by(
                    self.sessions.c.created_at).limit(1)).first()
                if oldest:
                    c.execute(_delete(self.sessions).where(self.sessions.c.token == oldest[0]))

    def session_has(self, tok: str) -> bool:
        from sqlalchemy import select as _select
        with self.engine.begin() as c:
            return c.execute(_select(self.sessions.c.token).where(
                self.sessions.c.token == tok)).first() is not None

    def session_del(self, tok: str) -> None:
        from sqlalchemy import delete as _delete
        with self.engine.begin() as c:
            c.execute(_delete(self.sessions).where(self.sessions.c.token == tok))

    # -- audit ---------------------------------------------------------------
    def audit_write(self, entry: dict) -> None:
        from sqlalchemy import insert as _insert
        with self.engine.begin() as c:
            c.execute(_insert(self.audit).values(
                ts=entry.get("ts", ""), event=entry.get("event", ""),
                ip=entry.get("ip", ""), actor=entry.get("actor", ""),
                details=json.dumps(entry.get("details") or {})))

    def audit_read(self, event=None, q=None, limit=100, offset=0):
        from sqlalchemy import func, or_, select as _select
        with self.engine.begin() as c:
            stmt = _select(self.audit).order_by(self.audit.c.id.desc())
            if event:
                stmt = stmt.where(self.audit.c.event == event)
            if q:
                like = f"%{q}%"
                stmt = stmt.where(or_(
                    self.audit.c.event.like(like), self.audit.c.actor.like(like),
                    self.audit.c.ip.like(like), self.audit.c.details.like(like)))
            total = c.execute(_select(func.count()).select_from(stmt.subquery())).scalar() or 0
            rows = c.execute(stmt.limit(limit).offset(offset)).mappings().all()
            entries = [{"ts": r["ts"], "event": r["event"], "ip": r["ip"] or "",
                        "actor": r["actor"] or "",
                        "details": _jload(r["details"], {})} for r in rows]
            counts = {}
            for r in c.execute(_select(self.audit.c.event, func.count()).group_by(
                    self.audit.c.event)).all():
                counts[r[0]] = r[1]
            return total, entries, counts


def _jload(s, default):
    try:
        v = json.loads(s) if isinstance(s, str) else s
        return v if v is not None else default
    except Exception:
        return default


def _cutoff_days(n: int) -> str:
    import datetime
    return (datetime.datetime.now(datetime.timezone.utc)
            - datetime.timedelta(days=n)).isoformat()


# --------------------------------------------------------------------------
# Backend selection (once, at import — sticky for process lifetime)
# --------------------------------------------------------------------------
def _init_backend():
    global backend_name, _pg
    url = _sql_url()
    if not url:
        return
    try:
        be = _SqlBackend(url)
        # probe + migrate from JSON on first use
        doc = be.load()
        if not doc.get("config") and not doc.get("intermediateCAs") and config.DB_FILE.exists():
            try:
                legacy = json.loads(config.DB_FILE.read_text(encoding="utf-8"))
                if legacy.get("config") or legacy.get("intermediateCAs") or legacy.get("certificates"):
                    be.save(legacy)
                    _migrated_from_json = True
                    # carry the audit trail (cap: newest 5000) so history stays visible
                    try:
                        log_f = config.LOGS_DIR / "audit.log"
                        if log_f.exists():
                            lines = [ln for ln in
                                     log_f.read_text(encoding="utf-8").splitlines() if ln.strip()]
                            for ln in lines[-5000:]:
                                try:
                                    be.audit_write(json.loads(ln))
                                except Exception:
                                    continue
                    except Exception:
                        pass
                else:
                    _migrated_from_json = False
            except Exception:
                _migrated_from_json = False
        else:
            _migrated_from_json = False
        _pg = be
        backend_name = "sqlite" if url.split("://")[0].startswith("sqlite") else "postgresql"
        _pg._migrated = _migrated_from_json
    except Exception as e:
        import sys
        print(f"WARNING: DATABASE_URL set but SQL backend unreachable ({e}). "
              f"STICKING to JSON store for this process.", file=sys.stderr, flush=True)


_init_backend()


def was_migrated() -> bool:
    return bool(_pg is not None and getattr(_pg, "_migrated", False))


# --------------------------------------------------------------------------
# Public API (backend-agnostic)
# --------------------------------------------------------------------------
def load() -> dict:
    if _pg is not None:
        return _pg.load()
    return _json_load()


def save(data: dict) -> None:
    if _pg is not None:
        with _lock:
            _pg.save(data)
        return
    _json_save(data)


# sessions (memory set for JSON, table for SQL)
_mem_sessions: set = set()


def session_add(tok: str) -> None:
    import datetime
    now = datetime.datetime.now(datetime.timezone.utc).isoformat()
    if _pg is not None:
        _pg.session_add(tok, now)
        return
    with _lock:
        _mem_sessions.add(tok)
        if len(_mem_sessions) > 500:
            _mem_sessions.pop()


def session_has(tok: str) -> bool:
    if _pg is not None:
        return _pg.session_has(tok)
    return tok in _mem_sessions


def session_del(tok: str) -> None:
    if _pg is not None:
        _pg.session_del(tok)
        return
    with _lock:
        _mem_sessions.discard(tok)


def audit_write(entry: dict) -> None:
    if _pg is not None:
        try:
            _pg.audit_write(entry)
        except Exception:
            pass


def audit_read(event=None, q=None, limit=100, offset=0):
    """Returns (total, entries, counts). SQL backend reads the table,
    JSON backend reads the log file."""
    if _pg is not None:
        return _pg.audit_read(event, q, limit, offset)
    log_f = config.LOGS_DIR / "audit.log"
    if not log_f.exists():
        return 0, [], {}
    entries = []
    for line in log_f.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            entries.append(json.loads(line))
        except Exception:
            continue
    entries.reverse()
    filtered = entries
    if event:
        filtered = [e for e in filtered if e.get("event") == event]
    if q:
        needle = q.lower()
        filtered = [e for e in filtered if needle in json.dumps(e, default=str).lower()]
    counts = {}
    for e in entries:
        counts[e.get("event", "?")] = counts.get(e.get("event", "?"), 0) + 1
    return len(filtered), filtered[offset:offset + limit], counts


def active_database_label() -> str:
    if backend_name == "postgresql":
        return "PostgreSQL"
    if backend_name == "sqlite":
        return "SQLite (file)"
    return "JSON file"
