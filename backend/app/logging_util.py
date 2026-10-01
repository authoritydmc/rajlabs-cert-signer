"""Structured JSONL logging + audit trail. Secrets are redacted."""
import json
import re
from datetime import datetime, timezone

from . import config

_LEVELS = {"debug": 10, "info": 20, "warn": 30, "error": 40}


def _now():
    return datetime.now(timezone.utc).isoformat()


def _mask(obj) -> str:
    try:
        s = json.dumps(obj, default=str)
    except Exception:
        return "[unserializable]"
    s = re.sub(r"(cert_[a-f0-9]{8})[a-f0-9]+", r"\1...", s)
    s = re.sub(r'("password"\s*:\s*")[^"]*(")', r"\1***\2", s)
    s = re.sub(r"(-----BEGIN [^-]+-----)[\s\S]*?(-----END [^-]+-----)",
               r"\1 ***REDACTED*** \2", s)
    return s


def _emit(level: str, msg: str, meta=None):
    if _LEVELS.get(level, 20) < _LEVELS.get(config.LOG_LEVEL, 20):
        return
    entry = {"ts": _now(), "level": level, "msg": msg}
    if meta is not None:
        try:
            entry["meta"] = json.loads(_mask(meta))
        except Exception:
            entry["meta"] = str(meta)[:2000]
    line = json.dumps(entry)
    print(line, flush=True)
    if config.LOG_FILE:
        try:
            with open(config.LOG_FILE, "a", encoding="utf-8") as f:
                f.write(line + "\n")
        except Exception:
            pass


class _Logger:
    def debug(self, msg, meta=None): _emit("debug", msg, meta)
    def info(self, msg, meta=None): _emit("info", msg, meta)
    def warn(self, msg, meta=None): _emit("warn", msg, meta)
    def error(self, msg, meta=None): _emit("error", msg, meta)


logger = _Logger()


def audit(event: str, details=None, request=None):
    ip, actor = "", "admin-ui/session"
    if request is not None:
        try:
            ip = request.headers.get("x-forwarded-for", "") or (request.client.host if request.client else "")
            tok = getattr(request.state, "api_token", None)
            if tok:
                actor = tok.get("name", "api-key")
        except Exception:
            pass
    entry = {"ts": _now(), "event": event, "ip": ip, "actor": actor,
             "details": details or {}}
    print(json.dumps({"ts": entry["ts"], "level": "audit", "msg": event,
                      "meta": {"ip": ip, "actor": actor}}), flush=True)
    try:
        with open(config.LOGS_DIR / "audit.log", "a", encoding="utf-8") as f:
            f.write(json.dumps(entry) + "\n")
    except Exception:
        pass
