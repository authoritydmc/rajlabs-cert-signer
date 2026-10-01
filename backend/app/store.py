"""JSON document store. Same schema as the Node engine's database.json,
so existing deployments (and their encrypted CA keys) carry over untouched."""
import json
import os
import tempfile
import threading

from . import config

_lock = threading.RLock()  # re-entrant: load() may call save() for first-boot init

_DEFAULTS = {"config": {}, "intermediateCAs": [], "apiTokens": [],
             "certificates": [], "serial": 2000}


def load() -> dict:
    with _lock:
        if not config.DB_FILE.exists():
            save(_DEFAULTS)
            return json.loads(json.dumps(_DEFAULTS))
        try:
            data = json.loads(config.DB_FILE.read_text(encoding="utf-8"))
        except Exception:
            data = {}
        for k, v in _DEFAULTS.items():
            data.setdefault(k, v if not isinstance(v, (dict, list)) else json.loads(json.dumps(v)))
        return data


def save(data: dict) -> None:
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
