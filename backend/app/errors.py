"""Standard error envelope shared by every API (same contract as Node engine)."""
from fastapi.responses import JSONResponse


def err(status: int, code: str, message: str, hint: str | None = None, **extra):
    body = {"success": False, "code": code, "error": message}
    if hint:
        body["hint"] = hint
    body.update(extra)
    return JSONResponse(status_code=status, content=body)


def ca_not_available(ca_hint=None):
    return JSONResponse(status_code=503, content={
        "success": False,
        "code": "CA_NOT_AVAILABLE",
        "error": ("CA_NOT_AVAILABLE: No Signing CA set up yet. Open Admin UI "
                  "\u2192 \U0001f9d9 Setup Wizard (or Intermediate CAs) and generate/import "
                  "at least one Signing CA (e.g. int-server for web/TLS, int-wifi for "
                  "RADIUS/802.1X, int-iot for devices), then retry."),
        "hint": ("Set up at least one Signing CA: Admin UI \u2192 \U0001f9d9 Setup Wizard "
                 "(1-click) or Intermediate CAs \u2192 Import. Suggested: int-server "
                 "(web/TLS), int-wifi (RADIUS/802.1X), int-iot (devices)."),
        "setupUrl": "/onboarding",
        "expectedCAs": ["int-server", "int-wifi", "int-iot"],
        "caHint": ca_hint or {"ca": None, "purpose": None},
    })


class ApiError(Exception):
    def __init__(self, status: int, code: str, message: str, hint: str | None = None, **extra):
        self.status, self.code, self.message, self.hint, self.extra = status, code, message, hint, extra
