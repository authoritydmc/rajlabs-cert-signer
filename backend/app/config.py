"""Environment configuration. BASE_URL unset = auto-detect per request."""
import os
from pathlib import Path

BACKEND_DIR = Path(__file__).resolve().parent.parent
# Repo root when running from source; /app inside the container.
REPO_ROOT = BACKEND_DIR.parent

PORT = int(os.getenv("PORT", "9000"))
BASE_URL = (os.getenv("BASE_URL", "") or "").strip().rstrip("/")
BASE_URL_FROM_ENV = bool(BASE_URL)
if not BASE_URL:
    BASE_URL = f"http://localhost:{PORT}"

BASE_PATH_RAW = (os.getenv("BASE_PATH", "") or "").strip().rstrip("/")
BASE_PATH = "" if BASE_PATH_RAW == "auto" else BASE_PATH_RAW

DATA_DIR = Path(os.getenv("DATA_DIR", str(REPO_ROOT / "data")))
CERTS_DIR = DATA_DIR / "issued-certs"
CRL_DIR = DATA_DIR / "crl"
LOGS_DIR = DATA_DIR / "logs"
DB_FILE = DATA_DIR / "database.json"
CREDENTIALS_FILE = DATA_DIR / "admin_credentials.txt"

for d in (DATA_DIR, CERTS_DIR, CRL_DIR, LOGS_DIR):
    d.mkdir(parents=True, exist_ok=True)

ADMIN_USER = os.getenv("ADMIN_USER", "admin")
ADMIN_PASSWORD = os.getenv("ADMIN_PASSWORD", "")
AUTH_TOKEN = os.getenv("AUTH_TOKEN", "")
ENCRYPTION_KEY = os.getenv("ENCRYPTION_KEY", "")
DATABASE_URL = os.getenv("DATABASE_URL", "")
LOG_LEVEL = (os.getenv("LOG_LEVEL", "info") or "info").lower()
LOG_FILE = os.getenv("LOG_FILE", "")
CORS_ORIGIN = os.getenv("CORS_ORIGIN", "*")

# Purpose -> intermediate CA routing (mirrors the Node engine).
CA_PURPOSE_MAP = {
    "server": ["int-server"], "web": ["int-server"],
    "tls": ["int-server"], "acme": ["int-server"],
    "wifi": ["int-wifi"], "radius": ["int-wifi"],
    "8021x": ["int-wifi"], "802.1x": ["int-wifi"],
    "eap": ["int-wifi"], "wireless": ["int-wifi"],
    "iot": ["int-iot"], "device": ["int-iot"],
    "mqtt": ["int-iot"], "embedded": ["int-iot"],
}
