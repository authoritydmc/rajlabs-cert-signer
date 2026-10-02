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

# Public PKI URLs & Extensions (RFC 5280 CRL Distribution Points & Authority Information Access)
# Supports {ca} template placeholder, e.g. "https://ca.rajlabs.in/crl/{ca}.crl"
CRL_URL_TEMPLATE = os.getenv("CRL_URL_TEMPLATE", "").strip()
CA_ISSUERS_URL_TEMPLATE = os.getenv("CA_ISSUERS_URL_TEMPLATE", "").strip()
OCSP_URL_TEMPLATE = os.getenv("OCSP_URL_TEMPLATE", "").strip()

# Raw fallback comma-separated lists from env
CRL_FALLBACK_URLS = [u.strip().rstrip("/") for u in os.getenv("CRL_FALLBACK_URLS", "").split(",") if u.strip()]
OCSP_FALLBACK_URLS = [u.strip().rstrip("/") for u in os.getenv("OCSP_FALLBACK_URLS", "").split(",") if u.strip()]
CA_ISSUERS_FALLBACK_URLS = [u.strip().rstrip("/") for u in os.getenv("CA_ISSUERS_FALLBACK_URLS", "").split(",") if u.strip()]

# Default public PKI hosts for rajlabs ecosystem
DEFAULT_PKI_HOSTS = [
    "https://ca.rajlabs.in",
    "https://certs.rajlabs.in",
    "https://crl.rajlabs.in",
    "http://crl.rajlabs.in",
    "http://certs.rajlabs.in",
    "https://backend.rajlabs.in/cert-signer",
]

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

