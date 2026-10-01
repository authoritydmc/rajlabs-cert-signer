"""AES-256-GCM vault for intermediate private keys.

Wire format is byte-compatible with the Node engine: ``iv:tag:ct`` (hex).
This lets existing database.json files migrate without re-importing CAs.
"""
import hashlib
import os
import stat

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from . import config

_MASTER_KEY_FILE = config.DATA_DIR / "master_encryption.key"


def _master_key() -> bytes:
    if config.ENCRYPTION_KEY:
        return hashlib.sha256(config.ENCRYPTION_KEY.encode()).digest()
    if not _MASTER_KEY_FILE.exists():
        key = AESGCM.generate_key(bit_length=256)
        fd = os.open(str(_MASTER_KEY_FILE), os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
        with os.fdopen(fd, "wb") as f:
            f.write(key)
        try:
            os.chmod(_MASTER_KEY_FILE, stat.S_IRUSR | stat.S_IWUSR)
        except Exception:
            pass
        return key
    return _MASTER_KEY_FILE.read_bytes()


_MASTER = _master_key()


def encrypt(text: str) -> str:
    iv = os.urandom(12)
    ct_tag = AESGCM(_MASTER).encrypt(iv, text.encode("utf-8"), None)
    ct, tag = ct_tag[:-16], ct_tag[-16:]
    return f"{iv.hex()}:{tag.hex()}:{ct.hex()}"


def decrypt(cipher_text: str) -> str:
    parts = cipher_text.split(":")
    if len(parts) != 3:
        return cipher_text  # stored raw (legacy)
    iv = bytes.fromhex(parts[0])
    tag = bytes.fromhex(parts[1])
    ct = bytes.fromhex(parts[2])
    return AESGCM(_MASTER).decrypt(iv, ct + tag, None).decode("utf-8")
