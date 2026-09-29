"""Encryption-at-rest for cloud LLM API keys.

Keys submitted through the dashboard are encrypted with a key derived from a
dedicated environment secret (``INV4R_SECRET_KEY``) that is separate from the
JWT signing secret. Only stdlib primitives are used (PBKDF2-HMAC-SHA256 key
derivation, HMAC-SHA256 counter-mode keystream, encrypt-then-MAC). The
plaintext key is never logged and never returned by the API — callers only
ever see a masked indicator.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
from pathlib import Path

_MAGIC = b"INV4R1"
_SALT_LEN = 16
_NONCE_LEN = 16
_TAG_LEN = 32
_KDF_ITERS = 200_000
_KEY_FILE = "cloud_key.json"
_DEV_SECRET = "inv4r-dev-secret-key-not-for-production"


def secrets_dir() -> Path:
    """Directory holding encrypted secrets (env-overridable, gitignored)."""
    return Path(os.environ.get("INV4R_SECRETS_DIR", "secrets"))


def _secret_key() -> str:
    env = os.environ.get("INV4R_SECRET_KEY")
    if env:
        return env
    if os.environ.get("INV4R_ENV", "development").lower() == "production":
        raise RuntimeError(
            "INV4R_SECRET_KEY must be set in production to encrypt API keys at rest")
    return _DEV_SECRET


def _derive(secret: str, salt: bytes) -> bytes:
    return hashlib.pbkdf2_hmac("sha256", secret.encode("utf-8"), salt, _KDF_ITERS, dklen=32)


def _keystream(key: bytes, nonce: bytes, length: int) -> bytes:
    out = bytearray()
    counter = 0
    while len(out) < length:
        out += hmac.new(key, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(out[:length])


def encrypt_secret(plaintext: str, secret: str | None = None) -> str:
    """Return an authenticated, base64-encoded ciphertext of ``plaintext``."""
    key = _derive(secret if secret is not None else _secret_key(), salt := os.urandom(_SALT_LEN))
    nonce = os.urandom(_NONCE_LEN)
    body = plaintext.encode("utf-8")
    cipher = bytes(a ^ b for a, b in zip(body, _keystream(key, nonce, len(body))))
    tag = hmac.new(key, _MAGIC + salt + nonce + cipher, hashlib.sha256).digest()
    return base64.urlsafe_b64encode(_MAGIC + salt + nonce + cipher + tag).decode("ascii")


def decrypt_secret(token: str, secret: str | None = None) -> str:
    """Reverse :func:`encrypt_secret`; raises ``ValueError`` on tampering."""
    try:
        raw = base64.urlsafe_b64decode(token.encode("ascii"))
    except Exception as exc:  # noqa: BLE001 - any decode failure is invalid input
        raise ValueError("malformed secret payload") from exc
    if not raw.startswith(_MAGIC) or len(raw) < len(_MAGIC) + _SALT_LEN + _NONCE_LEN + _TAG_LEN:
        raise ValueError("unrecognized secret payload")
    body = raw[len(_MAGIC):]
    salt, nonce = body[:_SALT_LEN], body[_SALT_LEN:_SALT_LEN + _NONCE_LEN]
    cipher, tag = body[_SALT_LEN + _NONCE_LEN:-_TAG_LEN], body[-_TAG_LEN:]
    key = _derive(secret if secret is not None else _secret_key(), salt)
    expected = hmac.new(key, _MAGIC + salt + nonce + cipher, hashlib.sha256).digest()
    if not hmac.compare_digest(tag, expected):
        raise ValueError("secret failed integrity check")
    return bytes(a ^ b for a, b in zip(cipher, _keystream(key, nonce, len(cipher)))).decode("utf-8")


def _key_path() -> Path:
    return secrets_dir() / _KEY_FILE


def save_cloud_key(api_key: str, provider: str = "openai") -> None:
    """Encrypt and persist a cloud provider API key at rest."""
    d = secrets_dir()
    d.mkdir(parents=True, exist_ok=True)
    try:
        os.chmod(d, 0o700)
    except OSError:
        pass
    payload = {"provider": provider or "openai", "token": encrypt_secret(api_key)}
    p = _key_path()
    p.write_text(json.dumps(payload), encoding="utf-8")
    try:
        os.chmod(p, 0o600)
    except OSError:
        pass


def load_cloud_key() -> tuple[str, str]:
    """Return ``(api_key, provider)``; ``("", "")`` when nothing is stored."""
    p = _key_path()
    if not p.exists():
        return "", ""
    try:
        data = json.loads(p.read_text(encoding="utf-8"))
        return decrypt_secret(str(data.get("token", ""))), str(data.get("provider", "") or "")
    except (ValueError, OSError, json.JSONDecodeError):
        return "", ""


def remove_cloud_key() -> bool:
    """Delete the stored key. Returns True when a key existed."""
    p = _key_path()
    if not p.exists():
        return False
    p.unlink()
    return True


def mask_key(api_key: str) -> str:
    """Human-readable indicator that never reveals the key itself."""
    if not api_key:
        return ""
    tail = api_key[-4:] if len(api_key) >= 4 else ""
    return f"API key configured, ending in {tail}" if tail else "API key configured"
