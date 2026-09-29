"""Authentication & RBAC for the INV4R API."""

from __future__ import annotations

import base64
import hashlib
import hmac
import json
import os
import secrets
import time
from pathlib import Path
from typing import Any

import yaml

PBKDF2_ITERATIONS = 120_000
SESSION_COOKIE = "inv4r_session"
_TOKEN_TTL_SECONDS = 12 * 3600

_ROLE_LEVEL = {"Analyst": 0, "Reviewer": 1, "Admin": 2}


def _users_file() -> Path:
    return Path(os.environ.get("INV4R_USERS_FILE", "users.yaml"))


def _secret() -> bytes:
    env = os.environ.get("INV4R_JWT_SECRET")
    if env:
        return env.encode("utf-8")
    return b"inv4r-dev-secret-change-me"


def validate_runtime_config() -> None:
    """Reject insecure authentication settings when the API is deployed."""
    if os.environ.get("INV4R_ENV", "development").lower() != "production":
        return
    secret = os.environ.get("INV4R_JWT_SECRET", "")
    if len(secret) < 32 or secret in {"change-me-in-production", "inv4r-dev-secret-change-me"}:
        raise RuntimeError("INV4R_JWT_SECRET must be a unique secret of at least 32 characters in production")
    # INV4R_SECRET_KEY is intentionally NOT required here: it only guards cloud
    # key storage, and demanding it unconditionally would break existing
    # deployments on upgrade. _secret_key() refuses at use-time instead.


def hash_password(password: str) -> str:
    salt = secrets.token_hex(16)
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), PBKDF2_ITERATIONS)
    return f"pbkdf2_sha256${PBKDF2_ITERATIONS}${salt}${dk.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        scheme, iters, salt, ref = stored.split("$")
    except ValueError:
        return False
    if scheme != "pbkdf2_sha256":
        return False
    dk = hashlib.pbkdf2_hmac("sha256", password.encode(), bytes.fromhex(salt), int(iters))
    return hmac.compare_digest(dk.hex(), ref)


def _b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).rstrip(b"=").decode("ascii")


def _b64url_decode(s: str) -> bytes:
    pad = "=" * (-len(s) % 4)
    return base64.urlsafe_b64decode(s + pad)


def issue_token(user: dict[str, Any]) -> str:
    header = _b64url(json.dumps({"alg": "HS256", "typ": "JWT"}).encode())
    now = int(time.time())
    payload = _b64url(json.dumps({
        "sub": user["email"], "role": user["role"], "name": user.get("name", ""),
        "iat": now, "exp": now + _TOKEN_TTL_SECONDS, "jti": secrets.token_hex(8),
    }).encode())
    signing = f"{header}.{payload}".encode("ascii")
    sig = _b64url(hmac.new(_secret(), signing, hashlib.sha256).digest())
    return f"{header}.{payload}.{sig}"


class AuthError(Exception):
    def __init__(self, message: str, status: int = 401) -> None:
        super().__init__(message)
        self.status = status


def verify_token(token: str) -> dict[str, Any]:
    try:
        header_b64, payload_b64, sig_b64 = token.split(".")
    except ValueError as exc:
        raise AuthError("malformed token") from exc
    try:
        header = json.loads(_b64url_decode(header_b64))
    except Exception as exc:
        raise AuthError("malformed token header") from exc
    if header.get("alg") != "HS256":
        raise AuthError("unsupported algorithm")
    signing = f"{header_b64}.{payload_b64}".encode("ascii")
    expected = _b64url(hmac.new(_secret(), signing, hashlib.sha256).digest())
    if not hmac.compare_digest(sig_b64, expected):
        raise AuthError("invalid token signature")
    try:
        payload = json.loads(_b64url_decode(payload_b64))
    except Exception as exc:
        raise AuthError("malformed token payload") from exc
    if payload.get("exp", 0) < time.time():
        raise AuthError("token expired")
    return payload


_SEED_USERS = [
    {"email": "admin@inv4r.io", "name": "Fleet Admin", "role": "Admin", "password": "inv4r-admin"},
    {"email": "reviewer@inv4r.io", "name": "Mapping Reviewer", "role": "Reviewer", "password": "inv4r-reviewer"},
    {"email": "analyst@inv4r.io", "name": "Read-only Analyst", "role": "Analyst", "password": "inv4r-analyst"},
]


def load_users() -> list[dict[str, Any]]:
    p = _users_file()
    if p.exists():
        data = yaml.safe_load(p.read_text(encoding="utf-8")) or {}
        users = data.get("users") or []
        if users:
            return users
    if os.environ.get("INV4R_ENV", "development").lower() == "production":
        email = os.environ.get("INV4R_BOOTSTRAP_ADMIN_EMAIL", "").strip().lower()
        password = os.environ.get("INV4R_BOOTSTRAP_ADMIN_PASSWORD", "")
        if not email or len(password) < 12:
            raise RuntimeError(
                "Production bootstrap requires INV4R_BOOTSTRAP_ADMIN_EMAIL and "
                "INV4R_BOOTSTRAP_ADMIN_PASSWORD (12+ characters) when no user store exists"
            )
        users = [{
            "email": email,
            "name": "INV4R Administrator",
            "role": "Admin",
            "password_hash": hash_password(password),
        }]
        save_users(users)
        return users

    users: list[dict[str, Any]] = []
    lines = ["INV4R API: seeded demo accounts — change these passwords before any real use:"]
    for u in _SEED_USERS:
        users.append({"email": u["email"], "name": u["name"], "role": u["role"],
                      "password_hash": hash_password(u["password"])})
        lines.append(f"    {u['role']:<8} {u['email']:<22} password: {u['password']}")
    p.write_text(yaml.safe_dump({"users": users}, sort_keys=False), encoding="utf-8")
    print("\n".join(lines), flush=True)
    return users


def save_users(users: list[dict[str, Any]]) -> None:
    p = _users_file()
    p.write_text(yaml.safe_dump({"users": users}, sort_keys=False), encoding="utf-8")


def add_user(email: str, name: str, role: str, password: str) -> dict[str, Any]:
    users = load_users()
    email_clean = email.strip().lower()
    for u in users:
        if u["email"].lower() == email_clean:
            raise ValueError(f"User with email '{email}' already exists.")
    new_u = {
        "email": email_clean,
        "name": name.strip() or email_clean.split("@")[0],
        "role": role if role in ("Admin", "Reviewer", "Analyst") else "Analyst",
        "password_hash": hash_password(password)
    }
    users.append(new_u)
    save_users(users)
    return {"email": new_u["email"], "name": new_u["name"], "role": new_u["role"]}


def admin_reset_password(email: str, new_password: str) -> bool:
    users = load_users()
    email_clean = email.strip().lower()
    found = False
    for u in users:
        if u["email"].lower() == email_clean:
            u["password_hash"] = hash_password(new_password)
            found = True
            break
    if not found:
        raise ValueError(f"User with email '{email}' not found.")
    save_users(users)
    return True


def delete_user(email: str) -> bool:
    users = load_users()
    email_clean = email.strip().lower()
    if email_clean == "admin@inv4r.io":
        raise ValueError("Cannot delete primary admin account.")
    new_users = [u for u in users if u["email"].lower() != email_clean]
    if len(new_users) == len(users):
        raise ValueError(f"User with email '{email}' not found.")
    save_users(new_users)
    return True


def authenticate(email: str, password: str) -> dict[str, Any]:
    email = (email or "").strip().lower()
    for u in load_users():
        if u["email"].lower() == email:
            if verify_password(password or "", u.get("password_hash", "")):
                return {"email": u["email"], "name": u.get("name", ""), "role": u["role"]}
            break
    raise AuthError("invalid credentials", 401)


def role_at_least(role: str, minimum: str) -> bool:
    return _ROLE_LEVEL.get(role, -1) >= _ROLE_LEVEL.get(minimum, 99)


def admin_only(user: dict[str, Any]) -> dict[str, Any]:
    if not role_at_least(user["role"], "Admin"):
        raise AuthError("admin access required", 403)
    return user


def reviewer_or_above(user: dict[str, Any]) -> dict[str, Any]:
    if not role_at_least(user["role"], "Reviewer"):
        raise AuthError("reviewer or admin access required", 403)
    return user


def analyst_only(user: dict[str, Any]) -> dict[str, Any]:
    if not role_at_least(user["role"], "Analyst"):
        raise AuthError("authenticated access required", 403)
    return user
