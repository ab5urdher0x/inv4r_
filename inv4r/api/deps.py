"""FastAPI dependency injection: auth/RBAC + engine/registry singletons."""

from __future__ import annotations

import os
from typing import Any

from fastapi import Depends, HTTPException, Request

from inv4r.api.auth import AuthError, role_at_least, verify_token
from inv4r.api.config import artifacts_dir, mappings_dir
from inv4r.engine import Engine
from inv4r.mapping.registry import MappingRegistry


def _current_user(request: Request) -> dict[str, Any] | None:
    """Resolve the caller identity from (in order): Bearer token, session"""
    auth = request.headers.get("Authorization", "")
    token = auth[7:].strip() if auth.lower().startswith("bearer ") else ""
    if not token and SESSION_COOKIE_NAME in request.cookies:
        token = request.cookies[SESSION_COOKIE_NAME]
    if token:
        try:
            claims = verify_token(token)
        except AuthError as exc:
            raise HTTPException(status_code=exc.status, detail=str(exc)) from exc
        return {
            "email": claims.get("sub", ""),
            "role": claims.get("role", "Analyst"),
            "name": claims.get("name", ""),
        }

    api_key = os.environ.get("INV4R_API_KEY", "")
    provided = request.headers.get("X-API-Key", "")
    if api_key and provided and provided == api_key:
        return {"email": "service@inv4r.io", "role": "Analyst", "name": "API Key"}

    return None


def authenticated(request: Request) -> dict[str, Any]:
    """Require any valid identity (Analyst or above)."""
    user = _current_user(request)
    if user is None:
        raise HTTPException(status_code=401, detail="authentication required")
    return user


def admin_only(user: dict[str, Any] = Depends(authenticated)) -> dict[str, Any]:
    if not role_at_least(user["role"], "Admin"):
        raise HTTPException(status_code=403, detail="admin access required")
    return user


def reviewer_or_above(user: dict[str, Any] = Depends(authenticated)) -> dict[str, Any]:
    if not role_at_least(user["role"], "Reviewer"):
        raise HTTPException(status_code=403, detail="reviewer or admin access required")
    return user


def analyst_only(user: dict[str, Any] = Depends(authenticated)) -> dict[str, Any]:
    if not role_at_least(user["role"], "Analyst"):
        raise HTTPException(status_code=403, detail="authenticated access required")
    return user


from inv4r.api.auth import SESSION_COOKIE as SESSION_COOKIE_NAME  # noqa: E402


_engine_inst: Engine | None = None
_preview_engine_inst: Engine | None = None
_registry_inst: MappingRegistry | None = None
_behaviour_inst: Any = None


def get_engine() -> Engine:
    global _engine_inst
    if _engine_inst is None:
        _engine_inst = Engine(
            mapping_dir=str(mappings_dir()),
            artifact_dir=str(artifacts_dir()),
        )
    return _engine_inst


def get_preview_engine() -> Engine:
    """Engine that may consult PENDING_REVIEW packs for a provisional preview.

    Kept separate from the authoritative engine and given its own artifact
    directory so a preview can never overwrite authoritative evidence.
    """
    global _preview_engine_inst
    if _preview_engine_inst is None:
        _preview_engine_inst = Engine(
            mapping_dir=str(mappings_dir()),
            artifact_dir=str(artifacts_dir() / "preview"),
            include_pending=True,
        )
    return _preview_engine_inst


def reset_preview_engine() -> None:
    """Drop the cached preview engine so the next preview re-reads the packs."""
    global _preview_engine_inst
    _preview_engine_inst = None


def reset_engine() -> None:
    """Drop the cached authoritative engine so it re-reads mapping packs.

    Called after a pack lifecycle change (approve/reject) so a newly ACTIVE pack
    is picked up without restarting the service.
    """
    global _engine_inst
    _engine_inst = None


def get_registry() -> MappingRegistry:
    global _registry_inst
    if _registry_inst is None:
        _registry_inst = MappingRegistry(str(mappings_dir()))
    return _registry_inst


def get_behaviour() -> Any:
    global _behaviour_inst
    if _behaviour_inst is None:
        from inv4r.behaviour.engine import BehaviourEngine
        _behaviour_inst = BehaviourEngine()
    return _behaviour_inst


def reset_singletons() -> None:
    """Test hook — drop cached engine/registry so env changes take effect."""
    global _engine_inst, _preview_engine_inst, _registry_inst, _behaviour_inst
    _engine_inst = None
    _preview_engine_inst = None
    _registry_inst = None
    _behaviour_inst = None
