"""INV4R API package — FastAPI application."""

from __future__ import annotations

import os

from fastapi import FastAPI, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from inv4r.api.routers import api


def create_app(allow_origins: list[str] | None = None) -> FastAPI:
    is_development = os.environ.get("INV4R_ENV", "development").lower() == "development"
    expose_docs = os.environ.get("INV4R_EXPOSE_DOCS", str(is_development)).lower() in {"1", "true", "yes"}
    app = FastAPI(
        title="INV4R API",
        description=(
            "INV4R — vendor-agnostic network configuration compliance auditor.\n\n"
            "Ingest device configs (single, bulk, zip) → normalize to the closed "
            "security-fact vocabulary → evaluate against CIS / NIST 800-53 / "
            "DISA STIG / ISO 27001 → PDF reports with remediation paths.\n\n"
            "RBAC: Analyst (read) < Reviewer (upload + approve) < Admin (settings + eval).\n\n"
            "Auth: POST /api/auth/login (demo seeds are printed on first boot), "
            "then Bearer token or inv4r_session cookie, or X-API-Key header "
            "(INV4R_API_KEY env) for machine-to-machine."
        ),
        version="0.2.0",
        docs_url="/docs" if expose_docs else None,
        redoc_url="/redoc" if expose_docs else None,
        openapi_url="/openapi.json" if expose_docs else None,
        lifespan=_lifespan,
    )
    app.include_router(api)

    if allow_origins is None:
        configured = os.environ.get("INV4R_CORS_ORIGINS", "")
        origins = [origin.strip() for origin in configured.split(",") if origin.strip()]
        if not origins and is_development:
            origins = ["http://localhost:3000"]
    else:
        origins = allow_origins
    if origins:
        app.add_middleware(
            CORSMiddleware,
            allow_origins=origins,
            allow_credentials=True,
            allow_methods=["GET", "POST"],
            allow_headers=["Authorization", "Content-Type", "X-API-Key"],
        )

    from inv4r.api.config import repo_root
    dashboard_dist = repo_root() / "dashboard" / "dist"
    frontend_dir = dashboard_dist

    @app.get("/", include_in_schema=False)
    async def serve_root():
        return FileResponse(str(frontend_dir / "index.html"), media_type="text/html")

    if (frontend_dir / "assets").is_dir():
        app.mount("/assets", StaticFiles(directory=str(frontend_dir / "assets")), name="assets")

    @app.get("/{path_:path}", include_in_schema=False)
    async def spa_fallback(path_: str):
        if "." in path_.rsplit("/", 1)[-1]:
            candidate = frontend_dir / path_
            if candidate.is_file():
                return FileResponse(str(candidate))
            from fastapi.responses import Response
            return Response(status_code=404, content="Not found")
        return FileResponse(str(frontend_dir / "index.html"), media_type="text/html")

    return app


async def _lifespan(app: FastAPI):
    """Startup/shutdown: resolve dirs, warm engine/registry singletons, seed users."""
    from inv4r.api.config import ensure_dirs
    from inv4r.api.deps import get_engine, get_registry
    ensure_dirs()
    get_engine()
    get_registry()
    # The learned lane must read the SAME mappings directory that approval
    # writes go to; otherwise the API appears to "learn nothing".
    from inv4r.api.config import mappings_dir as _mappings_dir
    from inv4r.ai.settings import get_settings, set_overrides
    if get_settings().mappings_dir in ("", "mappings"):
        set_overrides(mappings_dir=str(_mappings_dir()))
    from inv4r.api.auth import load_users, validate_runtime_config
    validate_runtime_config()
    load_users()
    try:
        yield
    finally:
        pass


def run_dev(host: str = "127.0.0.1", port: int = 8000, cors_origins: list[str] | None = None):
    """Convenience entry point for local development."""
    import uvicorn
    app = create_app(allow_origins=cors_origins)
    uvicorn.run(app, host=host, port=port)


if __name__ == "__main__":
    run_dev()
