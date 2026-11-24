from __future__ import annotations

import logging
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, HTTPException
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import FileResponse
from fastapi.staticfiles import StaticFiles

from app.api.routes import (
    access,
    access_view,
    accounts,
    activity,
    admin,
    audit_ops,
    auth,
    budgets,
    command_center,
    compliance,
    cost,
    dashboard,
    explorer,
    governance,
    health,
    home,
    intelligence,
    inventory,
    jobs,
    onboarding_wizard,
    operations,
    platform,
    reports,
    security,
    sync,
    system,
)
from app.core.config import get_settings
from app.core.logging import configure_logging
from app.database.seed import seed_reference_data
from app.database.session import get_session_factory


@asynccontextmanager
async def lifespan(app: FastAPI):
    configure_logging(fmt=get_settings().log_format)
    # Several API worker processes start at the same moment; reference data is idempotent, so a worker that loses
    # the race to another one (unique-key conflict) just rolls back. The migrate step has already seeded in production.
    from sqlalchemy.exc import IntegrityError, OperationalError
    with get_session_factory()() as db:
        try:
            seed_reference_data(db)
        except (IntegrityError, OperationalError) as exc:
            db.rollback()
            logging.getLogger("cloudnexus.startup").info("reference data seeded by another worker (%s)", type(exc).__name__)
    yield


def create_app() -> FastAPI:
    settings = get_settings()
    docs = None if settings.app_env == "production" else "/docs"
    app = FastAPI(title=settings.app_name, version="0.8.0", lifespan=lifespan, docs_url=docs, redoc_url=None,
                  openapi_url="/openapi.json" if docs else None)
    app.add_middleware(CORSMiddleware, allow_origins=settings.cors_origins, allow_credentials=True,
                       allow_methods=["GET", "POST", "PATCH", "PUT", "DELETE"], allow_headers=["content-type", "x-requested-with"])

    from collections import deque
    from time import monotonic

    from fastapi.responses import JSONResponse
    hits: dict[tuple[str, str], deque] = {}

    @app.middleware("http")
    async def rate_limit(request, call_next):
        """Per-IP sliding-window limit (in process). Behind several instances, enforce limits at the load balancer too."""
        path = request.url.path
        if path.startswith("/api/"):
            ip = request.client.host if request.client else "unknown"
            auth = path.startswith("/api/v1/auth/login") or path.startswith("/api/v1/auth/callback")
            limit = settings.auth_rate_limit_per_minute if auth else settings.rate_limit_per_minute
            if limit > 0:
                key, t = (ip, "auth" if auth else "api"), monotonic()
                q = hits.setdefault(key, deque())
                while q and t - q[0] > 60:
                    q.popleft()
                if len(q) >= limit:
                    return JSONResponse({"detail": "Too many requests. Please slow down."}, status_code=429, headers={"Retry-After": "60"})
                q.append(t)
                if len(hits) > 50_000:  # bound memory: drop clients idle for a minute; clear only as a last resort
                    for k in [k for k, v in hits.items() if not v or t - v[-1] > 60]:
                        del hits[k]
                    if len(hits) > 50_000:
                        hits.clear()
        return await call_next(request)

    @app.middleware("http")
    async def security_headers(request, call_next):
        resp = await call_next(request)
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
        resp.headers.setdefault("X-Frame-Options", "DENY")
        resp.headers.setdefault("Referrer-Policy", "same-origin")
        resp.headers.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()")
        resp.headers.setdefault("Cross-Origin-Opener-Policy", "same-origin")
        if request.url.path.startswith("/api/"):
            resp.headers.setdefault("Cache-Control", "no-store")
        else:  # the dashboard itself: no third-party scripts, no framing, no inline script
            resp.headers.setdefault("Content-Security-Policy", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; "
                                    "img-src 'self' data:; font-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; "
                                    "base-uri 'self'; form-action 'self'; object-src 'none'")
        if settings.app_env == "production":
            resp.headers.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return resp

    for r in (health.router, auth.router, inventory.router, dashboard.router, jobs.router, operations.router, admin.router,
              security.router, audit_ops.router, sync.router, explorer.router, budgets.router, access.router, cost.router, governance.router, command_center.router, intelligence.router, reports.router,
              activity.router, platform.router, home.router, accounts.router, access_view.router, system.router, compliance.router,
              onboarding_wizard.router):
        app.include_router(r)

    dist = Path(settings.frontend_dist) if settings.frontend_dist else None
    if dist and (dist / "index.html").exists():
        app.mount("/assets", StaticFiles(directory=dist / "assets"), name="assets")

        root = dist.resolve()

        @app.get("/{path:path}", include_in_schema=False)
        def spa(path: str):
            if path.startswith(("api/", "health")):
                raise HTTPException(404)
            candidate = (root / path).resolve()
            if path and candidate.is_file() and candidate.is_relative_to(root):  # e.g. /brand/latentview-logo.svg
                return FileResponse(candidate)
            last = path.rsplit("/", 1)[-1]
            if "." in last:  # a file that does not exist (/.env, /openapi.json, /x.php): 404, never the app shell
                raise HTTPException(404)
            return FileResponse(root / "index.html")

    return app


app = create_app()
