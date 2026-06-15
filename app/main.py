"""FastAPI application entrypoint."""

import logging
import time
import uuid

from fastapi import FastAPI, Request, Response
from starlette.middleware.trustedhost import TrustedHostMiddleware

from app import __version__
from app.config import settings
from app.models import HealthResponse
from app.routes import scans as scans_routes

log = logging.getLogger("sitescanner.api")

app = FastAPI(
    title="SecureStep Site Scanner",
    description=(
        "Backend API for the SecureStep Site Scanner ChatGPT App. "
        "Initiates controlled vulnerability scans against a target domain "
        "and returns structured results plus an email report."
    ),
    version=__version__,
    openapi_url="/openapi.json",
    docs_url="/docs",
    servers=[{"url": settings.public_base_url}] if settings.public_base_url else None,
)

if settings.trusted_hosts:
    app.add_middleware(
        TrustedHostMiddleware,
        allowed_hosts=[host.strip() for host in settings.trusted_hosts.split(",") if host.strip()],
    )

app.include_router(scans_routes.router)


@app.middleware("http")
async def request_logging_middleware(request: Request, call_next) -> Response:
    request_id = request.headers.get("X-Request-ID") or uuid.uuid4().hex
    start = time.perf_counter()
    response = await call_next(request)
    elapsed_ms = (time.perf_counter() - start) * 1000
    response.headers["X-Request-ID"] = request_id
    log.info(
        "request_id=%s method=%s path=%s status=%s duration_ms=%.2f client=%s",
        request_id,
        request.method,
        request.url.path,
        response.status_code,
        elapsed_ms,
        request.client.host if request.client else "-",
    )
    return response


@app.get("/health", tags=["meta"], operation_id="get_health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness check used by deployment tooling."""
    return HealthResponse()


def _diag() -> dict[str, object]:
    """Non-secret diagnostic snapshot of configuration."""
    return {
        "version": __version__,
        "email_provider": settings.email_provider,
        "scan_timeout_seconds": settings.scan_timeout_seconds,
        "max_concurrent_scans": settings.max_concurrent_scans,
        "rate_limit_per_minute": settings.rate_limit_per_minute,
        "rate_limit_per_hour": settings.rate_limit_per_hour,
        "max_pending_scans": settings.max_pending_scans,
        "api_auth_configured": bool(settings.sitescanner_api_key),
        "pdcp_dashboard_enabled": bool(settings.pdcp_api_key),
        "pdcp_team_configured": bool(settings.pdcp_team_id),
        "pdcp_cloud_upload_enabled": settings.pdcp_enable_cloud_upload,
    }


@app.get("/diag", tags=["meta"], include_in_schema=False)
async def diag() -> dict[str, object]:
    """Diagnostic endpoint, excluded from the public OpenAPI schema."""
    return _diag()
