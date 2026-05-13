"""FastAPI application entrypoint."""

from fastapi import FastAPI

from app import __version__
from app.config import settings
from app.models import HealthResponse
from app.routes import scans as scans_routes

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


app.include_router(scans_routes.router)


@app.get("/health", tags=["meta"], operation_id="get_health", response_model=HealthResponse)
async def health() -> HealthResponse:
    """Liveness check used by deployment tooling."""
    return HealthResponse()


def _diag() -> dict[str, object]:
    """Non-secret diagnostic snapshot of configuration."""
    return {
        "version": __version__,
        "redis_url": settings.redis_url,
        "email_provider": settings.email_provider,
        "scan_timeout_seconds": settings.scan_timeout_seconds,
        "max_concurrent_scans": settings.max_concurrent_scans,
        "pdcp_dashboard_enabled": bool(settings.pdcp_api_key),
        "pdcp_team_configured": bool(settings.pdcp_team_id),
        "pdcp_cloud_upload_enabled": settings.pdcp_enable_cloud_upload,
    }


@app.get("/diag", tags=["meta"], include_in_schema=False)
async def diag() -> dict[str, object]:
    """Diagnostic endpoint, excluded from the public OpenAPI schema."""
    return _diag()
