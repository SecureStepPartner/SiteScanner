"""API-key authentication dependency."""

from __future__ import annotations

import secrets
from typing import Annotated

from fastapi import HTTPException, Request, Security, status
from fastapi.security import APIKeyHeader, HTTPAuthorizationCredentials, HTTPBearer

from app.config import settings

api_key_header = APIKeyHeader(name="X-API-Key", auto_error=False)
bearer_auth = HTTPBearer(auto_error=False)


async def require_api_key(
    request: Request,
    bearer: Annotated[HTTPAuthorizationCredentials | None, Security(bearer_auth)],
    x_api_key: Annotated[str | None, Security(api_key_header)],
) -> str:
    """Require a configured API key for protected endpoints.

    ChatGPT Actions can send API keys either as a bearer token or as a custom
    `X-API-Key` header, so both are accepted. If auth is not configured, local
    development remains usable unless `REQUIRE_API_KEY=true` is set.
    """
    configured = settings.sitescanner_api_key.strip()
    provided = _extract_key(bearer=bearer, x_api_key=x_api_key)

    if not configured:
        if settings.require_api_key:
            raise HTTPException(
                status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                detail="API authentication is required but SITESCANNER_API_KEY is not configured.",
            )
        return f"ip:{request.client.host if request.client else 'unknown'}"

    if not provided or not secrets.compare_digest(provided, configured):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Invalid or missing API key.",
            headers={"WWW-Authenticate": "Bearer"},
        )

    return "api-key"


def _extract_key(
    *,
    bearer: HTTPAuthorizationCredentials | None,
    x_api_key: str | None,
) -> str | None:
    if x_api_key:
        return x_api_key.strip()
    if bearer and bearer.scheme.lower() == "bearer":
        return bearer.credentials.strip()
    return None
