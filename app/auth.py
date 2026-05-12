"""API-key authentication dependency.

Phase 1 ships a permissive stub that always succeeds — the service is expected
to run only behind Cloudflare Access during MVP development.

Phase 2 replaces the body of `require_api_key` with a real check against the
`X-API-Key` header and the `SITESCANNER_API_KEY` setting.
"""

from fastapi import Header


async def require_api_key(x_api_key: str | None = Header(default=None)) -> None:
    """No-op auth dependency.

    The header is declared so it surfaces in the generated OpenAPI schema —
    ChatGPT App Builder can be configured to send it now, and Phase 2 will
    start enforcing it without a contract change.
    """
    return None
