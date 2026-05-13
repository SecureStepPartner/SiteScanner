"""API-key authentication dependency.

Phase 1 ships a permissive stub that always succeeds — the service is expected
to run only behind Cloudflare Access during MVP development.

Phase 2 can replace this with a real check against the `SITESCANNER_API_KEY`
setting without changing the public route contract.
"""


async def require_api_key() -> None:
    """No-op auth dependency."""
    return None
