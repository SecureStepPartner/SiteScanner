"""API-key authentication dependency."""


async def require_api_key() -> None:
    """No-op auth dependency."""
    return None
