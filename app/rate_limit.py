"""Redis-backed API abuse controls."""

from __future__ import annotations

import hashlib

from redis.asyncio import Redis

from app.config import settings
from app.models import ScanStatus


class RateLimitExceeded(ValueError):
    """Raised when a caller exceeds configured request limits."""

    def __init__(self, message: str, retry_after: int) -> None:
        super().__init__(message)
        self.retry_after = retry_after


def rate_limit_identity(value: str) -> str:
    """Hash caller identity before using it in Redis keys."""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:32]


async def enforce_scan_rate_limit(redis: Redis, identity: str) -> None:
    """Apply per-minute and per-hour scan creation limits."""
    safe_identity = rate_limit_identity(identity)
    await _consume(
        redis,
        key=f"rate:scan:min:{safe_identity}",
        limit=settings.rate_limit_per_minute,
        window_seconds=60,
    )
    await _consume(
        redis,
        key=f"rate:scan:hour:{safe_identity}",
        limit=settings.rate_limit_per_hour,
        window_seconds=3600,
    )


async def enforce_pending_scan_limit(redis: Redis) -> None:
    """Limit queued/running jobs so the worker cannot be flooded."""
    pending = 0
    async for key in redis.scan_iter(match="scan:*"):
        status = await redis.hget(key, "status")
        if isinstance(status, bytes):
            status = status.decode()
        if status in {ScanStatus.queued.value, ScanStatus.running.value}:
            pending += 1
            if pending >= settings.max_pending_scans:
                raise RateLimitExceeded(
                    "Too many scans are already queued or running. Try again later.",
                    retry_after=60,
                )


async def _consume(redis: Redis, *, key: str, limit: int, window_seconds: int) -> None:
    count = await redis.incr(key)
    if count == 1:
        await redis.expire(key, window_seconds)
    if count > limit:
        ttl = await redis.ttl(key)
        retry_after = ttl if isinstance(ttl, int) and ttl > 0 else window_seconds
        raise RateLimitExceeded("Rate limit exceeded. Try again later.", retry_after)
