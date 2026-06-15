"""Redis-backed job state.

Each scan is stored as a single Redis hash at key `scan:{job_id}`. The hash
contains JSON-encoded fields; this keeps reads atomic and avoids schema drift
when fields are added later.
"""

from __future__ import annotations

import json
from datetime import datetime, timezone
from typing import Any

from redis.asyncio import Redis

from app.models import ScanResult, ScanStatus, ScanType

KEY_PREFIX = "scan:"
RESULT_TTL_SECONDS = 7 * 24 * 3600  # keep results for a week


def _key(job_id: str) -> str:
    return f"{KEY_PREFIX}{job_id}"


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


async def create_job(
    redis: Redis,
    *,
    job_id: str,
    domain: str,
    email: str,
    scan_type: ScanType,
) -> None:
    """Insert a new scan record in the `queued` state."""
    payload: dict[str, Any] = {
        "job_id": job_id,
        "domain": domain,
        "email": email,
        "scan_type": scan_type.value,
        "status": ScanStatus.queued.value,
        "created_at": _now(),
        "finished_at": "",
        "result": "",
        "error": "",
    }
    await redis.hset(_key(job_id), mapping=payload)
    await redis.expire(_key(job_id), RESULT_TTL_SECONDS)


async def set_status(redis: Redis, job_id: str, status: ScanStatus) -> None:
    await redis.hset(_key(job_id), "status", status.value)


async def set_result(
    redis: Redis,
    job_id: str,
    *,
    status: ScanStatus,
    result: ScanResult | None = None,
    error: str | None = None,
) -> None:
    """Write a terminal status with result or error."""
    mapping: dict[str, str] = {
        "status": status.value,
        "finished_at": _now(),
    }
    if result is not None:
        mapping["result"] = result.model_dump_json()
    if error is not None:
        mapping["error"] = error
    await redis.hset(_key(job_id), mapping=mapping)


async def get_job(redis: Redis, job_id: str) -> dict[str, str] | None:
    raw = await redis.hgetall(_key(job_id))
    if not raw:
        return None
    return {
        (k.decode() if isinstance(k, bytes) else k): (v.decode() if isinstance(v, bytes) else v)
        for k, v in raw.items()
    }


def parse_result_field(value: str | None) -> ScanResult | None:
    if not value:
        return None
    try:
        return ScanResult.model_validate_json(value)
    except (ValueError, json.JSONDecodeError):
        return None
