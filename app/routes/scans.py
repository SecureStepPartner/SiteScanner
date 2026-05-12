"""Scan endpoints — POST /scans (initiate) and GET /scans/{job_id} (status)."""

from __future__ import annotations

import uuid
from datetime import datetime

from arq import create_pool
from arq.connections import ArqRedis, RedisSettings
from fastapi import APIRouter, Depends, HTTPException, status

from app.auth import require_api_key
from app.config import settings
from app.models import (
    ScanCreated,
    ScanRequest,
    ScanResult,
    ScanStatus,
    ScanSummary,
    ScanType,
)
from app.store import create_job, get_job, parse_result_field
from app.validators import DomainValidationError, normalize_domain

router = APIRouter(tags=["scans"])

_arq_pool: ArqRedis | None = None


async def _get_pool() -> ArqRedis:
    global _arq_pool
    if _arq_pool is None:
        _arq_pool = await create_pool(RedisSettings.from_dsn(settings.redis_url))
    return _arq_pool


@router.post(
    "/scans",
    response_model=ScanCreated,
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="create_scan",
    summary="Initiate a vulnerability scan",
    dependencies=[Depends(require_api_key)],
)
async def create_scan(payload: ScanRequest) -> ScanCreated:
    """Enqueue a scan and return a job_id for polling."""
    try:
        domain = normalize_domain(payload.domain)
    except DomainValidationError as exc:
        raise HTTPException(status_code=400, detail=str(exc)) from exc

    job_id = uuid.uuid4().hex
    pool = await _get_pool()

    await create_job(
        pool,
        job_id=job_id,
        domain=domain,
        email=payload.email,
        scan_type=payload.scan_type,
    )
    await pool.enqueue_job("run_scan", job_id, _job_id=job_id)

    return ScanCreated(job_id=job_id, status=ScanStatus.queued)


@router.get(
    "/scans/{job_id}",
    response_model=ScanResult,
    operation_id="get_scan",
    summary="Get scan status and results",
    dependencies=[Depends(require_api_key)],
)
async def get_scan(job_id: str) -> ScanResult:
    """Return the current state of a scan, including findings when terminal."""
    pool = await _get_pool()
    record = await get_job(pool, job_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Scan {job_id} not found.")

    persisted = parse_result_field(record.get("result"))
    if persisted is not None:
        return persisted

    return ScanResult(
        job_id=record["job_id"],
        domain=record["domain"],
        scan_type=ScanType(record["scan_type"]),
        status=ScanStatus(record["status"]),
        created_at=datetime.fromisoformat(record["created_at"]),
        finished_at=(
            datetime.fromisoformat(record["finished_at"])
            if record.get("finished_at")
            else None
        ),
        summary=ScanSummary(),
        findings=[],
        error=record.get("error") or None,
    )
