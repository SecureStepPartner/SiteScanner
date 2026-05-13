"""Scan endpoints — initiate scans, poll status, and list recent scans."""

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


def _result_from_record(record: dict[str, str]) -> ScanResult:
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


@router.post(
    "/scan",
    response_model=ScanCreated,
    status_code=status.HTTP_202_ACCEPTED,
    operation_id="create_scan_scan_post",
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


@router.post(
    "/scans",
    include_in_schema=False,
    dependencies=[Depends(require_api_key)],
)
async def create_scan_alias(payload: ScanRequest) -> ScanCreated:
    return await create_scan(payload)


@router.get(
    "/scan/{scan_id}",
    response_model=ScanResult,
    operation_id="read_scan_scan__scan_id__get",
    summary="Get scan status and results",
    dependencies=[Depends(require_api_key)],
)
async def get_scan(scan_id: str) -> ScanResult:
    """Return the current state of a scan, including findings when terminal."""
    pool = await _get_pool()
    record = await get_job(pool, scan_id)
    if record is None:
        raise HTTPException(status_code=404, detail=f"Scan {scan_id} not found.")

    return _result_from_record(record)


@router.get(
    "/scans/{scan_id}",
    include_in_schema=False,
    dependencies=[Depends(require_api_key)],
)
async def get_scan_alias(scan_id: str) -> ScanResult:
    return await get_scan(scan_id)


@router.get(
    "/scans",
    response_model=list[ScanResult],
    operation_id="read_scans_scans_get",
    summary="List recent scans",
    dependencies=[Depends(require_api_key)],
)
async def list_scans() -> list[ScanResult]:
    """Return all stored scan records from Redis."""
    pool = await _get_pool()
    results: list[ScanResult] = []
    async for key in pool.scan_iter(match="scan:*"):
        raw_key = key.decode() if isinstance(key, bytes) else key
        job_id = raw_key.removeprefix("scan:")
        record = await get_job(pool, job_id)
        if record is not None:
            results.append(_result_from_record(record))

    results.sort(key=lambda item: item.created_at, reverse=True)
    return results
