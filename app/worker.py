"""arq worker — pulls scan jobs off Redis and runs them.

The worker process is launched separately from the API:

    arq app.worker.WorkerSettings
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone

from arq.connections import RedisSettings

from app.config import settings
from app.email import get_provider
from app.models import ScanResult, ScanStatus, ScanType
from app.parser import parse_jsonl
from app.scanner import run_nuclei
from app.store import get_job, set_result, set_status
from app.validators import to_target_url

log = logging.getLogger(__name__)


async def run_scan(ctx: dict, job_id: str) -> None:
    """Worker entrypoint for a single scan job.

    The job record is already in Redis (created by the API). This task moves
    it through `running` and into a terminal state.
    """
    redis = ctx["redis"]
    record = await get_job(redis, job_id)
    if record is None:
        log.error("run_scan: job %s not found in Redis", job_id)
        return

    await set_status(redis, job_id, ScanStatus.running)

    domain = record["domain"]
    email = record["email"]
    scan_type = ScanType(record["scan_type"])
    created_at = datetime.fromisoformat(record["created_at"])

    try:
        outcome = await run_nuclei(
            job_id=job_id,
            target_url=to_target_url(domain),
            scan_type=scan_type,
        )
    except Exception as exc:  # noqa: BLE001 — final safety net
        log.exception("run_scan: nuclei runner crashed for %s", job_id)
        await set_result(
            redis,
            job_id,
            status=ScanStatus.failed,
            error=f"runner_crash: {exc}",
        )
        return

    findings, summary = parse_jsonl(outcome.jsonl_path)

    if outcome.timed_out:
        status = ScanStatus.partial if findings else ScanStatus.timed_out
        error = "Scan exceeded the configured timeout."
    elif outcome.completed:
        status = ScanStatus.completed
        error = None
    else:
        status = ScanStatus.failed
        error = outcome.stderr_tail or f"nuclei exit code {outcome.return_code}"

    result = ScanResult(
        job_id=job_id,
        domain=domain,
        scan_type=scan_type,
        status=status,
        created_at=created_at,
        finished_at=datetime.now(timezone.utc),
        summary=summary,
        findings=findings,
        error=error,
        dashboard_url=outcome.dashboard_url,
    )

    await set_result(redis, job_id, status=status, result=result, error=error)

    try:
        await get_provider().send_report(email, result)
    except Exception:
        log.exception("Failed to send report email for job %s", job_id)


class WorkerSettings:
    """arq picks up this class via the CLI: `arq app.worker.WorkerSettings`."""

    functions = [run_scan]
    redis_settings = RedisSettings.from_dsn(settings.redis_url)
    max_jobs = settings.max_concurrent_scans
    job_timeout = settings.scan_timeout_seconds + 60
    keep_result = 0  # we persist results ourselves in scan:* hashes
