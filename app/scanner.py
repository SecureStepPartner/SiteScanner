"""Nuclei subprocess execution with wall-clock timeout and process-group cleanup.

The scanner is the single dangerous component of the service: it runs an
external program against an externally supplied URL. The safety properties it
must guarantee:

  * Inputs are passed as argv items — never interpolated into a shell command.
  * The child runs in its own process group (start_new_session=True) so the
    entire tree, including any helper processes Nuclei spawns, can be killed
    together.
  * A wall-clock timeout is enforced from Python via asyncio.wait_for. On
    expiry we SIGTERM the group, wait briefly, then SIGKILL. Whatever JSONL
    output Nuclei wrote before termination remains on disk for parsing.
"""

from __future__ import annotations

import asyncio
import logging
import os
import signal
from dataclasses import dataclass
from pathlib import Path

from app.config import settings
from app.models import ScanType

log = logging.getLogger(__name__)

ARTIFACT_ROOT = Path("/tmp/sitescanner")
NUCLEI_BIN = "nuclei"

# Per-profile flag sets. Phase 1 keeps these conservative; Phase 3 can add
# tag-curated profiles informed by client_scan.sh.
PROFILES: dict[ScanType, list[str]] = {
    ScanType.quick: [
        "-rl", "30",
        "-c", "20",
        "-timeout", "5",
        "-retries", "1",
        "-severity", "critical,high,medium,low,info",
        "-stats",
    ],
    ScanType.standard: [
        "-rl", "30",
        "-c", "20",
        "-timeout", "5",
        "-retries", "1",
        "-severity", "critical,high,medium,low,info",
        "-tags", "exposure,misconfig,tech,panel,tls,dns,cve",
        "-etags", "intrusive,fuzz,ssrf,fileupload,rce,oast,dos,bruteforce",
        "-stats",
    ],
}

SIGTERM_GRACE_SECONDS = 10.0


@dataclass
class ScanOutcome:
    completed: bool       # True if Nuclei exited on its own
    timed_out: bool       # True if wall clock fired
    return_code: int | None
    jsonl_path: Path
    stderr_tail: str


async def run_nuclei(
    *,
    job_id: str,
    target_url: str,
    scan_type: ScanType,
    timeout_seconds: int | None = None,
) -> ScanOutcome:
    """Run Nuclei against `target_url` and return where the JSONL landed.

    Always returns — even on timeout — so the caller can parse whatever
    partial output was written. Never raises on Nuclei errors; the caller
    inspects `completed` and `return_code` to decide the final status.
    """
    timeout = timeout_seconds or settings.scan_timeout_seconds

    job_dir = ARTIFACT_ROOT / job_id
    job_dir.mkdir(parents=True, exist_ok=True)
    jsonl_path = job_dir / "nuclei.jsonl"
    stderr_path = job_dir / "nuclei.stderr"

    argv = _build_argv(target_url=target_url, scan_type=scan_type, jsonl_path=jsonl_path)
    env = _build_env()

    log.info("Launching nuclei for job %s: %s", job_id, " ".join(argv))

    stderr_file = stderr_path.open("wb")
    try:
        proc = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.DEVNULL,
            stderr=stderr_file,
            start_new_session=True,
            env=env,
        )
    except FileNotFoundError as exc:
        stderr_file.close()
        log.error("Nuclei binary not found: %s", exc)
        return ScanOutcome(
            completed=False,
            timed_out=False,
            return_code=None,
            jsonl_path=jsonl_path,
            stderr_tail=f"nuclei binary not found: {exc}",
        )

    timed_out = False
    try:
        return_code = await asyncio.wait_for(proc.wait(), timeout=timeout)
    except asyncio.TimeoutError:
        timed_out = True
        return_code = await _terminate_group(proc)
    finally:
        stderr_file.close()

    return ScanOutcome(
        completed=not timed_out and return_code == 0,
        timed_out=timed_out,
        return_code=return_code,
        jsonl_path=jsonl_path,
        stderr_tail=_tail(stderr_path),
    )


def _build_argv(*, target_url: str, scan_type: ScanType, jsonl_path: Path) -> list[str]:
    base = [
        NUCLEI_BIN,
        "-u", target_url,
        "-jsonl",
        "-o", str(jsonl_path),
    ]
    base.extend(PROFILES.get(scan_type, PROFILES[ScanType.quick]))
    if settings.pdcp_api_key:
        base.append("-dashboard")
    return base


def _build_env() -> dict[str, str]:
    env = os.environ.copy()
    if settings.pdcp_api_key:
        env["PDCP_API_KEY"] = settings.pdcp_api_key
    return env


async def _terminate_group(proc: asyncio.subprocess.Process) -> int | None:
    """SIGTERM the process group, grace-wait, then SIGKILL if still alive."""
    try:
        pgid = os.getpgid(proc.pid)
    except ProcessLookupError:
        return proc.returncode

    log.warning("Scan timed out; SIGTERM to process group %s", pgid)
    try:
        os.killpg(pgid, signal.SIGTERM)
    except ProcessLookupError:
        return proc.returncode

    try:
        return await asyncio.wait_for(proc.wait(), timeout=SIGTERM_GRACE_SECONDS)
    except asyncio.TimeoutError:
        log.warning("SIGTERM grace expired; SIGKILL to process group %s", pgid)
        try:
            os.killpg(pgid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        try:
            return await asyncio.wait_for(proc.wait(), timeout=5.0)
        except asyncio.TimeoutError:
            return None


def _tail(path: Path, limit: int = 2000) -> str:
    if not path.exists():
        return ""
    try:
        data = path.read_bytes()
    except OSError:
        return ""
    if len(data) > limit:
        data = data[-limit:]
    return data.decode("utf-8", errors="replace")
