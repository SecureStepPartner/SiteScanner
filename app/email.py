"""Email report delivery.

Phase 1 ships a stub provider that writes the email to a file under
`/tmp/sitescanner/emails/`. The interface is small so a real provider
(SES, Postmark, SendGrid, SMTP) can be swapped in without touching callers.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from app.config import settings
from app.models import ScanResult

log = logging.getLogger(__name__)


class EmailProvider(Protocol):
    async def send_report(self, to_address: str, result: ScanResult) -> None: ...


class StubEmailProvider:
    """Writes outgoing emails to disk for inspection during development."""

    def __init__(self, outbox: Path = Path("/tmp/sitescanner/emails")) -> None:
        self.outbox = outbox
        self.outbox.mkdir(parents=True, exist_ok=True)

    async def send_report(self, to_address: str, result: ScanResult) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{timestamp}_{result.job_id}.txt"
        path = self.outbox / filename
        body = _render_text(result, to_address)
        path.write_text(body, encoding="utf-8")
        log.info("Stub email written to %s", path)


def _render_text(result: ScanResult, to_address: str) -> str:
    lines = [
        f"To: {to_address}",
        f"From: {settings.email_from}",
        f"Subject: SecureStep scan report for {result.domain} ({result.status.value})",
        "",
        f"Scan ID:       {result.job_id}",
        f"Domain:        {result.domain}",
        f"Scan type:     {result.scan_type.value}",
        f"Status:        {result.status.value}",
        f"Started:       {result.created_at.isoformat()}",
        f"Finished:      {result.finished_at.isoformat() if result.finished_at else '-'}",
        "",
        "Summary:",
        f"  total:    {result.summary.total}",
        f"  critical: {result.summary.critical}",
        f"  high:     {result.summary.high}",
        f"  medium:   {result.summary.medium}",
        f"  low:      {result.summary.low}",
        f"  info:     {result.summary.info}",
        "",
        "Findings (top 50):",
    ]
    for f in result.findings[:50]:
        lines.append(f"  [{f.severity.value:>8}] {f.name} — {f.matched_at}")
    if result.error:
        lines += ["", f"Error: {result.error}"]
    return "\n".join(lines) + "\n"


def get_provider() -> EmailProvider:
    """Return the configured provider. Phase 1 only knows the stub."""
    if settings.email_provider == "stub":
        return StubEmailProvider()
    log.warning("Unknown EMAIL_PROVIDER=%r, falling back to stub.", settings.email_provider)
    return StubEmailProvider()
