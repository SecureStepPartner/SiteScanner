import asyncio
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.config import Settings
from app.email import StubEmailProvider
from app.main import app, health
from app.models import Finding, ScanResult, ScanStatus, ScanSummary, ScanType, Severity


def test_health_endpoint_returns_ok() -> None:
    response = asyncio.run(health())

    assert response.status == "ok"


def test_openapi_exposes_scan_routes() -> None:
    schema = app.openapi()

    assert "/scan" in schema["paths"]
    assert "/scan/{scan_id}" in schema["paths"]


def test_scan_timeout_is_capped_at_15_minutes() -> None:
    with pytest.raises(ValidationError):
        Settings(scan_timeout_seconds=901)

    settings = Settings(scan_timeout_seconds=900)
    assert settings.scan_timeout_seconds == 900


def test_stub_email_provider_writes_report(tmp_path) -> None:
    result = ScanResult(
        job_id="job-123",
        domain="example.com",
        scan_type=ScanType.quick,
        status=ScanStatus.completed,
        created_at=datetime(2026, 5, 20, 0, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 5, 20, 0, 10, tzinfo=timezone.utc),
        summary=ScanSummary(total=1, high=1),
        findings=[
            Finding(
                template_id="http-missing-security-headers",
                name="Missing security headers",
                severity=Severity.high,
                matched_at="https://example.com",
            )
        ],
    )

    provider = StubEmailProvider(outbox=tmp_path)
    asyncio.run(provider.send_report("user@example.com", result))

    written_files = list(tmp_path.iterdir())
    assert len(written_files) == 1
    body = written_files[0].read_text(encoding="utf-8")
    assert "SecureStep scan report" in body
    assert "user@example.com" in body
    assert "example.com" in body
