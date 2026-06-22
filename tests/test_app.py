import asyncio
import socket
from datetime import datetime, timezone

import pytest
from pydantic import ValidationError

from app.auth import _extract_key
from app.config import Settings
from app.email import StubEmailProvider
from app.main import app, health
from app.models import Finding, ScanResult, ScanStatus, ScanSummary, ScanType, Severity
from app.reporting import AiReport, FindingSummary
from app.validators import DomainValidationError, normalize_domain, validate_public_dns_resolution


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


def test_domain_validation_blocks_internal_targets() -> None:
    assert normalize_domain(" HTTPS://Example.com/path ") == "example.com"

    for value in ["127.0.0.1", "localhost", "service.local", "10.0.0.1"]:
        with pytest.raises(DomainValidationError):
            normalize_domain(value)


def test_dns_validation_allows_public_resolution(monkeypatch) -> None:
    def fake_getaddrinfo(*args, **kwargs):
        return [
            (socket.AF_INET, socket.SOCK_STREAM, 6, "", ("93.184.216.34", 0)),
            (socket.AF_INET6, socket.SOCK_STREAM, 6, "", ("2606:2800:220:1:248:1893:25c8:1946", 0)),
        ]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    assert validate_public_dns_resolution("example.com") == [
        "2606:2800:220:1:248:1893:25c8:1946",
        "93.184.216.34",
    ]


def test_dns_validation_blocks_unsafe_resolution(monkeypatch) -> None:
    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("10.0.0.5", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(DomainValidationError, match="unsafe"):
        validate_public_dns_resolution("example.com")


def test_dns_validation_blocks_metadata_resolution(monkeypatch) -> None:
    def fake_getaddrinfo(*args, **kwargs):
        return [(socket.AF_INET, socket.SOCK_STREAM, 6, "", ("169.254.169.254", 0))]

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(DomainValidationError, match="unsafe"):
        validate_public_dns_resolution("example.com")


def test_dns_validation_fails_closed_on_resolution_error(monkeypatch) -> None:
    def fake_getaddrinfo(*args, **kwargs):
        raise socket.gaierror("not found")

    monkeypatch.setattr(socket, "getaddrinfo", fake_getaddrinfo)

    with pytest.raises(DomainValidationError, match="could not be resolved"):
        validate_public_dns_resolution("missing.example")


def test_auth_extracts_supported_api_key_headers() -> None:
    assert _extract_key(bearer=None, x_api_key="abc123") == "abc123"


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
    assert "Scan Report: example.com" in body
    assert "Vulnerability Assessment Report" in body
    assert "user@example.com" in body
    assert "example.com" in body
    assert "Narrative Assessment" in body
    assert "Overall Risk Posture" in body
    assert "Priority Actions" in body
    assert "Findings Summary Table" in body
    assert "security headers" in body.lower()


def test_stub_email_provider_uses_ai_report_when_available(tmp_path) -> None:
    result = ScanResult(
        job_id="job-456",
        domain="example.com",
        scan_type=ScanType.standard,
        status=ScanStatus.completed,
        created_at=datetime(2026, 5, 20, 0, 0, tzinfo=timezone.utc),
        finished_at=datetime(2026, 5, 20, 0, 10, tzinfo=timezone.utc),
        summary=ScanSummary(total=1, low=1),
    )
    report = AiReport(
        narrative_assessment=["Human readable client summary from OpenAI."],
        overall_risk_posture="Overall risk posture: Low.",
        priority_actions=["Implement recommended hardening controls."],
        finding_summaries=[
            FindingSummary(
                category="Web Security",
                finding="Missing HTTP security headers",
                severity="Low",
                business_risk="Reduced browser-side protection.",
                recommended_action="Add a hardened HTTP header baseline.",
            )
        ],
        closing_offer="We can walk through the findings in a review session.",
    )

    provider = StubEmailProvider(outbox=tmp_path)
    asyncio.run(provider.send_report("user@example.com", result, report))

    body = next(tmp_path.iterdir()).read_text(encoding="utf-8")
    assert "Human readable client summary from OpenAI." in body
    assert "Overall risk posture: Low." in body
    assert "We can walk through the findings" in body
