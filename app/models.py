"""Pydantic models — request, response, and internal scan records.

The request/response shapes here become the OpenAPI schema that the ChatGPT
App Builder Action consumes, so descriptions and examples matter.
"""

from datetime import datetime
from enum import Enum

from pydantic import BaseModel, EmailStr, Field


class ScanType(str, Enum):
    """Supported scan profiles. More can be added without API changes."""

    quick = "quick"
    standard = "standard"


class ScanStatus(str, Enum):
    """Lifecycle states for a scan job."""

    queued = "queued"
    running = "running"
    completed = "completed"
    partial = "partial"
    timed_out = "timed_out"
    failed = "failed"


class Severity(str, Enum):
    info = "info"
    low = "low"
    medium = "medium"
    high = "high"
    critical = "critical"
    unknown = "unknown"


class ScanRequest(BaseModel):
    """Payload sent by the ChatGPT App Builder Action to initiate a scan."""

    domain: str = Field(
        description="The target domain to scan, for example example.com.",
        examples=["example.com"],
        min_length=3,
        max_length=253,
    )
    email: EmailStr = Field(
        description="Email address that will receive the completed scan report.",
        examples=["security@example.com"],
    )
    scan_type: ScanType = Field(
        default=ScanType.quick,
        description="Scan profile. 'quick' uses a smaller template set; 'standard' is broader.",
    )


class ScanCreated(BaseModel):
    """Returned immediately when a scan is enqueued."""

    job_id: str = Field(description="Identifier used to retrieve scan status and results.")
    status: ScanStatus = Field(description="Initial job status.")
    message: str = Field(
        default="Scan accepted. Poll GET /scans/{job_id} for status and results.",
    )


class Finding(BaseModel):
    """A single Nuclei finding, normalized into our response schema."""

    template_id: str
    name: str
    severity: Severity
    matched_at: str
    description: str | None = None
    reference: list[str] | None = None


class ScanSummary(BaseModel):
    """Counts of findings, grouped by severity."""

    total: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    info: int = 0


class ScanResult(BaseModel):
    """Full result payload returned once a scan is in a terminal state."""

    job_id: str
    domain: str
    scan_type: ScanType
    status: ScanStatus
    created_at: datetime
    finished_at: datetime | None = None
    summary: ScanSummary = Field(default_factory=ScanSummary)
    findings: list[Finding] = Field(default_factory=list)
    error: str | None = None
    dashboard_url: str | None = None
    schema_version: str = Field(default="1.0")
