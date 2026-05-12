"""Parse the Nuclei JSONL output into our response schema."""

from __future__ import annotations

import json
from pathlib import Path

from app.models import Finding, ScanSummary, Severity


def parse_jsonl(path: Path) -> tuple[list[Finding], ScanSummary]:
    """Read a Nuclei JSONL file and return findings + a severity summary.

    Nuclei may write the file incrementally during a scan; this parser is
    line-tolerant — it silently skips empty lines and lines that fail JSON
    decoding so that a partial result on timeout still yields useful output.
    """
    findings: list[Finding] = []

    if not path.exists():
        return findings, ScanSummary()

    with path.open("r", encoding="utf-8", errors="replace") as f:
        for line in f:
            line = line.strip()
            if not line:
                continue
            try:
                row = json.loads(line)
            except json.JSONDecodeError:
                continue

            finding = _row_to_finding(row)
            if finding is not None:
                findings.append(finding)

    return findings, _summarize(findings)


def _row_to_finding(row: dict) -> Finding | None:
    info = row.get("info") or {}
    severity_raw = (info.get("severity") or "unknown").lower()
    try:
        severity = Severity(severity_raw)
    except ValueError:
        severity = Severity.unknown

    template_id = row.get("template-id") or row.get("template_id") or "unknown"
    name = info.get("name") or template_id
    matched_at = (
        row.get("matched-at")
        or row.get("matched_at")
        or row.get("host")
        or ""
    )
    description = info.get("description")
    references = info.get("reference") or info.get("references")

    return Finding(
        template_id=template_id,
        name=name,
        severity=severity,
        matched_at=matched_at,
        description=description,
        reference=list(references) if isinstance(references, list) else None,
    )


def _summarize(findings: list[Finding]) -> ScanSummary:
    summary = ScanSummary(total=len(findings))
    for f in findings:
        match f.severity:
            case Severity.critical:
                summary.critical += 1
            case Severity.high:
                summary.high += 1
            case Severity.medium:
                summary.medium += 1
            case Severity.low:
                summary.low += 1
            case Severity.info:
                summary.info += 1
            case _:
                pass
    return summary
