"""AI-assisted report generation from normalized scan results."""

from __future__ import annotations

import asyncio
import json
import logging

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from app.config import settings
from app.models import Finding, ScanResult

log = logging.getLogger(__name__)


class FindingSummary(BaseModel):
    model_config = ConfigDict(extra="forbid")

    category: str
    finding: str
    severity: str
    business_risk: str
    recommended_action: str


class AiReport(BaseModel):
    model_config = ConfigDict(extra="forbid")

    narrative_assessment: list[str] = Field(min_length=1)
    overall_risk_posture: str
    priority_actions: list[str] = Field(min_length=1)
    finding_summaries: list[FindingSummary]
    closing_offer: str


async def generate_ai_report(result: ScanResult) -> AiReport | None:
    """Generate a human-readable report. Returns None when AI is unavailable."""
    if not settings.openai_api_key.strip():
        return None

    payload = _scan_payload(result)

    def _generate() -> str:
        from openai import OpenAI

        client = OpenAI(api_key=settings.openai_api_key)
        response = client.responses.create(
            model=settings.openai_model,
            instructions=_instructions(),
            input=json.dumps(payload, ensure_ascii=False),
            text={
                "format": {
                    "type": "json_schema",
                    "name": "vulnerability_assessment_report",
                    "strict": True,
                    "schema": AiReport.model_json_schema(),
                }
            },
            store=False,
        )
        return response.output_text

    try:
        content = await asyncio.to_thread(_generate)
        return AiReport.model_validate_json(content)
    except (ValidationError, json.JSONDecodeError):
        log.exception("OpenAI generated an invalid report payload for job %s", result.job_id)
    except Exception:
        log.exception("OpenAI report generation failed for job %s", result.job_id)
    return None


def _scan_payload(result: ScanResult) -> dict[str, object]:
    return {
        "job_id": result.job_id,
        "domain": result.domain,
        "scan_type": result.scan_type.value,
        "status": result.status.value,
        "created_at": result.created_at.isoformat(),
        "finished_at": result.finished_at.isoformat() if result.finished_at else None,
        "dashboard_url": result.dashboard_url,
        "error": result.error,
        "summary": result.summary.model_dump(),
        "findings": [_finding_payload(f) for f in result.findings[:50]],
    }


def _finding_payload(finding: Finding) -> dict[str, object]:
    return {
        "template_id": finding.template_id,
        "name": finding.name,
        "severity": finding.severity.value,
        "matched_at": finding.matched_at,
        "description": finding.description,
        "reference": finding.reference or [],
    }


def _instructions() -> str:
    return """
You write client-facing vulnerability assessment reports for non-technical business readers.
Use only the provided scan JSON. Do not invent vulnerabilities, hosts, evidence, tools, or
finding counts. If there are no findings, clearly say no findings were identified and explain
the limits of automated scanning.

Return JSON only. Requirements:
- narrative_assessment: 4 to 7 paragraphs, plain language, extensive but grounded in findings.
- overall_risk_posture: one concise paragraph beginning with "Overall risk posture: Low.",
  "Overall risk posture: Moderate.", or "Overall risk posture: High." as appropriate.
- priority_actions: 3 to 5 practical remediation actions.
- finding_summaries: one row per meaningful finding or finding category, using business impact
  language. Group similar findings when useful.
- closing_offer: a short client-facing closing offer for remediation planning.

Use severity and finding names from the scan result. For informational findings, explain why
they matter operationally without overstating risk.
""".strip()
