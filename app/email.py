"""Email report delivery.

The service supports Resend for production delivery and a stub provider that
writes the email to a file under `/tmp/sitescanner/emails/` for local use.
"""

from __future__ import annotations

import asyncio
import json
import logging
import urllib.error
import urllib.request
from datetime import datetime, timezone
from pathlib import Path
from typing import Protocol

from app.config import settings
from app.models import ScanResult
from app.reporting import AiReport, FindingSummary

log = logging.getLogger(__name__)


class EmailProvider(Protocol):
    async def send_report(
        self,
        to_address: str,
        result: ScanResult,
        report: AiReport | None = None,
    ) -> None: ...


class StubEmailProvider:
    """Writes outgoing emails to disk for inspection during development."""

    def __init__(self, outbox: Path = Path("/tmp/sitescanner/emails")) -> None:
        self.outbox = outbox
        self.outbox.mkdir(parents=True, exist_ok=True)

    async def send_report(
        self,
        to_address: str,
        result: ScanResult,
        report: AiReport | None = None,
    ) -> None:
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"{timestamp}_{result.job_id}.txt"
        path = self.outbox / filename
        body = _render_text(result, to_address, report)
        path.write_text(body, encoding="utf-8")
        log.info("Stub email written to %s", path)


class ResendEmailProvider:
    """Send scan reports through Resend."""

    def __init__(self, api_key: str, from_address: str) -> None:
        self.api_key = api_key.strip()
        self.from_address = from_address.strip()

    async def send_report(
        self,
        to_address: str,
        result: ScanResult,
        report: AiReport | None = None,
    ) -> None:
        if not self.api_key:
            raise RuntimeError("RESEND_API_KEY is not configured.")

        payload = _render_resend_payload(result, to_address, self.from_address, report)
        await _post_resend_email(self.api_key, payload)


def _overall_risk_posture(result: ScanResult) -> str:
    if result.summary.critical or result.summary.high:
        return "High"
    if result.summary.medium:
        return "Moderate"
    return "Low"


def _narrative_assessment(result: ScanResult) -> str:
    total = result.summary.total
    if total == 0:
        return (
            "The automated scan completed without identifying any findings in the "
            "selected template set. In plain terms, no obvious externally visible "
            "issues were detected during this pass. That is a positive result, but "
            "it only covers what an automated external review can observe."
        )

    high_risk = result.summary.critical + result.summary.high
    if high_risk:
        return (
            f"The scan identified {high_risk} high-risk finding"
            f"{'s' if high_risk != 1 else ''}, which deserves prompt attention. "
            "Issues in this category can be directly exploitable or can materially "
            "increase the chance of compromise, disruption, or data exposure."
        )

    if result.summary.medium:
        return (
            "The scan did not identify critical or high-risk findings, but it did "
            "surface medium-severity items. These are usually not immediate break-in "
            "paths on their own, but they can weaken defenses and should be reviewed "
            "before attackers can combine them with other weaknesses."
        )

    return (
        "The scan mainly surfaced informational or low-severity items. In plain "
        "terms, this points more toward hardening opportunities than immediate "
        "compromise paths, but addressing them still reduces the attack surface "
        "and makes future exploitation more difficult."
    )


def _priority_actions(result: ScanResult) -> list[str]:
    actions: list[str] = []
    findings_text = " ".join(
        filter(
            None,
            [
                " ".join(
                    filter(
                        None,
                        [f.name, f.description or "", " ".join(f.reference or [])],
                    )
                ).lower()
                for f in result.findings[:10]
            ],
        )
    )

    if result.summary.critical or result.summary.high:
        actions.append(
            "Review and remediate the critical and high-severity findings first, "
            "because they are the most likely to have immediate business impact."
        )

    if "header" in findings_text or "csp" in findings_text or "clickjacking" in findings_text:
        actions.append(
            "Implement a baseline set of HTTP security headers, including a "
            "Content Security Policy, clickjacking protection, HSTS where "
            "appropriate, X-Content-Type-Options, and Referrer-Policy."
        )

    if "cookie" in findings_text or "samesite" in findings_text:
        actions.append(
            "Update cookies to use the safest compatible SameSite setting, and "
            "confirm Secure and HttpOnly are enabled for session-related cookies."
        )

    if "tls" in findings_text or "certificate" in findings_text:
        actions.append(
            "Validate TLS settings and certificate coverage, including modern "
            "protocol support, certificate scope, and renewal monitoring."
        )

    if "dns" in findings_text or "caa" in findings_text:
        actions.append(
            "Review DNS and certificate governance records so approved domains and "
            "issuers stay aligned with operational requirements."
        )

    if "waf" in findings_text:
        actions.append(
            "Confirm perimeter protections such as a WAF are actively enforced and "
            "tuned for the most important application routes."
        )

    if not actions:
        if result.summary.total == 0:
            actions.extend(
                [
                    "Continue routine patching and monitoring so the site stays current.",
                    "Repeat the assessment periodically, ideally with a broader scan "
                    "profile or authenticated testing where appropriate.",
                    "Review browser-facing protections such as security headers and "
                    "cookie settings as part of ongoing hardening.",
                ]
            )
        else:
            actions.extend(
                [
                    "Review the findings table and validate which items are real "
                    "issues versus informational observations.",
                    "Tackle configuration hardening items that reduce exposure even "
                    "when there is no direct exploit path.",
                    "Repeat the scan after remediation to confirm the risk has been "
                    "reduced.",
                ]
            )

    return actions[:5]


def _render_text(result: ScanResult, to_address: str, report: AiReport | None = None) -> str:
    narrative = report.narrative_assessment if report else [_narrative_assessment(result)]
    risk_posture = report.overall_risk_posture if report else _overall_risk_posture(result)
    actions = report.priority_actions if report else _priority_actions(result)
    finding_summaries = report.finding_summaries if report else _fallback_finding_summaries(result)

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
        f"Dashboard:     {result.dashboard_url or '-'}",
        "",
        "Summary:",
        f"  total:    {result.summary.total}",
        f"  critical: {result.summary.critical}",
        f"  high:     {result.summary.high}",
        f"  medium:   {result.summary.medium}",
        f"  low:      {result.summary.low}",
        f"  info:     {result.summary.info}",
        "",
        "1. Narrative Assessment:",
        *[f"  {paragraph}" for paragraph in narrative],
        "",
        "2. Overall Risk Posture:",
        f"  {risk_posture}",
        "",
        "3. Priority Actions:",
    ]
    for index, action in enumerate(actions, start=1):
        lines.append(f"  {index}. {action}")
    lines += [
        "",
        "4. Findings Summary Table:",
    ]
    for row in finding_summaries:
        lines.append(
            f"  [{row.severity}] {row.category}: {row.finding} | "
            f"Risk: {row.business_risk} | Action: {row.recommended_action}"
        )
    if not finding_summaries:
        lines.append("  No findings")
    closing_offer = report.closing_offer if report else _default_closing_offer()
    lines += [
        "",
        "5. Closing Offer:",
        f"  {closing_offer}",
        "",
        "This report was generated automatically. Analysis powered by OpenAI.",
        "This scan may not detect all vulnerabilities. "
        "A clean report does not guarantee complete security.",
    ]
    if settings.schedule_meeting_url:
        lines += ["", f"Schedule a meeting: {settings.schedule_meeting_url}"]
    if result.error:
        lines += ["", f"Error: {result.error}"]
    if result.dashboard_url:
        lines += ["", f"Dashboard URL: {result.dashboard_url}"]
    return "\n".join(lines) + "\n"


def get_provider() -> EmailProvider:
    """Return the configured provider."""
    if settings.email_provider == "stub":
        return StubEmailProvider()
    if settings.email_provider == "resend":
        return ResendEmailProvider(
            api_key=settings.resend_api_key,
            from_address=settings.email_from,
        )
    log.warning("Unknown EMAIL_PROVIDER=%r, falling back to stub.", settings.email_provider)
    return StubEmailProvider()


def _render_resend_payload(
    result: ScanResult,
    to_address: str,
    from_address: str,
    report: AiReport | None = None,
) -> dict[str, object]:
    subject = f"SecureStep scan report for {result.domain} ({result.status.value})"
    text_body = _render_text(result, to_address, report)
    html_body = _render_html(result, to_address, report)
    payload: dict[str, object] = {
        "from": from_address,
        "to": [to_address],
        "subject": subject,
        "text": text_body,
        "html": html_body,
    }
    return payload


def _render_html(result: ScanResult, to_address: str, report: AiReport | None = None) -> str:
    brand_color = "#1a237e"
    narrative = report.narrative_assessment if report else [_narrative_assessment(result)]
    risk_posture = report.overall_risk_posture if report else _overall_risk_posture(result)
    actions = report.priority_actions if report else _priority_actions(result)
    finding_summaries = report.finding_summaries if report else _fallback_finding_summaries(result)
    findings_rows = []
    for row in finding_summaries:
        findings_rows.append(
            "<tr>"
            f"<td>{_escape(row.category)}</td>"
            f"<td>{_escape(row.finding)}</td>"
            f"<td style='font-weight:700;color:{_severity_color(row.severity)};'>"
            f"{_escape(row.severity)}</td>"
            f"<td>{_escape(row.business_risk)}</td>"
            f"<td>{_escape(row.recommended_action)}</td>"
            "</tr>"
        )

    findings_html = "".join(findings_rows) or "<tr><td colspan='5'>No findings</td></tr>"
    dashboard = _escape(result.dashboard_url) if result.dashboard_url else "-"
    error = f"<p><strong>Error:</strong> {_escape(result.error)}</p>" if result.error else ""
    completed = result.finished_at.strftime("%Y-%m-%d %H:%M:%S UTC") if result.finished_at else "-"
    meeting_button = ""
    if settings.schedule_meeting_url:
        meeting_button = (
            f"<p><a href='{_escape(settings.schedule_meeting_url)}' "
            f"style='display:inline-block;background:{brand_color};color:#fff;"
            "padding:10px 14px;text-decoration:none;border-radius:4px;"
            "font-weight:700;'>Schedule a meeting</a></p>"
        )
    closing_offer = _escape(report.closing_offer if report else _default_closing_offer())

    return f"""
<!doctype html>
<html>
  <body style="font-family: Arial, sans-serif; color: #111; margin:0; padding:0;">
    <div style="max-width: 760px; margin:0 auto; padding: 18px 20px;">
      <h1 style="background:{brand_color}; color:#fff; margin:0; padding:8px 10px; font-size:24px;">
        Vulnerability Assessment Report
      </h1>
      <h2 style="background:{brand_color}; color:#fff; margin:8px 0 18px;
                 padding:6px 10px; font-size:16px;">
        Security scan results for {_escape(result.domain)}
      </h2>
      <table style="width:100%; border-collapse:collapse; margin-bottom:28px;">
        <tr>
          <td><strong>Scan ID:</strong> {_escape(result.job_id)}</td>
          <td style="text-align:right;"><strong>Completed:</strong> {_escape(completed)}</td>
        </tr>
        <tr>
          <td><strong>Severities:</strong> critical, high, medium, low, info</td>
          <td style="text-align:right;"><strong>Findings:</strong> {result.summary.total}</td>
        </tr>
        <tr>
          <td><strong>Status:</strong> {_escape(result.status.value)}</td>
          <td style="text-align:right;"><strong>Dashboard:</strong> {dashboard}</td>
        </tr>
      </table>
      {error}
      <h3>1. Narrative Assessment</h3>
      {"".join(f"<p>{_escape(paragraph)}</p>" for paragraph in narrative)}
      <h3>2. Overall Risk Posture</h3>
      <p>{_escape(risk_posture)}</p>
      <h3>3. Priority Actions</h3>
      <ol>
      {"".join(f"<li>{_escape(action)}</li>" for action in actions)}
      </ol>
      <h3>4. Findings Summary Table</h3>
      <table cellpadding="8" cellspacing="0"
             style="width:100%; border-collapse:collapse; border:1px solid #ddd;">
        <thead>
          <tr style="background:#f5f5f5;">
            <th style="border:1px solid #ddd; text-align:left;">Category</th>
            <th style="border:1px solid #ddd; text-align:left;">Finding</th>
            <th style="border:1px solid #ddd; text-align:left;">Severity</th>
            <th style="border:1px solid #ddd; text-align:left;">Business Risk</th>
            <th style="border:1px solid #ddd; text-align:left;">Recommended Action</th>
          </tr>
        </thead>
        <tbody>
          {findings_html}
        </tbody>
      </table>
      <h3>5. Closing Offer</h3>
      <p>{closing_offer}</p>
      <p>
        If helpful, we can provide a board-ready one-page summary, a remediation roadmap,
        or a technical remediation checklist for your IT or engineering team.
      </p>
      {meeting_button}
      <p style="color:#777; font-size:13px;">
        This report was generated automatically. Analysis powered by OpenAI.
      </p>
      <p style="color:#777; font-size:13px;">
        Warning: This scan may not detect all vulnerabilities. A clean report does not
        guarantee complete security.
      </p>
    </div>
  </body>
</html>
""".strip()


def _fallback_finding_summaries(result: ScanResult) -> list[FindingSummary]:
    return [
        FindingSummary(
            category=_category_for_finding(f.name, f.template_id),
            finding=f.name,
            severity=f.severity.value.title(),
            business_risk=f.description or "This finding may indicate a security hardening gap.",
            recommended_action=(
                "Review the affected endpoint and apply the recommended remediation."
            ),
        )
        for f in result.findings[:50]
    ]


def _category_for_finding(name: str, template_id: str) -> str:
    text = f"{name} {template_id}".lower()
    if "tls" in text or "ssl" in text or "certificate" in text:
        return "Cryptographic"
    if "dns" in text or "cname" in text or "caa" in text:
        return "DNS Security"
    if "cookie" in text or "header" in text or "xss" in text or "clickjacking" in text:
        return "Web Security"
    if "waf" in text or "technology" in text:
        return "Infrastructure Security"
    return "Security Finding"


def _severity_color(severity: str) -> str:
    normalized = severity.lower()
    if normalized in {"critical", "high"}:
        return "#b71c1c"
    if normalized == "medium":
        return "#e65100"
    if normalized == "low":
        return "#0d47a1"
    return "#455a64"


def _default_closing_offer() -> str:
    return (
        "If helpful, we can provide additional materials to make these results easier "
        "to share internally or to support remediation planning."
    )


def _escape(value: str) -> str:
    return (
        value.replace("&", "&amp;")
        .replace("<", "&lt;")
        .replace(">", "&gt;")
        .replace('"', "&quot;")
        .replace("'", "&#x27;")
    )


async def _post_resend_email(api_key: str, payload: dict[str, object]) -> None:
    body = json.dumps(payload).encode("utf-8")

    def _send() -> dict[str, object]:
        request = urllib.request.Request(
            "https://api.resend.com/emails",
            data=body,
            method="POST",
            headers={
                "Authorization": f"Bearer {api_key}",
                "Content-Type": "application/json",
                "User-Agent": "sitescanner/0.1.0",
            },
        )
        with urllib.request.urlopen(request, timeout=20) as response:
            response_body = response.read().decode("utf-8")
        return json.loads(response_body)

    try:
        response = await asyncio.to_thread(_send)
    except urllib.error.HTTPError as exc:
        detail = exc.read().decode("utf-8", errors="replace")
        raise RuntimeError(f"Resend returned HTTP {exc.code}: {detail}") from exc
    except urllib.error.URLError as exc:
        raise RuntimeError(f"Resend request failed: {exc}") from exc

    email_id = response.get("id")
    if not email_id:
        raise RuntimeError(f"Resend response missing email id: {response!r}")
    log.info("Resend email sent: %s", email_id)
