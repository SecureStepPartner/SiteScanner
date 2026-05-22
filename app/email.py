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


class ResendEmailProvider:
    """Send scan reports through Resend."""

    def __init__(self, api_key: str, from_address: str) -> None:
        self.api_key = api_key.strip()
        self.from_address = from_address.strip()

    async def send_report(self, to_address: str, result: ScanResult) -> None:
        if not self.api_key:
            raise RuntimeError("RESEND_API_KEY is not configured.")

        payload = _render_resend_payload(result, to_address, self.from_address)
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


def _render_text(result: ScanResult, to_address: str) -> str:
    narrative = _narrative_assessment(result)
    risk_posture = _overall_risk_posture(result)
    actions = _priority_actions(result)

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
        "Narrative Assessment:",
        f"  {narrative}",
        "",
        "Overall Risk Posture:",
        f"  {risk_posture}",
        "",
        "Priority Actions:",
    ]
    for index, action in enumerate(actions, start=1):
        lines.append(f"  {index}. {action}")
    lines += [
        "",
        "Findings Summary Table (top 50):",
    ]
    for f in result.findings[:50]:
        lines.append(f"  [{f.severity.value:>8}] {f.name} — {f.matched_at}")
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
) -> dict[str, object]:
    subject = f"SecureStep scan report for {result.domain} ({result.status.value})"
    text_body = _render_text(result, to_address)
    html_body = _render_html(result, to_address)
    payload: dict[str, object] = {
        "from": from_address,
        "to": [to_address],
        "subject": subject,
        "text": text_body,
        "html": html_body,
    }
    return payload


def _render_html(result: ScanResult, to_address: str) -> str:
    narrative = _escape(_narrative_assessment(result))
    risk_posture = _escape(_overall_risk_posture(result))
    actions = _priority_actions(result)
    findings_rows = []
    for f in result.findings[:50]:
        findings_rows.append(
            "<tr>"
            f"<td>{f.severity.value}</td>"
            f"<td>{_escape(f.name)}</td>"
            f"<td>{_escape(f.matched_at)}</td>"
            f"<td>{_escape(f.template_id)}</td>"
            "</tr>"
        )

    findings_html = "".join(findings_rows) or "<tr><td colspan='4'>No findings</td></tr>"
    dashboard = _escape(result.dashboard_url) if result.dashboard_url else "-"
    error = f"<p><strong>Error:</strong> {_escape(result.error)}</p>" if result.error else ""

    return f"""
<!doctype html>
<html>
  <body style="font-family: Arial, sans-serif; color: #222;">
    <h2>SecureStep scan report</h2>
    <p><strong>To:</strong> {_escape(to_address)}<br>
       <strong>Domain:</strong> {_escape(result.domain)}<br>
       <strong>Status:</strong> {_escape(result.status.value)}<br>
       <strong>Dashboard:</strong> {dashboard}</p>
    {error}
    <h3>Summary</h3>
    <ul>
      <li>Total: {result.summary.total}</li>
      <li>Critical: {result.summary.critical}</li>
      <li>High: {result.summary.high}</li>
      <li>Medium: {result.summary.medium}</li>
      <li>Low: {result.summary.low}</li>
      <li>Info: {result.summary.info}</li>
    </ul>
    <h3>Narrative Assessment</h3>
    <p>{narrative}</p>
    <h3>Overall Risk Posture</h3>
    <p>{risk_posture}</p>
    <h3>Priority Actions</h3>
    <ol>
      {"".join(f"<li>{_escape(action)}</li>" for action in actions)}
    </ol>
    <h3>Findings Summary Table</h3>
    <table cellpadding="6" cellspacing="0" border="1">
      <thead>
        <tr><th>Severity</th><th>Name</th><th>Matched</th><th>Template</th></tr>
      </thead>
      <tbody>
        {findings_html}
      </tbody>
    </table>
  </body>
</html>
""".strip()


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
