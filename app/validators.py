"""Domain validation.

Phase 1 keeps this permissive — only normalization and the most obvious shape
checks. Phase 2 hardens it with SSRF protections: blocking private IP ranges,
link-local, loopback, and cloud-metadata addresses, plus public-suffix parsing.
"""

import re
from ipaddress import ip_address

_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)
_BLOCKED_EXACT_NAMES = {"localhost"}
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan")


class DomainValidationError(ValueError):
    """Raised when an input domain cannot be accepted for scanning."""


def normalize_domain(raw: str) -> str:
    """Trim, lower-case, strip protocol/path, and return a bare domain.

    Examples:
        " HTTPS://Example.com/path "  -> "example.com"
        "www.example.com."            -> "www.example.com"
    """
    if not raw:
        raise DomainValidationError("Domain is empty.")

    candidate = raw.strip().lower()

    for prefix in ("https://", "http://"):
        if candidate.startswith(prefix):
            candidate = candidate[len(prefix):]

    candidate = candidate.split("/", 1)[0]
    candidate = candidate.split("?", 1)[0]
    candidate = candidate.split("#", 1)[0]
    candidate = candidate.rstrip(".")

    if "@" in candidate or ":" in candidate:
        raise DomainValidationError("Only public DNS hostnames are accepted.")

    try:
        ip_address(candidate)
    except ValueError:
        pass
    else:
        raise DomainValidationError("IP addresses are not accepted; provide a public domain.")

    if candidate in _BLOCKED_EXACT_NAMES or candidate.endswith(_BLOCKED_SUFFIXES):
        raise DomainValidationError("Local or internal hostnames are not accepted.")

    if not _DOMAIN_RE.match(candidate):
        raise DomainValidationError(f"Not a valid domain: {raw!r}")

    top_level_domain = candidate.rsplit(".", 1)[-1]
    if len(top_level_domain) < 2 or not top_level_domain.isalpha():
        raise DomainValidationError("Domain must use a public alphabetic top-level domain.")

    return candidate


def to_target_url(domain: str) -> str:
    """Build the URL passed to Nuclei. Always HTTPS in Phase 1."""
    return f"https://{domain}"
