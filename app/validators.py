"""Domain validation.

Phase 1 keeps this permissive — only normalization and the most obvious shape
checks. Phase 2 hardens it with SSRF protections: blocking private IP ranges,
link-local, loopback, and cloud-metadata addresses, plus public-suffix parsing.
"""

import re

_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)


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
    candidate = candidate.rstrip(".")

    if not _DOMAIN_RE.match(candidate):
        raise DomainValidationError(f"Not a valid domain: {raw!r}")

    return candidate


def to_target_url(domain: str) -> str:
    """Build the URL passed to Nuclei. Always HTTPS in Phase 1."""
    return f"https://{domain}"
