"""Domain validation.

Phase 1 keeps this permissive — only normalization and the most obvious shape
checks. Phase 2 hardens it with SSRF protections: blocking private IP ranges,
link-local, loopback, and cloud-metadata addresses, plus public-suffix parsing.
"""

import re
import socket
from ipaddress import ip_address, ip_network

_DOMAIN_RE = re.compile(
    r"^[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?"
    r"(\.[A-Za-z0-9]([A-Za-z0-9\-]{0,61}[A-Za-z0-9])?)+$"
)
_BLOCKED_EXACT_NAMES = {"localhost"}
_BLOCKED_SUFFIXES = (".localhost", ".local", ".internal", ".lan")
_METADATA_NETWORKS = (
    ip_network("169.254.169.254/32"),
    ip_network("169.254.0.0/16"),
    ip_network("fe80::/10"),
    ip_network("fc00::/7"),
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


def validate_public_dns_resolution(domain: str) -> list[str]:
    """Resolve a domain and reject unsafe A/AAAA targets.

    A syntactically public hostname can still resolve to internal or metadata
    address space. This check is intentionally fail-closed: unresolved domains
    are not scanned, and any unsafe DNS answer blocks the request.
    """
    try:
        answers = socket.getaddrinfo(domain, None, type=socket.SOCK_STREAM)
    except socket.gaierror as exc:
        raise DomainValidationError(f"Domain could not be resolved: {domain}") from exc

    resolved_ips = sorted({answer[4][0] for answer in answers})
    if not resolved_ips:
        raise DomainValidationError(f"Domain could not be resolved: {domain}")

    for resolved in resolved_ips:
        address = ip_address(resolved)
        if _is_unsafe_resolved_ip(address):
            raise DomainValidationError(
                f"Domain resolves to an unsafe internal or reserved address: {resolved}"
            )

    return resolved_ips


def _is_unsafe_resolved_ip(address) -> bool:
    if (
        address.is_private
        or address.is_loopback
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
        or address.is_unspecified
    ):
        return True
    return any(address in network for network in _METADATA_NETWORKS)


def to_target_url(domain: str) -> str:
    """Build the URL passed to Nuclei. Always HTTPS in Phase 1."""
    return f"https://{domain}"
