# Security Notes

This service exposes security scanning through an API. Treat it as sensitive
infrastructure.

## Implemented Controls

- API key authentication using bearer token or `X-API-Key`.
- Optional fail-closed auth with `REQUIRE_API_KEY=true`.
- Domain normalization with IP literals, localhost, and internal hostnames blocked.
- DNS-resolution validation before scan creation. A/AAAA records are resolved
  and the request is rejected if any answer points to private, loopback,
  link-local, reserved, multicast, unspecified, unique-local, or metadata
  address space.
- Nuclei executed without a shell; arguments are passed as argv items.
- Process group termination on timeout, with SIGTERM then SIGKILL.
- 15-minute maximum scan timeout enforced in settings.
- Redis-backed per-minute and per-hour scan creation rate limits.
- Pending scan limit to reduce queue flooding.
- Worker concurrency cap through ARQ settings.
- Request logging with `X-Request-ID`.
- Diagnostic endpoint excludes secrets and Redis credentials.
- Email report fallback if OpenAI generation fails.

## Required Production Settings

```env
SITESCANNER_API_KEY=<strong random value>
REQUIRE_API_KEY=true
TRUSTED_HOSTS=scanner.example.com
REDIS_URL=redis://redis:6379/0
```

Do not rely on browser-based Cloudflare Access for ChatGPT Actions. ChatGPT
cannot complete an interactive browser login. Use API-key auth at the API layer.

## DNS Resolution Guardrail

The API performs two layers of target validation before a scan is queued:

1. Syntax and hostname validation blocks obvious unsafe inputs such as raw IP
   addresses, `localhost`, hostnames with credentials or ports, and common
   internal suffixes such as `.local`, `.internal`, and `.lan`.
2. DNS validation resolves the submitted hostname and rejects the request if any
   A or AAAA record points to unsafe address space.

Unsafe address space includes:

- private RFC1918/unique-local ranges
- loopback
- link-local
- reserved
- multicast
- unspecified
- cloud metadata/internal ranges such as `169.254.169.254`

DNS failures are fail-closed: unresolved domains are rejected rather than
scanned.

## Abuse Prevention

Recommended starting limits:

```env
RATE_LIMIT_PER_MINUTE=5
RATE_LIMIT_PER_HOUR=30
MAX_PENDING_SCANS=25
MAX_CONCURRENT_SCANS=3
SCAN_TIMEOUT_SECONDS=900
```

Adjust downward for public demos or unknown users.

## Infrastructure Recommendations

- Run behind a stable Cloudflare Tunnel or reverse proxy with HTTPS.
- Restrict SSH with Cloudflare Access, MFA, and least-privilege Linux users.
- Keep Docker, OS packages, Nuclei, and templates updated.
- Monitor `web` and `worker` logs.
- Store secrets only in deployment environment or `.env` on the server, never in Git.
- Use a dedicated OpenAI API key and Resend key for this app.
