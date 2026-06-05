# Security Notes

This service exposes security scanning through an API. Treat it as sensitive
infrastructure.

## Implemented Controls

- API key authentication using bearer token or `X-API-Key`.
- Optional fail-closed auth with `REQUIRE_API_KEY=true`.
- Domain normalization with IP literals, localhost, and internal hostnames blocked.
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

