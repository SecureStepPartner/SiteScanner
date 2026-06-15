# QA Checklist

## Automated

```bash
ruff check .
pytest
```

## API

- `/health` returns `{"status":"ok"}`.
- `/openapi.json` contains the expected `PUBLIC_BASE_URL`.
- `/scan` rejects requests without API key when `REQUIRE_API_KEY=true`.
- `/scan` accepts valid API key.
- `/scan` rejects IP addresses, localhost, and invalid domains.
- Rate limit returns HTTP 429 after configured threshold.
- `/scan/{job_id}` returns queued/running/completed state.

## Worker

- Worker starts and connects to Redis.
- Nuclei is installed inside the Docker image.
- Scan timeout is capped at 900 seconds.
- Timed-out scans terminate safely.
- Results persist in Redis.

## Email

- Resend sends report from verified sender.
- OpenAI report generation works when quota is available.
- Fallback report sends if OpenAI is unavailable.
- Email uses the approved report structure and `#1a237e` branding.

