# Maintainer Notes

## Architecture

- `app/main.py`: FastAPI application and request logging.
- `app/routes/scans.py`: scan API endpoints and abuse controls.
- `app/auth.py`: API key authentication.
- `app/rate_limit.py`: Redis-backed rate and pending scan limits.
- `app/validators.py`: domain normalization and public-hostname validation.
- `app/scanner.py`: safe Nuclei subprocess execution and timeout handling.
- `app/worker.py`: ARQ worker orchestration and email delivery.
- `app/reporting.py`: OpenAI report generation.
- `app/email.py`: Resend/stub email rendering and delivery.
- `app/store.py`: Redis scan state persistence.

## Adding Scan Profiles

Add profile flags in `app/scanner.py` under `PROFILES`. Avoid intrusive,
destructive, brute-force, or DoS templates unless the client explicitly approves
them and the target authorization model supports it.

## Schema Changes

Pydantic models in `app/models.py` drive the OpenAPI schema consumed by ChatGPT
Actions. After schema changes:

```bash
ruff check .
pytest
curl "$PUBLIC_BASE_URL/openapi.json"
```

Then re-import or paste the schema in ChatGPT App Builder.

## Release Checklist

- Tests pass.
- `SITESCANNER_API_KEY` is set and ChatGPT Action auth matches it.
- `PUBLIC_BASE_URL` matches the stable production URL.
- `TRUSTED_HOSTS` is restricted for stable production domains.
- OpenAI and Resend keys have active billing/access.
- A test scan completes and email delivery is verified.

