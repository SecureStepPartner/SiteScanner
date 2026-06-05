# API Usage

Base URL comes from `PUBLIC_BASE_URL`, for example:

```text
https://scanner.example.com
```

## Authentication

Production deployments should set `SITESCANNER_API_KEY` and `REQUIRE_API_KEY=true`.
Clients may authenticate with either header:

```http
Authorization: Bearer <SITESCANNER_API_KEY>
```

or:

```http
X-API-Key: <SITESCANNER_API_KEY>
```

For ChatGPT Actions, configure API key authentication and use either bearer auth
or the custom header name `X-API-Key`.

## Start Scan

```bash
curl -X POST "$PUBLIC_BASE_URL/scan" \
  -H "Authorization: Bearer $SITESCANNER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "domain": "example.com",
    "email": "security@example.com",
    "scan_type": "quick"
  }'
```

Returns `202 Accepted` with:

```json
{
  "job_id": "abc123...",
  "status": "queued",
  "message": "Scan accepted. Poll GET /scans/{job_id} for status and results."
}
```

## Get Result

```bash
curl "$PUBLIC_BASE_URL/scan/$JOB_ID" \
  -H "Authorization: Bearer $SITESCANNER_API_KEY"
```

Terminal statuses:

- `completed`
- `partial`
- `timed_out`
- `failed`

## List Recent Scans

```bash
curl "$PUBLIC_BASE_URL/scans" \
  -H "Authorization: Bearer $SITESCANNER_API_KEY"
```

## Health Check

```bash
curl "$PUBLIC_BASE_URL/health"
```

Health is intentionally unauthenticated for deployment checks.

