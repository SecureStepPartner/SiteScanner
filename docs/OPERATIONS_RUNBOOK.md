# Operations Runbook

## Start / Restart

```bash
cd /home/securestep_dev/sitescanner/SiteScanner
docker compose up -d --build
```

With sudo, use the server sudo password when prompted.

## Logs

```bash
docker compose logs -f --timestamps web worker
docker compose logs --tail=200 web
docker compose logs --tail=200 worker
```

## Health Checks

```bash
curl http://localhost:8010/health
curl "$PUBLIC_BASE_URL/health"
curl "$PUBLIC_BASE_URL/openapi.json"
```

## Common Failures

### OpenAI insufficient quota

Symptom:

```text
openai.RateLimitError: 429 insufficient_quota
```

Fix: add billing/credits to the OpenAI account or replace `OPENAI_API_KEY`.
The system will still send fallback reports if AI generation fails.

### Port already in use

Symptom:

```text
failed to bind host port 0.0.0.0:8000
```

Fix: map another host port, for example `8010:8000`.

### Cloudflare quick tunnel URL stopped

Quick tunnels stop when `cloudflared` stops. Use `tmux` for temporary testing or
set up a named tunnel for production.

```bash
tmux new -s tunnel
cloudflared tunnel --url http://localhost:8010
```

Detach:

```text
Ctrl+B, then D
```

Reattach:

```bash
tmux attach -t tunnel
```

## Test A Scan

```bash
curl -X POST "$PUBLIC_BASE_URL/scan" \
  -H "Authorization: Bearer $SITESCANNER_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{"domain":"example.com","email":"security@example.com","scan_type":"quick"}'
```

Poll the returned `job_id`:

```bash
curl "$PUBLIC_BASE_URL/scan/$JOB_ID" \
  -H "Authorization: Bearer $SITESCANNER_API_KEY"
```

