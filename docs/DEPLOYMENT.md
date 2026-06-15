# Deployment Guide

## Docker Compose

Use Docker Compose for production-style deployment. The stack requires:

- `web`: FastAPI API server
- `worker`: ARQ worker that runs Nuclei and sends reports
- `redis`: queue and scan state

Example compose file:

```yaml
services:
  redis:
    image: redis:7-alpine
    restart: unless-stopped

  web:
    build:
      context: .
    command: uvicorn app.main:app --host 0.0.0.0 --port 8000
    env_file:
      - .env
    ports:
      - "8010:8000"
    depends_on:
      - redis
    restart: unless-stopped

  worker:
    build:
      context: .
    command: arq app.worker.WorkerSettings
    env_file:
      - .env
    depends_on:
      - redis
    restart: unless-stopped
```

## Required Environment

```env
REDIS_URL=redis://redis:6379/0
SITESCANNER_API_KEY=replace_with_strong_random_value
REQUIRE_API_KEY=true
EMAIL_PROVIDER=resend
RESEND_API_KEY=replace_with_resend_key
EMAIL_FROM=verified_sender@example.com
OPENAI_API_KEY=replace_with_openai_key
OPENAI_MODEL=gpt-5.5
PUBLIC_BASE_URL=https://scanner.example.com
```

Optional:

```env
PDCP_API_KEY=
PDCP_TEAM_ID=
SCHEDULE_MEETING_URL=
TRUSTED_HOSTS=scanner.example.com
RATE_LIMIT_PER_MINUTE=5
RATE_LIMIT_PER_HOUR=30
MAX_PENDING_SCANS=25
```

## Commands

```bash
docker compose up -d --build
docker compose ps
docker compose logs -f --timestamps web worker
curl http://localhost:8010/health
```

If using a temporary Cloudflare quick tunnel:

```bash
cloudflared tunnel --url http://localhost:8010
```

Quick tunnels are for testing only. Production should use a named Cloudflare
Tunnel and stable domain.

