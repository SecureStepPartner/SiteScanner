# SecureStep Site Scanner

Backend API for the SecureStep Site Scanner ChatGPT App. Receives scan requests
from ChatGPT, runs Nuclei-based vulnerability scans against a target domain,
and returns structured results along with an email report.

## Stack

- Python 3.11+ with FastAPI and uvicorn
- Redis with `arq` for the async job queue and worker
- Nuclei (ProjectDiscovery) executed as a supervised subprocess

## Local setup

```bash
# 1. Create and activate a virtual environment
python3 -m venv .venv
source .venv/bin/activate

# 2. Install runtime and development dependencies
pip install -e ".[dev]"

# 3. Copy environment configuration and fill in values
cp .env.example .env
# Edit .env

# 4. In another terminal, start Redis
redis-server

# 5. Start the API
uvicorn app.main:app --reload --host 0.0.0.0 --port 8000

# 6. In a third terminal, start the worker (added in later steps)
arq app.worker.WorkerSettings
```

Health check:

```bash
curl http://localhost:8000/health
```

OpenAPI schema (consumed by the ChatGPT App Builder Action) is published at
`http://localhost:8000/openapi.json` and interactive docs at `/docs`.

## Phase 1 status

The foundation is in place. Endpoints, scanner integration, worker, parser, and
email delivery are added incrementally on top.

## Repository layout

```
app/
  main.py        FastAPI app entrypoint
  config.py      Environment-driven configuration
  models.py      Pydantic request/response models
  routes/        HTTP endpoints
  store.py       Redis-backed job state
  worker.py      arq worker entrypoint
  scanner.py     Nuclei subprocess execution and timeout
  parser.py      Nuclei JSONL → structured findings
  email.py       Report delivery (stub by default)
  auth.py        API-key dependency (stub in Phase 1)
  validators.py  Domain validation (permissive in Phase 1)
client_scan.sh   Reference operator script (not used by the service)
```
