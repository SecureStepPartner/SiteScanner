# SecureStep Site Scanner

Backend API for the SecureStep Site Scanner ChatGPT App. Receives scan requests
from ChatGPT, runs Nuclei-based vulnerability scans against a target domain,
and returns structured results along with an email report.

## Stack

- Python 3.10+ with FastAPI and uvicorn
- Redis with `arq` for the async job queue and worker
- Nuclei (ProjectDiscovery) executed as a supervised subprocess

## Prerequisites

- Python 3.10 or newer
- Redis server (`sudo apt install redis-server` on Debian/Ubuntu, or `brew install redis` on macOS)
- The `nuclei` binary on `PATH`

### Install Nuclei

The service shells out to the `nuclei` binary, so it must be installed and on
`PATH` before any scan can run. Pick one method:

**Option 1 — prebuilt binary (no Go required):**

```bash
# Grab the latest Linux amd64 release into ~/.local/bin
cd /tmp
DL_URL=$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
  | grep '"browser_download_url".*linux_amd64\.zip"' | head -1 | cut -d '"' -f 4)
curl -sL "$DL_URL" -o nuclei.zip
unzip -o nuclei.zip
mkdir -p ~/.local/bin
mv nuclei ~/.local/bin/
chmod +x ~/.local/bin/nuclei
rm -f nuclei.zip LICENSE.md README*.md

# Make sure ~/.local/bin is on PATH (most distros include it by default)
echo "$PATH" | tr ':' '\n' | grep -q "$HOME/.local/bin" || \
  echo 'export PATH="$HOME/.local/bin:$PATH"' >> ~/.bashrc

# Verify
nuclei -version
```

**Option 2 — via Go (if Go is already installed):**

```bash
go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest
```

The first run of `nuclei` downloads its template library (~5,000+ files) into
`~/.config/nuclei` and `~/.cache/nuclei`. This happens automatically; expect a
30–60 second one-time delay before the first scan starts producing output.

For other platforms, see the project page:
<https://github.com/projectdiscovery/nuclei>.

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

# 6. In a third terminal, start the worker
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
