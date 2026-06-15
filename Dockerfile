FROM python:3.10-slim-bookworm

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1

ARG TARGETARCH

WORKDIR /app

RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates curl unzip \
    && rm -rf /var/lib/apt/lists/*

RUN set -eux; \
    case "${TARGETARCH:-amd64}" in \
      amd64) nuclei_arch="linux_amd64" ;; \
      arm64) nuclei_arch="linux_arm64" ;; \
      *) echo "Unsupported architecture: ${TARGETARCH:-unknown}" >&2; exit 1 ;; \
    esac; \
    dl_url="$(curl -s https://api.github.com/repos/projectdiscovery/nuclei/releases/latest \
      | grep "\"browser_download_url\".*${nuclei_arch}\\.zip\"" \
      | head -1 \
      | cut -d '"' -f 4)"; \
    test -n "$dl_url"; \
    curl -fsSL "$dl_url" -o /tmp/nuclei.zip; \
    unzip -d /tmp/nuclei /tmp/nuclei.zip; \
    install -m 0755 /tmp/nuclei/nuclei /usr/local/bin/nuclei; \
    rm -rf /tmp/nuclei /tmp/nuclei.zip

COPY pyproject.toml README.md LICENSE ./
COPY app ./app

RUN pip install --upgrade pip \
    && pip install .

EXPOSE 8000

CMD ["uvicorn", "app.main:app", "--host", "0.0.0.0", "--port", "8000"]
