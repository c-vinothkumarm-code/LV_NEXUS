# syntax=docker/dockerfile:1.7
# LV NEXUS production image: API + built web application in one image. The same image runs the scheduler and one-off
# jobs; the role is chosen by the first argument (see docker-entrypoint.sh): api | scheduler | migrate | job <name>.
#
# Supply-chain notes
#   - Base images are pinned by version. For production, also pin by digest:
#       docker buildx imagetools inspect python:3.13-slim-bookworm   ->  set PYTHON_IMAGE=python:3.13-slim-bookworm@sha256:...
#   - .dockerignore keeps .env files, keys, virtual environments and local data out of the build context.

ARG NODE_IMAGE=node:22-bookworm-slim
ARG PYTHON_IMAGE=python:3.13-slim-bookworm

# ---------------------------------------------------------------- web application
FROM ${NODE_IMAGE} AS frontend
WORKDIR /src
ENV CI=true NPM_CONFIG_UPDATE_NOTIFIER=false NPM_CONFIG_FUND=false
COPY frontend/package.json frontend/package-lock.json ./
RUN npm ci --no-audit
COPY frontend/ ./
RUN npm run build

# ---------------------------------------------------------------- python dependencies (built once, copied as a venv)
FROM ${PYTHON_IMAGE} AS deps
ENV PIP_NO_CACHE_DIR=1 PIP_DISABLE_PIP_VERSION_CHECK=1
RUN python -m venv /opt/venv
ENV PATH=/opt/venv/bin:$PATH
COPY backend/requirements.txt /tmp/requirements.txt
RUN pip install --upgrade pip setuptools wheel && pip install -r /tmp/requirements.txt

# ---------------------------------------------------------------- runtime
FROM ${PYTHON_IMAGE} AS runtime
ARG VERSION=dev
ARG REVISION=unknown
LABEL org.opencontainers.image.title="LV NEXUS" \
      org.opencontainers.image.description="LatentView multi-cloud governance, security and FinOps control plane (read-only towards the clouds)" \
      org.opencontainers.image.vendor="LatentView Analytics" \
      org.opencontainers.image.version="${VERSION}" \
      org.opencontainers.image.revision="${REVISION}"

ENV PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1 PYTHONFAULTHANDLER=1 \
    PATH=/opt/venv/bin:$PATH \
    APP_ENV=production FRONTEND_DIST=/app/frontend_dist \
    PORT=8080 WEB_CONCURRENCY=2 FORWARDED_ALLOW_IPS=127.0.0.1 \
    APP_VERSION=${VERSION}

# security updates for the base image, then nothing else (no compilers, no curl, no shell tools beyond the base)
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* \
    && groupadd --system --gid 10001 lvnexus && useradd --system --uid 10001 --gid lvnexus --home-dir /app --shell /usr/sbin/nologin lvnexus

WORKDIR /app
COPY --from=deps /opt/venv /opt/venv
COPY --chown=root:root backend/ ./
COPY --chown=root:root --from=frontend /src/dist /app/frontend_dist
COPY --chown=root:root --chmod=0755 docker-entrypoint.sh /usr/local/bin/docker-entrypoint.sh

# application code is owned by root and read-only for the service user; only /tmp is writable (tmpfs in compose)
USER 10001:10001
EXPOSE 8080
HEALTHCHECK --interval=30s --timeout=5s --start-period=40s --retries=3 \
  CMD ["python", "-c", "import os,sys,urllib.request; r=urllib.request.urlopen(f'http://127.0.0.1:{os.environ.get(\"PORT\",\"8080\")}/health', timeout=4); sys.exit(0 if r.status==200 else 1)"]
ENTRYPOINT ["docker-entrypoint.sh"]
CMD ["api"]
