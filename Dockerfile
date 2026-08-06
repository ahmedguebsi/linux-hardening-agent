# syntax=docker/dockerfile:1.7
#
# Multi-stage build for the hardening agent.
#
# Stage 1 builds a wheel with the full toolchain present. Stage 2 copies only
# the installed virtualenv into a slim base. The build toolchain, pip cache, and
# source tree never reach the final image, which keeps it small and removes a
# large amount of attack surface (a compiler in a production image is a gift to
# anyone who achieves code execution).

# ---------------------------------------------------------------------------
# Stage 1: builder
# ---------------------------------------------------------------------------
FROM python:3.13-slim-bookworm AS builder

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

WORKDIR /build

# Copy only the metadata first. Docker caches this layer, so editing source code
# does not re-run the dependency install step.
COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

# Build into a self-contained venv that stage 2 can copy wholesale. The agent
# has zero runtime dependencies, so this resolves nothing from the network
# beyond the build backend itself.
RUN python -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --upgrade pip setuptools wheel \
    && /opt/venv/bin/pip install --no-cache-dir . \
    && find /opt/venv -type d -name '__pycache__' -prune -exec rm -rf {} + \
    && find /opt/venv -type f -name '*.pyc' -delete

# ---------------------------------------------------------------------------
# Stage 2: runtime
# ---------------------------------------------------------------------------
FROM python:3.13-slim-bookworm AS runtime

# OCI labels: makes `docker inspect` and registry UIs useful, and lets scanners
# attribute findings to the right source repository.
LABEL org.opencontainers.image.title="hardening-agent" \
      org.opencontainers.image.description="Linux hardening audit and observability agent" \
      org.opencontainers.image.source="https://github.com/example/linux-hardening-agent" \
      org.opencontainers.image.licenses="MIT" \
      org.opencontainers.image.vendor="Ahmed Guebsi"

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PATH="/opt/venv/bin:${PATH}" \
    HARDENING_AGENT_EXPORTER_HOST=0.0.0.0 \
    HARDENING_AGENT_EXPORTER_PORT=9101 \
    HARDENING_AGENT_LOG_FORMAT=json

# A dedicated unprivileged account. The container audits the host through
# read-only bind mounts, so it needs no privileges of its own -- a compromised
# agent container cannot write to anything that matters.
RUN groupadd --system --gid 65532 nonroot \
    && useradd --system --uid 65532 --gid nonroot \
       --home-dir /var/lib/hardening-agent --no-create-home \
       --shell /usr/sbin/nologin nonroot \
    && mkdir -p /var/lib/hardening-agent/textfile /etc/hardening-agent \
    && chown -R nonroot:nonroot /var/lib/hardening-agent

COPY --from=builder --chown=root:root /opt/venv /opt/venv
COPY --chown=root:root config/agent.toml /etc/hardening-agent/agent.toml

USER nonroot:nonroot
WORKDIR /var/lib/hardening-agent

EXPOSE 9101

# Uses the agent's own readiness endpoint, so the container is only healthy once
# the first audit has actually completed -- not merely once the process starts.
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
    CMD ["python", "-c", "import sys,urllib.request; sys.exit(0 if urllib.request.urlopen('http://127.0.0.1:9101/readyz', timeout=4).status==200 else 1)"]

# Exec form, so the agent is PID 1 and receives SIGTERM directly from
# `docker stop`. With the shell form, sh would be PID 1, swallow the signal, and
# the container would be SIGKILLed after the grace period instead of shutting
# down gracefully.
ENTRYPOINT ["hardening-agent"]
CMD ["serve"]
