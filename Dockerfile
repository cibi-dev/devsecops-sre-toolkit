# ==============================================================================
# Enterprise Multi-Stage Dockerfile for DevSecOps & SRE Resilience Toolkit
# ==============================================================================

# Build Stage
FROM python:3.11-slim AS builder

WORKDIR /build

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1

RUN apt-get update && apt-get install -y --no-install-recommends \
    build-essential \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml .
RUN pip install --no-cache-dir --prefix=/install .

# Production Stage
FROM python:3.11-slim AS runtime

LABEL org.opencontainers.image.title="devsecops-sre-toolkit" \
      org.opencontainers.image.description="Enterprise DevSecOps, SRE & Autonomous Resilience Toolkit" \
      org.opencontainers.image.authors="cibi-dev" \
      org.opencontainers.image.vendor="SRE & DevSecOps Engineering" \
      org.opencontainers.image.licenses="MIT"

WORKDIR /app

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PYTHONPATH="/app:/app/packages/blue-green-deployer/src:/app/packages/chaos-fault-injector/src:/app/packages/container-secret-scanner/src:/app/packages/distributed-tracing-profiler/src:/app/packages/encrypted-backup-orchestrator/src:/app/packages/infra-drift-detector/src:/app/packages/langgraph-autonomous-code-healer/src:/app/packages/langgraph-type-coverage-refactorer/src:/app/packages/lightweight-ci-runner/src:/app/packages/linux-cis-hardener/src:/app/packages/linux-sre-watchdog/src:/app/packages/postmortem-incident-generator/src:/app/packages/prometheus-metrics-exporter/src:/app/packages/reverse-proxy-limiter/src:/app/packages/slo-burnrate-engine/src:/app/packages/stream-log-aggregator/src:/app/packages/synthetic-blackbox-prober/src"

# Copy installed dependencies from builder
COPY --from=builder /install /usr/local

# Create non-root user for DevSecOps compliance (CWE-250)
RUN groupadd -r sreops && useradd -r -g sreops -u 1001 -m -d /app sre_user

# Copy application files
COPY --chown=sre_user:sreops cli.py pyproject.toml README.md ./
COPY --chown=sre_user:sreops packages/ ./packages/

USER sre_user

ENTRYPOINT ["python3", "/app/cli.py"]
CMD ["demo"]
