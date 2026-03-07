## ── Builder stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:39e4e1ccb01578e3c86f7a0cf7b7fd89b8dbe2c27a88de11cf726ba669469f49 AS builder

WORKDIR /app

# Install build-time deps (git needed for setuptools-scm / VCS installs)
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --prefix=/install ".[api]"

## ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:39e4e1ccb01578e3c86f7a0cf7b7fd89b8dbe2c27a88de11cf726ba669469f49

ARG VERSION=dev

LABEL maintainer="W S <34316639+msaad00@users.noreply.github.com>"
LABEL description="agent-bom: AI supply chain security scanner — CVEs, config security, blast radius, compliance"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/msaad00/agent-bom"

# Copy only installed packages from builder (no git, curl, pip, setuptools)
COPY --from=builder /install /usr/local

# Create non-root user for least-privilege execution
RUN addgroup --system abom && adduser --system --ingroup abom abom

WORKDIR /workspace
RUN chown abom:abom /workspace

USER abom

ENV PYTHONUNBUFFERED=1
ENV TERM=xterm-256color

HEALTHCHECK --interval=30s --timeout=10s --start-period=5s --retries=3 \
    CMD agent-bom --version || exit 1

ENTRYPOINT ["agent-bom"]
CMD ["--help"]
