## ── Builder stage ────────────────────────────────────────────────────────────
FROM python:3.12.13-slim@sha256:7026274c107626d7e940e0e5d6730481a4600ae95d5ca7eb532dd4180313fea9 AS builder

WORKDIR /app

# Install build-time deps (git needed for setuptools-scm / VCS installs)
RUN apt-get update && apt-get install -y --no-install-recommends git \
    && rm -rf /var/lib/apt/lists/*

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --prefix=/install ".[api]"

## ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12.13-slim@sha256:7026274c107626d7e940e0e5d6730481a4600ae95d5ca7eb532dd4180313fea9

ARG VERSION=dev

LABEL maintainer="W S <34316639+msaad00@users.noreply.github.com>"
LABEL description="Security scanner for AI infrastructure — CVEs, blast radius, credential exposure, runtime enforcement"
LABEL org.opencontainers.image.version="${VERSION}"
LABEL org.opencontainers.image.source="https://github.com/msaad00/agent-bom"
LABEL org.opencontainers.image.licenses="Apache-2.0"

# Copy only installed packages from builder (no git, curl, pip, setuptools)
COPY --from=builder /install /usr/local
COPY --from=builder /app/LICENSE /app/LICENSE

# Apply latest OS security patches + upgrade pip (fixes CVE-2025-8869, CVE-2026-1703)
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/* \
    && pip install --no-cache-dir --upgrade pip

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
