# Glama MCP Server — stdio transport for Glama's mcp-proxy.
#
# Glama auto-generates a Dockerfile that uses `uv sync`, which places the
# `agent-bom` binary inside `.venv/bin/` — invisible to mcp-proxy's PATH.
# This Dockerfile uses `pip install` so the entry point lands on system PATH.
#
# Provide this Dockerfile via Glama Admin > Server Settings > Build.

## ── Builder stage ────────────────────────────────────────────────────────────
# Base image: python:3.12.13-slim (Debian-based). The main Dockerfile uses
# python:3.14.3-alpine3.23 (musl) instead — Glama's Dockerfile deliberately
# diverges from that because it `pip install`s wheels (cryptography, lxml,
# etc.) that lack musl-built artefacts, which would force a long compile
# step or wheel-incompatibility errors on Alpine. Both bases are
# independently digest-pinned and bumped by dependabot. Tracking: #1961.
FROM python:3.12.13-slim@sha256:7026274c107626d7e940e0e5d6730481a4600ae95d5ca7eb532dd4180313fea9 AS builder

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --prefix=/install ".[mcp-server]"

## ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12.13-slim@sha256:7026274c107626d7e940e0e5d6730481a4600ae95d5ca7eb532dd4180313fea9

COPY --from=builder /install /usr/local
COPY --from=builder /app/LICENSE /app/LICENSE

# Apply latest OS security patches (fixes base-image CVEs visible in Docker Scout)
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
COPY deploy/docker/pip-requirements.txt /tmp/pip-req.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/pip-req.txt && rm /tmp/pip-req.txt

# Create non-root user for least-privilege execution
RUN addgroup --system abom && adduser --system --ingroup abom abom
USER abom

# Verify entry point is on PATH
RUN agent-bom --version

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD agent-bom --version || exit 1

ENTRYPOINT ["agent-bom", "mcp", "server"]
