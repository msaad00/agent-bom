# Glama MCP Server — stdio transport for Glama's mcp-proxy.
#
# Glama auto-generates a Dockerfile, but this checked-in image keeps the Python
# environment reproducible from the reviewed lock and explicitly puts its
# `.venv/bin` entry points on PATH for mcp-proxy.
#
# Provide this Dockerfile via Glama Admin > Server Settings > Build.

## ── Builder stage ────────────────────────────────────────────────────────────
# Base image: python:3.12.13-slim (Debian-based). The main Dockerfile uses
# python:3.14.3-alpine3.23 (musl) instead — Glama's Dockerfile deliberately
# diverges because its locked wheels (cryptography, lxml, etc.) may lack
# musl-built artefacts, which would force a long compile
# step or wheel-incompatibility errors on Alpine. Both bases are
# independently digest-pinned and bumped by dependabot. Tracking: #1961.
FROM python:3.12.13-slim@sha256:7026274c107626d7e940e0e5d6730481a4600ae95d5ca7eb532dd4180313fea9 AS builder

WORKDIR /app

COPY --from=ghcr.io/astral-sh/uv:0.10.9@sha256:10902f58a1606787602f303954cea099626a4adb02acbac4c69920fe9d278f82 /uv /uvx /bin/
COPY pyproject.toml uv.lock README.md PYPI_README.md LICENSE ./
COPY src/ ./src/

RUN uv sync --locked --no-dev --no-editable --extra mcp-server

## ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12.13-slim@sha256:7026274c107626d7e940e0e5d6730481a4600ae95d5ca7eb532dd4180313fea9

COPY --from=builder /app/.venv /app/.venv
COPY --from=builder /app/LICENSE /app/LICENSE

# Apply latest OS security patches (fixes base-image CVEs visible in Docker Scout)
RUN apt-get update && apt-get upgrade -y --no-install-recommends && rm -rf /var/lib/apt/lists/*
COPY deploy/docker/pip-requirements.txt /tmp/pip-req.txt
RUN pip install --no-cache-dir --require-hashes -r /tmp/pip-req.txt && rm /tmp/pip-req.txt

# Create non-root user for least-privilege execution
RUN addgroup --system abom && adduser --system --ingroup abom abom
USER abom

# Keep the frozen venv entry point visible to Glama's mcp-proxy.
ENV VIRTUAL_ENV=/app/.venv
ENV PATH="/app/.venv/bin:${PATH}"

# Verify entry point is on PATH
RUN agent-bom --version

HEALTHCHECK --interval=60s --timeout=10s --start-period=10s --retries=3 \
    CMD agent-bom --version || exit 1

ENTRYPOINT ["agent-bom", "mcp", "server"]
