# Glama MCP Server — stdio transport for Glama's mcp-proxy.
#
# Glama auto-generates a Dockerfile that uses `uv sync`, which places the
# `agent-bom` binary inside `.venv/bin/` — invisible to mcp-proxy's PATH.
# This Dockerfile uses `pip install` so the entry point lands on system PATH.
#
# Provide this Dockerfile via Glama Admin > Server Settings > Build.

## ── Builder stage ────────────────────────────────────────────────────────────
# python:3.12-slim (pinned by hash for OpenSSF Scorecard — same as main Dockerfile)
FROM python:3.12-slim@sha256:39e4e1ccb01578e3c86f7a0cf7b7fd89b8dbe2c27a88de11cf726ba669469f49 AS builder

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir --prefix=/install ".[mcp-server]"

## ── Runtime stage ────────────────────────────────────────────────────────────
FROM python:3.12-slim@sha256:39e4e1ccb01578e3c86f7a0cf7b7fd89b8dbe2c27a88de11cf726ba669469f49

COPY --from=builder /install /usr/local
COPY --from=builder /app/LICENSE /app/LICENSE

# Create non-root user for least-privilege execution
RUN addgroup --system abom && adduser --system --ingroup abom abom
USER abom

# Verify entry point is on PATH
RUN agent-bom --version

ENTRYPOINT ["agent-bom", "mcp-server"]
