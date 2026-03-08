# Glama MCP Server — stdio transport for Glama's mcp-proxy.
#
# Glama auto-generates a Dockerfile that uses `uv sync`, which places the
# `agent-bom` binary inside `.venv/bin/` — invisible to mcp-proxy's PATH.
# This Dockerfile uses `pip install` so the entry point lands on system PATH.
#
# Provide this Dockerfile via Glama Admin > Server Settings > Build.

# python:3.12-slim (pinned by hash for OpenSSF Scorecard)
FROM python:3.12-slim@sha256:ccc7089399c8bb65dd1fb3ed6d55efa538a3f5e7fca3f5988ac3b5b87e593bf0

WORKDIR /app

COPY pyproject.toml README.md LICENSE ./
COPY src/ ./src/

RUN pip install --no-cache-dir ".[mcp-server]"

# Verify entry point is on PATH
RUN agent-bom --version

ENTRYPOINT ["agent-bom", "mcp-server"]
