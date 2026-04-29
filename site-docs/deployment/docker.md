# Docker Deployment

Use this page for containerized entrypoints. `agent-bom` is one product with
two deployable images:

If you still need to choose a deployment path, start with
[Deployment Overview](overview.md). This page is Docker-specific reference
material after that decision, not the primary production rollout guide.

- `agentbom/agent-bom` = the main runtime image for CLI scans, the API,
  scanner jobs, gateway, MCP server mode, and other non-browser entrypoints
- `agentbom/agent-bom-ui` = the standalone browser UI image used when the
  self-hosted control plane runs the UI separately from the API

Pilot on one workstation:

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

The UI image does not replace the API image. A self-hosted browser deployment
still needs the API/control-plane service from `agentbom/agent-bom`.

## Recommended vs advanced Docker paths

Use these in this order:

| Path | Status | Use when |
|---|---|---|
| `deploy/docker-compose.pilot.yml` | recommended | fastest one-machine pilot with the shipped images |
| `deploy/docker-compose.fullstack.yml` | advanced local example | you want a fuller single-machine compose setup and are comfortable editing local compose files |
| `deploy/docker-compose.platform.yml` | component example | you are focusing on the control-plane/platform layer only |
| `deploy/docker-compose.runtime.yml` | component example | you are focusing on proxy/runtime behavior only |

If you want the full self-hosted deployment path for your own infrastructure,
use `scripts/deploy/install-eks-reference.sh` instead of trying to stretch a
Compose file into production.

## Quick scan

```bash
docker run --rm ghcr.io/msaad00/agent-bom:latest scan
```

## With host config access

Mount your MCP client configs for auto-discovery:

```bash
docker run --rm \
  -v "$HOME/.config:/home/abom/.config:ro" \
  -v "$HOME/Library/Application Support:/home/abom/Library/Application Support:ro" \
  ghcr.io/msaad00/agent-bom:latest scan
```

## Self-hosted SSE server

```bash
docker build -f deploy/docker/Dockerfile.sse -t agent-bom-sse .
docker run -p 8080:8080 agent-bom-sse
```

## Proxies and custom CA bundles

All maintained agent-bom images accept the standard proxy variables:

- `HTTP_PROXY`
- `HTTPS_PROXY`
- `NO_PROXY`

They also support mounted enterprise CA bundles through:

- `SSL_CERT_FILE`
- `REQUESTS_CA_BUNDLE`
- `CURL_CA_BUNDLE`
- `PIP_CERT`

Example:

```bash
docker run --rm \
  -e HTTPS_PROXY=http://proxy.internal:8080 \
  -e NO_PROXY=localhost,127.0.0.1 \
  -e SSL_CERT_FILE=/certs/internal-ca.pem \
  -e REQUESTS_CA_BUNDLE=/certs/internal-ca.pem \
  -v ./internal-ca.pem:/certs/internal-ca.pem:ro \
  ghcr.io/msaad00/agent-bom:latest --version
```

## Runtime proxy sidecar

```bash
docker pull agentbom/agent-bom:0.83.0
docker run --rm -i \
  -v ./audit-logs:/var/log/agent-bom \
  agentbom/agent-bom:0.83.0 \
  --log /var/log/agent-bom/audit.jsonl \
  --block-undeclared \
  -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

## Images

| Image | Purpose |
|-------|---------|
| `ghcr.io/msaad00/agent-bom:latest` | Main runtime image: CLI, API, scanner jobs, gateway, MCP server |
| `agentbom/agent-bom-ui` | Standalone browser UI image for split control-plane deploys |
| `deploy/docker/Dockerfile.sse` | SSE MCP server |
| `deploy/docker/Dockerfile.runtime` | Local rebuild recipe for the runtime proxy path shipped in `agentbom/agent-bom` |
| `deploy/docker/Dockerfile.snowpark` | Snowflake Native App |
