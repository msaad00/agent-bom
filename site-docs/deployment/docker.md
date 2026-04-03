# Docker Deployment

## Quick scan

```bash
docker run --rm ghcr.io/msaad00/agent-bom:latest scan
```

## With host config access

Mount your MCP client configs for auto-discovery:

```bash
docker run --rm \
  -v "$HOME/.config:/root/.config:ro" \
  -v "$HOME/Library/Application Support:/root/Library/Application Support:ro" \
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
docker build -f deploy/docker/Dockerfile.runtime -t agent-bom-runtime .
docker run --rm -i \
  -v ./audit-logs:/var/log/agent-bom \
  agent-bom-runtime \
  --log /var/log/agent-bom/audit.jsonl \
  --block-undeclared \
  -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

## Images

| Image | Purpose |
|-------|---------|
| `ghcr.io/msaad00/agent-bom:latest` | CLI scanner |
| `deploy/docker/Dockerfile.sse` | SSE MCP server |
| `deploy/docker/Dockerfile.runtime` | Runtime proxy |
| `deploy/docker/Dockerfile.snowpark` | Snowflake Native App |
