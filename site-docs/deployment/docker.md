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
docker build -f Dockerfile.sse -t agent-bom-sse .
docker run -p 8080:8080 agent-bom-sse
```

## Runtime proxy sidecar

```bash
docker build -f Dockerfile.runtime -t agent-bom-runtime .
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
| `Dockerfile.sse` | SSE MCP server |
| `Dockerfile.runtime` | Runtime proxy |
| `Dockerfile.snowpark` | Snowflake Native App |
