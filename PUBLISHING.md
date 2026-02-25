# Platform Publishing Guide

How to publish agent-bom to each MCP ecosystem platform.

## Prerequisites

- agent-bom is already published on [PyPI](https://pypi.org/project/agent-bom/) (automated via release CI)
- Docker images are published to Docker Hub and GHCR (automated via release CI)
- MCP server supports both **stdio** and **SSE/streamable-http** transports

---

## 1. Smithery

Smithery requires a publicly accessible HTTP URL for the MCP server.

### Step 1: Deploy SSE server

The SSE server is deployed on Railway at `https://agent-bom-mcp.up.railway.app` (automated via `deploy-mcp-sse.yml`).

### Step 2: Publish to Smithery

**Option A — Web UI**:
1. Go to https://smithery.ai/servers/new
2. Namespace: `agent-bom`
3. Server ID: `agent-bom`
4. MCP Server URL: `https://agent-bom-mcp.up.railway.app/mcp`
5. Click **Continue**

**Option B — Automated**:
The `publish-registries.yml` workflow auto-publishes to Smithery on each release using `SMITHERY_API_TOKEN`.

### Verification

After publishing, check: https://smithery.ai/server/agent-bom/agent-bom

---

## 2. Official MCP Registry

Automated via `publish-mcp-registry.yml` using GitHub OIDC — no secrets needed.

### Manual submission

```bash
# Our entry is at: integrations/mcp-registry/server.json
# Validates and publishes automatically on each release
```

### Verification

Search for "agent-bom" at: https://registry.modelcontextprotocol.io

---

## 3. ToolHive

ToolHive uses OCI containers from GHCR.

### Step 1: Ensure GHCR image is published

The `publish-mcp.yml` CI workflow pushes to GHCR on each release:
- `ghcr.io/msaad00/agent-bom:latest` (stdio)
- `ghcr.io/msaad00/agent-bom-sse:latest` (SSE)

### Step 2: Submit to ToolHive catalog

```bash
# Fork the ToolHive catalog repo
gh repo fork stacklok/toolhive-catalog --clone

# Copy our entry
cp integrations/toolhive/server.json toolhive-catalog/servers/agent-bom.json

# Submit PR
cd toolhive-catalog
git checkout -b add-agent-bom
git add servers/agent-bom.json
git commit -m "feat: add agent-bom MCP server"
git push origin add-agent-bom
gh pr create --title "feat: add agent-bom security scanner" \
  --body "Adds agent-bom — AI supply chain security scanner with 7 MCP tools."
```

### Verification

After the PR is merged:
```bash
thv run agent-bom
```

---

## 4. ClawHub / OpenClaw

Automated via `publish-registries.yml` using `CLAWHUB_TOKEN`.

### Manual publish

```bash
npm install -g clawhub@latest
clawhub login --token "$CLAWHUB_TOKEN"
clawhub publish integrations/openclaw \
  --slug agent-bom --name "agent-bom" \
  --version "0.31.8"
```

### Verification

```bash
clawhub install agent-bom
```

---

## 5. Docker Hub

Automated via `.github/workflows/release.yml` on each tag push.

Images published:
- `agentbom/agent-bom:v{version}`
- `agentbom/agent-bom:latest`

---

## 6. GitHub Container Registry (GHCR)

Automated via `.github/workflows/publish-mcp.yml` after each release.

Images published:
- `ghcr.io/msaad00/agent-bom:{tag}` — stdio MCP server
- `ghcr.io/msaad00/agent-bom-sse:{tag}` — SSE MCP server

---

## 7. Creating a Release

Tag push triggers the full pipeline automatically:

```bash
git tag v0.31.8
git push origin v0.31.8
```

This triggers:
1. **release.yml** → PyPI + Docker Hub + Sigstore signing + GitHub Release
2. **publish-mcp.yml** → GHCR stdio + SSE containers (via workflow_run)
3. **publish-registries.yml** → Smithery + ClawHub (via workflow_run)
4. **publish-mcp-registry.yml** → Official MCP Registry (via workflow_run)
5. **deploy-mcp-sse.yml** → Railway deployment (via workflow_run)

---

## Platform Status

| Platform | Entry File | Automated | Trigger |
|----------|-----------|-----------|---------|
| **PyPI** | `pyproject.toml` | release.yml | tag push |
| **Docker Hub** | `Dockerfile` | release.yml | tag push |
| **GHCR (stdio)** | `Dockerfile.mcp` | publish-mcp.yml | workflow_run |
| **GHCR (SSE)** | `Dockerfile.sse` | publish-mcp.yml | workflow_run |
| **Smithery** | workflow API | publish-registries.yml | workflow_run |
| **ClawHub** | `integrations/openclaw/` | publish-registries.yml | workflow_run |
| **MCP Registry** | `integrations/mcp-registry/server.json` | publish-mcp-registry.yml | workflow_run |
| **ToolHive** | `integrations/toolhive/server.json` | — | Manual PR |
| **Railway** | `Dockerfile.sse` | deploy-mcp-sse.yml | workflow_run |
