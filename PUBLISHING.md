# Platform Publishing Guide

How to publish agent-bom to each MCP ecosystem platform.

## Prerequisites

- agent-bom is already published on [PyPI](https://pypi.org/project/agent-bom/) (automated via release CI)
- Docker images are published to Docker Hub and GHCR (automated via release CI)
- MCP server supports both **stdio** and **SSE** transports

---

## 1. Smithery

Smithery requires a publicly accessible HTTP URL for the MCP server.

### Step 1: Deploy SSE server

Pick one of the following deployment platforms:

**Railway** (recommended — simplest):
```bash
# Install Railway CLI
npm install -g @railway/cli

# Login and deploy
railway login
railway init
railway up
```

**Render**:
```bash
# Connect repo on https://dashboard.render.com
# Select "New Blueprint" → point to render.yaml in this repo
```

**Fly.io**:
```bash
# Install flyctl
curl -L https://fly.io/install.sh | sh

# Deploy
fly launch --config fly.toml
fly deploy
```

**Docker (any VPS)**:
```bash
docker build -f Dockerfile.sse -t agent-bom-sse .
docker run -d -p 8423:8423 --name agent-bom-mcp agent-bom-sse
```

### Step 2: Get your public URL

After deployment, note the public URL. Examples:
- Railway: `https://agent-bom-mcp.up.railway.app`
- Render: `https://agent-bom-mcp.onrender.com`
- Fly.io: `https://agent-bom-mcp.fly.dev`

### Step 3: Publish to Smithery

**Option A — Web UI**:
1. Go to https://smithery.ai
2. Click **Publish** → **MCP**
3. Namespace: `agent-bom`
4. Server ID: `agent-bom`
5. MCP Server URL: paste your public URL from Step 2
6. Click **Continue**

**Option B — CLI**:
```bash
npx @smithery/cli mcp publish <YOUR_URL> -n agent-bom/agent-bom
```

### Verification

After publishing, check: https://smithery.ai/server/@agent-bom/agent-bom

---

## 2. Official MCP Registry

The official MCP server registry at https://registry.modelcontextprotocol.io may auto-discover servers published on PyPI.

### Option A: Auto-discovery

Since agent-bom is on PyPI and includes MCP server metadata, it may be automatically indexed. Check:

```bash
curl -s "https://registry.modelcontextprotocol.io/v0/servers?search=agent-bom" | python -m json.tool
```

### Option B: Manual submission

If not auto-discovered, use our prepared registry entry:

```bash
# Our entry is at: integrations/mcp-registry/server.json
# Submit to the MCP registry team or create a PR if they have a public repo
```

### Verification

Search for "agent-bom" at: https://registry.modelcontextprotocol.io

---

## 3. ToolHive

ToolHive uses OCI containers from GHCR.

### Step 1: Ensure GHCR image is published

The `publish-mcp.yml` CI workflow pushes to GHCR on each release:
- `ghcr.io/agent-bom/agent-bom:latest` (stdio)
- `ghcr.io/agent-bom/agent-bom-sse:latest` (SSE)

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
  --body "Adds agent-bom — AI supply chain security scanner with 7 MCP tools for CVE scanning, blast radius, SBOM generation, compliance, and remediation."
```

### Verification

After the PR is merged, verify with:
```bash
thv run agent-bom
```

---

## 4. OpenClaw

### Submit the skill

```bash
# Our skill definition is at: integrations/openclaw/SKILL.md
# Submit to OpenClaw's skill registry following their contribution guidelines
```

### Verification

```bash
clawhub install agent-bom
agent-bom scan
```

---

## 5. Docker Hub

Automated via `.github/workflows/release.yml` on each GitHub Release.

Images published:
- `agentbom/agent-bom:v{version}`
- `agentbom/agent-bom:latest`

### Verification

```bash
docker pull agentbom/agent-bom:latest
docker run --rm agentbom/agent-bom --version
```

---

## 6. GitHub Container Registry (GHCR)

Automated via `.github/workflows/publish-mcp.yml` on each GitHub Release.

Images published:
- `ghcr.io/agent-bom/agent-bom:{tag}` — stdio MCP server
- `ghcr.io/agent-bom/agent-bom-sse:{tag}` — SSE MCP server
- Both with `:latest` tags

### Verification

```bash
docker pull ghcr.io/agent-bom/agent-bom:latest
docker run --rm ghcr.io/agent-bom/agent-bom
```

---

## 7. Creating a Release

To trigger all CI pipelines (PyPI, Docker Hub, GHCR, MCP containers):

```bash
# Ensure version is bumped in pyproject.toml
# Tag and push
git tag v0.27.0
git push origin v0.27.0

# Create GitHub Release (triggers all publish workflows)
gh release create v0.27.0 --generate-notes --title "agent-bom v0.27.0"
```

This triggers:
1. **release.yml** → PyPI publish + Docker Hub + Sigstore signing
2. **publish-mcp.yml** → GHCR stdio + SSE containers
3. **deploy-mcp-sse.yml** → Railway deployment (if configured)

---

## Platform Status Checklist

| Platform | Entry File | CI Automated | Manual Step |
|----------|-----------|-------------|-------------|
| **PyPI** | `pyproject.toml` | release.yml | None |
| **Docker Hub** | `Dockerfile` | release.yml | None |
| **GHCR (stdio)** | `integrations/toolhive/Dockerfile.mcp` | publish-mcp.yml | None |
| **GHCR (SSE)** | `Dockerfile.sse` | publish-mcp.yml | None |
| **Smithery** | `smithery.yaml` | — | Deploy SSE + publish URL |
| **MCP Registry** | `integrations/mcp-registry/server.json` | — | Check auto-discovery or submit |
| **ToolHive** | `integrations/toolhive/server.json` | — | PR to stacklok/toolhive-catalog |
| **OpenClaw** | `integrations/openclaw/SKILL.md` | — | Submit to OpenClaw registry |
