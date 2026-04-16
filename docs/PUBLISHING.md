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
Secure remote deployments should set `AGENT_BOM_MCP_BEARER_TOKEN` in Railway service
variables so the MCP transport can start with built-in Bearer auth. Keep TLS at your
ingress or platform edge.

If you need a public unauthenticated registry/demo endpoint, treat that as a separate,
explicitly less-trusted deployment surface rather than weakening the primary service.
Release automation now requires that public endpoint to be set explicitly via
`SMITHERY_MCP_URL`. It does not fall back to the protected Railway URL.

### Step 2: Publish to Smithery

**Option A — Web UI**:
1. Go to https://smithery.ai/servers/new
2. Namespace: `agent-bom`
3. Server ID: `agent-bom`
4. MCP Server URL: your separate public unauthenticated endpoint, e.g. `https://agent-bom--agent-bom.run.tools`
5. Click **Continue**

**Option B — Automated**:
The `publish-registries.yml` workflow auto-publishes to Smithery on each release using:
- `SMITHERY_API_TOKEN`
- `SMITHERY_MCP_URL`

Before publish, CI probes the public endpoint and fails if:
- the endpoint is unreachable
- the endpoint reports `auth_required=true`
- the endpoint is otherwise unsuitable for public registry publishing

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

For PyPI-backed MCP Registry publishing, keep the ownership marker in the
file referenced by `project.readme` in `pyproject.toml`, not only in
`README.md`:

```md
<!-- mcp-name: io.github.msaad00/agent-bom -->
```

### Verification

Search for "agent-bom" at: https://registry.modelcontextprotocol.io

---

## 3. ClawHub / OpenClaw

Automated via `publish-registries.yml` using `CLAWHUB_TOKEN`.

The public ClawHub surface is intentionally curated. Release automation publishes only:
- `agent-bom-scan`
- `agent-bom-registry`
- `agent-bom-compliance`
- `agent-bom-runtime`

See [`integrations/openclaw/README.md`](../integrations/openclaw/README.md) for the
curated publish set and rationale. The oversized omnibus root skill is kept in-repo
but is not part of the public ClawHub release surface.

### Manual publish

```bash
npm install -g clawhub@latest
clawhub login --token "$CLAWHUB_TOKEN"
clawhub publish integrations/openclaw/scan \
  --slug agent-bom-scan --name "agent-bom scan" \
  --version "0.76.4"
```

### Verification

```bash
clawhub install agent-bom-scan
```

---

## 5. Docker Hub

Automated via `.github/workflows/release.yml` on each tag push.

Images published:
- `agentbom/agent-bom:{version}`
- `agentbom/agent-bom:latest`

The Git tag remains `v{version}`. Docker Hub image tags are published without the `v` prefix.

`latest` is also refreshed independently by `.github/workflows/refresh-latest-container.yml`.
That workflow checks out the newest released tag, rebuilds it with current Alpine packages,
and republishes only `latest`. This keeps the floating tag current for base-image security
fixes without rewriting immutable semver image tags.

The daily `.github/workflows/container-rescan.yml` job should be treated as the alerting
surface for post-release base-image drift. It scans `latest` for fixable `MEDIUM+` and
`UNKNOWN` image findings, uploads SARIF into GitHub Security, and opens or updates the
automated base-image vulnerability issue when new actionable findings appear.

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
git tag v0.76.4
git push origin v0.76.4
```

This triggers:
1. **release.yml** → PyPI + Docker Hub + Sigstore signing + SBOM + provenance + GitHub Release
2. **publish-mcp.yml** → GHCR stdio + SSE containers (via workflow_run)
3. **publish-registries.yml** → Smithery + ClawHub (via workflow_run)
4. **publish-mcp-registry.yml** → Official MCP Registry (via workflow_run)
5. **deploy-mcp-sse.yml** → Railway deployment (via workflow_run)

Each GitHub Release should include these verification assets alongside the
wheel and source tarball:

- `agent-bom-sbom.cdx.json`
- `dist/*.sigstore.json`
- `dist/*.intoto.jsonl`

Use [`docs/RELEASE_VERIFICATION.md`](RELEASE_VERIFICATION.md) for the exact
verification flow against a tagged release.

Release operators should also review:

- [`docs/IMAGE_SECURITY.md`](IMAGE_SECURITY.md)
- [`docs/GOLDEN_IMAGE_PROGRAM.md`](GOLDEN_IMAGE_PROGRAM.md)
- [`security/image-exceptions.yaml`](../security/image-exceptions.yaml)

For dependency-heavy or security-driven releases, also verify:

- notable upgrade PRs include a short release-note summary
- major dependency bumps were reviewed for breaking changes before merge
- any user-visible install, auth, or deployment changes are called out in the GitHub Release notes
- deployed health/version/freshness surfaces still report the same release version after publish

---

## Platform Status

| Platform | Entry File | Automated | Trigger |
|----------|-----------|-----------|---------|
| **PyPI** | `pyproject.toml` | release.yml | tag push |
| **Docker Hub** | `Dockerfile` | release.yml | tag push |
| **GHCR (stdio)** | `Dockerfile.mcp` | publish-mcp.yml | workflow_run |
| **GHCR (SSE)** | `deploy/docker/Dockerfile.sse` | publish-mcp.yml | workflow_run |
| **Smithery** | workflow API | publish-registries.yml | workflow_run |
| **ClawHub** | curated `integrations/openclaw/*/SKILL.md` set | publish-registries.yml | workflow_run |
| **MCP Registry** | `integrations/mcp-registry/server.json` | publish-mcp-registry.yml | workflow_run |
| **Railway** | `deploy/docker/Dockerfile.sse` | deploy-mcp-sse.yml | workflow_run |
