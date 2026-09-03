# Platform Publishing Guide

How to publish agent-bom to each MCP ecosystem platform.

## Prerequisites

- agent-bom is already published on [PyPI](https://pypi.org/project/agent-bom/) (automated via release CI)
- Docker images are published to Docker Hub and GHCR (automated via release CI)
- MCP server supports both **stdio** and **SSE/streamable-http** transports

---

## 1. Smithery

Smithery runs agent-bom as a Smithery-managed remote MCP surface. Its public
catalog API exposes the listing, deployment URL, and tool inventory; the remote
transport itself is OAuth-gated by Smithery and does not expose agent-bom's raw
`/health` route. Do not use `https://server.smithery.ai/.../mcp` as an upstream
publish URL or health endpoint.

### Step 1: Keep the protected MCP deployment healthy

The primary SSE/streamable-http server is deployed on Railway at
`https://agent-bom-mcp.up.railway.app` (automated via `deploy-mcp-sse.yml`).
Secure remote deployments should set `AGENT_BOM_MCP_BEARER_TOKEN` in Railway
service variables so the MCP transport starts with built-in authentication. The
same protected origin publishes OAuth protected-resource/authorization-server
discovery and a static MCP server card; Smithery uses that OAuth2 contract to
index the catalog without receiving the deployment's bearer token. Keep TLS at
your ingress or platform edge.

The daily deployment-freshness workflow probes this protected Railway `/health`
surface with the configured bearer token, and probes Smithery through
`https://api.smithery.ai/servers/agent-bom/agent-bom` for catalog liveness,
remote deployment metadata, and non-empty tools.

### Step 2: Publish to Smithery

**Option A — Web UI**:
1. Go to https://smithery.ai/servers/new
2. Namespace: `agent-bom`
3. Server ID: `agent-bom`
4. Follow Smithery's managed remote flow for the `agent-bom/agent-bom` listing.
5. Click **Continue**

**Option B — Automated**:
The `publish-registries.yml` workflow parses the static server-card tool names
from the immutable release commit, then compares that contract with both the
live server card and Smithery's public catalog before publishing. If they
already match and the latest successful release is bound to the configured
upstream URL, the workflow skips a duplicate deployment. If capabilities or
the upstream changed, it creates an external release using:
- `SMITHERY_API_TOKEN`

`SMITHERY_MCP_URL` is retained only for the external-upstream publish mode. It
must never point at Smithery's hosted proxy URL. Freshness monitoring no longer
depends on that variable; it uses the Smithery catalog API directly.

Do not add the upstream bearer token to Smithery `configSchema`. Smithery
reserves the `Authorization` header for OAuth. If a capability scan pauses as
`AUTH_REQUIRED`, the workflow reads the release through Smithery's authenticated
API, accepts only an authorization URL on the configured Agent-Bom origin,
follows the bounded machine-to-machine PKCE callback without logging its OAuth
state. The only permitted redirect is the configured authorization endpoint to
Smithery's exact HTTPS callback; a second redirect or alternate host, port, or
path fails closed. The workflow never creates a duplicate while a matching
release remains active, retries every six hours, and fails honestly if the
provider still requires authorization or the exact catalog does not converge.

### Verification

After publishing, check:

```bash
curl -fsSL https://api.smithery.ai/servers/agent-bom/agent-bom \
  | jq '{qualifiedName, remote, deploymentUrl, tool_count: (.tools | length)}'
```

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
clawhub login --token "$CLAWHUB_TOKEN" --no-browser
clawhub publish integrations/openclaw/scan \
  --slug agent-bom-scan --name "agent-bom scan" \
  --version "0.103.2"
```

Release automation uses the same official `clawhub` CLI flow, not a custom
multipart API shim, so local publishing and CI stay aligned.

### Verification

```bash
clawhub install agent-bom-scan
```

---

## 4. Glama

Glama indexes the repository README and builds the MCP schema from
`integrations/glama/Dockerfile`. Glama synchronizes linked GitHub repositories
automatically at least daily. `publish-registries.yml` verifies the exact
released version and MCP tool set immediately after a release and every six
hours; it does not call an undocumented provider endpoint or report stale data
as published.

For an immediate provider-side refresh, open the server's admin page and use
**Sync Server**, then dispatch **Publish to Registries** again. Verification
requires both the released version marker and the exact MCP tool-name set
parsed from the immutable release commit; the live server card is checked
independently against the same contract.

A Glama hosted release is separate from directory synchronization. Creating
one remains a maintainer action in Glama: configure the Dockerfile build,
deploy and pass the build test, then create and publish the Glama release.

```bash
python scripts/check_glama_listing.py \
  --expected 0.103.2
```

---

## 5. Docker Hub

Automated via `.github/workflows/release.yml` on each tag push.

Images published:
- `agentbom/agent-bom:{version}`
- `agentbom/agent-bom:latest`
- `agentbom/agent-bom-ui:{version}`
- `agentbom/agent-bom-ui:latest`

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

## 6. Docker Images

Automated via `.github/workflows/publish-mcp.yml` after each release.

Images published:
- `agentbom/agent-bom:{tag}` — CLI, API, scanner jobs, gateway, and MCP server

---

## 7. Creating a Release

Tag push triggers the full pipeline automatically:

```bash
git tag v0.103.2
git push origin v0.103.2
```

This triggers:
1. **release.yml** → PyPI + Docker Hub + Sigstore signing + SBOM + provenance + GitHub Release
2. **publish-mcp.yml** → GHCR stdio + SSE containers (via workflow_run)
3. **publish-registries.yml** → Smithery + ClawHub (via workflow_run)
4. **publish-mcp-registry.yml** → Official MCP Registry (via workflow_run)
5. **deploy-mcp-sse.yml** → Railway deployment (called from the release workflow)

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
| **Glama directory** | `glama.json` + `integrations/glama/Dockerfile` | provider sync + strict verification | provider daily sync / publish-registries.yml every 6 hours |
| **ClawHub** | curated `integrations/openclaw/*/SKILL.md` set | publish-registries.yml | workflow_run |
| **MCP Registry** | `integrations/mcp-registry/server.json` | publish-mcp-registry.yml | workflow_run |
| **Railway** | `deploy/docker/Dockerfile.sse` | deploy-mcp-sse.yml | release workflow_call / workflow_dispatch |
