<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-light.svg" alt="agent-bom" width="480" />
  </picture>
</p>

<p align="center">
  <a href="https://github.com/msaad00/agent-bom/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/msaad00/agent-bom/ci.yml?branch=main&style=flat&label=Build" alt="Build"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/v/agent-bom?style=flat&label=Latest%20version&cacheSeconds=300" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/agentbom/agent-bom"><img src="https://img.shields.io/docker/pulls/agentbom/agent-bom?style=flat&label=Docker%20pulls" alt="Docker"></a>
  <a href="https://github.com/msaad00/agent-bom/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat" alt="License"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom"><img src="https://img.shields.io/ossf-scorecard/github.com/msaad00/agent-bom?style=flat&label=OpenSSF%20scorecard" alt="OpenSSF Scorecard"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center"><b>Open security scanner for AI supply chain — agents, MCP servers, packages, containers, cloud, GPU, and runtime.</b></p>

<p align="center">Start with the demo, then choose the entrypoint that matches your first job: repo scan, image scan, cloud posture, fix plan, dashboard, or runtime review.</p>

```text
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  |── better-sqlite3@9.0.0  (npm)
       |── sqlite-mcp  (MCP Server · unverified · root)
            |── Cursor IDE  (Agent · 4 servers · 12 tools)
            |── ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            |── query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

Blast radius is the core idea: `CVE -> package -> MCP server -> agent -> credentials -> tools`.

`agent-bom` scans local agent configs, MCP servers, instruction files, lockfiles, containers, cloud posture, GPU surfaces, and runtime evidence. CWE-aware impact keeps a DoS from being reported like credential compromise.

Try the built-in demo first:

```bash
agent-bom agents --demo --offline
```

The demo uses a curated sample so the output stays reproducible across releases. For real scans, run `agent-bom agents`, or add `-p .` to fold project manifests and lockfiles into the same result.

Choose the view that matches what you need:

- CLI: fast local proof that blast radius and remediation are real
- Graph: one focused path first, then expand only when needed
- Dashboard: persistent state, diff, and review

<details>
<summary><b>See the terminal demo</b></summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom terminal demo" width="820" />
</p>

</details>

## Recommended starting points

Pick the entrypoint that matches your first job:

| Goal | Run | What you get |
|---|---|---|
| Find what is installed and reachable | `agent-bom agents -p .` | Agent discovery, MCP mapping, project dependency findings, blast radius |
| Turn findings into a fix plan | `agent-bom agents -p . --remediate remediation.md` | Prioritized remediation plan with fix versions and reachable impact |
| Check a package before install | `agent-bom check flask@2.2.0 --ecosystem pypi` | Machine-readable pre-install verdict |
| Scan a container image | `agent-bom image nginx:latest` | OS and package CVEs with fixability |
| Audit IaC or cloud posture | `agent-bom iac Dockerfile k8s/ infra/main.tf` | Misconfigurations and posture findings |
| Review findings in a persistent graph | `agent-bom serve` | API, dashboard, unified graph, current-state and diff views. Requires `pip install 'agent-bom[ui]'` once. |
| Inspect live MCP traffic | `agent-bom proxy "<server command>"` | Inline runtime inspection, detector chaining, response/argument review |

## Quick start

```bash
pip install agent-bom                  # Standard CLI install
# pipx install agent-bom               # Isolated global install
# uvx agent-bom --help                 # Ephemeral run without installing

agent-bom agents                              # Discover + scan local AI agents and MCP servers
agent-bom agents -p .                         # Scan project lockfiles/manifests plus agent/MCP context
agent-bom where                               # Show MCP discovery paths checked on this machine
agent-bom mesh --project .                    # Show the live agent / MCP topology
agent-bom skills scan .                       # Scan CLAUDE.md, AGENTS.md, .cursorrules, skills/*
agent-bom check flask@2.0.0 --ecosystem pypi  # Pre-install CVE gate
agent-bom image nginx:latest                  # Container image scan
agent-bom iac Dockerfile k8s/ infra/main.tf   # IaC scan across one or more paths
```

## What to do after the first scan

```bash
agent-bom agents -p . --remediate remediation.md                    # Fix-first plan with versions and reachable impact
agent-bom agents -p . --compliance-export fedramp -o evidence.zip   # ZIP evidence bundle for auditors
pip install 'agent-bom[ui]'                                         # once, for API + dashboard
agent-bom serve                                                     # Review the same findings in the dashboard and graph
```

<details>
<summary><b>More commands</b></summary>

```bash
agent-bom cloud aws                     # Cloud AI posture + CIS benchmarks
agent-bom agents -f cyclonedx -o bom.json  # AI BOM / SBOM export
agent-bom check requests@2.33.0 -e pypi -f json  # Machine-readable pre-install verdict
agent-bom report diff before.json after.json -f json  # CI-friendly diff output
agent-bom agents -p . --compliance-export fedramp -o fedramp-evidence.zip  # Auditor-ready evidence bundle
agent-bom graph report.json                # Blast radius graph / graph HTML inputs
agent-bom proxy "npx @mcp/server-fs /ws"   # MCP security proxy
agent-bom secrets src/                  # Hardcoded secrets + PII
agent-bom verify agent-bom              # Verify this installation
agent-bom verify requests@2.33.0        # Package integrity verification
agent-bom verify --model-dir ./models   # Model weight hash verification
agent-bom serve                         # API + Next.js dashboard
```

</details>

---

## Why teams use it

- Blast radius that maps `CVE -> package -> MCP server -> agent -> credentials -> tools`
- One operator path across CLI, CI, API, dashboard, remediation, and MCP tools
- AI-native coverage across agents, MCP, runtime, containers, cloud, IaC, and GPU surfaces
- Compliance evidence bundles for `cmmc`, `fedramp`, and `nist-ai-rmf`

## Deploy in your own AWS / EKS

This is one of the core self-hosted paths now, not a side note:

- employee endpoints push fleet discovery into your control plane
- selected MCP workloads run the proxy locally or as sidecars
- gateway policy stays in your control plane
- Postgres, audit, secrets, ingress, and logs stay in your infra

```text
Employee laptops                    Your AWS / EKS cluster
Cursor / Claude / VS Code           ┌──────────────────────────────────────┐
Codex / Cortex / Continue           │ agent-bom control plane             │
         │                          │  - API + UI                         │
agent-bom agents --push ───────────▶│  - fleet / mesh / gateway / audit   │
         │                          │  - OIDC / RBAC / Postgres           │
         │                          └────────────────┬─────────────────────┘
         │                                           │
agent-bom proxy -- <mcp cmd>                         │ policy pull + audit push
         │                                           │
         └──────────────────────────────────────────▶│
                                                     ▼
                                        selected MCP workloads in EKS
                                        with agent-bom proxy sidecars
```

What that gives you:

- endpoint fleet visibility for developer laptops and local MCP clients
- runtime enforcement for selected MCP workloads in-cluster
- one control plane for fleet, mesh, findings, gateway policy, and audit
- no mandatory hosted vendor plane

Focused entrypoints:

```bash
# control plane in your cluster
helm install agent-bom deploy/helm/agent-bom \
  --set controlPlane.enabled=true \
  --set db.backend=postgres

# endpoint fleet sync
agent-bom agents --preset enterprise --introspect \
  --push-url https://agent-bom.example.com/v1/fleet/sync

# local MCP enforcement on a laptop or workstation
agent-bom proxy --policy ./policy.json -- <editor-mcp-command>
```

Operator guides:

- [Deploy In Your Own AWS / EKS Infrastructure](site-docs/deployment/own-infra-eks.md)
- [Enterprise MCP / Endpoint Pilot](site-docs/deployment/enterprise-pilot.md)
- [Endpoint Fleet](site-docs/deployment/endpoint-fleet.md)
- [Focused EKS MCP Pilot](site-docs/deployment/eks-mcp-pilot.md)
- [Packaged API + UI Control Plane](site-docs/deployment/control-plane-helm.md)
- [Performance, Sizing, and Benchmarks](site-docs/deployment/performance-and-sizing.md)

## Product views

These screenshots come from the live product path, using the built-in demo data pushed into the API.

### Dashboard

Risk summary, posture, and the highest-value attack paths without waiting on deep scan hydration.

![agent-bom dashboard](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png)

### Security graph / attack-path drilldown

The security graph starts with one vulnerable path in view so remediation stays fix-first: package -> vulnerability -> MCP server -> agent -> credential and tool exposure.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="agent-bom security graph attack-path drilldown" width="900" />
  </picture>
</p>

### Agent mesh

The current mesh is an agent-centered shared-infrastructure graph: selected agents, their shared MCP servers, tools, packages, and findings. It is not yet a pure runtime agent-to-agent interaction graph.

![agent-bom agent mesh](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png)

### Fix-first remediation

Risk, reach, fix version, and framework context stay in one review table so the operator can act without jumping between pages.

![agent-bom remediation view](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/remediation-live.png)

## Framework catalogs

Default scans use the bundled MITRE ATT&CK + CAPEC catalog, so results stay deterministic and offline-friendly. Refresh to a newer upstream snapshot only when you want to:

```bash
agent-bom db update-frameworks
agent-bom db status
```

The active catalog metadata is also surfaced in JSON output (`framework_catalogs`) and the API at `/v1/frameworks/catalogs`. Long-lived connected deployments can point at a synced catalog or opt into runtime refresh with `AGENT_BOM_MITRE_CATALOG_MODE`.

## How the data moves

One path: discover, analyze, persist, then operate across CLI, CI, API, dashboard, and exports.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-light.svg" alt="agent-bom scan and analysis flow" width="900" />
  </picture>
</p>

The broader topology stays explicit too: start from a scoped risky path, then expand outward to the MCP servers, packages, credentials, and tools that share that surface.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/topology-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/topology-light.svg" alt="agent-bom focused topology view" width="900" />
  </picture>
</p>

## Install & deploy

```bash
pip install agent-bom                        # CLI
docker run --rm agentbom/agent-bom agents    # Docker
```

| Mode | Command | Best for |
|------|---------|----------|
| CLI | `agent-bom agents` | Local audit + project scan |
| Endpoint fleet | `agent-bom agents --preset enterprise --introspect --push-url https://.../v1/fleet/sync` | Employee laptops and workstations pushing into a self-hosted fleet view |
| GitHub Action | `uses: msaad00/agent-bom@v0.76.4` | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom` | Isolated scans and containerized self-hosting surfaces |
| Kubernetes / Helm | `helm install agent-bom deploy/helm/agent-bom --set controlPlane.enabled=true` | Packaged self-hosted API + dashboard, scheduled discovery, and optional runtime monitor |
| REST API | `agent-bom api` | Platform integration and self-hosted control plane |
| MCP Server | `agent-bom mcp server` | Claude Desktop, Claude Code, Cursor, Codex, Windsurf, Cortex |
| Runtime proxy | `agent-bom proxy` | MCP traffic enforcement |
| Shield SDK | `from agent_bom.shield import Shield` | In-process protection |
| API + dashboard | `agent-bom serve` | Fleet visibility, audit exports, and central review. Requires `pip install 'agent-bom[ui]'` once. |

Backend choices stay explicit and optional:

- `SQLite` for local and single-node use
- `Postgres` / `Supabase` for the primary transactional control plane
- `ClickHouse` for analytics and event-scale persistence
- `Snowflake` for warehouse-native governance and selected backend paths with explicit parity limits

That means enterprises can run `agent-bom` locally, in CI, in Docker, in Kubernetes / Helm, as a self-hosted API + dashboard, as an MCP server for local or remote clients, and with Postgres, ClickHouse, or Snowflake where each backend actually fits. We do not require one hosted control plane or one cloud vendor.

Product references:
- [docs/PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md)
- [docs/PRODUCT_METRICS.md](docs/PRODUCT_METRICS.md)
- [docs/ENTERPRISE.md](docs/ENTERPRISE.md)
- [docs/SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md)
- [docs/RELEASE_VERIFICATION.md](docs/RELEASE_VERIFICATION.md)
- [How Agent-BOM Works](site-docs/architecture/how-agent-bom-works.md)

## Supply chain and release trust

The dependency and release story is explicit:

- bounded runtime dependency ranges in [pyproject.toml](pyproject.toml)
- locked Python and UI resolution in [uv.lock](uv.lock) and [ui/package-lock.json](ui/package-lock.json)
- per-PR dependency review plus scheduled extras audits
- signed release artifacts, provenance bundles, and published self-SBOMs

If you need the operator-facing details:

- [Supply Chain and Dependency Controls](docs/SUPPLY_CHAIN.md)
- [Release Verification](docs/RELEASE_VERIFICATION.md)

### CI/CD in 60 seconds

Use the GitHub Action when you want a fast CI gate: one step, one gate, SARIF in the Security tab, and a clean exit code for CI.

**Repo + MCP + instruction files**

```yaml
- uses: msaad00/agent-bom@v0.76.4
  with:
    scan-type: scan
    severity-threshold: high
    upload-sarif: true
    enrich: true
    fail-on-kev: true
```

**Container image gate**

```yaml
- uses: msaad00/agent-bom@v0.76.4
  with:
    scan-type: image
    scan-ref: ghcr.io/acme/agent-runtime:sha-abcdef
    severity-threshold: critical
```

**IaC gate**

```yaml
- uses: msaad00/agent-bom@v0.76.4
  with:
    scan-type: iac
    iac: Dockerfile,k8s/,infra/main.tf
    severity-threshold: high
```

**Air-gapped / pre-synced CI**

```yaml
- uses: msaad00/agent-bom@v0.76.4
  with:
    auto-update-db: false
    enrich: false
```

### Enterprise rollout

- `Developer endpoints`: run `agent-bom agents` locally or via MDM for workstation inventory and posture.
- `CI/CD`: use the GitHub Action for PR gates, SARIF upload, image gates, and IaC checks.
- `Central security team`: deploy `agent-bom serve` for fleet ingestion, posture, and audit exports.
- `Air-gapped / isolated`: run the Docker image with `--offline` and `auto-update-db: false` using a pre-synced local DB.

See [docs/ENTERPRISE_DEPLOYMENT.md](docs/ENTERPRISE_DEPLOYMENT.md) for rollout patterns, auth models, and storage backends.

<details>
<summary><b>Install extras</b></summary>

| Extra | Command |
|-------|---------|
| Cloud providers | `pip install 'agent-bom[cloud]'` |
| MCP server | `pip install 'agent-bom[mcp-server]'` |
| REST API | `pip install 'agent-bom[api]'` |
| Dashboard | `pip install 'agent-bom[ui]'` |

</details>

<details>
<summary><b>Output formats</b></summary>

JSON, SARIF, CycloneDX 1.6 (with ML BOM), SPDX 3.0, HTML, Graph JSON, Graph HTML, GraphML, Neo4j Cypher, JUnit XML, CSV, Markdown, Mermaid, SVG, Prometheus, Badge, Attack Flow, plain text.

OCSF is currently used for runtime and SIEM event delivery, not as a general `-f ocsf` report format.

</details>

---

## MCP server

36 security tools available inside any MCP-compatible AI assistant:

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "uvx",
      "args": ["agent-bom", "mcp", "server"]
    }
  }
}
```

Also on [Glama](https://glama.ai/mcp/servers/@msaad00/agent-bom), [Smithery](integrations/smithery.yaml), [MCP Registry](integrations/mcp-registry/server.json), and [OpenClaw](integrations/openclaw/README.md).

---

<details>
<summary><b>Trust & transparency</b></summary>

| When | What's sent | Where | Opt out |
|---|---|---|---|
| Default CVE lookups (`agents`, `scan`, `check`, `image`) | Package names + versions | OSV API | `--offline` |
| Floating version resolution | Package names, requested version/latest lookup | npm, PyPI, Go proxy | `--offline` |
| `--enrich` | CVE IDs | NVD, EPSS; KEV catalog download from CISA | Don't use `--enrich` |
| `--deps-dev` | Package names + versions | deps.dev | Don't use `--deps-dev` |
| `verify` | Package name + version | PyPI or npm integrity endpoints | Don't run `verify` |
| Optional push/integrations | Finding summaries or evidence bundles | Slack, Jira, Vanta, Drata | Don't pass those flags |

No source code, config contents, or credential values are sent. No telemetry or analytics. [Sigstore-signed](docs/PERMISSIONS.md) releases. See [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) and [PERMISSIONS.md](docs/PERMISSIONS.md) for the full trust model.

</details>

---

## Contributing

```bash
git clone https://github.com/msaad00/agent-bom.git && cd agent-bom
pip install -e ".[dev-all]"
pytest && ruff check src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) | [docs/CLI_DEBUG_GUIDE.md](docs/CLI_DEBUG_GUIDE.md) | [SECURITY.md](SECURITY.md) | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

Apache 2.0 — [LICENSE](LICENSE)
