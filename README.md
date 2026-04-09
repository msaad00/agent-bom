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

<p align="center"><b>Open security scanner and graph for agentic infrastructure — discover agents and MCP, map blast radius, and inspect runtime.</b></p>

<p align="center">Security and visibility for agentic infrastructure should be open, transparent, and accessible — not reserved for teams with enterprise budgets.</p>

<p align="center"><b>Package risk is only the start. What matters is what it can reach.</b></p>

```text
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  |── better-sqlite3@9.0.0  (npm)
       |── sqlite-mcp  (MCP Server · unverified · root)
            |── Cursor IDE  (Agent · 4 servers · 12 tools)
            |── ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            |── query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

**agent-bom maps the blast radius**: CVE → package → MCP server → AI agent → credentials → tools.

Package risk is only the start. agent-bom maps what it can reach across MCP servers, agents, credentials, tools, and runtime context. CWE-aware impact classification keeps a DoS from being reported like credential compromise.

`agent-bom` is now a real released product surface, not just a research repo: installable from PyPI, publishable through Docker, usable in GitHub Actions, deployable as an authenticated API and remote MCP service, and validated end to end through CLI, reports, API, dashboard, and policy gates.

For the canonical product brief and verified repo-derived metrics, see [docs/PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md) and [docs/PRODUCT_METRICS.md](docs/PRODUCT_METRICS.md). For enterprise-control traceability, see [docs/ENTERPRISE.md](docs/ENTERPRISE.md).

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom blast radius demo" width="900" />
</p>

Try the built-in demo first:

```bash
agent-bom agents --demo --offline
```

The GIF uses that curated sample so the output stays reproducible across releases. For real scans, run `agent-bom agents`, or add `-p .` to fold project lockfiles and manifests into the same scan.

Current repo-derived counts live in [docs/PRODUCT_METRICS.md](docs/PRODUCT_METRICS.md). The README keeps the product story stable and leaves fast-moving counts in the generated metrics appendix.

## First commands after install

If you only run three commands, make them these:

```bash
agent-bom agents -p .              # Local agent + MCP + project package scan
agent-bom serve                    # API + dashboard + unified graph explorer
agent-bom proxy "npx @mcp/server-fs /workspace"   # Runtime MCP inspection path
```

Pick the one that matches your first goal:

| Goal | Run | What you get |
|---|---|---|
| Find what is installed and reachable | `agent-bom agents -p .` | Agent discovery, MCP mapping, project dependency findings, blast radius |
| Review findings in a persistent graph | `agent-bom serve` | API, dashboard, unified graph, current-state and diff views |
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

<details>
<summary><b>More commands</b></summary>

```bash
agent-bom cloud aws                     # Cloud AI posture + CIS benchmarks
agent-bom agents -f cyclonedx -o bom.json  # AI BOM / SBOM export
agent-bom check requests@2.33.0 -e pypi -f json  # Machine-readable pre-install verdict
agent-bom report diff before.json after.json -f json  # CI-friendly diff output
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
- AI-native coverage across agents, skills, instruction files, runtime proxy traffic, containers, cloud, and IaC
- Unified graph explorer with snapshots, diff, search, impact, attack paths, and OCSF-ready export
- Supply-chain depth across lockfiles, transitive dependencies, model artifacts, provenance, and hash verification
- One operator path across CLI, CI, API, dashboard, reports, and MCP tools

## Graph explorer

The graph is now a first-class product path, not a side export. The same persisted graph supports current-state review, snapshot diffs, attack-path drilldown, search, impact, compliance posture, and OCSF-ready export.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/topology-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/topology-light.svg" alt="agent-bom unified graph explorer" width="900" />
  </picture>
</p>

Use whichever entrypoint fits your workflow:

```bash
agent-bom serve                    # Persist scans and explore them in the dashboard
agent-bom graph report.json        # Generate graph-facing output from an existing report
agent-bom mesh --project .         # Quick local topology view from the CLI
```

## Architecture at a glance

One pipeline: discovery and runtime inspection feed the scanners, the scanners feed the unified graph, and the same graph powers CLI, API, dashboard, search, diff, impact, attack-path drilldown, and OCSF-ready export.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-stack-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-stack-light.svg" alt="agent-bom architecture at a glance" width="900" />
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
| GitHub Action | `uses: msaad00/agent-bom@v0.76.0` | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom` | Isolated scans |
| MCP Server | `agent-bom mcp server` | Claude Desktop, Claude Code, Cursor, Codex, Windsurf, Cortex |
| Runtime proxy | `agent-bom proxy` | MCP traffic enforcement |
| Shield SDK | `from agent_bom.shield import Shield` | In-process protection |
| API + dashboard | `agent-bom serve` | Fleet visibility, audit exports, and central review |

### CI/CD in 60 seconds

Use the GitHub Action when you want a fast CI gate: one step, one gate, SARIF in the Security tab, and a clean exit code for CI.

**Repo + MCP + instruction files**

```yaml
- uses: msaad00/agent-bom@v0.76.0
  with:
    scan-type: scan
    severity-threshold: high
    upload-sarif: true
    enrich: true
    fail-on-kev: true
```

**Container image gate**

```yaml
- uses: msaad00/agent-bom@v0.76.0
  with:
    scan-type: image
    scan-ref: ghcr.io/acme/agent-runtime:sha-abcdef
    severity-threshold: critical
```

**IaC gate**

```yaml
- uses: msaad00/agent-bom@v0.76.0
  with:
    scan-type: iac
    iac: Dockerfile,k8s/,infra/main.tf
    severity-threshold: high
```

**Air-gapped / pre-synced CI**

```yaml
- uses: msaad00/agent-bom@v0.76.0
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

JSON, SARIF, CycloneDX 1.6 (with ML BOM), SPDX 3.0, HTML, Graph JSON, Graph HTML, GraphML, Neo4j Cypher, JUnit XML, CSV, Markdown, Mermaid, SVG, Prometheus, Badge, OCSF, Attack Flow, plain text.

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

Also on [Glama](https://glama.ai/mcp/servers/@msaad00/agent-bom), [Smithery](integrations/smithery.yaml), [MCP Registry](integrations/mcp-registry/server.json), and [OpenClaw](integrations/openclaw/SKILL.md).

---

## Trust & transparency

| When | What's sent | Where | Opt out |
|---|---|---|---|
| Default CVE lookups (`agents`, `scan`, `check`, `image`) | Package names + versions | OSV API | `--offline` |
| Floating version resolution | Package names, requested version/latest lookup | npm, PyPI, Go proxy | `--offline` |
| `--enrich` | CVE IDs | NVD, EPSS; KEV catalog download from CISA | Don't use `--enrich` |
| `--deps-dev` | Package names + versions | deps.dev | Don't use `--deps-dev` |
| `verify` | Package name + version | PyPI or npm integrity endpoints | Don't run `verify` |
| Optional push/integrations | Finding summaries or evidence bundles | Slack, Jira, Vanta, Drata | Don't pass those flags |

No source code, config contents, or credential values are sent. No telemetry or analytics. [Sigstore-signed](docs/PERMISSIONS.md) releases. See [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) and [PERMISSIONS.md](docs/PERMISSIONS.md) for the full trust model.

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
