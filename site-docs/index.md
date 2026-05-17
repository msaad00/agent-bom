# agent-bom

**Open security scanner and self-hosted control plane for AI/MCP infrastructure.**

`agent-bom` is also an open security data plane. It generates a
reachability-backed AI BOM across agents, MCP servers, tools, packages,
credential environment names, cloud, runtime, and skill surfaces, then exposes
the same evidence to humans and AI agents through CLI/CI, API/UI, MCP tools,
and selected runtime controls. For source-by-source boundaries, see the
[AI infrastructure coverage matrix](architecture/ai-infrastructure.md#coverage-matrix).

## What it does

```
better-sqlite3@9.0.0  (npm package)
  ├─ OSV/GHSA finding  (critical · advisory-backed)
  └─ sqlite-mcp  (MCP Server · unverified)
       ├─ Cursor IDE  (Agent · 4 servers · 12 tools)
       ├─ ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credential env names visible)
       └─ query_db, read_file, write_file  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

Package risk is only the start. agent-bom maps the reachable path from a vulnerable package instance to MCP servers, agents, credential names, tools, and runtime context.

## Quick start

```bash
pip install agent-bom
agent-bom agents                         # auto-discover local AI agents + MCP servers
agent-bom skills scan .                 # scan skills / instruction files
agent-bom check flask@2.0.0 --ecosystem pypi   # check a specific package
```

[Get started](getting-started/install.md){ .md-button .md-button--primary }
[View on GitHub](https://github.com/msaad00/agent-bom){ .md-button }

## Start with one lane

| Lane | First command | Artifact |
|---|---|---|
| **Local AI BOM** | `agent-bom agents --demo --offline` | terminal findings and graph-ready inventory |
| **Repository scan** | `agent-bom agents -p . -f html -o agent-bom-report.html` | local HTML review plus exportable evidence |
| **CI evidence** | `uses: msaad00/agent-bom@v0.86.5` | SARIF, pull-request summary, optional code scanning |
| **Assistant tools** | `agent-bom mcp server` | read-only security tools for MCP clients |
| **Self-hosted control plane** | `docker compose -f docker-compose.pilot.yml up -d` | API and dashboard in your infrastructure |

## One evidence model, four consumers

| Surface | Who uses it | What is shipped |
|---|---|---|
| **CLI / CI** | developers and pipelines | scans, SARIF/SBOM/HTML/JSON, graph exports, deterministic gates |
| **API / UI** | security teams and auditors | self-hosted control plane, graph cockpit, compliance, audit, evidence review |
| **MCP tools** | AI agents and coding assistants | 38 read-only tools, strict args, `exposure_paths`, `should_i_deploy` |
| **Runtime controls** | platform and runtime operators | proxy/gateway/Shield policy decisions, redacted audit, selected live evidence |

The dashboard is not the only door into the product. It is the human cockpit
over the same evidence that agents can request through MCP and platforms can
consume through API, CLI, reports, and exports.

## Current graph and agent surfaces

- `ExposurePath` is the shared investigation object for API, UI, reports, JSON,
  and MCP agent workflows.
- Sigma.js and graphology provide the WebGL overview path for broad graph
  scenes; React Flow remains the focused path and evidence renderer.
- The graph model includes time-versioned edges, semantic clusters, toxic-combo
  projection, identity taxonomy, and AWS IAM identity enrichment.
- MCP exposes `exposure_paths` and `should_i_deploy` for headless agents that
  need ranked investigation context or deploy guidance.

Neptune is an optional enterprise backend lane. The default self-hosted path
remains SQLite/Postgres, and the docs do not claim a live Neptune production
SLO or openCypher endpoint.

## Current boundaries

- `@agent-bom/runtime` is a TypeScript runtime-detector package, not a full
  scanner or API SDK.
- Managed agent-bom Cloud, posture-event streaming connectors, and
  detection-as-code YAML are roadmap items, not shipped product in this repo.
- AWS IAM identity enrichment is opt-in and read-only; it does not imply
  complete identity coverage across every provider.

## Key capabilities

| Capability | Description |
|---|---|
| **Discovery** | Auto-detect 29 first-class MCP client types plus dynamic/project surfaces |
| **CVE scanning** | OSV + NVD CVSS v4 + EPSS + CISA KEV + GHSA |
| **Blast radius** | Map CVE impact: package → vulnerability finding → MCP server (tools + credential env names) → connected agents |
| **Registry** | 427+ MCP server security metadata entries |
| **Compliance** | OWASP LLM/Agentic/MCP Top 10, MITRE ATLAS, EU AI Act, NIST AI RMF, CIS |
| **Runtime proxy** | Policy enforcement, credential leak detection, audit logging |
| **SBOM** | CycloneDX 1.6, SPDX 3.0 output |
| **Cloud** | AWS, Snowflake, Azure, GCP CIS benchmarks |

## Deploy In Your Infra

`agent-bom` is not limited to one hosting model. The clean self-hosted story is:

- **control plane**: API + UI + Postgres
- **scan**: CI jobs, scheduled CronJobs, or one-off discovery runs
- **fleet**: endpoint and collector inventory pushed into one control plane
- **runtime**: selected `agent-bom proxy` sidecars or local proxy wrappers
- **gateway**: central policy management for those proxy paths

| Need | Recommended path |
|---|---|
| local scan or CI gate | CLI or GitHub Action |
| self-hosted operator plane | API + UI + Postgres |
| your own AWS / EKS rollout | Helm control plane + scheduled scan jobs + selected proxy sidecars |
| developer workstation inventory | fleet sync |
| live MCP enforcement | proxy + gateway |
| assistant-facing tool server | `agent-bom mcp server` |

[Deployment Overview](deployment/overview.md){ .md-button .md-button--primary }
[Your Own AWS / EKS](deployment/own-infra-eks.md){ .md-button }
[Product Boundaries](deployment/product-boundaries.md){ .md-button }
