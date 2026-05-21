<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-light.svg" alt="agent-bom" width="360" />
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

<p align="center"><b>Open security scanner and self-hosted control plane for AI/MCP infrastructure.</b></p>
<p align="center">Headless agent primitives and human cockpit surfaces over the same evidence model.</p>

<p align="center">
  <a href="https://msaad00.github.io/agent-bom/">Docs</a> ·
  <a href="docs/FIRST_RUN.md">First Run</a> ·
  <a href="site-docs/deployment/overview.md">Self-host</a> ·
  <a href="https://github.com/marketplace/actions/agent-bom">GitHub Action</a> ·
  <a href="https://hub.docker.com/r/agentbom/agent-bom">Docker</a> ·
  <a href="https://github.com/msaad00/agent-bom/releases">Changelog</a>
</p>

`agent-bom` scans local and fleet AI infrastructure, builds an AI BOM across
agents, MCP servers, tools, packages, credential environment names, cloud,
runtime, and skills, then turns that inventory into findings, compliance
evidence, and graph-backed exposure paths.

The same evidence is available through CLI/CI, REST API, MCP tools, and a
self-hosted dashboard. Runtime proxy/gateway controls are optional and scoped
to environments where enforcement is worth the operational cost.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="agent-bom blast-radius drilldown — package to finding to MCP server to agent" width="900" />
  </picture>
</p>

```text
package -> vulnerability finding -> MCP server -> tools + credential refs -> agent
```

Blast radius is the core idea. A vulnerable package is not just a CVE row; it
is linked to the MCP server that loads it, the tools exposed by that server,
the credential environment names in reach, and the agents that can call it.

## First Run

```bash
pip install agent-bom
agent-bom agents --demo --offline
```

The demo uses real OSV/GHSA advisories against intentionally vulnerable sample
packages and produces graph-ready inventory without touching your source tree.
For a real local scan:

```bash
agent-bom agents -p . -f html -o agent-bom-report.html
```

Want an inspectable sample stack first?

```bash
agent-bom samples first-run
agent-bom agents --inventory agent-bom-first-run/inventory.json -p agent-bom-first-run --enrich
```

See [docs/FIRST_RUN.md](docs/FIRST_RUN.md) for the guided path from CLI output
to the dashboard.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom terminal demo" width="820" />
</p>

## Product Proof

The dashboard screenshots below are captured from the packaged UI with bundled
demo data, not mockups. The README keeps the first screen focused; expand the
gallery when you want to inspect the control-plane surfaces.

<details open>
<summary><b>Evidence cockpit and agent mesh</b></summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png" alt="agent-bom risk overview dashboard with posture score, findings, and attack path summary" width="900" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png" alt="agent-bom agent mesh graph showing agent, MCP server, package, tool, credential reference, and finding path" width="900" />
</p>

</details>

<details>
<summary><b>Graph investigation and remediation views</b></summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/security-graph-live.png" alt="agent-bom security graph with attack-path queue, graph evidence export, and remediation handoff" width="900" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/lineage-graph-live.png" alt="agent-bom lineage graph centered on an agent with bounded paths, filters, and graph evidence export" width="900" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dependency-map-live.png" alt="agent-bom dependency map with scan pipeline counts and package risk distribution" width="900" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/remediation-live.png" alt="agent-bom remediation dashboard with prioritized package fixes and compliance context" width="900" />
</p>

</details>

Screenshot capture rules and the full manifest live in
[docs/CAPTURE.md](docs/CAPTURE.md) and
[docs/images/product-screenshots.json](docs/images/product-screenshots.json).

## Start Here

| Goal | Command | Artifact |
|---|---|---|
| Local agent and MCP inventory | `agent-bom agents` | findings, AI BOM, graph-ready JSON |
| Repo and lockfile scan | `agent-bom agents -p .` | package findings, SARIF/SBOM/HTML when requested |
| Pre-install guard | `agent-bom check flask@2.0.0 --ecosystem pypi` | deterministic allow/warn/block result |
| Container image scan | `agent-bom image nginx:latest` | image findings and remediation |
| IaC scan | `agent-bom iac Dockerfile k8s/ infra/main.tf` | IaC findings and policy context |
| CI gate | `uses: msaad00/agent-bom@v0.87.1` | SARIF, PR summary, optional code-scanning upload |
| MCP tools | `pip install 'agent-bom[mcp-server]' && agent-bom mcp server` | strict-args security tools for MCP clients |
| Local API/UI | `pip install 'agent-bom[ui]' && agent-bom serve` | API plus bundled dashboard |
| Self-hosted pilot | `docker compose -f docker-compose.pilot.yml up -d` | API and dashboard in your environment |

The base wheel is the scanner and CLI path. Optional runtime surfaces fail fast
with install hints when their extras are missing.

MCP registry publishing is tracked through the committed Smithery manifest and
other registry metadata; install and liveness checks stay in the linked
integration docs instead of this front door.

## Shipped Surfaces

| Surface | Primary user | Current boundary |
|---|---|---|
| CLI / CI | developers and release gates | local scans, SARIF/SBOM/HTML/JSON, deterministic exit codes |
| REST API | control-plane integrations | scans, bulk findings, dataset versions, graph evidence, audit, runtime summaries |
| MCP tools | agents and assistants | strict arguments, read-only security queries, exposure paths, deploy decisions |
| Dashboard | security teams and operators | inventory, findings, graph cockpit, compliance, evidence, runtime posture |
| Runtime proxy/gateway | runtime operators | scoped MCP traffic inspection, policy decisions, redacted audit evidence |
| Python client | services, notebooks, and automation | typed helper for stable REST endpoints in the packaged wheel |
| TypeScript client | services and agent runtimes | typed helper for stable REST endpoints |

MCP server mode advertises 51 read-only security tools, 6 resources, and 6 workflow prompts.

CLI scan commands run local scan pipelines today. They share lower scanner and
discovery libraries with the API, but they are not API wrappers yet.

## Deploy In Your Boundary

`agent-bom` is designed for customer-controlled deployment: local CLI, Docker,
GitHub Action, Helm, EKS, Postgres, and optional runtime proxy/gateway.

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

Production self-hosting starts with the deployment chooser:

- [Deployment overview](site-docs/deployment/overview.md)
- [Helm chart](deploy/helm/agent-bom)
- [EKS reference installer](scripts/deploy/install-eks-reference.sh)
- [Docker Hub image](https://hub.docker.com/r/agentbom/agent-bom)

There is no managed cloud offering in this repository today. Product lane
boundaries are documented in [docs/PRODUCT_BOUNDARIES.md](docs/PRODUCT_BOUNDARIES.md).

## Trust Model

- Read-only discovery by default for cloud and local inventory.
- No mandatory telemetry.
- Credential values are redacted; credential environment names are preserved as
  evidence so exposure paths stay explainable.
- Findings can export as JSON, SARIF, CycloneDX, SPDX, Markdown, HTML, and
  compliance evidence bundles.
- API and runtime paths are designed for tenant scope, auth boundaries, and
  audit evidence.
- OpenAPI artifacts are committed for SDK and client contract checks.

Security and release references:

- [Threat model](docs/THREAT_MODEL.md)
- [Pentest readiness](docs/PENTEST_READINESS.md)
- [Product metrics](docs/PRODUCT_METRICS.md)
- [Release verification](docs/RELEASE_VERIFICATION.md)
- [GitHub Action](https://github.com/marketplace/actions/agent-bom)

## Product Views

The docs site carries the deployment-oriented walkthroughs behind those
screenshots:

- [Dashboard and graph capture protocol](docs/CAPTURE.md)
- [Documentation site](https://msaad00.github.io/agent-bom/)
- [Deployment overview](site-docs/deployment/overview.md)

## Contributing

Contributions are welcome. Start with:

- [CONTRIBUTING.md](CONTRIBUTING.md)
- [.agents/AGENTS.md](.agents/AGENTS.md)
- [Open issues](https://github.com/msaad00/agent-bom/issues)

License: Apache-2.0.
