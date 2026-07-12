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
  <a href="https://glama.ai/mcp/servers/msaad00/agent-bom"><img src="https://img.shields.io/badge/MCP-Glama-7c3aed?style=flat" alt="agent-bom on Glama"></a>
  <a href="https://smithery.ai/servers/agent-bom/agent-bom"><img src="https://img.shields.io/badge/MCP-Smithery-1f6feb?style=flat" alt="agent-bom on Smithery"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center"><b>Open security scanner and self-hosted control plane for AI, MCP, and cloud infrastructure.</b></p>
<p align="center">Headless agent primitives and human cockpit surfaces over one shared evidence model.</p>

<p align="center">
  <a href="https://msaad00.github.io/agent-bom/">Docs</a> ·
  <a href="docs/FIRST_RUN.md">First Run</a> ·
  <a href="site-docs/deployment/overview.md">Self-host</a> ·
  <a href="https://github.com/marketplace/actions/agent-bom">GitHub Action</a> ·
  <a href="https://hub.docker.com/r/agentbom/agent-bom">Docker</a> ·
  <a href="https://github.com/msaad00/agent-bom/releases">Changelog</a>
</p>

## Who It's For

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/persona-value-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/persona-value-light.svg" alt="agent-bom personas mapped to value proof: AppSec/GRC to SARIF and compliance, Platform/SRE to fleet sync and CI gates, agent builders to MCP inventory and runtime shield, security engineers to findings queue and attack paths" width="980" />
  </picture>
</p>

<p align="center"><em>Four buyer lanes · one evidence model (<code>Finding</code> + <code>UnifiedGraph</code>)</em></p>

<details>
<summary><b>Persona lane detail</b></summary>

- **AppSec / GRC** — SARIF, compliance packs, and audit-ready exports from the
  same scan that powers the dashboard.
- **Platform / SRE** — fleet sync, Helm deploy, CI gates, and SBOM output
  without a separate scanner stack.
- **Agent builders** — MCP inventory, Shield SDK, and optional runtime proxy or
  gateway enforcement on the same graph.
- **Security engineers** — findings queue, attack-path drilldown, and blast-radius
  context in CLI, API, and UI.

Snowflake is a supported connector lane, not the product center.

MCP server mode advertises 70 MCP tools, 6 resources, and 8 workflow prompts.
Registry metadata is tracked through the committed Smithery manifest and Glama
listing; install and liveness checks live in the integration docs.

</details>

## Start Here

Every lane writes into the same `Finding` and `ContextGraph` model. Pick the
entry point that matches your role; see [docs/PRODUCT_MAP.md](docs/PRODUCT_MAP.md)
for ingest lanes, auth boundaries, and surface detail.

| Need | Surface | First action | Main artifact |
|---|---|---|---|
| Scan a repo, image, or local agent config | CLI / CI | `agent-bom agents -p .` | JSON, SARIF, SBOM, HTML |
| Connect cloud and data-estate evidence | Cloud connectors | `agent-bom connect aws` then `agent-bom cloud scan` | assets, CIS findings, graph edges |
| Review posture as a team | API + dashboard | `pip install 'agent-bom[ui]' && agent-bom serve` | findings, graph, audit, compliance |
| Give agents security tools | MCP server | `agent-bom mcp server` | strict MCP tool responses |
| Govern runtime tool calls | Proxy / gateway | configure proxy or gateway policy | allow/warn/block audit trail |
| Package evidence for audit | Reports / exports | `agent-bom agents -p . -f html -o report.html` | SARIF, CycloneDX, SPDX, OCSF, compliance bundle |

| Goal | Command |
|---|---|
| Multi-hop exposure paths | `agent-bom graph` |
| LLM cost forecast | `agent-bom cost forecast` |
| Non-human identity posture | `agent-bom identity credential-expiry` |
| Advisory remediation plan | `agent-bom remediate -p .` |
| Gated-capability readiness | `agent-bom capabilities` |
| CI gate | `uses: msaad00/agent-bom@v0.94.2` |

Full command map: [docs/CLI_MAP.md](docs/CLI_MAP.md) · role routing:
[docs/START_HERE.md](docs/START_HERE.md) · repo layout:
[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md)

## First Run

```bash
pip install agent-bom
agent-bom db update                      # populate ~/.agent-bom vuln DB before --offline scans
agent-bom quickstart --run --offline    # sample scan, gateway policy seed, dashboard data
agent-bom agents -p . -f html -o agent-bom-report.html
```

Run `agent-bom db update` before `--offline` image or package scans. Guided path:
[docs/FIRST_RUN.md](docs/FIRST_RUN.md) · UI screenshots:
[docs/CAPTURE.md](docs/CAPTURE.md)

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom terminal demo" width="820" />
</p>

<details>
<summary><b>Product screenshots</b> — packaged dashboard on seeded demo data</summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png" alt="Risk overview dashboard with posture grade and attack paths" width="900" />
  <br/><em>Risk overview — posture grade, KPIs, and fix-first attack paths</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/cloud-accounts-live.png" alt="Cloud accounts onboarding with AWS, Azure, GCP, and Snowflake connectors" width="900" />
  <br/><em>Cloud accounts — read-only onboarding and CIS discovery per account</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/new-scan-live.png" alt="New Scan form with connected account picker and public repo URL mode" width="900" />
  <br/><em>New Scan — account vs ad-hoc scope with auto-detect surfaces</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/security-graph-live.png" alt="Fix-first attack-path queue with graph evidence export" width="900" />
  <br/><em>Security graph — fix-first attack-path queue with evidence export</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png" alt="Agent mesh graph across agents, MCP servers, packages, tools, and findings" width="900" />
  <br/><em>Blast radius — agent → MCP server → package → tool → CVE</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/gateway-policies-live.png" alt="Runtime gateway policy posture with rules and bound agents" width="900" />
  <br/><em>Runtime gateway — policy posture, rules, and bound agents</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/fleet-state-live.png" alt="Fleet lifecycle review state with owner and environment" width="900" />
  <br/><em>Fleet — lifecycle review state, owner, and environment</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/identity-audit-live.png" alt="Audit log filtered to identity resources with HMAC integrity counters" width="900" />
  <br/><em>Audit — identity lifecycle with tamper-evident HMAC counters</em>
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/remediation-live.png" alt="Fix-first remediation table with prioritized packages" width="900" />
  <br/><em>Remediation — prioritized fix list with framework context</em>
</p>

<sub>Synthetic seeded evidence for docs proof, captured from the real Next.js
routes with a visible <strong>Demo data — sample environment</strong> label — not a
claim these entities came from a buyer environment. Regenerate from the UI package
with <code>npm run capture:product-proof</code> (see
<a href="docs/CAPTURE.md">docs/CAPTURE.md</a>). CLI demo GIF:
<code>bash scripts/render_demo_gif.sh</code>.</sub>

</details>

## How It Works

Three lanes that match the commands and the sidebar: **scan** (`agents` / CI) →
**graph** (`ContextGraph` + blast radius) → **serve** (`agent-bom serve` — one
pane of glass). The Findings page is a posture queue inside serve — not a
product lane.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-light.svg" alt="agent-bom lanes: scan, ContextGraph blast radius, serve as one pane of glass" width="980" />
  </picture>
</p>

<details>
<summary><b>Control-plane architecture</b></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-light.svg" alt="agent-bom layered control-plane architecture" width="980" />
  </picture>
</p>

</details>

<details>
<summary><b>Blast radius drilldown</b></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="agent-bom blast-radius drilldown — package to finding to MCP server to agent" width="900" />
  </picture>
</p>

```text
package -> vulnerability finding -> MCP server -> tools + credential refs -> agent
```

</details>

<details>
<summary><b>What it is</b> — scanner, ContextGraph, and blast radius</summary>

`agent-bom` is a read-only scanner and self-hosted control plane for local
projects, agent fleets, MCP runtimes, and cloud estates (AWS, Azure, GCP,
Snowflake).

**ContextGraph** is agent-bom's unified evidence graph across CLI, API, UI, MCP
tools, reports, and gateway decisions. Findings, assets, packages, cloud
resources, identities, agents, MCP servers, credentials, and runtime decisions
all normalize into that graph so posture, blast radius, and enforcement read
from the same evidence.

Blast radius is the core idea: a vulnerable package is linked to the MCP server
that loads it, the tools it exposes, reachable credential references, and the
agents that can call it — not just a CVE row.

Coverage depth and honest boundaries:
[AI infrastructure scanning](docs/AI_INFRASTRUCTURE_SCANNING.md) ·
[product boundaries](docs/PRODUCT_BOUNDARIES.md)

</details>

<details>
<summary><b>Accuracy model</b> — match-confidence tiers and NVD key model</summary>

agent-bom normalizes advisory and distro evidence into canonical CVE findings
with match-confidence tiers:

`distro_confirmed` > `osv_range` > `osv_ecosystem` > `unfixed_distro` > `nvd_cpe_candidate`

Distro-confirmed findings are treated as confirmed. Optional NVD CPE candidate
matching widens long-tail OS/vendor software coverage, but remains review-grade
and off by default.

**NVD key model.** End users do not need an NVD API key. CVE/CPE enrichment
ships through the distributed vulnerability database. `NVD_API_KEY` is only an
optional self-hosted freshness knob for operators rebuilding or refreshing the
database.

Matching mechanics and release evidence:
[vulnerability matching](docs/VULNERABILITY_MATCHING.md) ·
[scanner accuracy baseline](docs/SCANNER_ACCURACY_BASELINE.md)

</details>

## Cloud, Deploy, Trust

**Cloud (read-only).** Four connectors — AWS, Azure, GCP, Snowflake — are
opt-in, agentless, and default-off. No secret values are read or stored.
`agent-bom connect <provider>` prints the grant template and enable flag without
network I/O until you opt in. Full intake map:
[docs/DATA_SOURCES.md](docs/DATA_SOURCES.md)

| Cloud | Enable | Scan |
|---|---|---|
| AWS | `AGENT_BOM_AWS_INVENTORY=1` | `agent-bom cloud aws` |
| Azure | `AGENT_BOM_AZURE_INVENTORY=1` | `agent-bom cloud azure` |
| GCP | `AGENT_BOM_GCP_INVENTORY=1` | `agent-bom cloud gcp` |
| Snowflake | SSO or key-pair auth | `pip install 'agent-bom[snowflake]'` then `agent-bom agents --snowflake` |

Snowflake auth defaults to browser SSO (`externalbrowser`); use
`SNOWFLAKE_AUTHENTICATOR=snowflake_jwt` with `SNOWFLAKE_PRIVATE_KEY_PATH` for
CI. agent-bom authenticates through the Python connector — no `snowsql` session
needed. Setup and grants: [docs/CLOUD_CONNECT.md](docs/CLOUD_CONNECT.md)

**Deploy in your boundary.** OSS CLI, self-hosted API/UI, gated hosted POC, or
optional Snowflake-native lane — no managed public SaaS in this repo yet.

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

Pilot compose binds to `127.0.0.1` with loopback CORS only. Use
`docker-compose.platform.yml` or [docs/HOSTED_POC.md](docs/HOSTED_POC.md) before
sharing a link.

- [Deploy anywhere](docs/DEPLOY_PLATFORM.md) · [Helm](deploy/helm/agent-bom) ·
  [EKS module](deploy/terraform/platform-eks) ·
  [Docker Hub](https://hub.docker.com/r/agentbom/agent-bom) ·
  [CloudFormation one-click](deploy/cloudformation)

**Trust.**

- Read-only discovery by default; no mandatory telemetry.
- Credential values redacted; env names preserved for explainable exposure paths.
- Exports: JSON, SARIF, CycloneDX, SPDX, OCSF, Markdown, HTML, compliance bundles.
- Tenant scope, auth boundaries, and audit evidence on API/runtime paths.

[Threat model](docs/THREAT_MODEL.md) · [Pentest readiness](docs/PENTEST_READINESS.md) ·
[Python client](docs/PYTHON_API.md) · [Go client](sdks/go/README.md) ·
[Release verification](docs/RELEASE_VERIFICATION.md) ·
[MCP security model](docs/MCP_SECURITY_MODEL.md)

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md),
[.agents/AGENTS.md](.agents/AGENTS.md), and the
[open issues](https://github.com/msaad00/agent-bom/issues).

License: Apache-2.0.
