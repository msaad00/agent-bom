<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-light.svg" alt="agent-bom" width="360" />
  </picture>
</p>

<p align="center">
  <a href="https://github.com/msaad00/agent-bom/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/msaad00/agent-bom/ci.yml?branch=main&style=flat&label=Build" alt="Build"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/v/agent-bom?style=flat&label=Latest%20version&cacheSeconds=60" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/agentbom/agent-bom"><img src="https://img.shields.io/docker/pulls/agentbom/agent-bom?style=flat&label=Docker%20pulls" alt="Docker"></a>
  <a href="https://github.com/msaad00/agent-bom/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat" alt="License"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom"><img src="https://img.shields.io/ossf-scorecard/github.com/msaad00/agent-bom?style=flat&label=OpenSSF%20scorecard" alt="OpenSSF Scorecard"></a>
  <a href="https://glama.ai/mcp/servers/msaad00/agent-bom"><img src="https://img.shields.io/badge/MCP-Glama-7c3aed?style=flat" alt="agent-bom on Glama"></a>
  <a href="https://smithery.ai/servers/agent-bom/agent-bom"><img src="https://img.shields.io/badge/MCP-Smithery-1f6feb?style=flat" alt="agent-bom on Smithery"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center"><b>Open security scanner and self-hosted control plane for AI, MCP, and cloud infrastructure.</b></p>
<p align="center">
  Scan from CLI, CI, Docker, or cloud connect on a control plane you run →
  centralize evidence → enforce runtime MCP/tool calls.
  One Finding + UnifiedGraph model across CLI, API, UI, and MCP.
</p>
<p align="center">
  <a href="https://demo.agent-bom.com"><b>Live demo</b></a> ·
  <a href="https://msaad00.github.io/agent-bom/">Docs</a> ·
  <a href="docs/FIRST_RUN.md">First Run</a> ·
  <a href="site-docs/deployment/overview.md">Self-host</a> ·
  <a href="https://github.com/marketplace/actions/agent-bom">GitHub Action</a> ·
  <a href="https://hub.docker.com/r/agentbom/agent-bom">Docker</a> ·
  <a href="https://github.com/msaad00/agent-bom/releases">Changelog</a>
</p>

## Blast radius

One finding fans out to the MCP servers that load it, reachable tools,
credential references, and agents that can reach it — not a CVE list in
isolation.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="agent-bom blast radius: one package finding fans out to MCP servers, agents, secrets, and tools" width="900" />
  </picture>
</p>

## Who it is for

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/persona-value-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/persona-value-light.svg" alt="agent-bom personas: AppSec/GRC, Platform/SRE, Developers, and AI/MCP owners with matching outcomes" width="900" />
  </picture>
</p>

| Team | Start here | Outcome |
|---|---|---|
| Developers / AI builders | `agent-bom scan .` | Inventory, findings, blast radius before changes ship |
| AppSec / security eng | `agent-bom scan . -f sarif -o findings.sarif` | Reachability triage, graph paths, CI gates |
| Platform / SRE / cloud | `pip install 'agent-bom[ui]' && agent-bom serve` or Helm | Customer-controlled API/UI, fleet evidence, runtime policy |
| GRC / audit | Compliance exports + control-plane evidence | Framework mappings, signed bundles, review context |
| AI / MCP owners | `pip install 'agent-bom[mcp-server]' && agent-bom mcp server` or `gateway serve` | Tool inventory and allow/warn/block decisions |

Evidence helper, not a GRC system of record, IAM, SIEM, or certification program.
Boundaries: [PRODUCT_BOUNDARIES.md](docs/PRODUCT_BOUNDARIES.md).

## How the tool works

1. **Scan** — CLI / CI / Docker / cloud connect → inventory, findings, SARIF/SBOM/HTML, graph
2. **Control plane** — `pip install 'agent-bom[ui]' && agent-bom serve` → tenant UI/API, attack paths, compliance, audit (self-host with Docker or Helm + Postgres). Loopback is the default; non-loopback hosts need real auth or an explicit `--allow-insecure-no-auth` (env vars alone are not enough).
3. **Runtime** — `agent-bom gateway serve --upstreams upstreams.yaml --bind 127.0.0.1:8090` → allow/warn/block on live MCP/tool calls

Discovery and static/cloud scanning are read-only. The control plane stores
evidence; gateway/proxy modes make explicit policy decisions at a separate
boundary.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-light.svg" alt="agent-bom three tool lanes: scan (CLI/CI/Docker/cloud connect), self-hosted control plane, and runtime gateway on one Finding + UnifiedGraph model" width="1100" />
  </picture>
</p>

## Graph lenses

Three graph lenses tell different stories: package-level lineage, multi-agent
mesh overlap, and lateral context — not three copies of the same CVE chain.

| Lineage (package hop) | Agent mesh (shared MCP) |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/lineage-graph-live.png" alt="Lineage graph focused on developer-copilot, GitHub MCP, next package version, and DEMO-VULN finding with labeled edges" width="430" /> | <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png" alt="Agent mesh showing developer-copilot and sre-runbook-agent converging on shared filesystem MCP with relationship labels" width="430" /> |
| *Investigation drilldown: agent → MCP → `next@` → critical finding.* | *Two agents, one shared server — tools and credentials in the same frame.* |

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/context-map-live.png" alt="Context map with path focus off: repo-write tool, GitHub credential, MCP servers, and agent lateral links" width="820" />
</p>

<p align="center"><em>Context map: neighborhood topology (tools, creds, servers) — not the same hero CVE strip as lineage.</em></p>

<details>
<summary><b>Investigation capture</b> — prioritized path with export/handoff chrome</summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/security-graph-live.png" alt="Prioritized attack path connecting identity, agent, MCP server, package, and critical finding" width="820" />
</p>

Path view is a single-row hop strip (scroll horizontally on long chains).
Recapture notes: [docs/CAPTURE.md](docs/CAPTURE.md).

</details>

<details>
<summary><b>Dashboard captures</b> — findings queue, remediation, posture, runtime, connections</summary>

| Findings queue | Remediation |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dependency-map-live.png" alt="Findings queue with severity, reachable agents, fixes, and review actions" width="430" /> | <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/remediation-live.png" alt="Prioritized remediation with risk reduction, ownership, and verification" width="430" /> |

| Risk overview | Runtime gateway |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png" alt="Overview with posture grade, findings, and operations" width="430" /> | <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/gateway-policies-live.png" alt="Runtime gateway KPI rollup and tool-call feed" width="430" /> |

| Connections | New scan |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/cloud-accounts-live.png" alt="Connections hub across cloud, code, AI, and data sources" width="430" /> | <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/new-scan-live.png" alt="New Scan workspace with collector plan and read-only boundary" width="430" /> |

[Live demo](https://demo.agent-bom.com) is a read-only sandbox with synthetic
showcase evidence. Prefer the local offline sample above for a reproducible CLI
walkthrough.

</details>

<details>
<summary><b>CLI walkthrough</b> — 0.97.5 console demo</summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom terminal demo showing inventory, findings, remediation, and package gate" width="820" />
</p>

Seeded `requests` typosquat produces an expected non-zero security-gate exit —
a demonstrated finding, not a failed recording.

</details>

Capture list: [docs/CAPTURE.md](docs/CAPTURE.md).

## Self-host

You run the control plane in your own boundary (no managed public SaaS in this
repo yet):

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

Pilot compose binds `127.0.0.1` with loopback CORS. Before sharing a link, use
`docker-compose.platform.yml` or [docs/HOSTED_POC.md](docs/HOSTED_POC.md).

| Target | Start here |
|---|---|
| Docker Compose | [pilot compose](deploy/docker-compose.pilot.yml) |
| Helm / Kubernetes | [chart](deploy/helm/agent-bom) — `helm install agent-bom oci://ghcr.io/msaad00/charts/agent-bom --version 0.97.4` |
| EKS | [Terraform module](deploy/terraform/platform-eks) |
| CloudFormation | [templates](deploy/cloudformation) |
| Snowflake SPCS | [install guide](docs/snowflake-native-app/INSTALL.md) |

Guides: [Deploy anywhere](docs/DEPLOY_PLATFORM.md) ·
[deployment overview](site-docs/deployment/overview.md).

<details>
<summary><b>Surfaces and entry points</b></summary>

| Need | First action | Artifact |
|---|---|---|
| Scan repo / image / agent config | `agent-bom scan .` or [GitHub Action](https://github.com/marketplace/actions/agent-bom) | JSON, SARIF, SBOM, HTML |
| Cloud / data estate | `agent-bom connect aws` then `agent-bom cloud scan` | assets, CIS findings, graph edges |
| Team posture UI | `pip install 'agent-bom[ui]' && agent-bom serve` | findings, graph, audit, compliance |
| MCP tools for agents | `pip install 'agent-bom[mcp-server]' && agent-bom mcp server` | strict MCP tool responses |
| Skills playbooks | [docs/skills/](docs/skills/) · OpenClaw / Cortex wrappers under `integrations/` | first command → findings / SBOM |
| Runtime tool governance | `agent-bom gateway serve --upstreams upstreams.yaml --bind 127.0.0.1:8090` | allow/warn/block audit |
| Audit package | `agent-bom scan . -f sarif -o findings.sarif` | SARIF, CycloneDX, SPDX, bundles |

Also: `agent-bom graph`, `agent-bom remediate -p .`, CI pin
`uses: msaad00/agent-bom@v0.97.5`. Maps: [CLI](docs/CLI_MAP.md) ·
[start here](docs/START_HERE.md) · [product map](docs/PRODUCT_MAP.md).

</details>

<details>
<summary><b>Auth, connectors, and architecture</b></summary>

**Control plane:** connect once; later jobs use the stored connection reference.
Humans: OAuth / OIDC / SAML (+ Snowflake OAuth PKCE) and SCIM. Agents/CI: scoped
API keys. Secrets are write-only (encrypted at rest, never read back). Non-loopback
deploys terminate TLS at the edge; API/UI stay on loopback or a private network.

**Cloud connectors** (opt-in, default-off, no secret values read):

| Cloud | Enable | Scan |
|---|---|---|
| AWS | `AGENT_BOM_AWS_INVENTORY=1` | `agent-bom cloud aws` |
| Azure | `AGENT_BOM_AZURE_INVENTORY=1` | `agent-bom cloud azure` |
| GCP | `AGENT_BOM_GCP_INVENTORY=1` | `agent-bom cloud gcp` |
| Snowflake | SSO or key-pair | `pip install 'agent-bom[snowflake]'` then `agent-bom scan --snowflake` |

[CLOUD_CONNECT.md](docs/CLOUD_CONNECT.md) · [DATA_SOURCES.md](docs/DATA_SOURCES.md) ·
[ENTERPRISE.md](docs/ENTERPRISE.md).

**Accuracy:** match tiers
`distro_confirmed` > `osv_range` > `osv_ecosystem` > `unfixed_distro` > `nvd_cpe_candidate`.
End users do not need an NVD API key; `NVD_API_KEY` is an optional operator
freshness knob. MCP server mode exposes 77 MCP tools, 6 resources, and 8 workflow prompts
over strict arguments. Agent distribution includes a committed
[Smithery manifest](integrations/smithery.yaml); external catalog liveness is
verified separately. Deep dive: [ARCHITECTURE.md](docs/ARCHITECTURE.md) ·
[vulnerability matching](docs/VULNERABILITY_MATCHING.md).

</details>

## Trust

- Read-only discovery by default; no mandatory telemetry
- Credential values redacted; env names kept for explainable exposure paths
- Exports: JSON, SARIF, CycloneDX, SPDX, Parquet, CSV, Markdown, HTML, PDF, compliance bundles
- Tenant scope, auth boundaries, and audit evidence on API/runtime paths

[Threat model](docs/THREAT_MODEL.md) · [Pentest readiness](docs/PENTEST_READINESS.md) ·
[Python client](docs/PYTHON_API.md) · [Go client](sdks/go/README.md) ·
[Release verification](docs/RELEASE_VERIFICATION.md) ·
[MCP security model](docs/MCP_SECURITY_MODEL.md)

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), and the
[open issues](https://github.com/msaad00/agent-bom/issues). Community chat:
[Discord](https://discord.gg/3YmYPqKZh5).

License: Apache-2.0.
