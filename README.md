<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-light.svg" alt="agent-bom" width="320" />
  </picture>
</p>

<p align="center">
  <a href="https://github.com/msaad00/agent-bom/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/msaad00/agent-bom/ci.yml?branch=main&style=flat&label=Build" alt="Build"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/v/agent-bom?style=flat&label=PyPI&cacheSeconds=60" alt="PyPI"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/pyversions/agent-bom?style=flat&label=Python" alt="Python versions"></a>
  <a href="https://hub.docker.com/r/agentbom/agent-bom"><img src="https://img.shields.io/docker/pulls/agentbom/agent-bom?style=flat&label=Docker%20pulls" alt="Docker pulls"></a>
  <a href="https://github.com/msaad00/agent-bom/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat" alt="License"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom"><img src="https://img.shields.io/ossf-scorecard/github.com/msaad00/agent-bom?style=flat&label=OpenSSF%20scorecard" alt="OpenSSF Scorecard"></a>
  <a href="https://glama.ai/mcp/servers/msaad00/agent-bom"><img src="https://img.shields.io/badge/MCP-Glama-7c3aed?style=flat" alt="agent-bom on Glama"></a>
  <a href="https://smithery.ai/servers/agent-bom/agent-bom"><img src="https://img.shields.io/badge/MCP-Smithery-1f6feb?style=flat" alt="agent-bom on Smithery"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center"><b>Open security scanner and self-hosted control plane for AI, MCP, and cloud infrastructure.</b></p>

<p align="center">
  Scan a repo, image, or cloud account. Get findings, an SBOM, and a graph that
  shows what each finding can actually reach — from one CLI, or a control plane
  you run yourself.
</p>

<p align="center">
  <b>15</b> package ecosystems · <b>16</b> compliance surfaces ·
  <b>77</b> MCP tools · <b>Apache-2.0</b> · no account required
</p>

<p align="center">
  <a href="#quick-start"><b>Quick start</b></a> ·
  <a href="https://demo.agent-bom.com"><b>Live demo</b></a> ·
  <a href="https://msaad00.github.io/agent-bom/">Docs</a>
</p>

## What it is

`agent-bom` discovers software, cloud, identity, AI-agent, and MCP evidence;
turns it into findings and relationship graphs; and carries the same evidence
into CI, a self-hosted control plane, and runtime policy enforcement.

- **Scan** locally or in CI and export console, JSON, SARIF, SBOM, HTML, and graph artifacts.
- **Centralize** findings, compliance evidence, jobs, inventory, and investigations in a control plane you run.
- **Enforce** MCP and tool-call policy through the gateway, proxy, and Shield SDK surfaces.

The product uses one Finding + UnifiedGraph model across CLI, API, UI, and MCP.
It does not require a hosted account for local scanning.

## Quick start

Run against the repository in your current directory:

```bash
pip install agent-bom
agent-bom scan .
```

The console shows inventory, findings, and reachable impact. Save an artifact
with `agent-bom scan . -f sarif -o findings.sarif`, or follow the
[first-run guide](docs/FIRST_RUN.md) for exit codes, formats, and CI use.

<details>
<summary><b>Try without a repository</b></summary>

Use the curated, explicitly synthetic sample when you only want to inspect the
output shape:

```bash
agent-bom scan --demo --offline
```

The sample intentionally contains blocking findings, so exit status `1` is
expected.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="Synthetic agent-bom console scan showing inventory, findings, and remediation" width="820" />
</p>

</details>

## How it works

1. Read-only collectors inventory the selected repository, image, agent configuration, or connected cloud scope.
2. Deterministic scanners normalize evidence into findings, packages, assets, identities, and relationships.
3. Exports, the control plane, and runtime policy consume that same evidence model.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-light.svg" alt="Scan, centralize, and enforce on one Finding and UnifiedGraph evidence model" width="1000" />
  </picture>
</p>

The browser experience keeps the evidence shared while presenting task-focused
workspaces: fix-first findings, path-first investigation, control evidence, and
posture summaries. Graph views preserve provenance where source evidence
provides it: collected, inferred, static, and runtime relationships remain
distinct, while unavailable provenance is not upgraded to observed. Interactive
views expose fit, zoom, pan, layout, and personal positioning controls.

## Who it is for

| Role | Start here | Primary outcome |
|---|---|---|
| Local developers | `agent-bom scan .` | Find and explain issues before code leaves the workstation |
| AppSec | `agent-bom scan . -f sarif -o findings.sarif` | Triage reachable findings and enforce CI gates |
| Security engineers | `pip install 'agent-bom[ui]' && agent-bom serve` | Investigate exposure paths, identities, and evidence provenance |
| Platform / SRE | `agent-bom connect aws` | Centralize estate inventory, jobs, and runtime controls |
| GRC / audit | `agent-bom report compliance-narrative scan.json` | Review control mappings and export evidence with explicit gaps |
| Leadership / CISO | `pip install 'agent-bom[ui]' && agent-bom serve` | Review posture, coverage, material risk, and change over time |
| AI / MCP owners | `pip install 'agent-bom[mcp-server]' && agent-bom mcp server` | Inventory tools and apply allow, warn, or block decisions |

AppSec and GRC remain separate workflows: findings and reachability are not
presented as audit certification. See [product boundaries](docs/PRODUCT_BOUNDARIES.md).

<details>
<summary><b>Product gallery</b></summary>

The gallery uses deterministic sample data, visibly labeled in the UI. It is
product-state proof, not customer or advisory evidence.

| Overview | Findings |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png" alt="Overview with posture, finding, coverage, and operations summaries" width="430" /> | <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dependency-map-live.png" alt="Findings queue with severity, evidence, and next actions" width="430" /> |

| Investigation | Remediation |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/security-graph-live.png" alt="Path-first investigation with provenance-aware synthetic graph evidence" width="430" /> | <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/remediation-live.png" alt="Compact prioritized remediation workflow" width="430" /> |

| Cloud and environment lineage | Agent mesh |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/lineage-graph-live.png" alt="Scoped environment lineage with interactive graph controls" width="430" /> | <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png" alt="Agent and MCP server relationships with labeled edges" width="430" /> |

[Capture protocol](docs/CAPTURE.md)

</details>

## Self-host

Start the loopback control plane:

```bash
pip install 'agent-bom[ui]'
agent-bom serve
```

For a shared deployment, use the documented Docker or Helm path and configure
real identity, TLS, PostgreSQL, encryption, and audit keys before exposing it.

| Target | Start here |
|---|---|
| Docker Compose | [Pilot compose](deploy/docker-compose.pilot.yml) |
| Helm / Kubernetes | `helm install agent-bom oci://ghcr.io/msaad00/charts/agent-bom --version 0.99.0` |
| EKS | [Terraform module](deploy/terraform/platform-eks) |
| Air-gapped | [Image bundle guide](site-docs/deployment/airgapped-image-bundle.md) |

> Pins target `v0.99.0`, the version this tree builds. Until that release is
> published, use the version shown on the PyPI badge above.

[Deployment overview](site-docs/deployment/overview.md) ·
[Enterprise configuration](docs/ENTERPRISE.md) ·
[Cloud connections](docs/CLOUD_CONNECT.md)

<details>
<summary><b>Advanced integrations and runtime entry points</b></summary>

| Need | First action | Artifact or next step |
|---|---|---|
| GitHub CI | `uses: msaad00/agent-bom@v0.99.0` | SARIF, PR summary, and a policy exit code |
| Cloud evidence | `agent-bom connect aws` | Stored connection reference; run scans from the control plane |
| Runtime gateway | `agent-bom gateway serve --from-control-plane http://127.0.0.1:8422 --bind 127.0.0.1:8090` | Allow, warn, and block audit events |
| Agent interface | `agent-bom mcp server` | 77 MCP tools, 6 resources, and 8 workflow prompts |
| Agent distribution | [Smithery](integrations/smithery.yaml) · [Glama](glama.json) · [MCP registry](integrations/mcp-registry) · [Docker MCP](integrations/docker-mcp-registry) | Registry-specific installation metadata |

The CLI, Docker, API, Helm chart, MCP server, gateway, and SDK are distribution
surfaces of the same product. EKS remains a deployment profile; Snowflake and
Snowpark remain connector/runtime integrations rather than hosted-core
dependencies.

</details>

<details>
<summary><b>Every way to install it</b></summary>

| Surface | Get it |
|---|---|
| Python package | `pip install agent-bom` — [PyPI](https://pypi.org/project/agent-bom/) |
| Container | `docker pull agentbom/agent-bom` — [Docker Hub](https://hub.docker.com/r/agentbom/agent-bom) |
| Kubernetes | `helm install agent-bom oci://ghcr.io/msaad00/charts/agent-bom` |
| GitHub Action | [`msaad00/agent-bom`](action.yml) |
| MCP server | `pip install 'agent-bom[mcp-server]' && agent-bom mcp server` |
| MCP registries | [Smithery](integrations/smithery.yaml) · [Glama](glama.json) · [MCP registry](integrations/mcp-registry) · [Docker MCP](integrations/docker-mcp-registry) |
| SDKs | [Python](sdks/python) · [TypeScript](sdks/typescript) · [Go](sdks/go) |

</details>

## Trust

- Read-only discovery by default; runtime write decisions are separate and explicit.
- Credentials are write-only where stored, encrypted at rest, and never returned by API responses.
- API and control-plane routes are tenant scoped and auth protected outside explicit local mode.
- Missing evidence is shown as unavailable or partial, never converted into a factual zero.
- Public examples and screenshots use deterministic synthetic identifiers only.

[Threat model](docs/THREAT_MODEL.md) ·
[Release verification](docs/RELEASE_VERIFICATION.md) ·
[Security policy](SECURITY.md) ·
[MCP security model](docs/MCP_SECURITY_MODEL.md)

## Contributing

Start with [CONTRIBUTING.md](CONTRIBUTING.md), [AGENTS.md](AGENTS.md), and the
[open issues](https://github.com/msaad00/agent-bom/issues).

Apache-2.0 licensed.
