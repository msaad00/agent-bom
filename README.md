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
<p align="center">Discover assets, scan and enrich findings, map blast radius and compliance, and enforce runtime policy—from a local CLI or your self-hosted control plane.</p>

<p align="center">
  <a href="https://demo.agent-bom.com"><b>Live demo</b></a> (read-only sandbox; if unreachable run <code>uvx agent-bom scan --demo --offline</code>) ·
  <a href="https://msaad00.github.io/agent-bom/">Docs</a> ·
  <a href="docs/FIRST_RUN.md">First Run</a> ·
  <a href="site-docs/deployment/overview.md">Self-host</a> ·
  <a href="https://github.com/marketplace/actions/agent-bom">GitHub Action</a> ·
  <a href="https://hub.docker.com/r/agentbom/agent-bom">Docker</a> ·
  <a href="https://github.com/msaad00/agent-bom/releases">Changelog</a>
</p>

## Scan your project in two commands

```bash
pip install agent-bom
agent-bom scan .
```

`.` means the current project. The local CLI reads it directly and prints
inventory, findings, reachable context, and fix-first actions; no control plane
is required. Export evidence when another tool needs it:
`agent-bom scan . -f sarif -o findings.sarif`. For scripts,
`--project .` (short form: `-p .`) is equivalent.

`-p`/`--project` expects a directory, not a manifest file. For large
monorepos, point it at the workspace or service under review and run one scan
per CI workspace; the current CLI does not pretend to provide an arbitrary
path-exclude language.

## Three ways to use it

| Product lane | First command | Evidence you get | Natural next step |
|---|---|---|---|
| **Scan and understand risk** — repos, images, SBOMs, agent/MCP config, IaC | `agent-bom scan .` | inventory, findings, fix priority, graph and standard report formats | gate CI or open the local report |
| **Centralize and visualize evidence** — fleet, cloud, identity, findings, compliance | `pip install 'agent-bom[ui]' && agent-bom serve` | tenant-scoped inventory, attack paths, compliance, jobs and audit | self-host with Docker or Helm + Postgres |
| **Enforce runtime behavior** — MCP and tool calls | `agent-bom gateway serve --upstreams upstreams.yaml --bind 127.0.0.1:8090` | allow/warn/block decisions and audit events | bind policies to agents and upstream MCPs |

Discovery and static/cloud scanning are read-only. The self-hosted control plane
stores evidence, and runtime modes make explicit policy decisions; those are
separate operational boundaries, not all one read-only pipeline.

## Who it is for

| Team | Start here | Outcome |
|---|---|---|
| Developers and AI builders | `agent-bom scan .` | Inventory, findings, blast radius, and fix-first actions before code or agent changes ship |
| AppSec and security engineering | `agent-bom scan . -f sarif -o findings.sarif` | Reachability-aware triage, graph paths, SBOMs, and CI gates |
| Platform, SRE, and cloud teams | `agent-bom serve` or a shipped Helm profile | Customer-controlled API/UI, fleet evidence, Postgres tenancy, and runtime policy |
| GRC, audit, and governance | Compliance exports and control-plane evidence views | Framework mappings, signed evidence bundles, audit history, and review context |
| AI/MCP owners | `agent-bom mcp server` or `agent-bom gateway serve ...` | Tool/server inventory and explicit allow, warn, or block decisions |

The product generates security and compliance evidence; it is not a replacement
for a GRC system of record, IAM, SIEM, or a complete certification program.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="agent-bom blast radius: one package finding fans out to MCP servers, agents, secrets, and tools" width="900" />
  </picture>
</p>

Blast radius links package risk to the MCP servers that load it, exposed tools,
credential references, and agents that can reach it. Coverage and boundaries:
[AI infrastructure scanning](docs/AI_INFRASTRUCTURE_SCANNING.md) ·
[product boundaries](docs/PRODUCT_BOUNDARIES.md) ·
[first-run guide](docs/FIRST_RUN.md).

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-light.svg" alt="agent-bom three product lanes: local scan, self-hosted control plane, and runtime gateway on one Finding + UnifiedGraph model" width="1100" />
  </picture>
</p>

Local CLI and CI call the scanner directly and do not require a server. The
self-hosted control plane adds an authenticated API and UI, tenant-scoped
persistence, fleet jobs, attack paths, compliance, and audit. Gateway and proxy
modes enforce live tool traffic at a separate runtime boundary.

<details>
<summary><b>Execution paths and persistence</b></summary>

| Boundary | Entry point | Service path | Persistence or artifact |
|---|---|---|---|
| Local scan | CLI, CI, Docker | Python scanner and correlation engine | console/files; optional SQLite history |
| Control plane | Next.js UI, REST SDK | TLS/HTTPS ingress → authentication/tenant/rate-limit/audit middleware → FastAPI services | Postgres + RLS for shared deployments; SQLite for a local pilot |
| Agent interface | MCP clients | MCP server → shared scanning, finding and graph services | the same normalized evidence contracts |
| Runtime enforcement | MCP/tool traffic | gateway or proxy → policy, detectors and audit | SQLite or Postgres audit records |

Neptune is an optional graph backend and ClickHouse is optional analytics.
Snowflake supports selected warehouse/store paths with documented parity
limits. MCP server mode exposes 76 MCP tools, 6 resources, and 8 workflow prompts
over strict arguments. Agent distribution includes a committed
[Smithery manifest](integrations/smithery.yaml); external catalog liveness is
verified separately. The implementation-level diagram and component
boundaries live in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

</details>

<details>
<summary><b>Evidence and accuracy boundaries</b></summary>

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
[scanner accuracy baseline](docs/SCANNER_ACCURACY_BASELINE.md) ·
[graph contract](docs/graph/CONTRACT.md) ·
[architecture deep dive](docs/ARCHITECTURE.md)

</details>

## See the product

Try the [live demo](https://demo.agent-bom.com) (read-only sandbox; if
unreachable, run `uvx agent-bom scan --demo --offline`). These
captures come from the shipped Next.js routes using explicitly labeled,
synthetic demo evidence.

### Prioritize an attack path, not just a CVE

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/security-graph-live.png" alt="Prioritized attack path connecting identity, agent, MCP server, package, and critical finding with evidence export and remediation handoff" width="900" />
</p>

The investigation lens connects identity and agent reachability to the MCP
server, package, and finding that create the exposure. Operators can export the
graph evidence or hand the path directly to remediation.

### See every finding and its reach

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dependency-map-live.png" alt="Findings queue with severity, reachable agents, available fixes, and false-positive review actions" width="900" />
</p>

### Move from risk to owner-ready work

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/remediation-live.png" alt="Prioritized remediation campaign with modeled risk reduction, reach, framework mappings, ownership, and verification state" width="900" />
</p>

<details>
<summary><b>More control-plane views</b> — posture, runtime, and evidence intake</summary>

| Risk overview | Review runtime decisions |
|:---:|:---:|
| <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png" alt="Overview command center with posture grade, unique findings, scan coverage, and operations" width="430" /> | <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/gateway-policies-live.png" alt="Runtime gateway KPI rollup and tool-call feed" width="430" /> |
| **Connect evidence sources** | **Start a scan** |
| <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/cloud-accounts-live.png" alt="Connections hub across cloud, code, AI, and data sources" width="430" /> | <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/new-scan-live.png" alt="New Scan evidence workspace with expected outputs, collector plan, and read-only boundary" width="430" /> |

</details>

<details>
<summary><b>Full CLI walkthrough</b> — current 0.97.2 console demo</summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom terminal demo showing inventory, findings, remediation, and package gate" width="820" />
</p>

The demo is intentionally comprehensive, so it is kept collapsed at README
display width. Its seeded `requests` typosquat produces an expected non-zero
security-gate exit; that is a demonstrated finding, not a failed recording.

</details>

Full capture list and reproducible commands: [docs/CAPTURE.md](docs/CAPTURE.md).

## Run it anywhere

The surfaces share normalized finding and graph contracts while keeping their
execution and authentication boundaries explicit. Pick the entry point that
matches your role:

| Need | Surface | First action | Main artifact |
|---|---|---|---|
| Scan a repo, image, or local agent config | CLI / CI | `agent-bom scan .` (or the [GitHub Action](https://github.com/marketplace/actions/agent-bom)) | JSON, SARIF, SBOM, HTML |
| Connect cloud and data-estate evidence | Cloud connectors | `agent-bom connect aws` then `agent-bom cloud scan` | assets, CIS findings, graph edges |
| Review posture as a team | API + dashboard | `pip install 'agent-bom[ui]' && agent-bom serve` | findings, graph, audit, compliance |
| Give agents security tools | MCP server | `agent-bom mcp server` | strict MCP tool responses |
| Govern runtime tool calls | Proxy / gateway | `agent-bom gateway serve --upstreams upstreams.yaml --bind 127.0.0.1:8090` | allow/warn/block audit trail |
| Package evidence for audit | Reports / exports | `agent-bom scan . -f sarif -o findings.sarif` | SARIF, CycloneDX, SPDX, HTML/PDF, compliance bundle |

Beyond the basics — `agent-bom graph` (multi-hop exposure paths),
`agent-bom remediate -p .` (advisory fix plan),
`agent-bom identity credential-expiry`, `agent-bom cost forecast`, and the CI
gate `uses: msaad00/agent-bom@v0.97.2`. Full command map:
[docs/CLI_MAP.md](docs/CLI_MAP.md) · role routing:
[docs/START_HERE.md](docs/START_HERE.md) · all entry points and auth
boundaries: [docs/PRODUCT_MAP.md](docs/PRODUCT_MAP.md)

**Deploy targets** — you run the control plane in your own boundary (no managed
public SaaS in this repo yet), fastest → most-managed:

- **Docker Compose** — fastest; one file, loopback by default → [pilot compose](deploy/docker-compose.pilot.yml)
- **Helm / Kubernetes** — cluster-native chart → [chart](deploy/helm/agent-bom)
- **EKS** — opinionated Terraform module → [module](deploy/terraform/platform-eks)
- **CloudFormation** — one-click AWS stack → [templates](deploy/cloudformation)
- **Snowflake (SPCS native app)** — host entirely inside your own Snowflake account → [install guide](docs/snowflake-native-app/INSTALL.md)

<details>
<summary><b>Local bring-up</b> — Docker Compose in two commands</summary>

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

Pilot compose binds to `127.0.0.1` with loopback CORS only. Use
`docker-compose.platform.yml` or [docs/HOSTED_POC.md](docs/HOSTED_POC.md) before
sharing a link. Full guides: [Deploy anywhere](docs/DEPLOY_PLATFORM.md).

</details>

## Connected control plane

For brokered control-plane sources, **connect once, then scheduled and operator
actions use the stored connection reference**—not a fresh credential prompt.
Standalone CLI scans remain independent: they read local files or explicitly
configured provider credentials and do not require a control-plane connection.

- **Humans** sign in via **OAuth / OIDC / SAML SSO** (standard providers plus a
  Snowflake OAuth authorization-code + PKCE flow), with **SCIM** for user and
  group provisioning (`src/agent_bom/api/{oidc,saml,scim}.py`,
  `snowflake_oauth.py`).
- **Agents / CI** authenticate with **scoped API keys / tokens**.
- **Sources** are onboarded **once** through read-only, agentless, brokered
  connectors — a single least-privilege managed role per source with
  short-lived, brokered credentials (e.g. AWS `sts:AssumeRole`); connection
  secrets are write-only (encrypted at rest, never read back).

Application-layer authentication, tenant isolation, rate limits, and audit are
enforced in middleware for UI and API/SDK requests. Non-loopback deployments
terminate HTTPS/TLS at Caddy, an ingress, an ALB, or an equivalent trusted edge;
the API and UI remain on loopback or a private network. MCP server and
gateway/proxy modes enforce their own documented transport authentication and
policy boundaries; none receives a privileged UI-only path.

Cloud connectors are opt-in, default-off, and read no secret values.
`agent-bom connect <provider>` prints the grant template and enable flag
without network I/O until you opt in:

| Cloud | Enable | Scan |
|---|---|---|
| AWS | `AGENT_BOM_AWS_INVENTORY=1` | `agent-bom cloud aws` |
| Azure | `AGENT_BOM_AZURE_INVENTORY=1` | `agent-bom cloud azure` |
| GCP | `AGENT_BOM_GCP_INVENTORY=1` | `agent-bom cloud gcp` |
| Snowflake | SSO or key-pair auth | `pip install 'agent-bom[snowflake]'` then `agent-bom scan --snowflake` |

Snowflake auth defaults to browser SSO (`externalbrowser`); use
`SNOWFLAKE_AUTHENTICATOR=snowflake_jwt` with `SNOWFLAKE_PRIVATE_KEY_PATH` for
CI. Setup and the exact grant per provider:
[docs/CLOUD_CONNECT.md](docs/CLOUD_CONNECT.md) · intake map:
[docs/DATA_SOURCES.md](docs/DATA_SOURCES.md) · enterprise auth surface:
[docs/ENTERPRISE.md](docs/ENTERPRISE.md)

## Trust

- Read-only discovery by default; no mandatory telemetry.
- Credential values redacted; env names preserved for explainable exposure paths.
- Exports: JSON, SARIF, CycloneDX, SPDX, Parquet, CSV, Markdown, HTML, PDF, compliance bundles.
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
