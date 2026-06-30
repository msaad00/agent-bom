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

## What It Is

`agent-bom` scans AI infrastructure across local projects, agent fleets, cloud
estates (AWS, Azure, GCP, Snowflake), registries, IaC, SBOMs, models, datasets,
and runtime. It builds one evidence graph of agents, MCP servers, tools,
packages, credential references, non-human identities, data systems, and exposed
resources. Every source converges into a unified `Finding` model and a unified
`ContextGraph`, so blast radius, multi-hop exposure paths, and exposure scoring
all read from the same evidence.

> `ContextGraph` is the customer-facing name for the unified evidence graph; it
> is persisted and served as `UnifiedGraph` in the API and MCP exports.

<details>
<summary><strong>What's new in 0.90.0</strong></summary>

- **Canonical CVE IDs** — `ALPINE-CVE-*` / `DEBIAN-CVE-*` are mapped to `CVE-*` for cross-tool parity.
- **Match-confidence tiers** on every finding: `distro_confirmed` > `osv_range` > `osv_ecosystem` > `unfixed_distro` > `nvd_cpe_candidate`.
- **NVD incremental sync** + **NVD CPE candidate matching** (opt-in via `AGENT_BOM_ENABLE_CPE_MATCH`) for non-ecosystem / OS / vendor software the OSV and distro feeds miss.
- **Parallel OSV** batches with bounded concurrency.

**Accuracy model.** Distro-confirmed findings match or exceed Trivy on published
benchmarks (e.g. alpine 3.14.2). The optional `nvd_cpe_candidate` tier is
review-grade and **off by default** — it widens long-tail coverage without
inflating confirmed counts. No Trivy/Grype/Syft subprocess is required.

**NVD key model.** CVE/CPE enrichment ships in the distributed vuln database
(built server-side with an org key), so end users — and MCP/agent callers — do
**not** supply an NVD key. `NVD_API_KEY` is an optional self-host/freshness knob,
never a per-user requirement.
</details>

<details>
<summary><strong>Who it's for</strong></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/persona-value-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/persona-value-light.svg" alt="agent-bom value by persona: developers (CLI/CI), security teams (API/dashboard), and automation (MCP tools)" width="980" />
  </picture>
</p>
</details>

The product goal is interoperability for humans and agents: developers get a
CLI/CI scanner, security teams get an API and dashboard, automation gets MCP
tools and typed schemas, and runtime controls can enforce the same evidence when
the operator chooses to enable them. Snowflake is one supported connector and
deployment lane; it is not the product center.

## How It Works

`agent-bom` is a read-only collection and evidence engine first: it discovers
assets, matches and enriches risk signals, normalizes everything into one graph,
then serves the same evidence through CLI, CI, API, UI, MCP, reports, and
runtime controls.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/how-it-works-light.svg" alt="agent-bom workflow from read-only intake through scan engine, evidence graph, control plane, and outputs" width="980" />
  </picture>
</p>

<details>
<summary><b>Control-plane architecture — sources, backend, API, MCP, UI, and consumers</b></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-light.svg" alt="agent-bom architecture showing sources, scan engine, unified model, control plane, and consumers" width="980" />
  </picture>
</p>

</details>

<details>
<summary><b>Scan pipeline — discover, match, enrich, evaluate, normalize, report</b></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-light.svg" alt="agent-bom scan pipeline from discovery through vulnerability matching, enrichment, analysis, reporting, and enforcement" width="980" />
  </picture>
</p>

</details>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="agent-bom blast-radius drilldown — package to finding to MCP server to agent" width="900" />
  </picture>
</p>

```text
package -> vulnerability finding -> MCP server -> tools + credential refs -> agent
```

Blast radius is the core idea: a vulnerable package is not just a CVE row — it
is linked to the MCP server that loads it, the tools that server exposes, the
credential environment names in reach, and the agents that can call it.

## What It Scans

| Domain | Coverage |
|---|---|
| Supply chain | Package and OS risk across npm, PyPI, Maven, Go, Cargo, NuGet, Composer, RubyGems, conda, Swift, Hex, Pub, apk, deb, and rpm, with OSV/GHSA/NVD enrichment, opt-in review-grade NVD CPE candidate matching for non-ecosystem software, transitive resolution, and dependency-confusion detection |
| Agents + MCP | MCP clients, servers, tools, transports, and trust posture with live introspection across 29 first-class client types |
| AI models + datasets | Malicious-model detection via safe pickle-opcode disassembly (no deserialization), model/dataset cards, and target-scoped PII/PHI dataset-file scanning |
| Cloud estate | Read-only, gated asset inventory and CIS posture across AWS, Azure, GCP, and Snowflake, plus AI/GPU provider posture |
| Identity (NHI) | Non-human identity discovery (Okta/Entra, gated), credential-expiry posture, and access-review recertification |
| LLM cost | Spend forecasting, budget runway, chargeback/allocation, and seasonal-aware spend-anomaly detection |
| Containers + IaC | OCI images, Dockerfile, Terraform, CloudFormation, Helm, and Kubernetes; registry sweeps across ECR/ACR/GAR and agentless AWS EBS disk side-scan (read-only, snapshot-based) |
| Secrets + runtime | Secret detection, MCP proxy/gateway, A2A and MCP auth-posture checks, inline firewall enforcement, and redaction |
| Compliance | Mapped governance frameworks plus ZIP evidence bundles for auditors |

CIS misconfigurations and graph toxic-combinations converge into the same
`Finding` stream and exit-code gate as package vulnerabilities, so a real
exposure can fail a pipeline. The graph adds correlation overlays on the same
base: AppSec findings organized around their application, LLM cost fused onto
the resources that incur it, read-only cloud audit-trail activity as behavioral
edges, and an estate-scale `CONTAINS` roll-up with drill-down so large clouds
stay readable.

### Current Coverage Boundaries

agent-bom is strongest today as a read-only CSPM/CIS, vuln/SCA, compliance,
runtime-policy, and graph-posture product. Connected account scans can run on a
schedule, so new or removed assets are picked up at the next scan and graph
history can show appeared/removed evidence. It is not yet an event-streaming
CDR product: CloudTrail/EventBridge, Azure Activity Log/Event Grid, and GCP
Audit Log/Pub/Sub ingestion are roadmap work.

For DSPM, Snowflake has the deepest current support because agent-bom can read
warehouse metadata, grants, tags, lineage, and governance activity visible to
the configured role. Other cloud data-store sensitivity is posture and metadata
based until classifier-backed content inspection, provider DLP/Macie wrapping,
and object/table/column-level access mapping land. Snowflake is therefore a
strong optional lane for Snowflake-heavy customers, not the required data plane
for the product.

## Product Map

Use this map when you are deciding where to start. Every lane writes into the
same `Finding` and `ContextGraph` model; the difference is the entry point,
credential boundary, and operator surface.

| Need | Surface | First action | Auth / data boundary | Main artifact |
|---|---|---|---|---|
| Scan a repo, image, or local agent config | CLI / CI | `agent-bom agents -p .` | local files only unless an opt-in connector is enabled | JSON, SARIF, SBOM, HTML |
| Connect cloud and selected data-estate evidence | Cloud and warehouse connectors | `agent-bom connect aws` then `agent-bom cloud scan` | read-only provider credentials; no secret values read or stored | cloud assets, CIS findings, Snowflake governance evidence, graph edges |
| Review posture as a team | API + dashboard | `pip install 'agent-bom[ui]' && agent-bom serve` | API key/OIDC/SAML/SCIM where configured; tenant-scoped state | findings, graph, audit, compliance |
| Give agents security tools | MCP server | `agent-bom mcp server` | read-mostly tools; Shield writes require admin role, scope, and audit reason | strict MCP tool responses |
| Govern runtime tool calls | Proxy / gateway | configure proxy or gateway policy | inline policy checks; redacted, auditable decisions | allow/warn/block audit trail |
| Package evidence for security and audit | Reports / exports | `agent-bom agents -p . -f html -o report.html` | caller-controlled export path | SARIF, CycloneDX, SPDX, OCSF, compliance bundle |

See [docs/PRODUCT_MAP.md](docs/PRODUCT_MAP.md) for the longer workflow map,
including backend choices, auth modes, and where each capability lives in the
CLI, API, MCP server, dashboard, and deployment docs.

## How Data Gets In

Today, agent-bom ingests through read-only pulls and explicit pushes, not
Snowpipe or a required streaming bus.

| Ingest lane | Current mechanism | Typical sources | Cadence |
|---|---|---|---|
| Read-only cloud / warehouse connectors | Assumable role, managed identity, ADC, or Snowflake key-pair; SDK/SQL `list`/`get`/`SELECT` calls only | AWS, Azure, GCP, Snowflake | on demand or scheduled polling |
| Direct scans | CLI/API scan job over local or submitted targets | repo, image, IaC, SBOM, MCP config, model, dataset | per command or job |
| Artifact import | Operator-provided standard evidence | CycloneDX, SPDX, SARIF, scanner JSON, OCSF-like evidence | per import |
| Runtime / gateway events | Authenticated API ingest from configured runtimes | MCP/tool-call auth, DLP decisions, LLM spans, proxy audit | event push |

Scheduled connectors re-run with the stored tenant-scoped connection and detect
new, changed, and removed assets at the next cadence through graph history and
diff evidence. Snowpipe/Streams are a future Snowflake-native option for
near-real-time telemetry landing in customer-owned Snowflake tables; they are
not required for the hosted demo, self-hosted platform, CLI, or current
Snowflake connector.

<details>
<summary><b>Product proof — dashboard, graph, and identity surfaces</b></summary>

Captured from the packaged UI with bundled demo scan data and seeded
control-plane records — synthetic data where needed, but the real scan, graph,
fleet, identity, audit, and gateway routes.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png" alt="agent-bom risk overview dashboard with posture score, findings, and attack path summary" width="900" />
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png" alt="agent-bom agent mesh graph showing agent, MCP server, package, tool, credential reference, and finding path" width="900" />
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/security-graph-live.png" alt="agent-bom security graph with attack-path queue, graph evidence export, and remediation handoff" width="900" />
</p>

Capture rules and the full manifest live in [docs/CAPTURE.md](docs/CAPTURE.md)
and [docs/images/product-screenshots.json](docs/images/product-screenshots.json).

</details>

## First Run

```bash
pip install agent-bom
agent-bom db update                      # populate ~/.agent-bom vuln DB before --offline scans
agent-bom quickstart --run --offline    # write sample, scan, seed gateway policy, populate the cockpit
agent-bom agents -p . -f html -o agent-bom-report.html   # a real local scan
```

Offline image and package scans require a populated local vulnerability database.
Run `agent-bom db update` (or allow the first online scan to warm the cache)
before `agent-bom image --offline`, `agent-bom agents --offline`, or CI jobs
that pass `--offline`.

The demo uses bundled advisory-backed OSV/GHSA ranges against intentionally
vulnerable sample packages, producing graph-ready inventory without touching
your source tree. See [docs/FIRST_RUN.md](docs/FIRST_RUN.md) for the guided path
from CLI output to the dashboard, and [docs/CAPTURE.md](docs/CAPTURE.md) to
reproduce the dashboard screenshots from a clean local control-plane store.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom terminal demo" width="820" />
</p>

## Start Here

| Goal | Command |
|---|---|
| Local agent and MCP inventory | `agent-bom agents` |
| Repo and lockfile scan | `agent-bom agents -p .` |
| Connect a cloud (read-only) | `agent-bom connect aws` |
| Cloud estate scan | `agent-bom cloud scan` |
| Multi-hop exposure paths | `agent-bom graph` |
| Report (HTML/SARIF/SBOM) | `agent-bom agents -p . -f html -o report.html` |
| LLM cost forecast | `agent-bom cost forecast` |
| Non-human identity posture | `agent-bom identity credential-expiry` |
| Advisory remediation plan | `agent-bom remediate -p .` |
| Gated-capability readiness | `agent-bom capabilities` |
| CI gate | `uses: msaad00/agent-bom@v0.90.0` |
| Local API and dashboard | `pip install 'agent-bom[ui]' && agent-bom serve` |

The base wheel is the scanner and CLI path; optional runtime surfaces fail fast
with install hints when their extras are missing.
[PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) is the repo map,
[docs/START_HERE.md](docs/START_HERE.md) routes by role, and
[docs/CLI_MAP.md](docs/CLI_MAP.md) groups every command by domain.

## Connect a Cloud (Read-Only Auth)

`agent-bom` reads four clouds — **AWS, Azure, GCP, and Snowflake** — through one
connection model. Every connector is **read-only, agentless, and keyless** by
default: only control-plane `list`/`get` (or `SHOW`/`SELECT`) APIs, no writes, no
secret values, and no data leaves your account. Each connector is opt-in and
default-off behind a per-provider env flag; with the flag unset, agent-bom does
zero cloud network I/O. `agent-bom connect aws | azure | gcp | snowflake` prints
the exact read-only grant, the opt-in env var, and whether local credentials are
detectable — without any network I/O until you opt in.

| Cloud | Read-only grant | Keyless / token auth | Enable | Scan |
|---|---|---|---|---|
| AWS | `SecurityAudit` managed policy | profile / SSO / instance role (boto3 chain) | `AGENT_BOM_AWS_INVENTORY=1` | `agent-bom cloud aws` |
| Azure | `Reader` (+ `Security Reader`) | `az login` / managed identity / cert SP | `AGENT_BOM_AZURE_INVENTORY=1` | `agent-bom cloud azure` |
| GCP | impersonated read-only service account | ADC / `gcloud` / workload identity | `AGENT_BOM_GCP_INVENTORY=1` | `agent-bom cloud gcp` |
| Snowflake | `ABOM_READONLY` role + key-pair user | RSA key-pair JWT (no password) | — | `agent-bom agents --snowflake` |

```bash
# AWS — attach SecurityAudit to the principal, then:
export AGENT_BOM_AWS_INVENTORY=1
export AWS_PROFILE=<readonly-profile>
agent-bom cloud aws --cis

# Run every configured cloud at once (read-only, auto-detects what is connected):
agent-bom cloud scan --fail-on-severity high
```

AWS, Azure, GCP, and Snowflake setup, the full grant templates, per-cloud permission
catalogs, and the "why read-only is enough" rationale live in
[docs/CLOUD_CONNECT.md](docs/CLOUD_CONNECT.md). agent-bom is one interoperable
scanner and control plane: it reads inventory and posture, normalizes it into
one graph, serves humans and agents from the same evidence, and emits findings;
it never writes, never reads secret contents, and never moves data out of your
account unless you explicitly configure an export destination.

## Deploy In Your Boundary

`agent-bom` is built for customer-controlled deployment across four lanes of one
product: the OSS CLI, the self-hosted API/UI platform, a gated hosted POC you
operate, and an optional Snowflake-native deployment for Snowflake-heavy
customers. A managed public SaaS control plane is roadmap work gated on
self-serve signup, tenant lifecycle, quotas, billing, and abuse controls.

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

- [Deploy anywhere guide](docs/DEPLOY_PLATFORM.md) — laptop, your Kubernetes, or hosted control plane
- [Helm chart](deploy/helm/agent-bom) and [one-apply EKS platform module](deploy/terraform/platform-eks)
- [Docker Hub image](https://hub.docker.com/r/agentbom/agent-bom)
- [CloudFormation one-click](deploy/cloudformation) — a read-only `cloud aws` scan via CodeBuild, no local credentials handed to agent-bom

There is no managed cloud offering in this repository; lane boundaries are
documented in [docs/PRODUCT_BOUNDARIES.md](docs/PRODUCT_BOUNDARIES.md).

## Trust Model

- Read-only discovery by default for cloud and local inventory.
- No mandatory telemetry.
- Credential values are redacted; credential environment names are preserved as
  evidence so exposure paths stay explainable.
- Findings export as JSON, SARIF, CycloneDX, SPDX, OCSF, Markdown, HTML, and
  compliance evidence bundles.
- API and runtime paths are designed for tenant scope, auth boundaries, and
  audit evidence; OpenAPI artifacts are committed for client contract checks.

References: [Threat model](docs/THREAT_MODEL.md) ·
[Pentest readiness](docs/PENTEST_READINESS.md) ·
[Python client](docs/PYTHON_API.md) · [Go client](sdks/go/README.md) ·
[Release verification](docs/RELEASE_VERIFICATION.md)

## Surfaces

| Surface | Primary user | Current boundary |
|---|---|---|
| CLI / CI | developers and release gates | local scans, SARIF/SBOM/HTML/JSON, deterministic exit codes |
| REST API | control-plane integrations | scans, bulk findings, dataset versions, evaluation runs, graph evidence, audit, runtime summaries |
| MCP tools | agents and assistants | strict arguments, read-mostly security queries, exposure paths, deploy decisions, audited Shield actions |
| Dashboard | security teams and operators | inventory, findings, graph cockpit, compliance, evidence, runtime posture |
| Runtime proxy/gateway | runtime operators | scoped MCP traffic inspection, policy decisions, redacted audit evidence |
| Python / TypeScript clients | services and agent runtimes | typed helpers for stable REST endpoints |

MCP server mode advertises 70 MCP tools, 6 resources, and 6 workflow prompts.
Most tools are read-only; Shield and identity write actions fail closed unless
the MCP request is authenticated with `AGENT_BOM_MCP_OPERATOR_TOKEN` and the
tool call includes the matching admin role, write scope, and audit reason. CLI
scan commands run local scan pipelines today and share lower
scanner and discovery libraries with the API, but they are not API wrappers yet.
MCP registry presence is tracked through the committed Smithery manifest and
other registry metadata; install and liveness checks live in the integration
docs, not this front door.

## Contributing

Contributions are welcome. Start with [CONTRIBUTING.md](CONTRIBUTING.md),
[.agents/AGENTS.md](.agents/AGENTS.md), and the
[open issues](https://github.com/msaad00/agent-bom/issues).

License: Apache-2.0.
