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
agents, MCP servers, tools, packages, credential environment names, cloud
estate, non-human identities, runtime, and skills, then turns that inventory
into findings, compliance evidence, LLM cost posture, and graph-backed
multi-hop exposure paths.

The same evidence is available through CLI/CI, REST API, MCP tools, and a
self-hosted dashboard. Runtime proxy/gateway controls — including inline
firewall enforcement and a secure-by-default gateway — are optional and scoped
to environments where enforcement is worth the operational cost.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="agent-bom blast-radius drilldown — package to finding to MCP server to agent" width="900" />
  </picture>
</p>

```text
package
  -> vulnerability finding
  -> MCP server
  -> tools + credential refs
  -> agent
```

Blast radius is the core idea. A vulnerable package is not just a CVE row; it
is linked to the MCP server that loads it, the tools exposed by that server,
the credential environment names in reach, and the agents that can call it.

## What It Scans

| Domain | Coverage |
|---|---|
| Supply chain | 15 package ecosystems (npm, PyPI, Maven, Go, Cargo, NuGet, Composer, RubyGems, conda, Hex, Pub, Swift, plus OS packages apk/deb/rpm) with OSV/GHSA enrichment, transitive resolution, and dependency-confusion detection |
| Agents + MCP | MCP clients, servers, tools, transports, trust posture, and live introspection across 29 first-class client types |
| AI models + datasets | Malicious-model detection via safe pickle-opcode disassembly (no deserialization), model/dataset cards, and PII/PHI dataset scanning |
| Cloud estate | Read-only, gated asset inventory across AWS, Azure, GCP, and Snowflake plus AI/GPU provider posture and CIS benchmarks. One connection model per cloud: a scoped read-only role and keyless/token auth — see [docs/CLOUD_CONNECT.md](docs/CLOUD_CONNECT.md) |
| Identity (NHI) | Non-human identity discovery (Okta/Entra, gated), credential-expiry posture, and access-review recertification campaigns |
| LLM cost | Spend forecasting, budget runway, chargeback/allocation, and seasonal-aware spend-anomaly detection |
| Containers + IaC | Native OCI image parsing plus Dockerfile, Terraform, CloudFormation, Helm, and Kubernetes; registry-wide sweeps across ECR/ACR/GAR (`cloud registry-scan`) and agentless AWS EBS disk side-scan (CWPP, snapshot-based, read-only) |
| Secrets + runtime | Secret detection, MCP proxy/gateway, A2A and MCP auth-posture checks, inline firewall enforcement, and redaction surfaces |
| Compliance | Mapped governance frameworks plus ZIP evidence bundles for auditors |

Findings converge on one unified `Finding` model and a unified `ContextGraph`,
so multi-hop attack-path fusion, blast radius, and exposure scoring all read
from the same evidence. The graph adds correlation overlays on top of that base:
an ASPM layer that organizes AppSec findings around the application they belong
to, LLM cost fused onto the resources that incur it, read-only cloud audit-trail
activity as behavioral edges, and an estate-scale `CONTAINS` roll-up with
drill-down so large clouds stay readable instead of one sprawling canvas.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/control-loop-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/control-loop-light.svg" alt="agent-bom control loop from discovery to graph evidence to gateway policy and runtime enforcement" width="900" />
  </picture>
</p>

## First Run

```bash
pip install agent-bom
agent-bom quickstart --dry-run --offline   # print the onboarding plan
agent-bom quickstart --run --offline        # write sample, scan, seed gateway policy, populate the cockpit
agent-bom agents --demo --offline
```

The demo uses bundled advisory-backed OSV/GHSA ranges against intentionally
vulnerable sample packages and produces graph-ready inventory without touching
your source tree.
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

To reproduce the dashboard screenshots from a clean local control-plane store:

```bash
make build-ui
uv run agent-bom serve --persist /tmp/agent-bom-demo.db --allow-insecure-no-auth
uv run agent-bom agents --demo --offline --no-auto-update-db -f json -o /tmp/agent-bom-demo.json
curl -sS -H 'content-type: application/json' --data-binary @/tmp/agent-bom-demo.json \
  http://127.0.0.1:8422/v1/results/push
```

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom terminal demo" width="820" />
</p>

## Product Proof

The dashboard screenshots below are captured from the packaged UI with bundled
demo scan data and seeded control-plane records, not static mockups. The data is
synthetic where needed, but the routes are the real scan, graph, fleet,
identity, audit, and gateway surfaces. The README keeps the first screen
focused; expand the gallery when you want to inspect the control-plane surfaces.

<details open>
<summary><b>Evidence cockpit and agent mesh</b></summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png" alt="agent-bom risk overview dashboard with posture score, findings, and attack path summary" width="900" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png" alt="agent-bom agent mesh graph showing agent, MCP server, package, tool, credential reference, and finding path" width="900" />
</p>

</details>

<details open>
<summary><b>Graph views beyond the agent mesh</b></summary>

The graph proof set is intentionally split across modes: fix-first exposure
paths, root-centered lineage, lateral context, and package risk distribution.
That keeps each view readable instead of forcing every relationship into one
sprawling canvas.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/security-graph-live.png" alt="agent-bom security graph with attack-path queue, graph evidence export, and remediation handoff" width="900" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/lineage-graph-live.png" alt="agent-bom lineage graph centered on an agent with bounded paths, filters, and graph evidence export" width="900" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/context-map-live.png" alt="agent-bom context map showing agent-to-server reachability and lateral movement context" width="900" />
</p>

</details>

<details open>
<summary><b>Environment state and identity lifecycle</b></summary>

Fleet and identity views use the same control-plane APIs that operators use for
customer-owned deployments. The sample below seeds environment, owner, lifecycle
state, and agent identity events so the screenshots show how local scan evidence
connects to reviewable governance records.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/fleet-state-live.png" alt="agent-bom fleet state dashboard showing lifecycle distribution, approved and discovered agents, owner metadata, environment labels, and discovery state" width="900" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/identity-audit-live.png" alt="agent-bom audit log filtered to identity lifecycle events with HMAC integrity counters and issue, rotate, revoke rows" width="900" />
</p>

</details>

<details>
<summary><b>Dependency and remediation views</b></summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dependency-map-live.png" alt="agent-bom dependency map with scan pipeline counts, supply-chain treemap, blast-radius chart, and EPSS by CVSS risk map" width="900" />
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/remediation-live.png" alt="agent-bom remediation dashboard with prioritized package fixes and compliance context" width="900" />
</p>

</details>

<details>
<summary><b>Runtime policy and audit posture</b></summary>

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/gateway-policies-live.png" alt="agent-bom gateway policy dashboard showing advisory runtime posture, enabled policy count, rule counts, and bound agents" width="900" />
</p>

</details>

Screenshot capture rules and the full manifest live in
[docs/CAPTURE.md](docs/CAPTURE.md) and
[docs/images/product-screenshots.json](docs/images/product-screenshots.json).

## Start Here

| Goal | Command | Artifact |
|---|---|---|
| Local agent and MCP inventory | `agent-bom agents` | findings, AI BOM, graph-ready JSON |
| Read-only cloud onboarding | `agent-bom connect aws` | exact read-only grant + opt-in env var; no network I/O until you opt in |
| Guided local onboarding | `agent-bom quickstart --dry-run --offline` | scan, sample-data, and local API/UI next steps |
| One-command onboarding | `agent-bom quickstart --run --offline` | writes sample, runs a graph-persisting scan, seeds a baseline gateway policy |
| Repo and lockfile scan | `agent-bom agents -p .` | package findings, SARIF/SBOM/HTML when requested |
| Pre-install guard | `agent-bom check flask@2.0.0 --ecosystem pypi` | deterministic allow/warn/block result |
| Container image scan | `agent-bom image nginx:latest` | image findings and remediation |
| IaC scan | `agent-bom iac Dockerfile k8s/ infra/main.tf` | IaC findings and policy context |
| Cloud posture check | `agent-bom cloud aws --cis` | runtime CIS posture evidence |
| Cloud estate inventory | `agent-bom cloud inventory --provider aws` | read-only, gated asset inventory (AWS/Azure/GCP) |
| Snowflake AI BOM + CIS | `agent-bom agents --snowflake` | Cortex agents, Snowpark apps, and CIS posture (read-only, key-pair) |
| LLM cost forecast | `agent-bom cost forecast` | spend burn-rate, budget runway, and chargeback posture |
| Non-human identity posture | `agent-bom identity credential-expiry` | expiring/overdue NHI credentials and access reviews |
| Advisory remediation plan | `agent-bom remediate -p .` | prioritized, blast-radius-ordered fixes (optional `--apply` / `--open-pr`) |
| Gated-capability readiness | `agent-bom capabilities` | every gated feature: state, why, and how to unlock |
| CI gate | `uses: msaad00/agent-bom@v0.89.2` | SARIF, PR summary, optional code-scanning upload |
| MCP tools | `pip install 'agent-bom[mcp-server]' && agent-bom mcp server` | strict-args security tools for MCP clients |
| Local API/UI | `pip install 'agent-bom[ui]' && agent-bom serve` | API plus bundled dashboard |
| First-run extras | `pip install 'agent-bom[all]'` | supported onboarding extras; MLflow remains separately installed |
| Self-hosted pilot | `docker compose -f docker-compose.pilot.yml up -d` | API and dashboard in your environment |

The base wheel is the scanner and CLI path. Optional runtime surfaces fail fast
with install hints when their extras are missing.

New to the repo? [PROJECT_STRUCTURE.md](PROJECT_STRUCTURE.md) is the repo map,
[docs/START_HERE.md](docs/START_HERE.md) routes you by role, and
[docs/CLI_MAP.md](docs/CLI_MAP.md) groups every command by domain.

MCP registry publishing is tracked through the committed Smithery manifest and
other registry metadata; install and liveness checks stay in the linked
integration docs instead of this front door.

## Shipped Surfaces

| Surface | Primary user | Current boundary |
|---|---|---|
| CLI / CI | developers and release gates | local scans, SARIF/SBOM/HTML/JSON, deterministic exit codes |
| REST API | control-plane integrations | scans, bulk findings, dataset versions, evaluation runs, graph evidence, audit, runtime summaries |
| MCP tools | agents and assistants | strict arguments, read-mostly security queries, exposure paths, deploy decisions, audited Shield actions |
| Dashboard | security teams and operators | inventory, findings, graph cockpit, compliance, evidence, runtime posture |
| Runtime proxy/gateway | runtime operators | scoped MCP traffic inspection, policy decisions, redacted audit evidence |
| Python client | services, notebooks, and automation | typed helper for stable REST endpoints in the packaged wheel |
| TypeScript client | services and agent runtimes | typed helper for stable REST endpoints |

MCP server mode advertises 70 MCP tools, 6 resources, and 6 workflow prompts.
Most tools are read-only. The three Shield write actions fail closed unless
the caller supplies `operator_role=admin`, `operator_scopes=shield:write`, and
an audit reason.

CLI scan commands run local scan pipelines today. They share lower scanner and
discovery libraries with the API, but they are not API wrappers yet.

Runtime enforcement is explicit. Proxy mode either wraps a target MCP server
for audit and policy decisions, or runs that server through Docker/Podman
isolation when a sandbox image is supplied:

```bash
agent-bom proxy --no-isolate --policy policy.json --detect-credentials --block-undeclared -- npx @mcp/server-github
agent-bom proxy --sandbox-image ghcr.io/acme/mcp-runtime@sha256:<digest> \
  --sandbox-image-pin-policy enforce --block-undeclared -- npx @mcp/server-postgres
```

## Connect a Cloud (Read-Only)

`agent-bom` reads four clouds — **AWS, Azure, GCP, and Snowflake** — through one
connection model. Every connector is **read-only, agentless, and keyless** by
default: only control-plane `list`/`get` (or `SHOW`/`SELECT`) APIs, no writes, no
secret values, no data leaves your account. Each connector is **opt-in and
default-off**, gated by a per-provider env flag; with the flag unset, agent-bom
does zero cloud network I/O.

The *only* thing that differs per cloud is the line that mints the read-only
role — because each platform's grant primitive is different. Everything else is
identical: enable with `AGENT_BOM_<PROVIDER>_INVENTORY=1`, authenticate with the
cloud's own identity (never a secret handed to agent-bom), get the same graph
and findings out.

`agent-bom connect aws | azure | gcp | snowflake` prints the exact read-only
setup for each source — the Terraform module, the opt-in inventory env var, and
whether local credentials are already detectable — without doing any network
I/O until you opt in.

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

# Azure — assign Reader (+ Security Reader), then:
export AGENT_BOM_AZURE_INVENTORY=1
az login
agent-bom cloud azure --cis

# GCP — grant a read-only SA and impersonate it (no key file):
export AGENT_BOM_GCP_INVENTORY=1
export AGENT_BOM_GCP_IMPERSONATE_SA=<sa-email>      # e.g. abom-readonly@<project-id>.iam.gserviceaccount.com
gcloud auth application-default login
agent-bom cloud gcp --project <project-id> --cis

# Snowflake — create ABOM_READONLY + a key-pair user (see CLOUD_CONNECT.md), then:
export SNOWFLAKE_ACCOUNT=<org-account>
export SNOWFLAKE_USER=ABOM_SCANNER
export SNOWFLAKE_AUTHENTICATOR=snowflake_jwt
export SNOWFLAKE_PRIVATE_KEY_PATH=/path/to/abom_key.p8
agent-bom agents --snowflake
```

A read-only **estate inventory** across the enabled clouds (reference only, no
findings):

```bash
agent-bom cloud inventory --provider all        # or aws | azure | gcp
```

Or run one cloud-aware scan across every configured provider at once —
`--provider all` (the default) auto-detects which clouds are connected and
skips the rest:

```bash
agent-bom cloud scan                            # all configured clouds, read-only
agent-bom cloud scan --provider aws --cis --show-passed
agent-bom cloud registry-scan --provider ecr --region us-east-1   # sweep an ECR/ACR/GAR registry
```

CIS misconfigurations and graph toxic-combinations converge into the same
`Finding` stream and exit-code gate as package vulnerabilities, so a real
exposure can fail a pipeline:

```bash
agent-bom agents --aws --azure --gcp --snowflake --fail-on-severity high
agent-bom graph                                 # multi-hop exposure paths
agent-bom identity credential-expiry            # non-human identity posture
agent-bom db freshness                          # confirm vuln data is current before gating
```

The full grant templates, per-cloud permission catalogs, and the
"why read-only is enough" rationale live in
[docs/CLOUD_CONNECT.md](docs/CLOUD_CONNECT.md). agent-bom is a **scanner, not a
platform** — it reads inventory and posture, normalizes it into one graph, and
emits findings; it never writes, never reads secret contents, and never moves
data out of your account.

<!-- TODO: capture real (redacted) screenshot: cross-cloud security graph with AWS + Azure + GCP + Snowflake nodes and a multi-hop exposure path -->
<!-- TODO: capture real (redacted) screenshot: findings table filtered to cloud CIS misconfigurations across the four providers -->
<!-- TODO: capture real (redacted) screenshot: identity/CIEM path from a cloud principal to a sensitive data store -->

## Deploy In Your Boundary

`agent-bom` is designed for customer-controlled deployment: local CLI, Docker,
GitHub Action, Helm, EKS, Postgres, and optional runtime proxy/gateway.

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

Production self-hosting starts with the deployment chooser:

- [Deploy anywhere guide](docs/DEPLOY_PLATFORM.md) — one product, three tiers (laptop, your Kubernetes, hosted control plane)
- [Deployment overview](site-docs/deployment/overview.md)
- [Helm chart](deploy/helm/agent-bom)
- [One-apply EKS platform module](deploy/terraform/platform-eks) — `terraform apply` the full control plane (cluster, Postgres, secrets, ingress)
- [EKS reference installer](scripts/deploy/install-eks-reference.sh)
- [Docker Hub image](https://hub.docker.com/r/agentbom/agent-bom)

For a zero-install AWS scan, deploy the
[CloudFormation one-click template](deploy/cloudformation) — it runs a
read-only `agent-bom cloud aws` scan in your account via CodeBuild, no local
credentials handed to agent-bom.

There is no managed cloud offering in this repository today. Product lane
boundaries are documented in [docs/PRODUCT_BOUNDARIES.md](docs/PRODUCT_BOUNDARIES.md).

## Trust Model

- Read-only discovery by default for cloud and local inventory.
- No mandatory telemetry.
- Credential values are redacted; credential environment names are preserved as
  evidence so exposure paths stay explainable.
- Findings can export as JSON, SARIF, CycloneDX, SPDX, OCSF, Markdown, HTML, and
  compliance evidence bundles.
- API and runtime paths are designed for tenant scope, auth boundaries, and
  audit evidence.
- OpenAPI artifacts are committed for SDK and client contract checks.

Security and release references:

- [Threat model](docs/THREAT_MODEL.md)
- [Pentest readiness](docs/PENTEST_READINESS.md)
- [Python API and control-plane client](docs/PYTHON_API.md)
- [Go control-plane client](sdks/go/README.md)
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
