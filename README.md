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

<p align="center"><b>Open security scanner for AI supply chain — agents, MCP servers, packages, containers, cloud, GPU, and runtime.</b></p>

<p align="center">Every CVE in your AI stack is a credential leak waiting to happen. <code>agent-bom</code> follows the chain end-to-end and tells you exactly which fix collapses it.</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="agent-bom blast-radius drilldown — package → CVE → MCP server → agent → credentials → tools" width="900" />
  </picture>
</p>

```text
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  |── better-sqlite3@9.0.0  (npm)
       |── sqlite-mcp  (MCP Server · unverified · root)
            |── Cursor IDE  (Agent · 4 servers · 12 tools)
            |── ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            |── query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

Blast radius is the core idea: `CVE -> package -> MCP server -> agent -> credentials -> tools`. CWE-aware impact keeps a DoS from being reported like credential compromise.

## Try the demo

```bash
agent-bom agents --demo --offline
```

The demo uses a curated sample so the output stays reproducible across releases. Every CVE shown is a real OSV/GHSA match against a genuinely vulnerable package version — no fabricated findings (locked in by [`tests/test_demo_inventory_accuracy.py`](tests/test_demo_inventory_accuracy.py)). For a real scan, run `agent-bom agents`, or add `-p .` to fold project manifests and lockfiles into the same result.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom terminal demo — one CLI run produces blast radius, remediation, and SBOM" width="820" />
</p>

## Pick your entrypoint

| Goal | Run | Runs where | What it touches |
|---|---|---|---|
| Discover what is installed on this machine or repo | `agent-bom agents -p .` | local CLI, CI runner, or scan job | local agent configs, MCP servers, project manifests, lockfiles, blast radius |
| Turn findings into a fix plan | `agent-bom agents -p . --remediate remediation.md` | same place as the scan | prioritized upgrades with reachable impact and remediation hints |
| Check one package before install | `agent-bom check flask@2.2.0 --ecosystem pypi` | local CLI or CI gate | package metadata and vulnerability verdict only |
| Scan a container image | `agent-bom image nginx:latest` | local CLI, CI runner, or scan job | image layers, OS packages, language packages, fixability |
| Audit IaC or cloud posture | `agent-bom iac Dockerfile k8s/ infra/main.tf` | local CLI, CI runner, or scheduled job | Terraform, Kubernetes, Helm, Dockerfiles, optional live-cluster posture |
| Run the control plane locally | `agent-bom serve` | one workstation or server | API + bundled local UI + persisted jobs/graph on the same machine |
| Inspect live local MCP traffic | `agent-bom proxy "<server command>"` | next to the MCP client or workload | inline stdio/runtime inspection, policy evaluation, audit push |
| Run a shared remote MCP traffic plane | `agent-bom gateway serve` | cluster or server | shared HTTP/SSE remote MCP traffic, tenant policy, audit, rate limits |

## Quick start

```bash
pip install agent-bom                  # CLI
# pipx install agent-bom               # isolated global install
# uvx agent-bom --help                 # ephemeral run

agent-bom agents                              # discover + scan local AI agents and MCP servers
agent-bom agents -p .                         # add project lockfiles + manifests
agent-bom check flask@2.0.0 --ecosystem pypi  # pre-install CVE gate
agent-bom image nginx:latest                  # container image scan
agent-bom iac Dockerfile k8s/ infra/main.tf   # IaC scan, optionally `--k8s-live`
```

Self-hosted pilot:

```bash
curl -fsSL https://raw.githubusercontent.com/msaad00/agent-bom/main/deploy/docker-compose.pilot.yml -o docker-compose.pilot.yml
docker compose -f docker-compose.pilot.yml up -d
# Dashboard -> http://localhost:3000
```

Production chart from a checked-out repo:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

After the first scan:

```bash
agent-bom agents -p . --remediate remediation.md                  # fix-first plan
agent-bom agents -p . --compliance-export fedramp -o evidence.zip # tamper-evident evidence bundle
pip install 'agent-bom[ui]' && agent-bom serve                    # API + bundled local UI
```

<details>
<summary><b>Product views</b> — dashboard, remediation, and graph surfaces</summary>

## Product views

These come from the live product path, using the built-in demo data pushed through the API. See [`docs/CAPTURE.md`](docs/CAPTURE.md) for the canonical capture protocol.

### Dashboard — Risk overview

The landing page is the **Risk overview**: a letter-grade gauge, the four headline counters (actively exploited · credentials exposed · reachable tools · top attack-path risk), the security-posture grade with sub-scores (policy + controls, open evidence, packages + CVEs, reach + exposure, MCP configuration), and the score breakdown for each driver.

![agent-bom dashboard overview](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-live.png)

### Dashboard — Attack paths and exposure

The second dashboard frame focuses on the fix-first path list and the coverage / backlog KPIs below it, so the attack-path drilldown stays readable without a tall stitched screenshot.

![agent-bom dashboard attack paths and exposure](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/dashboard-paths-live.png)

### Fix-first remediation

Risk, reach, fix version, and framework context in one review table — operators act without jumping between pages.

![agent-bom remediation view](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/remediation-live.png)

### Agent mesh

Agent-centered shared-infrastructure graph — selected agents, their shared MCP servers, tools, packages, and findings.

![agent-bom agent mesh](https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/mesh-live.png)

</details>

<details>
<summary><b>How a scan moves through the system</b> — five stages, no source code or credentials leave your machine</summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-light.svg" alt="agent-bom scan pipeline — discover, scan, analyze, report, enforce" width="900" />
  </picture>
</p>

Inside the engine: parsers, taint, call graph, blast-radius scoring.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/engine-internals-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/engine-internals-light.svg" alt="agent-bom engine internals" width="900" />
  </picture>
</p>

External calls are limited to package metadata, version lookups, and CVE enrichment.

</details>

---

# Enterprise self-hosted deployment

**`agent-bom` runs inside your infrastructure: your VPC, your EKS cluster, your Postgres, your SSO, your KMS. No hosted control plane. No mandatory vendor backend. No mandatory telemetry.**

The easiest way to understand the product is:

- **start with inventory** using scans and fleet sync
- **add runtime later** with proxy or gateway where you actually need enforcement

That is the adoption wedge behind the product:

- inventory-first teams can see which MCP servers are running, what tools they expose, and which credentials back them
- runtime-focused teams can layer in proxy or gateway without changing the control plane

## Deployment modes

| Mode | Deploy | Use when | Adds |
|---|---|---|---|
| **Local scan** | CLI or CI only | You want discovery, CVEs, IaC, image, and MCP config analysis | no persistent control plane |
| **Inventory-first self-hosted** | API + UI + Postgres + scan jobs + fleet sync | You want endpoint and MCP inventory without rolling out runtime enforcement first | `/fleet`, `/agents`, findings, graph, remediation, audit |
| **Selective runtime enforcement** | inventory-first, plus `proxy` on chosen workloads | You need inline MCP inspection near stdio or workload-local MCPs | policy enforcement, runtime audit, local blocking |
| **Shared remote MCP control** | inventory-first, plus `gateway` | You want a central HTTP traffic plane for shared remote MCPs | central relay, shared rate limits, remote MCP policy/audit |
| **Full self-hosted platform** | control plane + scan + fleet + selected proxy + selected gateway | You want one operator plane across inventory, findings, runtime, and evidence | the full product stack in your own infra |

## Runtime model

`proxy` and `gateway` are **peer runtime surfaces**, not a required serial chain.

| Surface | Deploy it when | Handles | Does not replace |
|---|---|---|---|
| **`agent-bom proxy`** | you need workload-local or endpoint-local MCP enforcement | stdio MCPs, sidecars, local audit, local policy decisions | inventory, fleet sync, or shared remote relay |
| **`agent-bom gateway serve`** | you need a shared remote MCP plane | HTTP/SSE remote MCP traffic, tenant rate limits, shared policy, audit | local stdio enforcement or every runtime path |

### How the product connects

| Path | Starts from | Lands in | Why it exists |
|---|---|---|---|
| **Inventory path** | `agent-bom agents`, scan jobs, CI, fleet sync | API + UI + Postgres | discover what is installed, configured, risky, and reachable |
| **Proxy path** | local editor, endpoint, or sidecar workload | local MCPs + control-plane audit/policy | inline runtime inspection close to the workload |
| **Gateway path** | shared remote MCP clients | remote MCPs + control-plane audit/policy | central policy and shared remote MCP traffic |
| **Control-plane path** | browser UI or API client | API + UI + Postgres | review findings, graph, remediation, audit, fleet, and policy |

Deployment truth:

- the **browser UI drives workflows**
- the **API owns state, auth, RBAC, graph, audit, and policy**
- **workers do scans and ingest**
- **fleet gives inventory without proxy**
- **proxy and gateway are core features deployed where they fit**

## What becomes visible before proxy rollout

With scans and fleet sync alone, teams can already see:

- which endpoints have MCP clients or collectors
- which MCP servers are configured
- transport: `stdio`, `sse`, or `http`
- declared tools
- command or URL
- credential-backed environment variables
- last seen and last synced state
- package, image, IaC, and related finding context

That is why the inventory story matters: adoption should not require teams to
start with a runtime rollout.

## Self-hosted shape in one table

| Layer | Usually deploy first | Notes |
|---|---|---|
| **Ingress + auth** | yes | OIDC or SAML in front of the control plane |
| **API + UI** | yes | one operator plane, same-origin browser app |
| **Workers / scan jobs** | yes | discovery, scans, imports, scheduled jobs |
| **Fleet sync** | yes for endpoint visibility | gives MCP inventory without proxy |
| **Proxy** | optional | add only where inline local enforcement is needed |
| **Gateway** | optional | add only where shared remote MCP traffic needs a central plane |
| **Postgres** | yes | primary transactional store |
| **ClickHouse / S3** | optional | analytics and backup/export scale |

## One product, two deployable images

- `agentbom/agent-bom` = CLI, API, jobs, gateway, proxy, MCP server mode
- `agentbom/agent-bom-ui` = browser control-plane UI

Users should not think about that split directly:

- **pilot**: one Compose file
- **production**: one Helm chart

## Local vs self-hosted

| If you run... | It can scan or manage | It cannot directly reach |
|---|---|---|
| `agent-bom agents -p .` on your laptop | local repo, local MCP configs, local manifests, local endpoint context | cluster-only resources unless you pass credentials or run from that environment |
| `agent-bom serve` on one machine | scans and UI workflows for paths that machine can access | another developer laptop's local files or cluster-internal services it cannot reach |
| Helm / Compose control plane in your infra | scan jobs, fleet sync, graph, audit, remediation, API/UI workflows | endpoint-local stdio traffic unless proxy is deployed there |
| `agent-bom proxy` on an endpoint or sidecar | that workload's live MCP traffic | shared remote MCP traffic that never passes through that proxy |
| `agent-bom gateway serve` in cluster | shared remote MCP traffic routed through it | local stdio MCP sessions that stay on endpoints |

## Start here by scenario

| Need | Start here |
|---|---|
| fastest local pilot | [Deployment Overview](site-docs/deployment/overview.md) |
| self-host in your AWS / EKS | [Deploy In Your Own AWS / EKS Infrastructure](site-docs/deployment/own-infra-eks.md) |
| reference AWS rollout from cluster creation onward | [AWS Company Rollout](site-docs/deployment/aws-company-rollout.md) |
| endpoint inventory and laptop rollout | [Endpoint Fleet](site-docs/deployment/endpoint-fleet.md) |
| proxy and gateway runtime operations | [Runtime Operations](site-docs/deployment/runtime-operations.md) |
| trust model, auth, tenant isolation | [ENTERPRISE_SECURITY_PLAYBOOK.md](docs/ENTERPRISE_SECURITY_PLAYBOOK.md) |

<details>
<summary><b>Deep deployment notes</b></summary>

### What each surface owns

| Surface | Owns | Does not own |
|---|---|---|
| **UI** | run-now actions, review, export, policy workflows | direct collection |
| **API / control plane** | auth, RBAC, tenant scope, orchestration, persistence, graph, audit, policy | inline MCP enforcement |
| **Workers** | scans, ingest, normalization, imports | browser sessions |
| **Fleet** | endpoint and collector inventory | runtime blocking |
| **Proxy** | local inline MCP inspection and audit relay | central policy storage |
| **Gateway** | shared remote MCP traffic and shared runtime policy evaluation | full control-plane persistence |

### Backend choices

| Backend | Best for |
|---|---|
| **SQLite** | laptops and single-node local use |
| **Postgres / Supabase** | default self-hosted control plane |
| **ClickHouse** | audit/event analytics at higher scale |
| **Snowflake** | warehouse-native governance workflows where the published backend parity fits |

### Shipped Helm examples

| File | Use when |
|---|---|
| [`eks-mcp-pilot-values.yaml`](deploy/helm/agent-bom/examples/eks-mcp-pilot-values.yaml) | focused MCP and fleet pilot |
| [`eks-production-values.yaml`](deploy/helm/agent-bom/examples/eks-production-values.yaml) | production rollout |
| [`eks-istio-kyverno-values.yaml`](deploy/helm/agent-bom/examples/eks-istio-kyverno-values.yaml) | zero-trust / regulated rollout |
| [`eks-snowflake-values.yaml`](deploy/helm/agent-bom/examples/eks-snowflake-values.yaml) | Snowflake-backed deployment |

</details>

---

## Trust & transparency

agent-bom is a **read-only scanner**. It never writes configs, never executes MCP servers, never stores credential values. No telemetry. No analytics. Releases are [Sigstore-signed](docs/PERMISSIONS.md) with SLSA provenance and self-published SBOMs.

| When | What's sent | Where | Opt out |
|---|---|---|---|
| Default CVE lookups | Package names + versions | OSV API | `--offline` |
| Floating version resolution | Names + requested version | npm / PyPI / Go proxy | `--offline` |
| `--enrich` | CVE IDs | NVD, EPSS, CISA KEV | omit `--enrich` |
| `--deps-dev` | Package names + versions | deps.dev | omit `--deps-dev` |
| `verify` | Package + version | PyPI / npm integrity endpoints | don't run `verify` |
| Optional integrations | Finding summaries | Slack / Jira / Vanta / Drata | don't pass those flags |

Full trust model: [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) · [PERMISSIONS.md](docs/PERMISSIONS.md) · [SUPPLY_CHAIN.md](docs/SUPPLY_CHAIN.md) · [RELEASE_VERIFICATION.md](docs/RELEASE_VERIFICATION.md).

## Compliance

Bundled mappings for FedRAMP, CMMC, NIST AI RMF, ISO 27001, SOC 2, OWASP LLM Top-10, MITRE ATLAS, and EU AI Act. Export tamper-evident evidence packets in one command.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/compliance-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/compliance-light.svg" alt="agent-bom compliance mapping — finding to control to evidence packet" width="900" />
  </picture>
</p>

```bash
agent-bom agents -p . --compliance-export fedramp -o fedramp-evidence.zip
agent-bom agents -p . --compliance-export nist-ai-rmf -o evidence.zip
```

The audit log itself is HMAC-chained and exportable as a signed JSON/JSONL bundle at `GET /v1/audit/export`.

## Install & deploy

```bash
pip install agent-bom                        # CLI
docker run --rm agentbom/agent-bom agents    # Docker
```

For published containers, the packaging model is:

- one product, two deployable images
- `agentbom/agent-bom` = the main runtime image for CLI, API, jobs, gateway,
  proxy-related entrypoints, and MCP server mode
- `agentbom/agent-bom-ui` = the browser dashboard image for the same
  self-hosted control plane

| Mode | Best for |
|------|----------|
| CLI (`agent-bom agents`) | local audit + project scan |
| Endpoint fleet (`--push-url …/v1/fleet/sync`) | employee laptops pushing into self-hosted fleet |
| GitHub Action (`uses: msaad00/agent-bom@v0.81.1`) | CI/CD + SARIF |
| Docker (`agentbom/agent-bom`) | isolated scans, API jobs, and non-browser self-hosted entrypoints |
| Browser UI image (`agentbom/agent-bom-ui`) | the dashboard image paired with the same self-hosted control plane |
| Kubernetes / Helm (`helm install agent-bom deploy/helm/agent-bom`) | self-hosted API + dashboard, scheduled discovery |
| REST API (`agent-bom api`) | platform integration, self-hosted control plane |
| MCP server (`agent-bom mcp server`) | Claude Desktop, Claude Code, Cursor, Codex, Windsurf, Cortex |
| Runtime proxy (`agent-bom proxy`) | MCP traffic enforcement |
| Shield SDK (`from agent_bom.shield import Shield`) | in-process protection |

Backend choices stay explicit and optional:

- `SQLite` for local and single-node use
- `Postgres` / `Supabase` for the primary transactional control plane
- `ClickHouse` for analytics and event-scale persistence
- `Snowflake` for warehouse-native governance and selected backend paths

Run locally, in CI, in Docker, in Kubernetes, as a self-hosted API + dashboard, or as an MCP server — no mandatory hosted control plane, no mandatory cloud vendor.

References: [PRODUCT_BRIEF.md](docs/PRODUCT_BRIEF.md) · [PRODUCT_METRICS.md](docs/PRODUCT_METRICS.md) · [ENTERPRISE.md](docs/ENTERPRISE.md) · [How agent-bom works](site-docs/architecture/how-agent-bom-works.md).

<details>
<summary><b>CI/CD in 60 seconds</b></summary>

```yaml
- uses: msaad00/agent-bom@v0.81.1
  with:
    scan-type: scan
    severity-threshold: high
    upload-sarif: true
    enrich: true
    fail-on-kev: true
```

Container image gate, IaC gate, air-gapped CI, MCP scan, and the SARIF / SBOM examples are documented in [site-docs/getting-started/quickstart.md](site-docs/getting-started/quickstart.md).

</details>

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

<details>
<summary><b>Install extras + output formats</b></summary>

| Extra | Command |
|-------|---------|
| Cloud providers | `pip install 'agent-bom[cloud]'` |
| MCP server | `pip install 'agent-bom[mcp-server]'` |
| REST API | `pip install 'agent-bom[api]'` |
| Dashboard | `pip install 'agent-bom[ui]'` |
| SAML SSO | `pip install 'agent-bom[saml]'` |

JSON · SARIF · CycloneDX 1.6 (with ML BOM) · SPDX 3.0 · HTML · Graph JSON · Graph HTML · GraphML · Neo4j Cypher · JUnit XML · CSV · Markdown · Mermaid · SVG · Prometheus · Badge · Attack Flow · plain text. OCSF is used for runtime / SIEM event delivery, not as a general report format.

</details>

## Contributing

```bash
git clone https://github.com/msaad00/agent-bom.git && cd agent-bom
pip install -e ".[dev-all]"
pytest && ruff check src/
```

[CONTRIBUTING.md](CONTRIBUTING.md) · [docs/CLI_DEBUG_GUIDE.md](docs/CLI_DEBUG_GUIDE.md) · [SECURITY.md](SECURITY.md) · [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

Apache 2.0 — [LICENSE](LICENSE)
