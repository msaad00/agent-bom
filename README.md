<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/agent-bom/agent-bom/main/docs/images/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/agent-bom/agent-bom/main/docs/images/logo-light.svg" alt="agent-bom" width="480" />
  </picture>
</p>

<p align="center">
  <a href="https://github.com/agent-bom/agent-bom/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/agent-bom/agent-bom/ci.yml?style=flat&logo=github&label=Build" alt="Build"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/v/agent-bom?style=flat&label=Latest%20version" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/agentbom/agent-bom"><img src="https://img.shields.io/docker/pulls/agentbom/agent-bom?style=flat&label=Docker%20pulls" alt="Docker"></a>
  <a href="https://github.com/agent-bom/agent-bom/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat" alt="License"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/agent-bom/agent-bom"><img src="https://api.securityscorecards.dev/projects/github.com/agent-bom/agent-bom/badge" alt="OpenSSF"></a>
  <a href="https://github.com/agent-bom/agent-bom/stargazers"><img src="https://img.shields.io/github/stars/agent-bom/agent-bom?style=flat&logo=github&label=Stars" alt="Stars"></a>
</p>

<p align="center">
  <b>Generate AI Bills of Materials. Scan AI agents and MCP servers for CVEs. Map blast radius. Enterprise remediation with named assets and risk narratives. OWASP LLM Top 10 + MITRE ATLAS + NIST AI RMF.</b>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/agent-bom/agent-bom/main/docs/images/architecture-dark.svg">
    <img src="https://raw.githubusercontent.com/agent-bom/agent-bom/main/docs/images/architecture-light.svg" alt="agent-bom architecture" width="800" style="padding: 20px 0" />
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/agent-bom/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/agent-bom/agent-bom/main/docs/images/blast-radius-light.svg" alt="Blast radius attack surface" width="800" style="padding: 20px 0" />
  </picture>
</p>

---

## Why agent-bom?

<table>
<tr>
<td width="55%" valign="top">

**Not just "this package has a CVE."**

agent-bom answers the question security teams actually need:

> *If this CVE is exploited, which AI agents are compromised, which credentials leak, and which tools can an attacker reach?*

- **AI-BOM generation** — structured inventory of agents, servers, packages, credentials, tools
- **Blast radius analysis** — maps CVEs to agents, credentials, and MCP tools
- **Enterprise remediation** — named assets, impact percentages, risk narratives per fix
- **OWASP LLM Top 10 + MITRE ATLAS + NIST AI RMF** — triple threat framework tagging on every finding
- **AI-powered enrichment** — LLM-generated risk narratives, executive summaries, and threat chains via `--ai-enrich`
- **103-server MCP registry** — risk levels, provenance, tool inventories (incl. OpenClaw)
- **Policy-as-code** — block unverified servers, enforce risk thresholds in CI
- **Read-only** — never writes configs, never runs servers, never stores secrets
- **Works everywhere** — CLI, Docker, REST API, Cloud UI, CI/CD, Prometheus, Kubernetes

</td>
<td width="45%" valign="top">

**What it scans:**

| Source | How |
|--------|-----|
| MCP configs | Auto-discover (9 clients incl. OpenClaw) |
| Docker images | Grype / Syft / Docker CLI |
| Kubernetes | kubectl across namespaces |
| Terraform | Bedrock, Vertex AI, Azure |
| GitHub Actions | AI env vars + SDK steps |
| Python agents | 10 frameworks detected |
| Cloud providers | AWS, Azure, GCP, Databricks, Snowflake, Nebius |
| AI platforms | HuggingFace, W&B, MLflow, OpenAI |
| MCP servers | Runtime introspection via MCP SDK |
| Existing SBOMs | CycloneDX / SPDX import |

**What it outputs:**

Console, HTML dashboard, SARIF, CycloneDX 1.6, SPDX 3.0, Prometheus, OTLP, JSON, REST API

</td>
</tr>
</table>

---

## Quick links

- **[Install](#install)** — `pip install agent-bom` or Docker
- **[Get started](#get-started)** — scan in 30 seconds
- **[AI-BOM export](#ai-bom-export)** — CycloneDX, SPDX, JSON, SARIF, HTML
- **[Remediation plan](#enterprise-remediation-plan)** — named assets, risk narratives
- **[Cloud UI](#cloud-ui)** — enterprise aggregate dashboard
- **[CI integration](#ci-integration)** — GitHub Actions + SARIF upload
- **[REST API](#rest-api)** — FastAPI on port 8422
- **[Skills](skills/)** — downloadable workflow playbooks (AI-BOM, cloud audit, OWASP, incident response)
- **[MCP Registry](data/mcp-registry.yaml)** — 103 known servers with metadata
- **[PERMISSIONS.md](PERMISSIONS.md)** — auditable trust contract
- **[Roadmap](#roadmap)** — what's coming next

---

## Get started

```bash
pip install agent-bom

# Auto-discover and scan local AI agents
agent-bom scan

# HTML dashboard with severity donut + blast radius chart
agent-bom scan -f html -o report.html && open report.html

# CI gate — fail on critical/high CVEs
agent-bom scan --fail-on-severity high -q
```

No config needed. Auto-discovers Claude Desktop, Claude Code, Cursor, Windsurf, Cline, VS Code Copilot, Continue, Zed, Cortex Code, and OpenClaw on macOS, Linux, and Windows.

---

## Install

| Mode | Command |
|------|---------|
| Core CLI | `pip install agent-bom` |
| AWS discovery | `pip install 'agent-bom[aws]'` |
| Databricks | `pip install 'agent-bom[databricks]'` |
| Snowflake | `pip install 'agent-bom[snowflake]'` |
| Nebius GPU cloud | `pip install 'agent-bom[nebius]'` |
| All cloud | `pip install 'agent-bom[cloud]'` |
| REST API | `pip install 'agent-bom[api]'` |
| Dashboard | `pip install 'agent-bom[ui]'` |
| OpenTelemetry | `pip install 'agent-bom[otel]'` |
| Docker | `docker run --rm -v ~/.config:/root/.config:ro agentbom/agent-bom scan` |

---

## Core capabilities

### CVE scanning + blast radius

```bash
agent-bom scan --enrich                    # OSV + NVD CVSS + EPSS + CISA KEV
agent-bom scan --image myapp:latest        # Docker image (all ecosystems via Grype)
agent-bom scan --k8s --all-namespaces      # Every pod in the cluster
agent-bom scan --sbom syft-output.cdx.json # Pipe in existing SBOMs
```

Every vulnerability is mapped to: **which agents** are affected, **which credentials** are exposed, **which MCP tools** an attacker can reach.

### OWASP LLM Top 10 tagging

| Code | Triggered when |
|------|---------------|
| **LLM05** | Any package CVE (always) |
| **LLM06** | Credential env var exposed alongside CVE |
| **LLM08** | Server with >5 tools + CRITICAL/HIGH CVE |
| **LLM02** | Tool with shell/exec semantics |
| **LLM07** | Tool that reads files or prompts |
| **LLM04** | AI framework + HIGH+ CVE |

### MITRE ATLAS threat mapping

Every finding is also mapped to [MITRE ATLAS](https://atlas.mitre.org/) adversarial ML techniques:

| Technique | Triggered when |
|-----------|---------------|
| **AML.T0010** | Any package CVE (always — supply chain compromise) |
| **AML.T0062** | Credentials exposed alongside vulnerability |
| **AML.T0061** | >3 tools reachable through compromised path |
| **AML.T0051** | Tools can access prompts/context (injection surface) |
| **AML.T0056** | Tools can read files (meta prompt extraction) |
| **AML.T0043** | Tools with shell/exec capability (adversarial data) |
| **AML.T0020** | AI framework + HIGH+ CVE (training data poisoning) |
| **AML.T0058** | AI framework + creds + HIGH+ (agent context poisoning) |

### NIST AI RMF compliance mapping

Every finding is also mapped to the [NIST AI Risk Management Framework](https://www.nist.gov/artificial-intelligence/ai-risk-management-framework) (AI RMF 1.0) — covering all four functions:

| Subcategory | Triggered when |
|-------------|---------------|
| **GOVERN-1.7** | Any package CVE (always — third-party component risk) |
| **MAP-3.5** | Any package CVE (always — supply chain risk assessed) |
| **GOVERN-6.1** | Shell/exec tools reachable (third-party assessment) |
| **GOVERN-6.2** | AI framework + creds + HIGH+ (contingency planning) |
| **MAP-1.6** | >3 tools reachable (interface mapping) |
| **MAP-5.2** | Data/file access tools reachable (deployment impact) |
| **MEASURE-2.5** | AI framework + HIGH+ CVE (security testing) |
| **MEASURE-2.9** | Fix available (mitigation effectiveness) |
| **MANAGE-1.3** | CISA KEV finding (documented risk response) |
| **MANAGE-2.2** | Credentials exposed (anomalous event detection) |
| **MANAGE-2.4** | AI framework + creds + HIGH+ (remediation) |
| **MANAGE-4.1** | Credentials + tools exposed (post-deployment monitoring) |

### MCP runtime introspection

Connect to live MCP servers to discover their actual runtime capabilities:

```bash
agent-bom scan --introspect                 # introspect all discovered servers
agent-bom scan --introspect --introspect-timeout 15  # custom timeout per server
```

Introspection is **read-only** — it only calls `tools/list` and `resources/list` (never `tools/call`). It enables:

- **Runtime tool discovery** — see actual tools exposed by running servers
- **Drift detection** — compare config-declared tools vs runtime reality
- **Hidden capability discovery** — find tools not declared in configs
- **Server enrichment** — merge runtime data into the AI-BOM inventory

Requires the MCP SDK: `pip install mcp`

### Threat framework coverage matrix

After every scan, agent-bom shows which OWASP + ATLAS + NIST AI RMF categories were triggered — and how many findings per category:

**CLI** — `print_threat_frameworks()` renders three Rich tables with bar charts:

```
┌───────────── OWASP LLM Top 10 ──────────────┐    ┌─────── NIST AI RMF 1.0 ────────┐
│ LLM05  Supply Chain Vulnerabilities    12 ████│    │ GOVERN-1.7  Third-party risk 12 ████│
│ LLM06  Sensitive Information Disclosure 4 ██  │    │ MAP-3.5     Supply chain    12 ████│
│ LLM08  Excessive Agency                2 █   │    │ MANAGE-2.2  Event detection  4 ██  │
│ LLM01  Prompt Injection                —     │    │ MEASURE-2.5 Security test    2 █   │
│ ...                                          │    │ ...                               │
└──────────────────────────────────────────────┘    └─────────────────────────────────┘
```

**JSON** — `threat_framework_summary` section with per-category counts:

```json
{
  "threat_framework_summary": {
    "owasp_llm_top10": [{"code": "LLM05", "name": "Supply Chain Vulnerabilities", "findings": 12, "triggered": true}],
    "mitre_atlas": [{"technique_id": "AML.T0010", "name": "ML Supply Chain Compromise", "findings": 12, "triggered": true}],
    "nist_ai_rmf": [{"subcategory_id": "MAP-3.5", "name": "AI supply chain risks assessed", "findings": 12, "triggered": true}],
    "total_owasp_triggered": 4,
    "total_atlas_triggered": 5,
    "total_nist_triggered": 6
  }
}
```

**Cloud UI** — three-column threat matrix grid with hit/miss indicators and finding counts per category.

### AI-BOM export

Every scan produces a complete **AI Bill of Materials** — a structured document listing all agents, MCP servers, packages, credentials, tools, and vulnerabilities. Export in any standard format:

```bash
agent-bom scan -f cyclonedx -o ai-bom.cdx.json   # CycloneDX 1.6
agent-bom scan -f spdx -o ai-bom.spdx.json       # SPDX 3.0
agent-bom scan -f json -o ai-bom.json             # Full AI-BOM (document_type: "AI-BOM")
agent-bom scan -f sarif -o results.sarif           # GitHub Security tab
agent-bom scan -f html -o report.html              # Interactive HTML dashboard
```

The JSON output includes `"document_type": "AI-BOM"` and `"spec_version": "1.0"` at the top level for programmatic identification. Console output shows an export hint panel after every scan.

### Enterprise remediation plan

Each remediation tells you exactly **what will be protected** when you fix it:

```
 3. upgrade python 3.11.14 → 3.13.10
    clears 2 vuln(s) • impact score: 14
    agents:       claude-desktop-agent (100%)
    credentials:  YOUTUBE_API_KEY (100%)
    tools:        read_file, execute_command, web_search (3 of 8 — 38%)
    mitigates:    LLM05 LLM06 AML.T0010 AML.T0062
    ⚠ if not fixed: attacker exploiting CVE-2025-1234 can reach
      claude-desktop-agent → YOUTUBE_API_KEY → execute_command
```

- **Named assets** — which specific agents, credentials, and tools are at risk
- **Percentages** — what fraction of your total inventory each fix protects
- **Threat tags** — which OWASP LLM + MITRE ATLAS + NIST AI RMF categories are mitigated
- **Risk narratives** — plain-text explanation of what happens if you don't remediate

### Policy-as-code

```bash
agent-bom scan --policy policy.json --fail-on-severity high
```

```json
[
  {"id": "no-unverified-high", "unverified_server": true, "severity_gte": "HIGH", "action": "fail"},
  {"id": "warn-excessive-agency", "min_tools": 6, "action": "warn"},
  {"id": "block-kev", "severity_gte": "CRITICAL", "action": "fail"}
]
```

### Cloud provider discovery

Discover AI agents directly from cloud provider APIs — no manual inventory files needed. Customer pays for compute; scans run in your environment with your credentials.

```bash
# AWS — Bedrock agents + Lambda + EKS + Step Functions + EC2
agent-bom scan --aws --aws-region us-east-1
agent-bom scan --aws --aws-include-lambda --aws-include-eks --aws-include-step-functions

# Snowflake — Cortex Agents, MCP Servers, Search, Snowpark, Streamlit, query history
agent-bom scan --snowflake

# Databricks — cluster libraries, model serving endpoints
agent-bom scan --databricks

# Nebius — GPU cloud K8s clusters + container services
agent-bom scan --nebius --nebius-project-id my-project

# CoreWeave — K8s-native, use the --k8s flag with your cluster context
agent-bom scan --k8s --context=coreweave-cluster --all-namespaces

# Combine with local scans
agent-bom scan --aws --databricks --snowflake --image myapp:latest --enrich
```

| Provider | What's discovered | Install |
|----------|------------------|---------|
| **AWS** | Bedrock agents, Lambda functions, EKS clusters, Step Functions workflows, EC2 instances, ECS images, SageMaker endpoints | `pip install 'agent-bom[aws]'` |
| **Snowflake** | Cortex Agents, native MCP Servers (with tool specs), Cortex Search Services, Snowpark packages, Streamlit apps, query history audit trail, custom functions/procedures | `pip install 'agent-bom[snowflake]'` |
| **Databricks** | Cluster PyPI/Maven packages, model serving endpoints | `pip install 'agent-bom[databricks]'` |
| **Azure** | AI Foundry agents, Container Apps | `pip install 'agent-bom[azure]'` |
| **GCP** | Vertex AI endpoints, Cloud Run services | `pip install 'agent-bom[gcp]'` |
| **Nebius** | Managed K8s clusters, container services + images | `pip install 'agent-bom[nebius]'` |
| **CoreWeave** | K8s-native — use `--k8s --context=coreweave-cluster` | (core CLI) |

<details>
<summary><b>AWS deep discovery flags</b></summary>

| Flag | Discovers |
|------|-----------|
| `--aws` | Bedrock agents, ECS images, SageMaker endpoints (default) |
| `--aws-include-lambda` | Standalone Lambda functions (filtered by AI runtimes) |
| `--aws-include-eks` | EKS clusters → reuses `--k8s` pod image scanning per cluster |
| `--aws-include-step-functions` | Step Functions workflows → extracts Lambda/SageMaker/Bedrock ARNs |
| `--aws-include-ec2` | EC2 instances (requires `--aws-ec2-tag KEY=VALUE` for safety) |

</details>

<details>
<summary><b>Snowflake deep discovery</b></summary>

Snowflake discovery covers the full Cortex AI stack:

- **Cortex Agents** — `SHOW AGENTS IN ACCOUNT` discovers agentic orchestration systems
- **Native MCP Servers** — `SHOW MCP SERVERS IN ACCOUNT` + `DESCRIBE MCP SERVER` parses YAML tool specs. `SYSTEM_EXECUTE_SQL` tools are flagged as **[HIGH-RISK]**
- **Query History Audit** — scans `INFORMATION_SCHEMA.QUERY_HISTORY()` for `CREATE MCP SERVER` and `CREATE AGENT` statements to catch objects created outside standard flows
- **Custom Tools** — inventories `INFORMATION_SCHEMA.FUNCTIONS` and `INFORMATION_SCHEMA.PROCEDURES` with language annotation (Python/Java/JavaScript) for attack surface analysis
- **Cortex Search + Snowpark + Streamlit** — existing discovery for search services, packages, and apps

</details>

Cloud SDKs are optional extras — install only what you need. Authentication uses each provider's standard credential chain (env vars, config files, IAM roles).

### Graph visualization

Cloud and local agents are visualized as an interactive dependency graph in the HTML dashboard. Provider nodes connect to agents, which connect to servers and packages. CVE nodes are attached to vulnerable packages with severity coloring.

Export the raw graph for use in Cytoscape, Sigma.js, or other tools:

```bash
agent-bom scan --aws -f graph -o agent-graph.json
```

### OpenClaw scanning

[OpenClaw](https://github.com/openclaw/openclaw) (213k+ stars) is the fastest-growing open-source AI agent. agent-bom auto-discovers OpenClaw configs and scans them for vulnerabilities — including 7+ known CVEs (RCE, SSRF, secret leakage) and 800+ malicious skills in ClawHub.

```bash
# Auto-discovers ~/.openclaw/config.json and project-level .openclaw/openclaw.json
agent-bom scan

# Combine with live introspection
agent-bom scan --introspect
```

### AI-powered enrichment

Use LLMs to generate contextual risk analysis beyond template-based output. Supports 100+ LLM providers via [litellm](https://github.com/BerriAI/litellm) — OpenAI, Anthropic, Ollama (local), and more.

```bash
pip install 'agent-bom[ai-enrich]'

# Enrich with GPT-4o-mini (default)
agent-bom scan --ai-enrich

# Use a different model
agent-bom scan --ai-enrich --ai-model anthropic/claude-3-haiku-20240307

# Use local Ollama
agent-bom scan --ai-enrich --ai-model ollama/llama3
```

What `--ai-enrich` generates:
- **Risk narratives** — contextual 2-3 sentence analysis per finding (why this CVE matters in your agent's tool chain)
- **Executive summary** — one-paragraph CISO brief with risk rating and actions
- **Threat chains** — red-team-style attack chain analysis through MCP tools

### MCP Server Registry (103 servers)

Ships with a curated registry of 103 known MCP servers — including OpenClaw and its ecosystem. Each entry includes: package name + version pin, ecosystem, risk level, tool names, credential env vars, license, and source URL.

Unverified servers in your configs trigger a warning. Policy rules can block them in CI.

---

## Deployment models

| Mode | Command | Best for |
|------|---------|----------|
| Developer CLI | `agent-bom scan` | Local audit, pre-commit checks |
| Pre-install check | `agent-bom check express@4.18.2 -e npm` | Before running any MCP server |
| CI/CD gate | `agent-bom scan --fail-on-severity high -q` | Block PRs on critical CVEs |
| Docker | `docker run agentbom/agent-bom scan` | Isolated, reproducible scans |
| REST API | `agent-bom api` | Dashboards, SIEM, scripting |
| Dashboard | `agent-bom serve` | Team-visible security dashboard |
| Prometheus | `--push-gateway` or `--otel-endpoint` | Continuous monitoring |
| K8s CronJob | Helm chart + CronJob | Cluster-wide auditing |

---

## CI integration

```yaml
- name: AI supply chain scan
  run: |
    pip install agent-bom
    agent-bom scan --inventory agents.json --enrich --fail-on-severity high \
      -f sarif -o results.sarif

- name: Upload to GitHub Security tab
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

SARIF output includes OWASP LLM tags in `result.properties` — visible directly in GitHub Advanced Security.

---

## REST API

```bash
pip install agent-bom[api]
agent-bom api   # http://127.0.0.1:8422  →  /docs for Swagger UI
```

| Endpoint | Description |
|----------|-------------|
| `GET /health` | Liveness + `X-Agent-Bom-Read-Only: true` header |
| `POST /v1/scan` | Start async scan (returns `job_id`) |
| `GET /v1/scan/{job_id}` | Poll status + results |
| `GET /v1/scan/{job_id}/stream` | SSE real-time progress |
| `GET /v1/registry` | Full MCP server registry |
| `GET /v1/registry/{id}` | Single registry entry |

---

## Cloud UI

The Next.js dashboard (`ui/`) provides an enterprise-grade web interface on top of the REST API:

- **Security posture dashboard** — fleet-wide severity distribution, scan source breakdown, top vulnerable packages across all scans
- **Vulnerability explorer** — group by severity, package, or agent with full-text search
- **Scan detail** — per-job blast radius table, threat framework matrix, remediation plan with impact bars
- **Severity chart** — stacked bar chart with critical/high/medium/low percentage breakdown
- **Source tracking** — each finding tagged by source (MCP agents, container images, K8s pods, SBOMs)

```bash
cd ui && npm install && npm run dev   # http://localhost:3000
```

Requires the REST API backend running on port 8422.

---

## Skills

Downloadable workflow playbooks in [`skills/`](skills/) — structured instructions for common security workflows. Each skill is a self-contained markdown document with goals, steps, decision points, and output artifacts.

| Skill | What it does |
|-------|-------------|
| [**AI-BOM Generator**](skills/ai-bom-generator.md) | Full asset discovery + scan + enrich + AI Bill of Materials generation across all sources |
| [**Cloud Security Audit**](skills/cloud-security-audit.md) | Multi-cloud AI asset discovery and vulnerability assessment (AWS, Azure, GCP, Snowflake, Databricks, Nebius, CoreWeave) |
| [**OWASP LLM Assessment**](skills/owasp-llm-assessment.md) | Systematic OWASP LLM Top 10 + MITRE ATLAS threat assessment with per-category remediation |
| [**Incident Response**](skills/incident-response.md) | Given a CVE, find all affected agents, map blast radius, triage, and remediate |
| [**Pre-Deploy Gate**](skills/pre-deploy-gate.md) | CI/CD security gate — block deployments with critical CVEs or policy violations |
| [**MCP Server Review**](skills/mcp-server-review.md) | Evaluate an MCP server before adopting — registry lookup, CVE scan, tool risk analysis |
| [**Compliance Export**](skills/compliance-export.md) | Generate audit-ready CycloneDX, SPDX, SARIF with threat framework coverage reports |

---

## AI supply chain coverage

agent-bom covers the AI infrastructure landscape through multiple scanning strategies:

| Layer | How agent-bom covers it | Examples |
|-------|------------------------|----------|
| **GPU clouds** | `--k8s --context=<cluster>` | CoreWeave, Lambda Labs, Paperspace, DGX Cloud |
| **AI platforms** | Cloud provider modules | AWS Bedrock/SageMaker, Azure AI Foundry, GCP Vertex AI, Databricks, Snowflake Cortex, HuggingFace Hub, W&B, MLflow, OpenAI |
| **Container workloads** | `--image` via Grype/Syft | NVIDIA Triton, NIM, vLLM, TGI, Ollama, any OCI image |
| **K8s-native inference** | `--k8s` discovers pods | KServe, Seldon Core, Kubeflow, Ray Serve, BentoML |
| **AI frameworks** | Dependency scanning (PyPI/npm) | LangChain, LlamaIndex, AutoGen, CrewAI, PyTorch, Transformers, NeMo |
| **Vector databases** | `--image` for self-hosted | Weaviate, Qdrant, Milvus, ChromaDB, pgvector |
| **LLM providers** | API key detection + SDK scanning | OpenAI, Anthropic, Cohere, Mistral, Gemini |
| **MCP ecosystem** | Auto-discovery (10 clients) + registry (103 servers) | Claude Desktop, Cursor, Windsurf, Cline, OpenClaw |
| **IaC + CI/CD** | `--tf-dir` and `--gha` | Terraform AI resources, GitHub Actions AI workflows |

---

## agent-bom vs ToolHive

These tools solve different problems and are **complementary**.

| | agent-bom | ToolHive |
|---|---|---|
| **Purpose** | Scan + audit AI supply chain | Deploy + manage MCP servers |
| **CVE scanning** | OSV, NVD, EPSS, CISA KEV, Grype | No |
| **Blast radius** | Agents, credentials, tools | No |
| **OWASP + ATLAS + NIST** | Triple-framework tagging on every finding | No |
| **MCP server isolation** | No (scanner only) | Yes (containers + seccomp) |
| **Secret injection** | No | Yes (Vault, AWS SM) |
| **Read-only** | Yes | No (manages processes) |

**Together:** ToolHive runs your MCP servers securely. agent-bom audits whether the packages they depend on have known CVEs and what the blast radius would be.

---

## Trust & permissions

- **`--dry-run`** — shows every file and API URL that would be accessed, then exits
- **[PERMISSIONS.md](PERMISSIONS.md)** — auditable contract: what is read, what APIs are called, what is never done
- **API headers** — every response includes `X-Agent-Bom-Read-Only: true`
- **Sigstore signing** — releases v0.7.0+ signed via [cosign](https://www.sigstore.dev/)
- **Credential redaction** — only env var **names** appear in reports as `***REDACTED***`

---

## Roadmap

- [x] MITRE ATLAS adversarial ML threat mapping
- [x] SLSA provenance + SHA256 integrity verification
- [x] Threat framework coverage matrix (CLI + JSON + UI)
- [x] Enterprise remediation plan with named assets + risk narratives
- [x] Enterprise aggregate dashboard (Cloud UI)
- [x] AI-BOM export identity (CycloneDX, SPDX, JSON, SARIF)
- [x] Cloud provider discovery (AWS, Azure, GCP, Databricks, Snowflake, Nebius, CoreWeave)
- [x] Deep cloud scanning — Snowflake Cortex Agents/MCP Servers, AWS Lambda/EKS/Step Functions/EC2
- [x] Graph visualization (provider → agent → server → package → CVE)
- [x] Security skills — downloadable workflow playbooks for AI-BOM, cloud audit, OWASP, incident response
- [x] AI platform discovery — HuggingFace Hub, Weights & Biases, MLflow, OpenAI
- [x] NIST AI RMF compliance mapping (Govern, Map, Measure, Manage)
- [x] MCP runtime introspection — connect to live servers for tool/resource discovery + drift detection
- [x] OpenClaw discovery — auto-scan OpenClaw configs, 7+ known CVEs, ClawHub malicious skill detection
- [x] AI-powered enrichment — LLM-generated risk narratives, executive summaries, and threat chains via litellm
- [ ] Jupyter notebook AI library scanning
- [ ] ToolHive integration (`--toolhive` flag for managed server scanning)
- [ ] License compliance engine (SPDX license detection + copyleft chain analysis)

---

## Contributing

```bash
git clone https://github.com/agent-bom/agent-bom.git && cd agent-bom
pip install -e ".[dev]"
pytest && ruff check src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) | [SECURITY.md](SECURITY.md)

---

Apache 2.0 — [LICENSE](LICENSE)

<!-- Badge reference links -->
[release-img]: https://img.shields.io/pypi/v/agent-bom?style=flat&label=Latest%20version
[ci-img]: https://img.shields.io/github/actions/workflow/status/agent-bom/agent-bom/ci.yml?style=flat&logo=github&label=Build
[license-img]: https://img.shields.io/badge/License-Apache%202.0-blue?style=flat
[docker-img]: https://img.shields.io/docker/pulls/agentbom/agent-bom?style=flat&label=Docker%20pulls
[stars-img]: https://img.shields.io/github/stars/agent-bom/agent-bom?style=flat&logo=github&label=Stars
[ossf-img]: https://api.securityscorecards.dev/projects/github.com/agent-bom/agent-bom/badge
