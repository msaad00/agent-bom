<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-light.svg" alt="agent-bom" width="480" />
  </picture>
</p>

<p align="center">
  <a href="https://github.com/msaad00/agent-bom/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/msaad00/agent-bom/ci.yml?style=flat&logo=github&label=Build" alt="Build"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/v/agent-bom?style=flat&label=Latest%20version" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/agentbom/agent-bom"><img src="https://img.shields.io/docker/pulls/agentbom/agent-bom?style=flat&label=Docker%20pulls" alt="Docker"></a>
  <a href="https://github.com/msaad00/agent-bom/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat" alt="License"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom"><img src="https://api.securityscorecards.dev/projects/github.com/msaad00/agent-bom/badge" alt="OpenSSF"></a>
  <a href="https://www.bestpractices.dev/projects/12114"><img src="https://www.bestpractices.dev/projects/12114/badge" alt="OpenSSF Best Practices"></a>
<a href="https://github.com/msaad00/agent-bom/stargazers"><img src="https://img.shields.io/github/stars/msaad00/agent-bom?style=flat&logo=github&label=Stars" alt="Stars"></a>
  <a href="https://github.com/msaad00/agent-bom/discussions"><img src="https://img.shields.io/github/discussions/msaad00/agent-bom?style=flat&logo=github&label=Discussions" alt="Discussions"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center">
  <b>Security scanner for AI infrastructure and supply chain.</b><br>
  Discover → Scan → Analyze → Enforce — AI BOM generation, CVEs, blast radius, runtime proxy, 14 compliance frameworks.
</p>

---

## Quick start

```bash
pip install agent-bom
agent-bom scan                     # auto-detect MCP agents + scan for CVEs
agent-bom check flask@2.0.0       # pre-install CVE gate
```

<details>
<summary><b>Focused commands</b></summary>

```bash
# MCP agents
agent-bom mcp                     # discover + scan MCP agents
agent-bom mcp inventory           # discover only, no CVE scan

# Container & filesystem
agent-bom image nginx:latest      # container image scan
agent-bom fs /mnt/vm-snapshot     # filesystem / VM disk snapshot
agent-bom sbom vendor-bom.json    # ingest existing SBOM

# Infrastructure
agent-bom iac Dockerfile k8s/     # misconfig scanning (82 rules)
agent-bom cloud aws               # AWS posture + CIS benchmark (60 checks)

# Runtime & CI/CD
agent-bom proxy "npx server"      # MCP traffic enforcement
agent-bom scan --fail-on-severity critical -f sarif -o results.sarif
```

</details>

Discovers 22 MCP client types, resolves server dependencies, scans against OSV/NVD/GHSA, and maps blast radius — which agents, credentials, and tools each CVE affects.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-v0.71.0.gif" alt="agent-bom demo — pre-install CVE check, full scan with blast radius analysis, SARIF export, runtime proxy, 32 MCP tools" width="900" />
</p>

<p align="center">
  <picture>
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-output-dark.svg" alt="agent-bom scan output with GPU infrastructure scan" width="800" />
  </picture>
</p>

---

## Why agent-bom?

> **Traditional scanners tell you a package has a CVE.**
> **agent-bom tells you which AI agents are compromised, which credentials leak, which tools an attacker reaches — and then blocks it in real time.**

Four capabilities, one tool:

1. **Scan** — discover AI agents, MCP servers, cloud services, model files, GPU resources. Generate an AI BOM. Check every dependency against OSV + NVD + GHSA + EPSS + CISA KEV.
2. **Analyze** — blast radius mapping (CVE → package → server → agent → credentials → tools), credential exposure, posture scoring, 14-framework compliance
3. **Enforce** — runtime MCP proxy with 7 behavioral detectors (rug pull, injection, credential leak, exfil, cloaking, rate limiting, vector DB injection), policy-as-code
4. **Trust** — audit CLAUDE.md, .cursorrules, AGENTS.md, SKILL.md for malicious patterns, typosquatting, and Sigstore provenance

Read-only. Agentless. Open source.

```
CVE-2025-1234  (CRITICAL . CVSS 9.8 . CISA KEV)
  |-- better-sqlite3@9.0.0  (npm)
       |-- sqlite-mcp  (MCP Server . unverified . root)
            |-- Cursor IDE  (Agent . 4 servers . 12 tools)
            |-- ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            |-- query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 -> 11.7.0
```

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="Blast Radius" width="800" />
  </picture>
</p>

---

## MCP server

32 tools available to any MCP-compatible AI assistant.

```bash
pip install 'agent-bom[mcp-server]'
agent-bom mcp-server
```

Add to your MCP client config (Claude Desktop, Cursor, etc.):

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "agent-bom",
      "args": ["mcp-server"]
    }
  }
}
```

Also available on [Glama](https://glama.ai/mcp/servers/@msaad00/agent-bom), [Smithery](integrations/smithery.yaml), [MCP Registry](integrations/mcp-registry/server.json), and [OpenClaw](integrations/openclaw/SKILL.md).

---

## Docker

```bash
docker run --rm -v ~/.config:/root/.config:ro agentbom/agent-bom scan
docker run --rm agentbom/agent-bom scan --image nginx:latest
docker run --rm agentbom/agent-bom mcp-server   # MCP server mode
```

---

## Instruction file trust

AI agents run on instruction files — CLAUDE.md, .cursorrules, AGENTS.md, SKILL.md. A malicious or compromised instruction file is a supply chain attack that executes with full agent permissions. agent-bom audits every instruction file it finds.

```
agent-bom scan --skill-only

CLAUDE.md  →  SUSPICIOUS (high confidence)
  [CRITICAL] Credential/secret file access
             "cat ~/.aws/credentials" detected — reads secret files
  [HIGH]     Safety confirmation bypass
             "--dangerously-skip-permissions" found — disables all guardrails
  [HIGH]     Typosquatting risk: server name "filessystem" (→ filesystem)
  [MEDIUM]   External URL in instructions: https://malicious-cdn.com/hook.js

  Trust categories
    Purpose & Capability  WARN  — description vs. actual tool mismatch
    Instruction Scope     FAIL  — file reads outside home directory
    Install Mechanism     FAIL  — unverified install source, no Sigstore sig
    Credentials           WARN  — 3 env vars undocumented
    Persistence/Privilege PASS  — no persistence, no privilege escalation
```

Five trust categories, 17 behavioral risk patterns, Sigstore signature verification. No network calls — fully local static analysis.

---

## How it works

1. **Discover** -- auto-detect MCP configs, Docker images, K8s pods, cloud resources, model files
2. **Scan** -- send package names + versions to public APIs (OSV.dev, NVD, EPSS, CISA KEV). No secrets leave your machine.
3. **Analyze** -- blast radius mapping, tool poisoning detection, compliance tagging, posture scoring
4. **Track** -- persistent asset database records first_seen, last_seen, resolved status, and MTTR per vulnerability across scans
5. **Report** -- 17 output formats: JSON, SARIF, CycloneDX 1.6, SPDX 3.0, HTML, JUnit XML, CSV, Markdown, Mermaid, SVG, Prometheus, and more. Alert dispatch to Slack/webhooks.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-light.svg" alt="Scan pipeline" width="800" />
  </picture>
</p>

**Read-only guarantee.** Never writes configs, never runs servers, never stores secrets. `--dry-run` previews everything. Every release is [Sigstore-signed](docs/PERMISSIONS.md).

---

## CLI reference

<details>
<summary><b>Scan commands</b></summary>

```bash
# Auto-detect — discovers MCP agents, packages, IaC, and scans everything
agent-bom scan                              # full auto-detect scan
agent-bom scan --enrich                     # + NVD CVSS + EPSS + CISA KEV
agent-bom scan -f html -o report.html       # HTML interactive report
agent-bom scan --fail-on-severity high -q   # CI/CD gate

# Focused commands — fast, specific, fewer flags
agent-bom image nginx:latest                # container image scan
agent-bom fs /mnt/vm-snapshot               # filesystem / VM disk snapshot
agent-bom fs . --offline                    # scan current directory (offline)
agent-bom iac Dockerfile k8s/ infra/        # IaC misconfigurations (82 rules)
agent-bom sbom vendor-bom.json              # ingest CycloneDX/SPDX SBOM
agent-bom scan --os-packages                # scan host OS packages (dpkg/rpm/apk)
agent-bom check flask@2.0.0                 # pre-install CVE gate
```

</details>

<details>
<summary><b>MCP commands</b></summary>

```bash
agent-bom mcp                               # discover + scan MCP agents
agent-bom mcp inventory                      # discover agents/servers (no CVE scan)
agent-bom mcp introspect --all               # live server tool listing
agent-bom mcp registry                       # browse MCP server security registry
agent-bom mcp where                          # show config file locations
agent-bom mcp server                         # start agent-bom as MCP server
```

</details>

<details>
<summary><b>Cloud commands</b></summary>

Requires cloud provider credentials (aws/az/gcloud CLI configured).

```bash
agent-bom cloud aws                          # AWS posture + CIS v3.0 (60 checks)
agent-bom cloud azure                        # Azure posture + CIS v2.0 (95 checks)
agent-bom cloud gcp                          # GCP posture + CIS v3.0 (59 checks)
agent-bom cloud                              # scan all configured providers
```

</details>

<details>
<summary><b>Runtime enforcement</b></summary>

Sit between your MCP client and server, enforce policy in real time:

```bash
# Launch MCP server through the runtime proxy — zero-config
agent-bom run "npx/@modelcontextprotocol/server-filesystem /tmp"
agent-bom run "uvx/mcp-server-git" --policy policy.yml
agent-bom run "ghcr.io/owner/mcp-server:latest"

# Intercept every tool call — 7 detectors active
agent-bom proxy "uvx mcp-server-filesystem /" --policy policy.yml

# Standalone protection engine
agent-bom protect --mode http

# Watch MCP configs for drift
agent-bom watch --webhook https://hooks.slack.com/...

# Introspect live servers — list tools, detect drift
agent-bom mcp introspect --all
agent-bom mcp introspect --all --baseline baseline.json

# Policy file — 17 conditions, zero code required
# policy.yml:
#   block_tools: [run_shell, exec_command]
#   require_agent_identity: true
#   rate_limit: {threshold: 50, window_seconds: 60}
```

</details>

Auto-discovers 22 MCP client types: Claude Desktop, Claude Code, Cursor, Windsurf, Cline, VS Code Copilot, Continue, Zed, Cortex Code, Codex CLI, Gemini CLI, Goose, Snowflake CLI, OpenClaw, Roo Code, Amazon Q, ToolHive, Docker MCP Toolkit, JetBrains AI, Junie, Copilot CLI, Tabnine, and custom paths.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/topology-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/topology-light.svg" alt="MCP Topology" width="800" />
  </picture>
</p>

---

## What it covers

<details>
<summary><b>Key capabilities</b></summary>

| Capability | Details |
|---|---|
| **CVE scanning** | OSV + NVD + GHSA + EPSS + CISA KEV, 11 ecosystems, severity on basic scan |
| **AI agent discovery** | 22 MCP client types + Docker + K8s + running processes |
| **Blast radius mapping** | CVE → package → server → agent → credentials → tools |
| **Runtime proxy** | 7 behavioral detectors, policy-as-code, per-tool rate limiting |
| **IaC scanning** | 82 rules across Dockerfile, K8s, Terraform, CloudFormation |
| **Cloud posture** | AWS (60), Azure (95), GCP (59) CIS benchmark checks |
| **Compliance** | 14 frameworks (OWASP, NIST, MITRE, CIS, ISO, SOC 2, CMMC, EU AI Act) |
| **Instruction file trust** | CLAUDE.md/.cursorrules — 17 patterns, typosquat, Sigstore |
| **AI platform discovery** | HuggingFace, OpenAI, Ollama, W&B, MLflow |
| **Output formats** | 17 formats (JSON, SARIF, HTML, CycloneDX, SPDX, JUnit, CSV, ...) |

</details>

<details>
<summary><b>What it scans — full coverage</b></summary>

| Capability | Details |
|---|---|
| **AI agent discovery** | 22 MCP client types + Docker Compose + running processes + containers + K8s pods/CRDs |
| **GPU/ML package scanning** | NVIDIA CSAF advisories for CUDA, cuDNN, PyTorch, TensorFlow, JAX, vLLM + AMD ROCm via OSV |
| **AI supply chain** | Model provenance (pickle risk, digest, gating), HuggingFace Hub, Ollama, MLflow, W&B |
| **AI cloud inventory** | Coreweave, Nebius, Snowflake, Databricks, OpenAI, HuggingFace Hub — config discovery + CVE tagging |
| **Blast radius mapping** | CVE → package → server → agent → credentials → tools |
| **Credential exposure** | Which secrets leak per vulnerability, per agent |
| **Tool poisoning detection** | Description injection, capability combos, drift detection |
| **Privilege detection** | root, shell access, privileged containers, per-tool permissions |
| **14-framework compliance** | OWASP LLM + MCP + Agentic + AISVS v1.0, MITRE ATLAS, NIST AI RMF + CSF + 800-53, FedRAMP, EU AI Act, SOC 2, ISO 27001, CIS |
| **MITRE ATT&CK mapping** | Dynamic technique lookup by tactic phase (no hardcoded T-codes) |
| **Posture scorecard** | Letter grade (A-F), 6 dimensions, incident correlation (P1-P4) |
| **Policy-as-code + Jira** | 17 conditions, CI gate, auto-create Jira tickets for violations |
| **SIEM push** | Splunk HEC, Datadog Logs, Elasticsearch — raw or OCSF format |
| **Server health checks** | Lightweight liveness probe — reachable, tool count, latency, protocol |
| **Lateral movement analysis** | Agent context graph, shared credentials, BFS attack paths |
| **427+ server MCP registry** | Risk levels, tool inventories, auto-synced weekly |
| **Cloud vector DB scanning** | Pinecone index inventory, risk flags, replica counts via API key |
| **Dependency graph export** | DOT, Mermaid, JSON — agent → server → package → CVE graph |
| **OIDC/SSO authentication** | JWT verification (Okta, Google, Azure AD, Auth0) for REST API |
| **Instruction file trust** | SKILL.md/CLAUDE.md/.cursorrules — 17 behavioral patterns, typosquat detection, Sigstore provenance verification |
| **Browser extension scanning** | Chrome/Edge/Firefox manifest.json — nativeMessaging, dangerous permissions, AI assistant domain access |
| **Persistent asset tracking** | SQLite DB — first_seen/last_seen/resolved/reopened per vulnerability, MTTR calculation, scan-over-scan diff |

</details>

<details>
<summary><b>What it scans</b></summary>

| Source | How |
|--------|-----|
| MCP configs | Auto-discover (22 clients + Docker Compose) |
| Docker images | Grype / Syft / Docker CLI fallback |
| Kubernetes | kubectl across namespaces |
| Cloud providers | AWS, Azure, GCP, Databricks, Snowflake, Coreweave, Nebius |
| AI cloud services | OpenAI, HuggingFace Hub, W&B, MLflow, Ollama |
| GPU/ML packages | PyTorch, TF, JAX, vLLM, CUDA toolkit, cuDNN, TensorRT, ROCm |
| Terraform / GitHub Actions | AI resources + env vars |
| Jupyter notebooks | AI library imports + model refs |
| Model files | 13 formats (.gguf, .safetensors, .pkl, ...) |
| Skill files | CLAUDE.md, .cursorrules, AGENTS.md — behavioral audit, typosquat detection, Sigstore trust verification |
| Browser extensions | Chrome, Brave, Edge, Firefox — dangerous permission detection (nativeMessaging, cookies, AI host access) |
| Existing SBOMs | CycloneDX / SPDX import |

</details>

<details>
<summary><b>What it outputs — 17 formats</b></summary>

| Format | Flag | Use case |
|--------|------|----------|
| Console (default) | — | Rich terminal output with color-coded severity |
| Console (verbose) | `--verbose` | Full output: agent tree, severity chart, attack flow, frameworks |
| JSON | `-f json` | Programmatic consumption, dashboards |
| HTML | `-f html` | Shareable interactive dashboard — no server required |
| SARIF 2.1.0 | `-f sarif` | GitHub Code Scanning inline annotations |
| CycloneDX 1.6 | `-f cyclonedx` | Industry-standard SBOM, OWASP Dependency-Track |
| SPDX 3.0 | `-f spdx` | SPDX-compatible AI BOM with AI extensions |
| JUnit XML | `-f junit` | CI/CD integration (Jenkins, GitLab CI, Azure DevOps) |
| CSV | `-f csv` | Spreadsheet import, SIEM ingestion |
| Markdown | `-f markdown` | PR comments, wiki pages, issue bodies |
| Mermaid | `-f mermaid` | Supply chain / attack flow / lifecycle diagrams |
| SVG | `-f svg` | Embeddable vector diagrams |
| Graph JSON | `-f graph` | Cytoscape.js-compatible element list |
| Graph HTML | `-f graph-html` | Interactive graph viewer — open in browser |
| Prometheus | `-f prometheus` | Metrics scraping, Pushgateway, OTLP export |
| Badge | `-f badge` | Shields.io endpoint JSON |

```bash
agent-bom scan -f cyclonedx -o ai-bom.cdx.json   # CycloneDX 1.6
agent-bom scan -f sarif -o results.sarif           # GitHub Security tab
agent-bom scan -f html -o report.html              # Interactive dashboard
agent-bom scan -f junit -o results.xml             # JUnit for CI/CD
agent-bom scan -f csv -o findings.csv              # Spreadsheet/SIEM
agent-bom scan -f markdown -o report.md            # PR comments
agent-bom scan -o -                                # Pipe any format to stdout
```

</details>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/compliance-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/compliance-light.svg" alt="Compliance coverage" width="800" />
  </picture>
</p>

---

## Deployment

| Mode | Command | Best for |
|------|---------|----------|
| CLI | `agent-bom scan` | Local audit |
| GitHub Action | `uses: msaad00/agent-bom@v0.71.3 | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom scan` | Isolated scans (linux/amd64, linux/arm64) |
| REST API | `agent-bom api` | Dashboards, SIEM |
| MCP Server | `agent-bom mcp-server` (32 tools) | Inside any MCP client |
| Dashboard | `agent-bom serve` · [Full deploy guide](docs/DEPLOYMENT.md) | API + Next.js UI (15 pages) · Postgres/Supabase |
| Runtime proxy | `agent-bom proxy` | Intercept + enforce MCP traffic in real time |
| Protect engine | `agent-bom protect` | 7 behavioral detectors (rug pull, injection, credential leak, exfil sequences, response cloaking, rate limiting, vector DB injection) |
| Config watcher | `agent-bom watch` | Filesystem watch on MCP configs, alert on drift |
| Pre-install guard | `agent-bom guard pip install <pkg>` | Block vulnerable installs |

<details>
<summary><b>Install extras</b></summary>

| Mode | Command |
|------|---------|
| Core CLI | `pip install agent-bom` |
| Cloud (all) | `pip install 'agent-bom[cloud]'` |
| REST API | `pip install 'agent-bom[api]'` |
| MCP server | `pip install 'agent-bom[mcp-server]'` |
| OIDC/SSO auth | `pip install 'agent-bom[oidc]'` |
| Dashboard | `pip install 'agent-bom[ui]'` |
| Docker | `docker run --rm -v ~/.config:/root/.config:ro agentbom/agent-bom scan` |

</details>

<details>
<summary><b>GitHub Action</b></summary>

```yaml
- uses: msaad00/agent-bom@v0.71.3
  with:
    severity-threshold: high
    upload-sarif: true
    enrich: true
    fail-on-kev: true
```

</details>

<details>
<summary><b>REST API</b></summary>

```bash
pip install agent-bom[api]
agent-bom api --api-key $SECRET --rate-limit 30   # http://127.0.0.1:8422/docs
```

| Endpoint | Description |
|----------|-------------|
| `POST /v1/scan` | Start async scan |
| `GET /v1/scan/{id}` | Results + status |
| `GET /v1/scan/{id}/attack-flow` | Per-CVE blast radius graph |
| `GET /v1/registry` | 427+ server registry |
| `GET /v1/compliance` | Full 14-framework compliance posture |
| `GET /v1/posture` | Enterprise posture scorecard (A-F) |
| `GET /v1/posture/credentials` | Credential risk ranking |
| `GET /v1/posture/incidents` | Incident correlation (P1-P4) |
| `POST /v1/traces` | OpenTelemetry trace ingestion |
| `GET /v1/scan/{id}/context-graph` | Lateral movement paths |
| `GET /v1/malicious/check` | Malicious package check |
| `GET /v1/proxy/status` | Live proxy metrics (tool calls, blocked, latency p95) |
| `GET /v1/proxy/alerts` | Runtime behavioral alerts from audit log |
| `GET /v1/audit` | Query JSONL audit trail (HMAC integrity verified) |
| `WS /ws/proxy/metrics` | Live metrics push every second (tool_calls, blocked, latency_p95) |
| `GET /v1/assets` | Persistent vulnerability asset inventory (first_seen, resolved, MTTR) |
| `GET /v1/assets/stats` | Aggregate asset statistics — open/resolved/critical counts |
| `WS /ws/proxy/alerts` | Real-time alert stream — new alerts arrive as they happen |

</details>

<details>
<summary><b>Pre-install guard</b></summary>

Scan packages against OSV and NVD **before** they are installed. Blocks installs when critical/high CVEs are found.

```bash
agent-bom guard pip install requests flask   # scan then install
agent-bom guard npm install express          # same for npm

# Shell alias — intercept every install automatically
alias pip='agent-bom guard pip'
alias npm='agent-bom guard npm'
```

Options:
- `--min-severity` — minimum severity to block (`critical`, `high`, `medium`; default: `high`)
- `--allow-risky` — warn but proceed instead of blocking

</details>

<details>
<summary><b>Cloud + AI platforms</b></summary>

**Cloud infrastructure** (requires credentials):

| Provider | What it scans | CIS checks |
|----------|--------------|------------|
| **AWS** | Bedrock, Lambda, ECS, EKS, SageMaker | 60 checks (v3.0) |
| **Azure** | AI Foundry, Container Apps, Functions | 95 checks (v2.0) |
| **GCP** | Vertex AI, Cloud Run, GKE | 59 checks (v3.0) |

**AI platform discovery** (API key based):

| Platform | What it discovers |
|----------|------------------|
| **HuggingFace** | Models, spaces, inference endpoints, provenance |
| **OpenAI** | Assistants, fine-tuned models, files |
| **Ollama** | Locally downloaded models (zero config) |
| **W&B** | Runs, artifacts, model registry |
| **MLflow** | Models, experiments, deployments |

**MCP scanning** (zero config):
- Snowflake Cortex Code (CoCo) — via MCP discovery, no Snowflake credentials needed

</details>

<details>
<summary><b>Docker platform support</b></summary>

Docker images are published for **linux/amd64** and **linux/arm64**. Both architectures are validated in CI on every PR.

| Platform | Method | Notes |
|----------|--------|-------|
| Linux x64 / arm64 | Docker | Native support |
| macOS (Intel / Apple Silicon) | Docker Desktop | Runs Linux containers via virtualization |
| Windows x64 | Docker Desktop (WSL 2) | Runs Linux containers; mount `%APPDATA%` paths for MCP config discovery |
| Windows Server | Python CLI | `pip install agent-bom` -- no Docker Desktop required |

Windows-specific volume mount examples and GPU scanning notes: [docs/WINDOWS_CONTAINERS.md](docs/WINDOWS_CONTAINERS.md)

</details>

<details>
<summary><b>Upgrade / Uninstall</b></summary>

```bash
pip install --upgrade agent-bom          # upgrade
pip uninstall agent-bom                  # uninstall
rm -rf ~/.agent-bom                      # remove local data
```

</details>

---

## Ecosystem

| Platform | Link |
|----------|------|
| PyPI | `pip install agent-bom` |
| Docker | `docker run agentbom/agent-bom scan` |
| GitHub Action | `uses: msaad00/agent-bom@v0.71.3 |
| Glama | [glama.ai/mcp/servers/@msaad00/agent-bom](https://glama.ai/mcp/servers/@msaad00/agent-bom) |
| MCP Registry | [server.json](integrations/mcp-registry/server.json) |
| OpenClaw | [SKILL.md](integrations/openclaw/SKILL.md) |
| Smithery | [smithery.yaml](integrations/smithery.yaml) |
| Railway | [Dockerfile.sse](deploy/docker/Dockerfile.sse) |

---

## Architecture

<details>
<summary><b>Architecture stack</b></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-stack-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-stack-light.svg" alt="Architecture stack" width="800" />
  </picture>
</p>

</details>

<details>
<summary><b>Engine internals</b></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/engine-internals-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/engine-internals-light.svg" alt="Engine internals" width="800" />
  </picture>
</p>

</details>

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full diagrams: data flow pipeline, blast radius propagation, compliance framework mapping, integration architecture, and deployment topology.

**New to MCP security?** [docs/MCP_SECURITY_MODEL.md](docs/MCP_SECURITY_MODEL.md) explains the MCP ecosystem, where attacks happen (supply chain, tool poisoning, rug pull, credential exfil, instruction file compromise), and exactly how agent-bom's scanner, proxy, and MCP server each address them.

---

## Trust & transparency

**What data leaves your machine?**

| When | What's sent | Where | Opt out |
|---|---|---|---|
| `agent-bom scan` | Package names + versions only | OSV API | `--offline` |
| `--enrich` | CVE IDs only | NVD, EPSS, KEV APIs | Don't use `--enrich` |
| `agent-bom upgrade --check` | Nothing (reads PyPI JSON) | PyPI | `--no-update-check` |
| Everything else | **Nothing** | Nowhere | N/A |

**No source code, no secrets, no telemetry, no analytics ever leave your machine.**

**Security guarantees:**

- **Agentless / read-only** -- never writes configs, runs servers, provisions resources, or stores secrets
- **No telemetry** -- zero analytics, zero phone-home, zero tracking
- **Ephemeral credentials** -- cloud provider keys used only during scan, never persisted to disk
- **Credential redaction** -- only env var **names** in reports; values never read or logged
- **No shell injection** -- subprocess uses `asyncio.create_subprocess_exec`; command + args validated before every spawn
- **No SSRF** -- all outbound URLs hardcoded or validated; DNS rebinding defense blocks private/loopback/cloud-metadata ranges
- **No path traversal** -- `validate_path(restrict_to_home=True)` on all user-supplied paths; MCP tool inputs sanitized
- **No SQL injection** -- all database queries use parameterized statements
- **Proxy MITM-safe** -- size guard (10 MB), rate limiting, credential leak detection, audit trail
- **Audit integrity** -- JSONL audit logs stored at `0600`, HMAC-signed (SHA-256)
- **API security** -- scrypt KDF for API keys, RBAC (admin/analyst/viewer), OIDC/JWT (RS256/ES256, `none` algorithm rejected)
- **`--dry-run`** -- preview every file and API URL before access

**Supply chain integrity:**

- **Sigstore signed** -- releases v0.7.0+ signed via cosign OIDC
- **SLSA provenance** -- build provenance attestation on every release
- **Self-scanning** -- CI scans agent-bom's own dependencies before every release
- **OpenSSF Scorecard** -- [automated supply chain scoring](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom)
- **OpenSSF Best Practices** -- [Silver badge (100%)](https://www.bestpractices.dev/projects/12114)
- **Continuous fuzzing** -- [ClusterFuzzLite](https://github.com/msaad00/agent-bom/blob/main/.github/workflows/cflite-pr.yml) fuzzes SBOM parsers, policy evaluator, and skill parser
- **[PERMISSIONS.md](docs/PERMISSIONS.md)** -- full auditable trust contract
- **[SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md)** -- enterprise security design documentation

---

<details>
<summary><b>Roadmap</b></summary>

**GPU / AI compute**
- [x] GPU container discovery (Docker — NVIDIA images, CUDA labels, `--gpus` runtime)
- [x] Kubernetes GPU node inventory (nvidia.com/gpu capacity/allocatable, CUDA driver labels)
- [x] Unauthenticated DCGM exporter detection (port 9400 metrics leak)
- [ ] Remote Docker host scanning (currently local daemon only)
- [ ] NVIDIA GPU CVE feed — CUDA/cuDNN specific advisories beyond OSV
- [ ] GPU utilization and memory anomaly detection

**AI supply chain**
- [x] OSV + GHSA + NVD + EPSS + CISA KEV vulnerability enrichment
- [x] ML model file scanning (.gguf, .safetensors, .onnx) + SHA-256 + Sigstore
- [x] HuggingFace model provenance and dataset card scanning
- [ ] Dataset poisoning detection
- [ ] Training pipeline scanning (MLflow DAGs, Kubeflow pipelines)
- [ ] Model card authenticity verification (beyond hash/sigstore)

**Asset tracking / posture**
- [x] Persistent SQLite asset database — first_seen, last_seen, resolved, reopened per vulnerability
- [x] MTTR (Mean Time To Remediate) calculation across scans
- [x] Scan-over-scan diff — new, resolved, reopened, unchanged counts
- [x] REST API: `/v1/assets` + `/v1/assets/stats` for dashboard integration
- [ ] SLA enforcement — time-to-fix deadlines per severity (critical < 7d, high < 30d)
- [ ] Trend analytics — vulnerability count over time, resolution velocity

**Agents / MCP**
- [x] 22 MCP client config discovery paths, live introspection, tool drift detection
- [x] Runtime proxy with 7 behavioral detectors (rug pull, injection, credential leak, exfil sequences, response cloaking, rate limiting, vector DB injection) + semantic injection scoring
- [x] Semantic injection scoring — weighted 10-signal model, 0.0–1.0 risk score, MEDIUM/HIGH alerts
- [ ] Agent memory / vector store content scanning for injected instructions
- [ ] LLM API call tracing (which model was called, with what context)

**Identity / access**
- [x] OIDC/JWT auth for REST API (Okta, Google Workspace, Azure AD, Auth0, GitHub OIDC)
- [x] Agent-level identity — JWT/opaque token in `_meta.agent_identity`, tracked on every audit log entry, `require_agent_identity` policy enforcement
- [ ] MCP server identity attestation — cryptographic proof of server identity at runtime
- [ ] Agent-to-agent permission boundary enforcement

**Compliance / standards**
- [x] 14 frameworks: OWASP LLM, OWASP MCP, OWASP Agentic, OWASP AISVS v1.0, ATLAS, NIST AI RMF, NIST CSF, NIST 800-53, FedRAMP, EU AI Act, ISO 27001, SOC 2, CIS Controls, CMMC 2.0
- [ ] CIS AI benchmarks (pending CIS publication)
- [ ] License compliance engine (OSS license risk flagging)
- [ ] Workflow engine scanning (n8n, Zapier, Make)

**Ecosystem coverage (11 ecosystems)**
- [x] Python (requirements.txt, Pipfile.lock, poetry.lock, pip-compile)
- [x] Node.js (package-lock.json, yarn.lock, pnpm-lock.yaml)
- [x] Go (go.sum)
- [x] Rust (Cargo.lock)
- [x] Java (pom.xml, gradle.lockfile)
- [x] .NET (*.deps.json, packages.lock.json)
- [x] Ruby (Gemfile.lock + Gemfile) — v0.70.8
- [x] Conda (environment.yml, conda-lock.yml)
- [x] PHP (composer.lock) — v0.71.0
- [x] Swift (Package.resolved v2/v3) — v0.71.0
- [x] MCP (claude_desktop_config.json, mcp.json)
- [x] Windows platform docs + Docker Desktop guidance ([WINDOWS_CONTAINERS.md](docs/WINDOWS_CONTAINERS.md))
- [ ] Windows-native container images (nanoserver/servercore)

See the full list of [shipped features](https://github.com/msaad00/agent-bom/releases).

</details>

---

## Contributing

```bash
git clone https://github.com/msaad00/agent-bom.git && cd agent-bom
pip install -e ".[dev]"
pytest && ruff check src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) | [SECURITY.md](SECURITY.md) | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | [GOVERNANCE.md](docs/GOVERNANCE.md) | [ROADMAP.md](docs/ROADMAP.md) | [THREAT_MODEL.md](docs/THREAT_MODEL.md)

---

Apache 2.0 -- [LICENSE](LICENSE)
