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
  <a href="https://github.com/msaad00/agent-bom/stargazers"><img src="https://img.shields.io/github/stars/msaad00/agent-bom?style=flat&logo=github&label=Stars" alt="Stars"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center">
  <b>Open-source security scanner for AI agent infrastructure.<br>Discover configurations, scan dependencies, map blast radius, enforce compliance.</b>
</p>

---

## Get started

```bash
pip install agent-bom

agent-bom scan                                     # auto-discover + scan
agent-bom scan --enrich                            # + NVD CVSS + EPSS + CISA KEV
agent-bom scan -f html -o report.html              # HTML dashboard
agent-bom scan --enforce                           # tool poisoning detection
agent-bom scan --fail-on-severity high -q          # CI gate
agent-bom scan --image myapp:latest                # Docker image scanning
agent-bom scan --k8s --all-namespaces              # K8s cluster
agent-bom scan --aws --snowflake --databricks      # Multi-cloud
agent-bom scan --aws-cis-benchmark                 # CIS AWS Foundations v3.0
agent-bom scan --snowflake-cis-benchmark           # CIS Snowflake v1.0
agent-bom scan --hf-model meta-llama/Llama-3.1-8B  # model provenance
```

Auto-discovers Claude Desktop, Claude Code, Cursor, Windsurf, Cline, VS Code Copilot, Continue, Zed, Cortex Code (CoCo), Codex CLI, Gemini CLI, Goose, Snowflake CLI, OpenClaw, Roo Code, Amazon Q, ToolHive, Docker MCP, JetBrains AI, and Junie.

<details>
<summary><b>Install extras</b></summary>

| Mode | Command |
|------|---------|
| Core CLI | `pip install agent-bom` |
| Cloud (all) | `pip install 'agent-bom[cloud]'` |
| AWS | `pip install 'agent-bom[aws]'` |
| Snowflake | `pip install 'agent-bom[snowflake]'` |
| Databricks | `pip install 'agent-bom[databricks]'` |
| Nebius GPU cloud | `pip install 'agent-bom[nebius]'` |
| REST API | `pip install 'agent-bom[api]'` |
| Dashboard | `pip install 'agent-bom[ui]'` |
| AI enrichment | `pip install 'agent-bom[ai-enrich]'` |
| MCP server | `pip install 'agent-bom[mcp-server]'` |
| OpenTelemetry | `pip install 'agent-bom[otel]'` |
| Docker | `docker run --rm -v ~/.config:/root/.config:ro agentbom/agent-bom scan` |

</details>

---

## Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/enterprise-overview-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/enterprise-overview-light.svg" alt="agent-bom enterprise overview" width="800" />
  </picture>
</p>

---

## Why agent-bom

Traditional scanners tell you a package has a CVE. agent-bom tells you **which AI agents are compromised**, **which credentials leak**, **which tools an attacker reaches**, and gives you a **fix-first priority** across your entire AI stack.

What sets it apart: AI agent discovery (20 clients), blast radius mapping (CVE → agent → creds → tools), CIS benchmarks (AWS, Snowflake), 10-framework compliance, and policy-as-code — all open source.

---

## How a CVE propagates through your AI stack

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="Blast Radius — How a CVE propagates through the AI stack" width="800" />
  </picture>
</p>

```
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  └─ better-sqlite3@9.0.0  (npm)
       └─ sqlite-mcp  (MCP Server · unverified · 🛡 root)
            ├─ Cursor IDE  (Agent · 4 servers · 12 tools)
            ├─ ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            └─ query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

---

## Scan pipeline

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scanner-architecture-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scanner-architecture-light.svg" alt="Scan Pipeline — 7-stage workflow" width="800" />
  </picture>
</p>

## Six modes, one engine

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/modes-flow-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/modes-flow-light.svg" alt="agent-bom modes — CLI, MCP Server, REST API, Runtime Proxy, GitHub Action, Dashboard" width="800" />
  </picture>
</p>

1. **Discover** — auto-detect MCP configs across 20 clients (Claude Desktop, Cursor, JetBrains AI, Junie, Codex CLI, Gemini CLI, Goose, etc.)
2. **Extract** — pull server names, package names, env var **names**, and tool lists. Credential **values** are never read.
3. **Scan** — send only package names + versions to public APIs (OSV.dev, NVD, EPSS, CISA KEV). NVD status tracking (Analyzed/Modified/Rejected) with remediation links.
4. **Analyze** — CVE blast radius mapping, per-CVE compliance tagging across 10 frameworks, tool poisoning detection (`--enforce`), model provenance
5. **Score** — posture scorecard (grade A–F), credential risk ranking, incident correlation by agent (P1–P4)
6. **Report** — JSON, SARIF, CycloneDX, SPDX, HTML, or console output. Alert dispatch to Slack/webhooks. Nothing stored server-side.

> **Individual developers:** Steps 1–4 are automatic. Enterprise features (steps 5–6) activate with `--enrich`, `--posture`, or the REST API.

---

## How to deploy

| Use case | Deploy | Command |
|----------|--------|---------|
| Quick local scan | CLI | `agent-bom scan` |
| CI/CD gate | GitHub Action | `uses: msaad00/agent-bom@v0.57.0` |
| Security dashboard | API + UI | `agent-bom serve` |
| MCP tool integration | MCP server | `agent-bom mcp-server` (19 tools) |
| K8s fleet scanning | Helm | `helm install deploy/helm/agent-bom` |
| Analytics + viz | Docker Compose | `cd infra/clickhouse && docker compose up` |
| Snowflake governance | API | `agent-bom api --snowflake` |
| Isolated scan | Docker | `docker run agentbom/agent-bom scan` |

---

## Enterprise scan workflow

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-workflow-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-workflow-light.svg" alt="Enterprise Scan Workflow — Architecture & Data Flow" width="800" />
  </picture>
</p>

**Trust guarantees:** Read-only (no file writes, no config changes, no servers started). `--dry-run` previews all files and API calls then exits. Every release is Sigstore-signed. Run `agent-bom verify agent-bom` to check integrity. See [PERMISSIONS.md](PERMISSIONS.md) for the full auditable trust contract.

<details>
<summary><b>Architecture data flow (Mermaid)</b></summary>

```mermaid
graph TB
    subgraph Input["Input Sources"]
        MCP["MCP Configs\n20 Clients"]
        Docker["Docker Images"]
        K8s["Kubernetes"]
        Cloud["Cloud APIs\nAWS / Azure / GCP / Snowflake"]
        SBOM["Existing SBOMs\nCycloneDX / SPDX"]
        AI["AI Platforms\nHuggingFace / W&B / MLflow"]
    end

    subgraph Core["Core Engine"]
        Discovery["Discovery Engine"]
        Parser["Package Parser"]
        Scanner["Vulnerability Scanner\nOSV + NVD + EPSS + KEV"]
        Blast["Blast Radius Analyzer"]
        Compliance["Compliance Tagger\n10 Frameworks"]
        Posture["Posture Scorer"]
    end

    subgraph Output["Output Channels"]
        Console["Console / HTML"]
        SBOM_Out["CycloneDX / SPDX / SARIF"]
        API["REST API + MCP Server"]
        Alerts["Slack / Webhook / Jira"]
    end

    MCP --> Discovery
    Docker --> Discovery
    K8s --> Discovery
    Cloud --> Discovery
    SBOM --> Discovery
    AI --> Discovery

    Discovery --> Parser
    Parser --> Scanner
    Scanner --> Blast
    Blast --> Compliance
    Compliance --> Posture

    Posture --> Console
    Posture --> SBOM_Out
    Posture --> API
    Posture --> Alerts
```

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for the full set of architecture diagrams including data flow pipeline, blast radius propagation, compliance framework mapping, and integration architecture.

</details>

<details>
<summary><b>Full feature comparison vs Grype / Syft / Trivy</b></summary>

| | Grype / Syft / Trivy | agent-bom |
|---|---|---|
| Package CVE detection | Yes | Yes — OSV + NVD CVSS v4 + EPSS + CISA KEV + GHSA + NVIDIA CSAF + NVD status tracking |
| SBOM generation | Yes (Syft) | Yes — CycloneDX 1.6, SPDX 3.0, SARIF |
| **AI agent discovery** | — | 20 MCP clients + Docker Compose auto-discovered |
| **Blast radius mapping** | — | CVE → package → server → agent → credentials → tools |
| **Credential exposure** | — | Which secrets leak per vulnerability, per agent |
| **MCP tool reachability** | — | Which tools an attacker reaches post-exploit |
| **Privilege detection** | — | runs_as_root, shell_access, container_privileged, per-tool permissions |
| **Enterprise remediation** | — | Named assets, impact percentages, risk narratives |
| **10-framework compliance** | — | OWASP Agentic + OWASP LLM + OWASP MCP + MITRE ATLAS + NIST AI RMF + EU AI Act + NIST CSF 2.0 + ISO 27001 + SOC 2 + CIS Controls v8 |
| **CVE-level compliance tags** | — | Per-vulnerability framework mapping (severity, KEV, EPSS, CWE, AI package, fix availability) |
| **SAST code scanning** | — | Semgrep wrapper with CWE-based compliance mapping across all 10 frameworks |
| **Malicious package detection** | — | OSV MAL- prefix + typosquat heuristics (57 popular packages) |
| **OpenSSF Scorecard enrichment** | — | Package health scores from api.securityscorecards.dev |
| **Tool poisoning detection** | — | Description injection, capability combos, CVE exposure, drift |
| **Model weight provenance** | — | SHA-256 hash, Sigstore file detection, HuggingFace metadata |
| **Policy-as-code** | — | Block unverified servers, enforce thresholds in CI/CD, EPSS/scorecard conditions |
| **Posture scorecard** | — | Letter grade (A–F), 6-dimension scoring, weighted enterprise posture |
| **Incident correlation** | — | Group vulns by agent, P1–P4 priority, SOC-ready incident summaries |
| **Credential risk ranking** | — | Rank exposed credentials by blast radius severity tier |
| **AI framework recognition** | — | GPU/ML packages flagged as high-risk in image scans (via Grype/Syft) |
| **Lateral movement analysis** | — | Agent context graph, shared server/credential detection, BFS attack paths |
| **CIS Benchmarks** | — | AWS Foundations v3.0 (18 checks), Snowflake v1.0 (12 checks) |
| **427+ server MCP registry** | — | Risk levels, tool inventories, auto-synced weekly |

</details>

---

## What it scans

<table>
<tr>
<td width="50%" valign="top">

**Input sources:**

| Source | How |
|--------|-----|
| MCP configs | Auto-discover (20 clients + Docker Compose) |
| Docker images | Grype / Syft / Docker CLI fallback |
| Kubernetes | kubectl across namespaces |
| Cloud providers | AWS, Azure, GCP, Databricks, Snowflake, Nebius, CoreWeave |
| CIS benchmarks | AWS Foundations v3.0, Snowflake v1.0 |
| Terraform / GitHub Actions | AI resources + env vars |
| AI platforms | HuggingFace, W&B, MLflow, OpenAI |
| Jupyter notebooks | AI library imports + model refs |
| Model files | 13 formats (.gguf, .safetensors, .pkl, ...) |
| Skill files | CLAUDE.md, .cursorrules, AGENTS.md |
| Prompt templates | .prompt, .promptfile, prompt.yaml |
| Ollama models | Local inventory via API + manifests |
| Source code (SAST) | Semgrep wrapper with CWE mapping |
| Existing SBOMs | CycloneDX / SPDX import |

</td>
<td width="50%" valign="top">

**Output formats:**

Console, HTML dashboard, SARIF, CycloneDX 1.6, SPDX 3.0, Prometheus, OTLP, JSON, REST API

**Read-only guarantee:** Never writes configs, never runs servers, never stores secrets. All API calls are read-only. See [PERMISSIONS.md](PERMISSIONS.md).

**Ecosystem:**

| Platform | Link |
|----------|------|
| PyPI | `pip install agent-bom` |
| Docker | `docker run agentbom/agent-bom scan` |
| GitHub Action | `uses: msaad00/agent-bom@v0.57.0` |
| MCP Registry | [server.json](integrations/mcp-registry/server.json) |
| ToolHive | [registry entry](integrations/toolhive/server.json) |
| OpenClaw | [SKILL.md](integrations/openclaw/SKILL.md) |
| Smithery | [smithery.yaml](smithery.yaml) |
| Railway | [Dockerfile.sse](Dockerfile.sse) |
| Helm | [`deploy/helm/agent-bom/`](deploy/helm/agent-bom/) |

</td>
</tr>
</table>

---

## For individual developers

> Auto-discover your MCP configs, scan for CVEs, understand blast radius, and fix what matters. No compliance paperwork needed.

### CVE scanning + blast radius

Every vulnerability is mapped through your AI stack: **which agents** are affected, **which credentials** are exposed, **which MCP tools** an attacker can reach, and **what to fix first**.

Enrichment sources: OSV batch (primary), NVD CVSS v4 + status tracking (Analyzed/Modified/Rejected), FIRST EPSS exploit probability, CISA KEV active exploitation catalog, GHSA, NVIDIA CSAF. Each CVE includes remediation source links from NVD references.

### Guided remediation

Each fix tells you exactly what will be protected — named agents, credentials, tools, impact percentages, and risk narratives. Fixed versions are identified automatically.

### Privilege detection

Every MCP server is assessed for privilege escalation risk:

| Signal | Detection |
|--------|-----------|
| **runs_as_root** | `sudo` in command/args, Docker `Config.User` empty/"0"/"root" |
| **shell_access** | bash/sh/zsh/powershell command, exec/shell tools |
| **container_privileged** | Docker `HostConfig.Privileged`, CapAdd/CapDrop |
| **tool_permissions** | Per-tool read/write/execute/destructive classification |

Privilege levels: **critical** (privileged container, CAP_SYS_ADMIN) → **high** (root, shell) → **medium** (fs write, network) → **low** (read-only).

### MCP runtime introspection

Connect to live servers to discover runtime tools/resources and detect drift from configs. Read-only — only calls `tools/list` and `resources/list`.

```bash
agent-bom scan --introspect
```

### Tool poisoning detection

Static analysis of MCP tool descriptions for prompt injection patterns, dangerous capability combinations (EXECUTE + WRITE), CVE exposure in server dependencies, and tool drift detection via introspection.

```bash
agent-bom scan --enforce                       # tool poisoning + enforcement checks
agent-bom scan --enforce --introspect          # + drift detection against live servers
```

### Malicious package detection

OSV MAL- prefix flagging + typosquat heuristics against 57 popular AI/ML packages. Catches known-malicious npm/PyPI packages before they enter your MCP stack.

<details>
<summary><b>Skill file + prompt scanning</b></summary>

Scan CLAUDE.md, .cursorrules, AGENTS.md for embedded MCP servers, packages, and credentials. 7 security checks: typosquat detection, shell access, dangerous server names, unverified servers, excessive credentials, external URLs, unknown packages.

```bash
agent-bom scan --skill CLAUDE.md    # explicit
agent-bom scan --scan-prompts       # prompt template security
```

</details>

<details>
<summary><b>Model weight provenance</b></summary>

SHA-256 hash verification, Sigstore signature file detection, and HuggingFace model metadata (author, license, model card, gated status, download count).

```bash
agent-bom scan --hf-model meta-llama/Llama-3.1-8B          # HuggingFace provenance
agent-bom scan --model-files ./models --model-provenance   # hash + signature checks
```

</details>

<details>
<summary><b>Docker image + Jupyter notebook scanning</b></summary>

3-tier container scanning (Grype → Syft → Docker CLI fallback). Detect 29+ AI libraries, pip installs, credentials in notebooks. Scan 13 model file formats.

```bash
agent-bom scan --image myapp:latest        # Docker image scanning
agent-bom scan --jupyter ./notebooks       # notebook audit
agent-bom scan --model-files ./models      # model file scanning
```

</details>

<details>
<summary><b>Pre-install guard</b></summary>

Intercept `pip install` or `npm install` to scan packages for CVEs before they land. Alias-ready for transparent protection.

```bash
agent-bom guard pip install flask requests     # scan then install
agent-bom guard npm install express            # same for npm
alias pip='agent-bom guard pip'                # transparent protection
```

Blocks on critical/high CVEs by default. Use `--allow-risky` to install anyway with a warning.

</details>

<details>
<summary><b>Runtime security — proxy, protect, watch</b></summary>

Three runtime modes for continuous MCP security. Each must be explicitly configured per-server — agent-bom is not an endpoint agent.

**Proxy** — intercept all MCP JSON-RPC traffic between client and server. Policy enforcement, credential leak detection, replay detection, rate limiting, JSONL audit log, Prometheus metrics.

```bash
agent-bom proxy -- npx @modelcontextprotocol/server-filesystem /tmp
agent-bom proxy --policy policy.json --log audit.jsonl -- npx @mcp/server-github
agent-bom proxy --detect-credentials --block-undeclared -- npx @mcp/server-postgres
```

**Protect** — 5-detector anomaly engine. Accepts OTel traces or runs as HTTP sidecar. Detects tool drift (rug pulls), shell injection in arguments, credential leaks in responses, rate anomalies, and suspicious call sequences (exfiltration patterns).

```bash
echo '{"tool_name":"exec","arguments":{"cmd":"rm -rf /"}}' | agent-bom protect
cat otel-export.jsonl | agent-bom protect --alert-file alerts.jsonl
agent-bom protect --mode http --port 8423    # HTTP sidecar
```

**Watch** — filesystem watchers on MCP config files. Re-scans on change, diffs against last scan, sends alerts on new servers/vulns/credentials.

```bash
agent-bom watch                                           # monitor all discovered configs
agent-bom watch --webhook https://hooks.slack.com/...     # alert to Slack
agent-bom watch --log alerts.jsonl                        # alert to file
```

</details>

<details>
<summary><b>Registry sync</b></summary>

Keep the local MCP server registry current with live sources:

```bash
agent-bom registry glama-sync         # import from Glama.ai (18,000+ servers)
agent-bom registry sync               # sync from Official MCP Registry
agent-bom registry sync-all           # all sources (Official + Smithery + Glama)
```

</details>

> **That's all you need.** Run `agent-bom scan` and you're done.
> Everything below is for teams deploying agent-bom as an enterprise security platform.

---

## For enterprise teams

> Compliance mapping, SBOM export, policy-as-code, posture scoring, CI/CD gates, cloud discovery, and fleet management.

### 10-framework compliance mapping

Every finding is tagged against ten frameworks simultaneously — both at the blast radius level (deployment context) and at the individual CVE level (severity, KEV, EPSS, CWE, AI package, fix availability):

| Category | Frameworks |
|----------|-----------|
| **AI-specific** | OWASP Agentic Top 10, OWASP LLM Top 10, OWASP MCP Top 10, MITRE ATLAS, NIST AI RMF 1.0, EU AI Act |
| **Enterprise GRC** | NIST CSF 2.0, ISO 27001:2022, SOC 2, CIS Controls v8 |

- **OWASP Agentic Top 10** — ASI01 through ASI10 (agent autonomy, tool misuse, spawn persistence)
- **OWASP LLM Top 10** — LLM01 through LLM10 (7 categories triggered)
- **OWASP MCP Top 10** — MCP01 through MCP10 (8 categories triggered) — token exposure, tool poisoning, supply chain, shadow servers
- **MITRE ATLAS** — AML.T0010, AML.T0043, AML.T0051, etc. (13 techniques mapped)
- **NIST AI RMF 1.0** — Govern, Map, Measure, Manage (12 subcategories mapped)
- **EU AI Act** — ART-5 through ART-17 (prohibited practices, high-risk classification, cybersecurity)
- **NIST CSF 2.0** — Govern, Identify, Protect, Detect, Respond (14 categories mapped)
- **ISO 27001:2022** — Annex A controls A.5.19 through A.8.28 (9 controls mapped)
- **SOC 2** — Trust Services Criteria CC6 through CC9 (9 criteria mapped)
- **CIS Controls v8** — Safeguards CIS-02, CIS-07, CIS-16 (10 safeguards mapped)

> **CIS Controls v8 vs. CIS Benchmarks:** agent-bom ships both. CIS Controls v8 maps generic security safeguards ("what to do"). Platform-specific CIS Benchmarks run live checks ("how to verify"): `--aws-cis-benchmark` (18 checks, IAM/Storage/Logging/Networking) and `--snowflake-cis-benchmark` (12 checks, Auth/Network/Data/Monitoring/Access). GCP, Azure, and Kubernetes benchmarks are planned.

### AI-BOM export

```bash
agent-bom scan -f cyclonedx -o ai-bom.cdx.json   # CycloneDX 1.6
agent-bom scan -f spdx -o ai-bom.spdx.json       # SPDX 3.0
agent-bom scan -f sarif -o results.sarif           # GitHub Security tab
agent-bom scan -f json -o ai-bom.json             # Full AI-BOM
agent-bom scan -f html -o report.html              # Interactive dashboard
agent-bom scan -f mermaid                          # Mermaid supply chain diagram
agent-bom scan -f graph -o graph.json              # Cytoscape-compatible graph JSON
```

### Policy-as-code

```bash
agent-bom scan --policy policy.json --fail-on-severity high
```

Supported policy conditions: `severity_gte`, `is_kev`, `ai_risk`, `has_credentials`, `ecosystem`, `package_name_contains`, `min_agents`, `min_tools`, `unverified_server`, `registry_risk_gte`, `owasp_tag`, `owasp_mcp_tag`, `is_malicious`, `min_scorecard_score`, `max_epss_score`, `has_kev_with_no_fix`. See [`policy.json`](policy.json) for an example template.

### Enterprise security operations

**Posture scorecard** — letter grade (A–F), numeric score (0–100), 6-dimension breakdown:

| Dimension | Weight | Measures |
|-----------|--------|----------|
| Vulnerability Posture | 30% | Severity distribution, fix availability |
| Credential Hygiene | 20% | Credential exposure footprint |
| Supply Chain Quality | 15% | OpenSSF Scorecard coverage |
| Compliance Coverage | 15% | Threat framework tag mapping |
| Active Exploitation | 10% | KEV, high-EPSS presence |
| Configuration Quality | 10% | Registry verification, tool declarations |

**Incident correlation** — group vulnerabilities by agent for SOC workflows:
- Priority levels: P1 (KEV/multi-critical) → P2 (critical+creds) → P3 (high) → P4 (monitor)
- Per-agent: unique CVEs, KEV IDs, exposed credentials, affected packages, recommended actions

**Credential risk ranking** — rank all exposed credentials by blast radius:
- Risk tiers: critical (critical CVE exposure) → high → medium → low
- Aggregated across all agents and servers per credential

### Cloud provider discovery

See [AI Infrastructure Scanning Guide](docs/AI_INFRASTRUCTURE_SCANNING.md) for GPU container scanning examples (NVIDIA + AMD ROCm).

```bash
agent-bom scan --aws --aws-region us-east-1       # Bedrock, Lambda, EKS, ECS, EC2, Step Functions
agent-bom scan --aws --aws-cis-benchmark          # CIS AWS Foundations v3.0 (18 checks)
agent-bom scan --snowflake                         # Cortex Agents, MCP Servers, Search, Snowpark
agent-bom scan --snowflake-cis-benchmark          # CIS Snowflake Benchmark v1.0 (12 checks)
agent-bom scan --databricks                        # Cluster libraries, model serving
agent-bom scan --nebius --nebius-project-id proj   # GPU cloud K8s + containers
agent-bom scan --k8s --context=coreweave-cluster   # CoreWeave / any K8s
```

<details>
<summary><b>Cloud provider details</b></summary>

| Provider | Depth | What's discovered | Install |
|----------|-------|------------------|---------|
| **Snowflake** | **Deep** | Cortex Agents, native MCP Servers, Search, Snowpark, Streamlit, query history, governance, activity, observability | `pip install 'agent-bom[snowflake]'` |
| **AWS** | **Standard** | Bedrock agents, Lambda package extraction, EKS, ECS, Step Functions, EC2, SageMaker | `pip install 'agent-bom[aws]'` |
| **Databricks** | Preview | Cluster packages, model serving endpoints | `pip install 'agent-bom[databricks]'` |
| **Azure** | **Standard** | OpenAI deployments, Functions, Container Instances, ML endpoints, AI Foundry workspaces, Container Apps | `pip install 'agent-bom[azure]'` |
| **GCP** | **Standard** | Vertex AI endpoints, Cloud Functions, GKE, Cloud Run | `pip install 'agent-bom[gcp]'` |
| **Nebius** | Preview | Managed K8s, container services | `pip install 'agent-bom[nebius]'` |
| **CoreWeave** | Via K8s | K8s-native — `--k8s --context=coreweave-cluster` | (core CLI) |
| **Ollama** | Standard | Local model inventory via API + manifests | (core CLI) |

> **Snowflake** is the deepest integration — includes governance audit (access history, privilege grants, data classification), agent activity timeline, and Cortex observability. Other providers have functional discovery at varying depth. PRs welcome.

</details>

<details>
<summary><b>Interactive security graph visualization</b></summary>

The dashboard (`agent-bom api`) serves interactive [React Flow](https://reactflow.dev/) graphs:

- **Agent Mesh** (`/mesh`) — cross-agent topology with vulnerability overlay, shared server detection, credential blast analysis
- **Attack Flow** (`/scan?view=attack-flow`) — CVE-centric blast radius graph: CVE → Package → Server → Agent → Credentials → Tools
- **Supply Chain Lineage** (`/graph`) — full dependency lineage with hover highlighting and detail panels
- **Context Graph** (`/context`) — lateral movement analysis: agent-to-agent attack paths via shared servers, credentials, and tools

</details>

<details>
<summary><b>AI-powered enrichment</b></summary>

LLM-generated risk narratives, executive summaries, and threat chain analysis. Works with local Ollama (free) or 100+ providers via litellm.

```bash
agent-bom scan --ai-enrich                              # auto-detect Ollama
agent-bom scan --ai-enrich --ai-model ollama/llama3      # specific model
```

</details>

<details>
<summary><b>Supplemental advisory enrichment</b></summary>

Beyond OSV.dev, agent-bom checks supplemental sources to catch CVEs not yet indexed:

- **GitHub Security Advisories (GHSA)** — all ecosystems (PyPI, npm, Go, Maven, Cargo, NuGet)
- **NVIDIA CSAF advisories** — GPU/ML packages (CUDA, cuDNN, TensorRT, NCCL)

Both sources deduplicate by CVE ID against OSV results.

</details>

---

## Deployment

| Mode | Command | Best for |
|------|---------|----------|
| CLI | `agent-bom scan` | Local audit |
| Pre-install check | `agent-bom check express@4.18.2 -e npm` | Before running MCP servers |
| Pre-install guard | `agent-bom guard pip install flask` | Scan-before-install hook |
| GitHub Action | `uses: msaad00/agent-bom@v0.57.0` | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom scan` | Isolated scans |
| REST API | `agent-bom api` | Dashboards, SIEM |
| Runtime proxy | `agent-bom proxy` | Opt-in MCP traffic audit (per-server) |
| MCP Server | `agent-bom mcp-server` | Inside any MCP client |
| Dashboard | `agent-bom serve` | API + Next.js dashboard |
| Snowflake | `SNOWFLAKE_ACCOUNT=... agent-bom api` | Snowpark + SiS |
| Prometheus | `--push-gateway` / `--otel-endpoint` | Monitoring |

### GitHub Action

```yaml
- uses: msaad00/agent-bom@v0.57.0
  with:
    severity-threshold: high
    upload-sarif: true
    enrich: true
    fail-on-kev: true
```

### REST API

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
| `GET /v1/compliance` | Full 10-framework compliance posture |
| `GET /v1/compliance/{framework}` | Single framework (owasp-llm, owasp-mcp, owasp-agentic, atlas, nist, eu-ai-act, nist-csf, iso-27001, soc2, cis) |
| `GET /v1/posture` | Enterprise posture scorecard (grade A–F, 6 dimensions) |
| `GET /v1/posture/credentials` | Credential risk ranking by blast radius |
| `GET /v1/posture/incidents` | Incident correlation by agent (P1–P4) |
| `POST /v1/traces` | OpenTelemetry trace ingestion + vulnerable tool call flagging |
| `GET /v1/scan/{id}/context-graph` | Agent context graph + lateral movement paths |
| `GET /v1/malicious/check` | Malicious package / typosquat check |

### MCP Server

```bash
pip install agent-bom[mcp-server]
agent-bom mcp-server                    # stdio
agent-bom mcp-server --transport sse    # remote
```

19 tools: `scan`, `check`, `blast_radius`, `policy_check`, `registry_lookup`, `generate_sbom`, `compliance`, `remediate`, `verify`, `where`, `inventory`, `diff`, `skill_trust`, `marketplace_check`, `code_scan`, `context_graph`, `analytics_query`, `cis_benchmark`, `fleet_scan`

### Cloud UI

```bash
cd ui && npm install && npm run dev   # http://localhost:3000
```

15-section Next.js dashboard:

| Page | Description |
|------|-------------|
| Dashboard | Security posture summary + stat cards |
| Scan | Enterprise scan form with cloud options |
| Vulnerabilities | CVE browser with severity/EPSS/KEV filters |
| Agents | Fleet registry + lifecycle state management |
| Compliance | 10-framework compliance posture (OWASP Agentic, OWASP LLM, OWASP MCP, ATLAS, NIST AI RMF, EU AI Act, NIST CSF 2.0, ISO 27001, SOC 2, CIS Controls v8) |
| Lineage Graph | Interactive supply chain graph — dagre layout, 7 node types, filter panel |
| Agent Mesh | Cross-agent topology — shared server detection, credential blast radius, tool overlap |
| Gateway | Runtime MCP policy rules + audit log |
| Registry | 427+ MCP server browser |
| Fleet | Agent trust scoring + fleet management |
| Activity | Agent activity timeline + AI observability |
| Governance | Snowflake access, privileges, data classification |
| Traces | OpenTelemetry trace ingestion + vulnerable tool call flagging |
| Context Graph | Lateral movement analysis — agent-to-agent attack paths, shared credentials, tool overlap |
| Jobs | Background scan job management |

### Snowflake Deployment

```bash
pip install 'agent-bom[api,snowflake]'
```

| Component | Description |
|-----------|-------------|
| Snowflake Table Storage | `SnowflakeJobStore`, `SnowflakeFleetStore`, `SnowflakePolicyStore` — auto-detect key-pair or password auth |
| Snowpark Container Services | `Dockerfile.snowpark` + `snowflake/setup.sql` — run the API inside Snowflake |
| Streamlit in Snowflake | `snowflake/streamlit_app.py` — 6-tab SiS dashboard reading from shared tables |
| Native App | `snowflake/native-app/` — Marketplace-distributable package |

Set `SNOWFLAKE_ACCOUNT` + `SNOWFLAKE_USER` + auth (`SNOWFLAKE_PRIVATE_KEY_PATH` or `SNOWFLAKE_PASSWORD`) and the API auto-switches to Snowflake persistence.

See [DEPLOYMENT.md](DEPLOYMENT.md) for full Snowflake architecture and setup instructions.

<details>
<summary><b>Snowflake deployment architecture</b></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/snowflake-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/snowflake-light.svg" alt="Snowflake Deployment Architecture" width="800" />
  </picture>
</p>

</details>

<details>
<summary><b>Enterprise deployment topology</b></summary>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/deployment-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/deployment-light.svg" alt="Enterprise Deployment Topology" width="800" />
  </picture>
</p>

</details>

---

## MCP Server Registry (427+ servers)

Registry of 427+ known MCP servers with risk levels, tool inventories, credential env vars, categories, and version pins. Risk levels are derived from server category (filesystem/shell = high, database/cloud = medium, search/monitoring = low). Credential env vars are inferred from package-name heuristics (21 patterns). Auto-synced weekly from the [Official MCP Registry](https://registry.modelcontextprotocol.io). 375 servers manually verified; 52 auto-enriched. Unverified servers trigger warnings. Policy rules can block them in CI.

Browse: [mcp_registry.json](src/agent_bom/mcp_registry.json) | Expand: `python scripts/expand_registry.py`

---

## AI supply chain coverage

| Layer | Coverage | Examples |
|-------|----------|----------|
| **GPU/ML packages** | `--image` via Grype/Syft | NVIDIA CUDA, cuDNN, TensorRT, AMD ROCm — flagged by package name matching |
| **GPU clouds** | `--k8s` pod discovery | CoreWeave, Lambda Labs, Nebius, Paperspace — image-level scanning |
| **AI platforms** | Cloud modules | Bedrock, Vertex AI, Snowflake Cortex, Databricks |
| **Containers** | `--image` via Grype/Syft | NVIDIA NGC, ROCm, vLLM, Triton, Ollama — any OCI image |
| **AI frameworks** | Dependency scan | LangChain, LlamaIndex, AutoGen, PyTorch, JAX, TensorFlow |
| **Inference servers** | `--image` | vLLM, Triton, TGI, llama.cpp |
| **MLOps** | Dependency scan | MLflow, W&B, Ray, ClearML |
| **MCP ecosystem** | Auto-discovery + registry | 20 clients, 427+ servers |
| **LLM providers** | API key + SDK detection | OpenAI, Anthropic, Cohere, Mistral |
| **IaC + CI/CD** | `--tf-dir`, `--gha` | Terraform AI resources, GitHub Actions |

> See [AI Infrastructure Scanning Guide](docs/AI_INFRASTRUCTURE_SCANNING.md) for GPU container scanning examples (NVIDIA + AMD ROCm).

---

## Trust & permissions

- **`--dry-run`** — preview every file and API URL before access, then exit without reading anything
- **[PERMISSIONS.md](PERMISSIONS.md)** — auditable trust contract with all config paths enumerated
- **Read-only** — never writes configs, runs servers, provisions resources, or stores secrets
- **Credential redaction** — only env var **names** in reports; values, tokens, passwords never read
- **Sigstore signed** — releases v0.7.0+ signed via cosign OIDC; verify PyPI integrity with `agent-bom verify agent-bom@0.57.0` (SHA-256 + SLSA provenance)
- **No binary needed (MCP)** — SSE transport requires zero local install; local CLI available for air-gapped use
- **OpenSSF Scorecard** — [automated supply chain scoring](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom)

---

## Roadmap

**Next up:**
- [ ] CIS Benchmarks: GCP v3.0, Azure v2.1, Kubernetes v1.9
- [ ] Snowflake org-level multi-account CIS evaluation
- [ ] License compliance engine
- [ ] Workflow engine scanning (n8n, Zapier, Make)

<details>
<summary><b>Shipped features (50+)</b></summary>

| Area | Highlights |
|------|-----------|
| **Discovery** | 20 MCP clients, K8s pods, 7 cloud providers, Docker Compose, Ollama, HuggingFace |
| **Scanning** | OSV + NVD CVSS v4 + EPSS + KEV + GHSA + NVIDIA CSAF, malicious package detection, typosquat heuristics |
| **Analysis** | Blast radius mapping, lateral movement graphs, credential risk ranking, incident correlation (P1-P4) |
| **Compliance** | 10 frameworks (OWASP Agentic/LLM/MCP, MITRE ATLAS, NIST AI RMF, EU AI Act, NIST CSF 2.0, ISO 27001, SOC 2, CIS Controls v8) |
| **CIS Benchmarks** | AWS Foundations v3.0 (18 checks), Snowflake v1.0 (12 checks) |
| **Runtime** | MCP proxy, 5-detector protection engine, config watchers, OTel trace ingestion |
| **Enterprise** | Posture scorecard (A-F), policy-as-code (16 conditions), SAST via Semgrep, pre-install guard |
| **Output** | JSON, SARIF, CycloneDX, SPDX, HTML, Mermaid, Cytoscape graph, Prometheus, Slack/webhook alerts |
| **Integrations** | Jira, Slack, Vanta, Drata, GitHub Action, Snowflake Native App, Streamlit dashboard |

See [CHANGELOG.md](CHANGELOG.md) for the full version history.

</details>

---

## Contributing

```bash
git clone https://github.com/msaad00/agent-bom.git && cd agent-bom
pip install -e ".[dev]"
pytest && ruff check src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) | [SECURITY.md](SECURITY.md) | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | [Skills](skills/)

---

Apache 2.0 — [LICENSE](LICENSE)
