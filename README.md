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
  <a href="https://pepy.tech/projects/agent-bom"><img src="https://static.pepy.tech/badge/agent-bom/month" alt="Downloads"></a>
  <a href="https://github.com/msaad00/agent-bom/stargazers"><img src="https://img.shields.io/github/stars/msaad00/agent-bom?style=flat&logo=github&label=Stars" alt="Stars"></a>
  <a href="https://github.com/msaad00/agent-bom/discussions"><img src="https://img.shields.io/github/discussions/msaad00/agent-bom?style=flat&logo=github&label=Discussions" alt="Discussions"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center">
  <b>Scan your AI infrastructure. Enforce it at runtime.</b><br>
  CVEs, blast radius, credential exposure, 11 compliance frameworks — then proxy MCP traffic and enforce policy in real time.
</p>

---

## Quick start

```bash
pip install agent-bom        # install
agent-bom scan               # auto-discover MCP configs + scan
agent-bom scan --enrich      # + NVD CVSS + EPSS + CISA KEV enrichment
```

That's it. agent-bom discovers your MCP client configs (Claude Desktop, Cursor, Windsurf, and 20 more), resolves every server's dependencies, checks them against OSV/NVD/GHSA, and maps the blast radius — which agents, credentials, and tools are affected by each vulnerability.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-v0.65.0.gif" alt="agent-bom demo — scan, CVE check, blast radius, runtime proxy, 31 MCP tools" width="900" />
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

Three capabilities, one tool: **scanner** (CVEs, blast radius, compliance, supply chain) + **proxy** (intercepts MCP traffic, enforces policy, detects 7 behavioral attack patterns) + **instruction file trust** (audits CLAUDE.md, .cursorrules, AGENTS.md, SKILL.md for malicious patterns, typosquatting, and Sigstore provenance). Read-only. Agentless. Open source.

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

31 tools available to any MCP-compatible AI assistant.

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

Also available on [Glama](https://glama.ai/mcp/servers/@msaad00/agent-bom), [Smithery](smithery.yaml), [MCP Registry](integrations/mcp-registry/server.json), and [OpenClaw](integrations/openclaw/SKILL.md).

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
5. **Report** -- JSON, SARIF, CycloneDX, SPDX, HTML, Mermaid, or console. Alert dispatch to Slack/webhooks.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-light.svg" alt="Scan pipeline" width="800" />
  </picture>
</p>

**Read-only guarantee.** Never writes configs, never runs servers, never stores secrets. `--dry-run` previews everything. Every release is [Sigstore-signed](PERMISSIONS.md).

---

## CLI reference

<details>
<summary><b>Scanning options</b></summary>

```bash
agent-bom scan                                     # auto-discover + scan
agent-bom scan --enrich                            # + NVD CVSS + EPSS + CISA KEV
agent-bom scan -f html -o report.html              # HTML dashboard
agent-bom scan --enforce                           # tool poisoning detection
agent-bom scan --fail-on-severity high -q          # CI gate
agent-bom scan --image myapp:latest                # Docker image scanning
agent-bom scan --k8s --all-namespaces              # K8s image scanning (cluster-wide)
agent-bom scan --k8s-mcp                           # Discover MCP pods + CRDs in Kubernetes
agent-bom scan --include-processes                 # Scan running host MCP processes (psutil)
agent-bom scan --include-containers                # Scan Docker containers for MCP servers
agent-bom scan --health-check                      # Probe discovered servers for liveness
agent-bom scan --siem splunk --siem-url https://...  # Push findings to SIEM
agent-bom scan --aws --snowflake --databricks      # Multi-cloud
agent-bom scan --hf-model meta-llama/Llama-3.1-8B  # model provenance
agent-bom scan --vector-db-scan                    # Scan self-hosted + Pinecone cloud vector DBs
agent-bom scan --gpu-scan                          # Discover GPU containers + K8s nodes, detect unauthenticated DCGM exporters
agent-bom scan --browser-extensions               # Scan Chrome/Edge/Firefox extensions for dangerous permissions
agent-bom scan --skill-only                       # Audit AI instruction files (CLAUDE.md, .cursorrules, AGENTS.md)
agent-bom scan --save report.json                  # Save + track assets (first_seen, resolved, MTTR)
agent-bom graph report.json --format dot           # Export dependency graph (DOT/Mermaid/JSON)
agent-bom proxy-configure --apply                  # Auto-wrap MCP configs with security proxy
```

</details>

<details>
<summary><b>Runtime enforcement</b></summary>

Sit between your MCP client and server, enforce policy in real time:

```bash
# Wrap a single server — intercept every tool call
agent-bom proxy --command "uvx mcp-server-filesystem /" --policy policy.yml

# Protect mode — run standalone detector engine
agent-bom protect --mode http

# Watch MCP configs for drift — alert on changes
agent-bom watch --webhook https://hooks.slack.com/...

# Introspect a live MCP server — list tools, detect drift
agent-bom introspect --command "uvx mcp-server-filesystem /"
agent-bom introspect --all                                         # auto-discover all configured servers
agent-bom introspect --all --baseline baseline.json               # exit 1 on new/removed tools

# Policy file — 17 conditions, zero code required
# policy.yml:
#   blocked_tools: [run_shell, exec_command]
#   require_agent_identity: true
#   rate_limit: {threshold: 50, window_seconds: 60}
```

</details>

Auto-discovers 22 MCP clients: Claude Desktop, Claude Code, Cursor, Windsurf, Cline, VS Code Copilot, Continue, Zed, Cortex Code, Codex CLI, Gemini CLI, Goose, Snowflake CLI, OpenClaw, Roo Code, Amazon Q, ToolHive, Docker MCP Toolkit, JetBrains AI, Junie, and custom paths.

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/topology-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/topology-light.svg" alt="MCP Topology" width="800" />
  </picture>
</p>

---

## What it covers

<details>
<summary><b>agent-bom vs. traditional scanners</b></summary>

| | Traditional scanners | agent-bom |
|---|---|---|
| Package CVE detection | Yes | Yes (OSV + NVD + EPSS + CISA KEV + GHSA + NVIDIA CSAF) |
| SBOM generation | Yes | Yes (CycloneDX 1.6, SPDX 3.0, SARIF) |
| **AI agent discovery** | -- | 22 MCP clients + Docker Compose + running processes + containers + K8s pods/CRDs |
| **GPU/ML package scanning** | -- | NVIDIA CSAF advisories for CUDA, cuDNN, PyTorch, TensorFlow, JAX, vLLM + AMD ROCm via OSV |
| **AI supply chain** | -- | Model provenance (pickle risk, digest, gating), HuggingFace Hub, Ollama, MLflow, W&B |
| **AI cloud inventory** | -- | Coreweave, Nebius, Snowflake, Databricks, OpenAI, HuggingFace Hub — config discovery + CVE tagging |
| **Blast radius mapping** | -- | CVE -> package -> server -> agent -> credentials -> tools |
| **Credential exposure** | -- | Which secrets leak per vulnerability, per agent |
| **Tool poisoning detection** | -- | Description injection, capability combos, drift detection |
| **Privilege detection** | -- | root, shell access, privileged containers, per-tool permissions |
| **11-framework compliance** | -- | OWASP LLM + MCP + Agentic + AISVS v1.0, MITRE ATLAS, NIST AI RMF + CSF, EU AI Act, SOC 2, ISO 27001, CIS |
| **MITRE ATT&CK mapping** | -- | Dynamic technique lookup by tactic phase (no hardcoded T-codes) |
| **Posture scorecard** | -- | Letter grade (A-F), 6 dimensions, incident correlation (P1-P4) |
| **Policy-as-code + Jira** | -- | 17 conditions, CI gate, auto-create Jira tickets for violations |
| **SIEM push** | -- | Splunk HEC, Datadog Logs, Elasticsearch — raw or OCSF format |
| **Proxy auto-configure** | -- | Wrap every MCP server config with `agent-bom proxy` in one command |
| **Server health checks** | -- | Lightweight liveness probe — reachable, tool count, latency, protocol |
| **Lateral movement analysis** | -- | Agent context graph, shared credentials, BFS attack paths |
| **427+ server MCP registry** | -- | Risk levels, tool inventories, auto-synced weekly |
| **Cloud vector DB scanning** | -- | Pinecone index inventory, risk flags, replica counts via API key |
| **Dependency graph export** | -- | DOT, Mermaid, JSON — agent → server → package → CVE graph |
| **OIDC/SSO authentication** | -- | JWT verification (Okta, Google, Azure AD, Auth0) for REST API |
| **Instruction file trust** | -- | SKILL.md/CLAUDE.md/.cursorrules — 17 behavioral patterns, typosquat detection, Sigstore provenance verification |
| **Browser extension scanning** | -- | Chrome/Edge/Firefox manifest.json — nativeMessaging, dangerous permissions, AI assistant domain access |
| **Persistent asset tracking** | -- | SQLite DB — first_seen/last_seen/resolved/reopened per vulnerability, MTTR calculation, scan-over-scan diff |

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
<summary><b>What it outputs</b></summary>

Console, JSON, HTML, SARIF, CycloneDX 1.6, SPDX 3.0, Mermaid, SVG, Graph (DOT/JSON/HTML), Prometheus, Badge, REST API — 13 formats total.

```bash
agent-bom scan -f cyclonedx -o ai-bom.cdx.json   # CycloneDX 1.6
agent-bom scan -f spdx -o ai-bom.spdx.json       # SPDX 3.0
agent-bom scan -f sarif -o results.sarif           # GitHub Security tab
agent-bom scan -f html -o report.html              # Interactive dashboard
agent-bom scan -f graph -o graph.json              # Cytoscape-compatible
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
| GitHub Action | `uses: msaad00/agent-bom@v0.70.4 | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom scan` | Isolated scans (linux/amd64, linux/arm64) |
| REST API | `agent-bom api` | Dashboards, SIEM |
| MCP Server | `agent-bom mcp-server` (31 tools) | Inside any MCP client |
| Dashboard | `agent-bom serve` · [Full deploy guide](docs/DEPLOYMENT.md) | API + Next.js UI (15 pages) · Postgres/Supabase |
| Runtime proxy | `agent-bom proxy` | Intercept + enforce MCP traffic in real time |
| Protect engine | `agent-bom protect` | 7 behavioral detectors (rug pull, injection, credential leak, exfil sequences, response cloaking, rate limiting, vector DB injection) |
| Config watcher | `agent-bom watch` | Filesystem watch on MCP configs, alert on drift |
| Pre-install guard | `agent-bom guard pip install <pkg>` | Block vulnerable installs |
| Snowflake | [DEPLOYMENT.md](DEPLOYMENT.md) | Snowpark + SiS |

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
- uses: msaad00/agent-bom@v0.70.4
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
| `GET /v1/compliance` | Full 11-framework compliance posture |
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
<summary><b>Cloud providers</b></summary>

| Provider | Depth | Install |
|----------|-------|---------|
| **Snowflake** | Deep (Cortex, MCP, governance, observability) | `pip install 'agent-bom[snowflake]'` |
| **AWS** | Standard (Bedrock, Lambda, EKS, ECS, SageMaker) | `pip install 'agent-bom[aws]'` |
| **Azure** | Standard (OpenAI, Functions, AI Foundry, Container Apps) | `pip install 'agent-bom[azure]'` |
| **GCP** | Standard (Vertex AI, Cloud Functions, GKE, Cloud Run) | `pip install 'agent-bom[gcp]'` |
| **Databricks** | Preview (Cluster packages, model serving) | `pip install 'agent-bom[databricks]'` |
| **Nebius** | Preview (Managed K8s, containers) | `pip install 'agent-bom[nebius]'` |
| **CoreWeave** | Via K8s | `--k8s --context=coreweave-cluster` |

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
| GitHub Action | `uses: msaad00/agent-bom@v0.70.4 |
| Glama | [glama.ai/mcp/servers/@msaad00/agent-bom](https://glama.ai/mcp/servers/@msaad00/agent-bom) |
| MCP Registry | [server.json](integrations/mcp-registry/server.json) |
| ToolHive | [registry entry](integrations/toolhive/server.json) |
| OpenClaw | [SKILL.md](integrations/openclaw/SKILL.md) |
| Smithery | [smithery.yaml](smithery.yaml) |
| Railway | [Dockerfile.sse](Dockerfile.sse) |

---

## Architecture

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-stack-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-stack-light.svg" alt="Architecture stack" width="800" />
  </picture>
</p>

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

---

## Trust & permissions

- **Read-only** -- never writes configs, runs servers, provisions resources, or stores secrets
- **Credential redaction** -- only env var **names** in reports; values never read or logged
- **No shell injection** -- subprocess uses `asyncio.create_subprocess_exec`; command + args validated before every spawn
- **No SSRF** -- all outbound URLs hardcoded or validated; DNS rebinding defense blocks private/loopback/cloud-metadata ranges
- **No path traversal** -- `validate_path(restrict_to_home=True)` on all user-supplied paths; MCP tool inputs sanitized
- **No SQL injection** -- all database queries use parameterized statements
- **Proxy size guard** -- messages >10 MB dropped before parsing; protects against DoS
- **Audit integrity** -- JSONL audit logs stored at `0600`, HMAC-signed (SHA-256). Set `AGENT_BOM_AUDIT_HMAC_KEY` in production for cross-restart verifiability.
- **API security** -- scrypt KDF for API keys, RBAC (admin/analyst/viewer), OIDC/JWT (RS256/ES256, `none` algorithm rejected), constant-time comparison
- **`--dry-run`** -- preview every file and API URL before access
- **Sigstore signed** -- releases v0.7.0+ signed via cosign OIDC
- **OpenSSF Scorecard** -- [automated supply chain scoring](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom)
- **OpenSSF Best Practices** -- [passing badge (100%)](https://www.bestpractices.dev/projects/12114) — 67/67 criteria
- **Continuous fuzzing** -- [ClusterFuzzLite](https://github.com/msaad00/agent-bom/blob/main/.github/workflows/cflite-pr.yml) fuzzes SBOM parsers, policy evaluator, and skill parser
- **[PERMISSIONS.md](PERMISSIONS.md)** -- full auditable trust contract

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
- [x] 11 frameworks: OWASP LLM, OWASP MCP, OWASP Agentic, OWASP AISVS v1.0, ATLAS, NIST AI RMF, EU AI Act, NIST CSF, ISO 27001, SOC 2, CIS Controls
- [ ] CIS AI benchmarks (pending CIS publication)
- [ ] License compliance engine (OSS license risk flagging)
- [ ] Workflow engine scanning (n8n, Zapier, Make)

**Ecosystem coverage**
- [ ] Maven / Go ecosystem — test coverage thin (PyPI, npm, cargo, pip best covered)
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

See [CONTRIBUTING.md](CONTRIBUTING.md) | [SECURITY.md](SECURITY.md) | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md) | [GOVERNANCE.md](GOVERNANCE.md) | [ROADMAP.md](ROADMAP.md) | [THREAT_MODEL.md](THREAT_MODEL.md)

---

Apache 2.0 -- [LICENSE](LICENSE)
