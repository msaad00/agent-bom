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
  <b>AI supply chain security scanner. Scan packages and images for CVEs. Assess config security — credential exposure, tool access, privilege escalation. Map blast radius from vulnerabilities to credentials and tools. OWASP LLM Top 10 + OWASP MCP Top 10 + MITRE ATLAS + NIST AI RMF.</b>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/enterprise-overview-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/enterprise-overview-light.svg" alt="agent-bom enterprise overview" width="800" />
  </picture>
</p>

---

## Why agent-bom?

> **Traditional scanners tell you a package has a CVE.**
> **agent-bom tells you which AI agents are compromised, which credentials leak, which tools an attacker reaches, and what the business impact is.**

```
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  └─ better-sqlite3@9.0.0  (npm)
       └─ sqlite-mcp  (MCP Server · unverified · 🛡 root)
            ├─ Cursor IDE  (Agent · 4 servers · 12 tools)
            ├─ ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            └─ query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

| | Grype / Syft / Trivy | agent-bom |
|---|---|---|
| Package CVE detection | Yes | Yes — OSV + NVD CVSS v4 + EPSS + CISA KEV + GHSA + NVIDIA CSAF |
| SBOM generation | Yes (Syft) | Yes — CycloneDX 1.6, SPDX 3.0, SARIF |
| **AI agent discovery** | — | 18 MCP clients + Docker Compose auto-discovered |
| **Blast radius mapping** | — | CVE → package → server → agent → credentials → tools |
| **Credential exposure** | — | Which secrets leak per vulnerability, per agent |
| **MCP tool reachability** | — | Which tools an attacker reaches post-exploit |
| **Privilege detection** | — | runs_as_root, shell_access, container_privileged, per-tool permissions |
| **Enterprise remediation** | — | Named assets, impact percentages, risk narratives |
| **6-framework compliance** | — | OWASP Agentic Top 10 + OWASP LLM Top 10 + OWASP MCP Top 10 + MITRE ATLAS + NIST AI RMF + EU AI Act |
| **Malicious package detection** | — | OSV MAL- prefix + typosquat heuristics (57 popular packages) |
| **OpenSSF Scorecard enrichment** | — | Package health scores from api.securityscorecards.dev |
| **Tool poisoning detection** | — | Description injection, capability combos, CVE exposure, drift |
| **Model weight provenance** | — | SHA-256 hash, Sigstore file detection, HuggingFace metadata |
| **Policy-as-code** | — | Block unverified servers, enforce thresholds in CI/CD |
| **AI framework recognition** | — | GPU/ML packages flagged as high-risk in image scans (via Grype/Syft) |
| **427+ server MCP registry** | — | Risk levels, tool inventories, auto-synced weekly |

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="Blast Radius — How a CVE propagates through the AI stack" width="800" />
  </picture>
</p>

<table>
<tr>
<td width="50%" valign="top">

**What it scans:**

| Source | How |
|--------|-----|
| MCP configs | Auto-discover (18 clients + Docker Compose) |
| Docker images | Grype / Syft / Docker CLI fallback |
| Kubernetes | kubectl across namespaces |
| Cloud providers | AWS, Azure, GCP, Databricks, Snowflake, Nebius |
| Terraform / GitHub Actions | AI resources + env vars |
| AI platforms | HuggingFace, W&B, MLflow, OpenAI |
| Jupyter notebooks | AI library imports + model refs |
| Model files | 13 formats (.gguf, .safetensors, .pkl, ...) |
| Skill files | CLAUDE.md, .cursorrules, AGENTS.md |
| Prompt templates | .prompt, .promptfile, prompt.yaml |
| Ollama models | Local inventory via API + manifests |
| Existing SBOMs | CycloneDX / SPDX import |

</td>
<td width="50%" valign="top">

**What it outputs:**

Console, HTML dashboard, SARIF, CycloneDX 1.6, SPDX 3.0, Prometheus, OTLP, JSON, REST API

**Read-only guarantee:** Never writes configs, never runs servers, never stores secrets. All API calls are read-only. See [PERMISSIONS.md](PERMISSIONS.md).

**Ecosystem:**

| Platform | Link |
|----------|------|
| PyPI | `pip install agent-bom` |
| Docker | `docker run agentbom/agent-bom scan` |
| GitHub Action | `uses: msaad00/agent-bom@v0.36.1` |
| MCP Registry | [server.json](integrations/mcp-registry/server.json) |
| ToolHive | [registry entry](integrations/toolhive/server.json) |
| OpenClaw | [SKILL.md](integrations/openclaw/SKILL.md) |
| Smithery | [smithery.yaml](smithery.yaml) |
| Railway | [Dockerfile.sse](Dockerfile.sse) |

</td>
</tr>
</table>

---

## How it works

1. **Discover** — auto-detect MCP configs across 18 clients (Claude Desktop, Cursor, Codex CLI, Gemini CLI, Goose, etc.)
2. **Extract** — pull server names, package names, env var **names**, and tool lists. Credential **values** are never read.
3. **Scan** — send only package names + versions to public APIs (OSV.dev, NVD, EPSS, CISA KEV). No hostnames, no secrets, no auth tokens.
4. **Analyze** — CVE blast radius mapping, tool poisoning detection (`--enforce`), OWASP/ATLAS/NIST threat models, model provenance (`--hf-model`)
5. **Report** — JSON, SARIF, CycloneDX, SPDX, HTML, or console output. Nothing stored server-side.

**Trust guarantees:** Read-only (no file writes, no config changes, no servers started). `--dry-run` previews all files and API calls then exits. Every release is Sigstore-signed. Run `agent-bom verify agent-bom` to check integrity. See [PERMISSIONS.md](PERMISSIONS.md) for the full auditable trust contract.

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
agent-bom scan --hf-model meta-llama/Llama-3.1-8B  # model provenance
```

Auto-discovers Claude Desktop, Claude Code, Cursor, Windsurf, Cline, VS Code Copilot, Continue, Zed, Cortex Code (CoCo), Codex CLI, Gemini CLI, Goose, Snowflake CLI, OpenClaw, Roo Code, Amazon Q, ToolHive, and Docker MCP Toolkit.

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

## Core capabilities

### CVE scanning + blast radius

Every vulnerability is mapped through your AI stack: **which agents** are affected, **which credentials** are exposed, **which MCP tools** an attacker can reach, and **what to fix first**.

Enrichment sources: OSV batch (primary), NVD CVSS v4, FIRST EPSS exploit probability, CISA KEV active exploitation catalog.

### Privilege detection

Every MCP server is assessed for privilege escalation risk:

| Signal | Detection |
|--------|-----------|
| **runs_as_root** | `sudo` in command/args, Docker `Config.User` empty/"0"/"root" |
| **shell_access** | bash/sh/zsh/powershell command, exec/shell tools |
| **container_privileged** | Docker `HostConfig.Privileged`, CapAdd/CapDrop |
| **tool_permissions** | Per-tool read/write/execute/destructive classification |

Privilege levels: **critical** (privileged container, CAP_SYS_ADMIN) → **high** (root, shell) → **medium** (fs write, network) → **low** (read-only).

### 6-framework compliance mapping

Every finding is tagged against six frameworks simultaneously:

- **OWASP Agentic Top 10** — ASI01 through ASI10 (agent autonomy, tool misuse, spawn persistence)
- **OWASP LLM Top 10** — LLM01 through LLM10 (7 categories triggered)
- **OWASP MCP Top 10** — MCP01 through MCP10 (8 categories triggered) — token exposure, tool poisoning, supply chain, shadow servers
- **MITRE ATLAS** — AML.T0010, AML.T0043, AML.T0051, etc. (9 techniques mapped)
- **NIST AI RMF 1.0** — Govern, Map, Measure, Manage (12 subcategories mapped)
- **EU AI Act** — ART-5 through ART-17 (prohibited practices, high-risk classification, cybersecurity)

### Enterprise remediation

Each fix tells you exactly what will be protected — named agents, credentials, tools, percentages, threat tags, and risk narratives.

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

### Cloud provider discovery

```bash
agent-bom scan --aws --aws-region us-east-1       # Bedrock, Lambda, EKS, ECS, EC2, Step Functions
agent-bom scan --snowflake                         # Cortex Agents, MCP Servers, Search, Snowpark
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

### Additional capabilities

<details>
<summary><b>MCP runtime introspection</b></summary>

Connect to live servers to discover runtime tools/resources and detect drift from configs. Read-only — only calls `tools/list` and `resources/list`.

```bash
agent-bom scan --introspect
```

</details>

<details>
<summary><b>Skill file scanning + security audit</b></summary>

Scan CLAUDE.md, .cursorrules, AGENTS.md for embedded MCP servers, packages, and credentials. 7 security checks: typosquat detection, shell access, dangerous server names, unverified servers, excessive credentials, external URLs, unknown packages.

```bash
agent-bom scan --skill CLAUDE.md    # explicit
agent-bom scan --skill-only         # skills only
agent-bom scan --no-skill           # skip skills
```

</details>

<details>
<summary><b>Prompt template scanning</b></summary>

Scan .prompt, .promptfile, system_prompt.*, prompt.yaml/json files for hardcoded secrets, prompt injection patterns, unsafe instructions, and sensitive data exposure.

```bash
agent-bom scan --scan-prompts
```

</details>

<details>
<summary><b>AI-powered enrichment</b></summary>

LLM-generated risk narratives, executive summaries, and threat chain analysis. Works with local Ollama (free) or 100+ providers via litellm.

```bash
agent-bom scan --ai-enrich                              # auto-detect Ollama
agent-bom scan --ai-enrich --ai-model ollama/llama3      # specific model
agent-bom scan --ai-enrich --ai-model openai/gpt-4o-mini # cloud LLM
```

</details>

<details>
<summary><b>Tool poisoning detection + enforcement</b></summary>

Static analysis of MCP tool descriptions for prompt injection patterns, dangerous capability combinations (EXECUTE + WRITE), CVE exposure in server dependencies, and tool drift detection via introspection.

```bash
agent-bom scan --enforce                       # tool poisoning + enforcement checks
agent-bom scan --enforce --introspect          # + drift detection against live servers
```

</details>

<details>
<summary><b>Model weight provenance</b></summary>

SHA-256 hash verification, Sigstore signature file detection (`.sig`/`.sigstore`/`.bundle` presence — not cryptographic verification), and HuggingFace model metadata (author, license, model card, gated status, download count).

```bash
agent-bom scan --model-files ./models --model-provenance   # hash + signature checks
agent-bom scan --hf-model meta-llama/Llama-3.1-8B          # HuggingFace provenance
```

</details>

<details>
<summary><b>Jupyter notebook + model file scanning</b></summary>

Detect 29+ AI libraries, pip installs, credentials in notebooks. Scan 13 model file formats with security flags for pickle-based formats.

```bash
agent-bom scan --jupyter ./notebooks
agent-bom scan --model-files ./models
```

</details>

<details>
<summary><b>Interactive security graph visualization</b></summary>

The dashboard (`agent-bom api`) serves interactive [React Flow](https://reactflow.dev/) graphs — the same rendering approach used by enterprise security platforms:

- **Agent Mesh** (`/mesh`) — cross-agent topology with vulnerability overlay, shared server detection, credential blast analysis, severity filtering, and search
- **Attack Flow** (`/scan?view=attack-flow`) — CVE-centric blast radius graph: CVE → Package → Server → Agent → Credentials → Tools
- **Supply Chain Lineage** (`/graph`) — full dependency lineage with hover highlighting and detail panels

All graph views include: dagre auto-layout, hover highlighting (BFS connected nodes), click-to-inspect detail panels, minimap, OWASP LLM Top 10 + OWASP MCP Top 10 + MITRE ATLAS + NIST AI RMF framework tagging on every node.

CLI output formats for CI/CD and automation:

```bash
agent-bom scan -f graph -o graph.json    # Cytoscape-compatible JSON
agent-bom scan -f html -o report.html    # standalone interactive HTML report
agent-bom scan -f mermaid                # Mermaid text (for docs/markdown)
agent-bom scan -f sarif -o results.sarif # GitHub Security tab integration
```

</details>

<details>
<summary><b>Supplemental advisory enrichment</b></summary>

Beyond OSV.dev, agent-bom checks supplemental sources to catch CVEs not yet indexed:

- **GitHub Security Advisories (GHSA)** — all ecosystems (PyPI, npm, Go, Maven, Cargo, NuGet)
- **NVIDIA CSAF advisories** — GPU/ML packages (CUDA, cuDNN, TensorRT, NCCL)

Both sources deduplicate by CVE ID against OSV results. Packages without a pinned version are auto-resolved from npm/PyPI registries before scanning.

</details>

---

## Deployment

| Mode | Command | Best for |
|------|---------|----------|
| CLI | `agent-bom scan` | Local audit |
| Pre-install check | `agent-bom check express@4.18.2 -e npm` | Before running MCP servers |
| GitHub Action | `uses: msaad00/agent-bom@v0.36.1` | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom scan` | Isolated scans |
| REST API | `agent-bom api` | Dashboards, SIEM |
| Runtime proxy | `agent-bom proxy` | Opt-in MCP traffic audit (per-server) |
| MCP Server | `agent-bom mcp-server` | Inside any MCP client |
| Dashboard | `agent-bom serve` | API + Next.js dashboard |
| Snowflake | `SNOWFLAKE_ACCOUNT=... agent-bom api` | Snowpark + SiS |
| Prometheus | `--push-gateway` / `--otel-endpoint` | Monitoring |

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-workflow-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-workflow-light.svg" alt="Enterprise Scan Workflow" width="800" />
  </picture>
</p>

### GitHub Action

```yaml
- uses: msaad00/agent-bom@v0.36.1
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
| `GET /v1/compliance` | Full 6-framework compliance posture |
| `GET /v1/compliance/{framework}` | Single framework (owasp-llm, owasp-mcp, owasp-agentic, atlas, nist, eu-ai-act) |
| `POST /v1/traces` | OpenTelemetry trace ingestion + vulnerable tool call flagging |
| `GET /v1/malicious/check` | Malicious package / typosquat check |

### MCP Server

```bash
pip install agent-bom[mcp-server]
agent-bom mcp-server                    # stdio
agent-bom mcp-server --transport sse    # remote
```

14 tools: `scan`, `check`, `blast_radius`, `policy_check`, `registry_lookup`, `generate_sbom`, `compliance`, `remediate`, `verify`, `where`, `inventory`, `diff`, `skill_trust`, `marketplace_check`

### Cloud UI

```bash
cd ui && npm install && npm run dev   # http://localhost:3000
```

14-section Next.js dashboard:

| Page | Description |
|------|-------------|
| Dashboard | Security posture summary + stat cards |
| Scan | Enterprise scan form with cloud options |
| Vulnerabilities | CVE browser with severity/EPSS/KEV filters |
| Agents | Fleet registry + lifecycle state management |
| Compliance | 6-framework compliance posture (OWASP Agentic, OWASP LLM, OWASP MCP, ATLAS, NIST, EU AI Act) |
| Lineage Graph | Interactive supply chain graph — dagre layout, 7 node types, filter panel |
| Agent Mesh | Cross-agent topology — shared server detection, credential blast radius, tool overlap |
| Gateway | Runtime MCP policy rules + audit log |
| Registry | 427+ MCP server browser |
| Fleet | Agent trust scoring + fleet management |
| Activity | Agent activity timeline + AI observability |
| Governance | Snowflake access, privileges, data classification |
| Traces | OpenTelemetry trace ingestion + vulnerable tool call flagging |
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

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/snowflake-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/snowflake-light.svg" alt="Snowflake Deployment Architecture" width="800" />
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/deployment-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/deployment-light.svg" alt="Enterprise Deployment Topology" width="800" />
  </picture>
</p>

---

## MCP Server Registry (427+ servers)

Curated registry of 427+ known MCP servers with risk levels, tool inventories, credential env vars, categories, and version pins. Auto-synced weekly from the [Official MCP Registry](https://registry.modelcontextprotocol.io). Unverified servers trigger warnings. Policy rules can block them in CI.

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
| **MCP ecosystem** | Auto-discovery + registry | 18 clients, 427+ servers |
| **LLM providers** | API key + SDK detection | OpenAI, Anthropic, Cohere, Mistral |
| **IaC + CI/CD** | `--tf-dir`, `--gha` | Terraform AI resources, GitHub Actions |

> See [AI Infrastructure Scanning Guide](docs/AI_INFRASTRUCTURE_SCANNING.md) for GPU container scanning examples (NVIDIA + AMD ROCm).

---

## Trust & permissions

- **`--dry-run`** — preview every file and API URL before access, then exit without reading anything
- **[PERMISSIONS.md](PERMISSIONS.md)** — auditable trust contract with all config paths enumerated
- **Read-only** — never writes configs, runs servers, provisions resources, or stores secrets
- **Credential redaction** — only env var **names** in reports; values, tokens, passwords never read
- **Sigstore signed** — releases v0.7.0+ signed via cosign OIDC; verify PyPI integrity with `agent-bom verify agent-bom@0.36.1` (SHA-256 + SLSA provenance)
- **No binary needed (MCP)** — SSE transport requires zero local install; local CLI available for air-gapped use
- **OpenSSF Scorecard** — [automated supply chain scoring](https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom)

---

## Roadmap

**Shipped:**
- [x] Cloud AI inventory — AWS Bedrock, Azure AI Foundry, GCP Vertex, Snowflake Cortex, Databricks, Nebius
- [x] Tool poisoning / prompt injection detection — `--enforce` with description injection, capability combos, CVE exposure, drift
- [x] Model weight provenance — SHA-256 hash, Sigstore file detection, HuggingFace metadata (`--model-provenance`, `--hf-model`)
- [x] 18 MCP client discovery — Codex CLI, Gemini CLI, Goose, Snowflake CLI, full Cortex Code (CoCo) coverage
- [x] K8s AI workload discovery — `--k8s --all-namespaces` with pod-level scanning
- [x] OWASP MCP Top 10 compliance mapping — MCP01–MCP10 risk tagging
- [x] Malicious package detection — OSV MAL- prefix flagging + typosquat heuristics
- [x] OpenSSF Scorecard enrichment — `--scorecard` for package health scoring
- [x] AI framework package recognition — GPU/ML packages (CUDA, ROCm, vLLM, JAX, etc.) flagged as high-risk in image scans
- [x] Runtime MCP proxy — opt-in stdio proxy (`agent-bom proxy`) wraps individual MCP server commands for traffic interception; requires per-server client reconfiguration
- [x] Enterprise integrations — Jira, Slack, Vanta, Drata
- [x] Runtime sidecar Docker container — `Dockerfile.runtime` + Docker Compose for MCP proxy deployment
- [x] EU AI Act compliance mapping — ART-5 through ART-17 risk classification
- [x] OWASP Agentic Top 10 — ASI01 through ASI10 agent-specific risk tagging
- [x] Marketplace trust check — `marketplace_check` MCP tool for pre-install validation
- [x] OpenTelemetry trace ingestion — `POST /v1/traces` for vulnerable tool call flagging
- [x] CMMC/FedRAMP compliance evidence export — `--compliance-export` ZIP bundles
- [x] Agent spawn tree visualization — parent-child delegation chains
- [x] RSP v3.0 alignment badge — Anthropic Responsible Scaling Policy compliance indicator
- [x] Claude Code config security scanner — Check Point CVE vector detection
- [x] Over-permission analyzer — mission profile enforcement per agent type
- [x] Alert pipeline — AlertDispatcher with Slack, webhook, and in-memory channels; auto-trigger on scan
- [x] Runtime protection engine — unified 5-detector orchestration with OTel trace ingestion
- [x] Multi-tenant fleet — tenant_id scoping, X-Tenant-ID header, per-tenant stats

**Planned:**
- [ ] CIS AI benchmarks
- [ ] License compliance engine
- [ ] Workflow engine scanning (n8n, Zapier, Make)

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
