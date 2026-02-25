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
  <b>AI Bill of Materials generator. CVE scanning for AI agents and MCP servers. Blast radius mapping. Privilege detection. OWASP LLM Top 10 + MITRE ATLAS + NIST AI RMF.</b>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/architecture-light.svg" alt="agent-bom architecture" width="800" style="padding: 20px 0" />
  </picture>
</p>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/blast-radius-light.svg" alt="Blast radius attack surface" width="800" style="padding: 20px 0" />
  </picture>
</p>

---

## Why agent-bom?

> **Grype tells you a package has a CVE.**
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
| Package CVE detection | Yes | Yes — OSV + NVD CVSS v4 + EPSS + CISA KEV |
| SBOM generation | Yes (Syft) | Yes — CycloneDX 1.6, SPDX 3.0, SARIF |
| **AI agent discovery** | — | 13 MCP clients + Docker Compose auto-discovered |
| **Blast radius mapping** | — | CVE → package → server → agent → credentials → tools |
| **Credential exposure** | — | Which secrets leak per vulnerability, per agent |
| **MCP tool reachability** | — | Which tools an attacker reaches post-exploit |
| **Privilege detection** | — | runs_as_root, shell_access, container_privileged, per-tool permissions |
| **Enterprise remediation** | — | Named assets, impact percentages, risk narratives |
| **Triple-framework tagging** | — | OWASP LLM Top 10 + MITRE ATLAS + NIST AI RMF |
| **Policy-as-code** | — | Block unverified servers, enforce thresholds in CI/CD |
| **427+ server MCP registry** | — | Risk levels, tool inventories, auto-synced weekly |

<table>
<tr>
<td width="50%" valign="top">

**What it scans:**

| Source | How |
|--------|-----|
| MCP configs | Auto-discover (13 clients + Docker Compose) |
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
| GitHub Action | `uses: msaad00/agent-bom@v0.31.8` |
| MCP Registry | [server.json](integrations/mcp-registry/server.json) |
| ToolHive | [registry entry](integrations/toolhive/server.json) |
| OpenClaw | [SKILL.md](integrations/openclaw/SKILL.md) |
| Smithery | [smithery.yaml](smithery.yaml) |
| Railway | [Dockerfile.sse](Dockerfile.sse) |

</td>
</tr>
</table>

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/deployment-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/deployment-light.svg" alt="Enterprise deployment topology" width="800" style="padding: 20px 0" />
  </picture>
</p>

---

## Get started

```bash
pip install agent-bom

agent-bom scan                                     # auto-discover + scan
agent-bom scan --enrich                            # + NVD CVSS + EPSS + CISA KEV
agent-bom scan -f html -o report.html              # HTML dashboard
agent-bom scan --fail-on-severity high -q          # CI gate
agent-bom scan --image myapp:latest                # Docker image scanning
agent-bom scan --k8s --all-namespaces              # K8s cluster
agent-bom scan --aws --snowflake --databricks      # Multi-cloud
```

Auto-discovers Claude Desktop, Claude Code, Cursor, Windsurf, Cline, VS Code Copilot, Continue, Zed, Cortex Code, OpenClaw, ToolHive, Docker MCP Toolkit, and VS Code native MCP.

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

### Triple-framework threat mapping

Every finding is tagged against three frameworks simultaneously:

- **OWASP LLM Top 10** — LLM01 through LLM10 (6 categories triggered)
- **MITRE ATLAS** — AML.T0010, AML.T0043, AML.T0051, etc. (8 techniques mapped)
- **NIST AI RMF 1.0** — Govern, Map, Measure, Manage (12 subcategories mapped)

### Enterprise remediation

Each fix tells you exactly what will be protected — named agents, credentials, tools, percentages, threat tags, and risk narratives.

### AI-BOM export

```bash
agent-bom scan -f cyclonedx -o ai-bom.cdx.json   # CycloneDX 1.6
agent-bom scan -f spdx -o ai-bom.spdx.json       # SPDX 3.0
agent-bom scan -f sarif -o results.sarif           # GitHub Security tab
agent-bom scan -f json -o ai-bom.json             # Full AI-BOM
agent-bom scan -f html -o report.html              # Interactive dashboard
```

### Policy-as-code

```bash
agent-bom scan --policy policy.json --fail-on-severity high
```

### Cloud provider discovery

```bash
agent-bom scan --aws --aws-region us-east-1       # Bedrock, Lambda, EKS, ECS, SageMaker, EC2
agent-bom scan --snowflake                         # Cortex Agents, MCP Servers, Search, Snowpark
agent-bom scan --databricks                        # Cluster libraries, model serving
agent-bom scan --nebius --nebius-project-id proj   # GPU cloud K8s + containers
agent-bom scan --k8s --context=coreweave-cluster   # CoreWeave / any K8s
```

<details>
<summary><b>Cloud provider details</b></summary>

| Provider | What's discovered | Install |
|----------|------------------|---------|
| **AWS** | Bedrock agents, Lambda, EKS, Step Functions, EC2, ECS, SageMaker | `pip install 'agent-bom[aws]'` |
| **Snowflake** | Cortex Agents, native MCP Servers, Search, Snowpark, Streamlit, query history | `pip install 'agent-bom[snowflake]'` |
| **Databricks** | Cluster packages, model serving endpoints | `pip install 'agent-bom[databricks]'` |
| **Azure** | AI Foundry agents, Container Apps | `pip install 'agent-bom[azure]'` |
| **GCP** | Vertex AI endpoints, Cloud Run | `pip install 'agent-bom[gcp]'` |
| **Nebius** | Managed K8s, container services | `pip install 'agent-bom[nebius]'` |
| **CoreWeave** | K8s-native — `--k8s --context=coreweave-cluster` | (core CLI) |
| **Ollama** | Local model inventory via API + manifests | (core CLI) |

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
<summary><b>Jupyter notebook + model file scanning</b></summary>

Detect 29+ AI libraries, pip installs, credentials in notebooks. Scan 13 model file formats with security flags for pickle-based formats.

```bash
agent-bom scan --jupyter ./notebooks
agent-bom scan --model-files ./models
```

</details>

<details>
<summary><b>Attack flow visualization</b></summary>

CLI attack flow tree, interactive HTML graphs (Cytoscape.js), per-CVE React Flow diagrams via REST API.

```bash
agent-bom scan --aws -f graph -o graph.json   # export graph data
```

</details>

---

## Deployment

| Mode | Command | Best for |
|------|---------|----------|
| CLI | `agent-bom scan` | Local audit |
| Pre-install check | `agent-bom check express@4.18.2 -e npm` | Before running MCP servers |
| GitHub Action | `uses: msaad00/agent-bom@v0.31.8` | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom scan` | Isolated scans |
| REST API | `agent-bom api` | Dashboards, SIEM |
| MCP Server | `agent-bom mcp-server` | Inside any MCP client |
| Dashboard | `agent-bom serve` | Team UI |
| Prometheus | `--push-gateway` / `--otel-endpoint` | Monitoring |

### GitHub Action

```yaml
- uses: msaad00/agent-bom@v0.31.8
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

### MCP Server

```bash
pip install agent-bom[mcp-server]
agent-bom mcp-server                    # stdio
agent-bom mcp-server --transport sse    # remote
```

8 tools: `scan`, `check`, `blast_radius`, `policy_check`, `registry_lookup`, `generate_sbom`, `compliance`, `remediate`

### Cloud UI

```bash
cd ui && npm install && npm run dev   # http://localhost:3000
```

Security posture dashboard, vulnerability explorer, attack flow diagrams, supply chain graph, registry browser, enterprise scan form.

---

## MCP Server Registry (427+ servers)

Curated registry of 427+ known MCP servers with risk levels, tool inventories, credential env vars, categories, and version pins. Auto-synced weekly from the [Official MCP Registry](https://registry.modelcontextprotocol.io). Unverified servers trigger warnings. Policy rules can block them in CI.

Browse: [mcp_registry.json](src/agent_bom/mcp_registry.json) | Expand: `python scripts/expand_registry.py`

---

## AI supply chain coverage

| Layer | Coverage | Examples |
|-------|----------|----------|
| **GPU clouds** | `--k8s` | CoreWeave, Lambda Labs, Paperspace |
| **AI platforms** | Cloud modules | Bedrock, Vertex AI, Snowflake Cortex, Databricks |
| **Containers** | `--image` | NVIDIA NIM, vLLM, Ollama, any OCI image |
| **AI frameworks** | Dependency scan | LangChain, LlamaIndex, AutoGen, PyTorch |
| **MCP ecosystem** | Auto-discovery + registry | 13 clients, 427+ servers |
| **LLM providers** | API key + SDK detection | OpenAI, Anthropic, Cohere, Mistral |
| **IaC + CI/CD** | `--tf-dir`, `--gha` | Terraform AI resources, GitHub Actions |

---

## Trust & permissions

- **`--dry-run`** — preview every file and API URL before access
- **[PERMISSIONS.md](PERMISSIONS.md)** — auditable trust contract
- **Read-only** — never writes configs, runs servers, or stores secrets
- **Sigstore signed** — releases v0.7.0+ signed via cosign
- **Credential redaction** — only env var **names** in reports

---

## Roadmap

- [ ] CIS AI benchmarks
- [ ] Agent guardrails engine — runtime policy enforcement
- [ ] EU AI Act compliance mapping
- [ ] Multi-language SDK detection (Go, Rust, Java)
- [ ] Workflow engine scanning (n8n, Zapier, Make)
- [ ] License compliance engine

---

## Contributing

```bash
git clone https://github.com/msaad00/agent-bom.git && cd agent-bom
pip install -e ".[dev]"
pytest && ruff check src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) | [SECURITY.md](SECURITY.md) | [Skills](skills/)

---

Apache 2.0 — [LICENSE](LICENSE)
