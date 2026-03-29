<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/logo-light.svg" alt="agent-bom" width="480" />
  </picture>
</p>

<p align="center">
  <a href="https://github.com/msaad00/agent-bom/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/msaad00/agent-bom/ci.yml?branch=main&style=flat&label=Build" alt="Build"></a>
  <a href="https://pypi.org/project/agent-bom/"><img src="https://img.shields.io/pypi/v/agent-bom?style=flat&label=Latest%20version" alt="PyPI"></a>
  <a href="https://hub.docker.com/r/agentbom/agent-bom"><img src="https://img.shields.io/docker/pulls/agentbom/agent-bom?style=flat&label=Docker%20pulls" alt="Docker"></a>
  <a href="https://github.com/msaad00/agent-bom/blob/main/LICENSE"><img src="https://img.shields.io/badge/License-Apache%202.0-blue?style=flat" alt="License"></a>
  <a href="https://securityscorecards.dev/viewer/?uri=github.com/msaad00/agent-bom"><img src="https://img.shields.io/ossf-scorecard/github.com/msaad00/agent-bom?style=flat&label=OpenSSF%20scorecard" alt="OpenSSF Scorecard"></a>
</p>
<!-- mcp-name: io.github.msaad00/agent-bom -->

<p align="center"><b>Open security platform for agentic infrastructure. Broad scanning, blast radius, runtime, and trust.</b></p>

<p align="center"><b>Your AI agent's dependencies have a CVE. Which credentials leak?</b></p>

```text
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  |── better-sqlite3@9.0.0  (npm)
       |── sqlite-mcp  (MCP Server · unverified · root)
            |── Cursor IDE  (Agent · 4 servers · 12 tools)
            |── ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            |── query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

**agent-bom maps the blast radius**: CVE → package → MCP server → AI agent → credentials → tools.

Traditional scanners often stop at `CVE → package`. agent-bom shows which credentials and tools are actually at risk — with CWE-aware impact classification so a DoS vuln doesn't falsely claim credential exposure.

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-latest.gif" alt="agent-bom demo" width="900" />
</p>

## Quick start

```bash
pip install agent-bom

agent-bom agents                              # Discover + scan local AI agents and MCP servers
agent-bom agents -p .                         # Scan project manifests plus agent/MCP context
agent-bom check flask@2.0.0 --ecosystem pypi  # Pre-install CVE gate
agent-bom image nginx:latest                  # Container image scan
agent-bom iac Dockerfile k8s/ infra/main.tf   # IaC misconfigurations
```

<details>
<summary><b>More commands</b></summary>

```bash
agent-bom cloud aws                     # Cloud AI posture + CIS benchmarks
agent-bom agents -f cyclonedx -o bom.json  # AI BOM / SBOM export
agent-bom proxy "npx @mcp/server-fs /ws"   # MCP security proxy
agent-bom secrets src/                  # Hardcoded secrets + PII
agent-bom verify requests@2.33.0        # Package integrity verification
agent-bom serve                         # API + Next.js dashboard
```

</details>

---

## How it works

```mermaid
flowchart LR
    DISCOVER["🔍 Discover\n30 MCP clients\nProjects · Images · Cloud"] --> SCAN["🛡️ Scan\n15 ecosystems\nCVE · Secrets · IaC"]
    SCAN --> ANALYZE["📊 Analyze\nBlast radius\n14 frameworks · CWE impact"]
    ANALYZE --> OUTPUT["📤 Output\nCI/CD gates · SARIF · SBOM\nAPI · Dashboard · MCP tools"]
    DISCOVER -.-> PROTECT["🔒 Protect\nRuntime proxy\nShield SDK · policy"]

    style DISCOVER stroke:#58a6ff,stroke-width:2px
    style SCAN stroke:#f85149,stroke-width:2px
    style ANALYZE stroke:#d29922,stroke-width:2px
    style OUTPUT stroke:#3fb950,stroke-width:2px
    style PROTECT stroke:#f778ba,stroke-width:2px,stroke-dasharray: 5 5
```

### Blast radius — what makes agent-bom different

```mermaid
flowchart LR
    CVE["🔴 CVE-2025-1234\nCRITICAL · CVSS 9.8\nCISA KEV · EPSS 94%"]
    PKG["📦 better-sqlite3\n@9.0.0"]
    SRV["🔧 sqlite-mcp\nMCP Server"]
    AGT["🤖 Cursor IDE\n4 servers · 12 tools"]
    CRED["🔑 ANTHROPIC_KEY\nDB_URL · AWS_SECRET"]

    CVE --> PKG --> SRV --> AGT --> CRED

    style CVE stroke:#f85149,stroke-width:2px
    style PKG stroke:#d29922,stroke-width:2px
    style SRV stroke:#58a6ff,stroke-width:2px
    style AGT stroke:#3fb950,stroke-width:2px
    style CRED stroke:#f85149,stroke-width:2px
```

Blast radius is **CWE-aware**: an RCE (CWE-94) shows full credential exposure, a DoS (CWE-400) does not. Impact categories: code-execution, credential-access, file-access, injection, ssrf, data-leak, availability, client-side.

---

## What it scans

| Source | Details |
|--------|---------|
| **AI agents + MCP servers** | 30 client types auto-detected (Claude Desktop, Cursor, Windsurf, VS Code, Codex CLI, Gemini CLI, and more) |
| **AI supply chain** | Blast radius mapping, dependency confusion detection, CWE-aware impact classification |
| **Packages** | 15 ecosystems — Python, Node.js, Go, Rust, Java, .NET, Ruby, PHP, Swift, Conda, Alpine, Debian, RPM |
| **Vulnerabilities** | OSV + NVD + GHSA + EPSS + CISA KEV, VEX generation, reachability analysis |
| **Container images + K8s** | Native OCI parser, Docker images, running containers, Kubernetes pod scanning |
| **IaC** | Dockerfile, Terraform, CloudFormation, Helm, Kubernetes manifests (138 rules) |
| **Cloud AI + GPU infra** | AWS Bedrock/SageMaker, Azure AI, GCP Vertex, Databricks, Snowflake, GPU/DCGM probes |
| **AI platforms** | HuggingFace, W&B, Ollama, OpenAI, vector databases (Pinecone, Weaviate, ChromaDB) |
| **AI code + models** | AST analysis (10+ frameworks), 13 model formats, provenance + hash verification |
| **Secrets + PII** | 34 credential patterns + 11 PII patterns across source, config, and .env files |
| **SBOM** | CycloneDX 1.6 with ML BOM extensions, SPDX 3.0, ingests existing SBOMs |
| **Instruction files** | CLAUDE.md, .cursorrules, AGENTS.md — trust analysis + tool poisoning detection |

**Read-only. Agentless. No secrets leave your machine.**

---

## Runtime protection

MCP security proxy with 112 detection patterns, 8 detectors, PII redaction, and kill switch:

```bash
agent-bom proxy "npx @mcp/server-filesystem /workspace"
```

**Shield SDK** — drop-in Python middleware:
```python
from agent_bom.shield import Shield
shield = Shield(deep=True)
alerts = shield.check_tool_call("exec", {"command": "rm -rf /"})
safe = shield.redact(response_text)  # [REDACTED:OpenAI API Key]
```

---

## Compliance (14 frameworks)

Every finding is tagged with mapped framework controls:

| Framework | Coverage |
|-----------|----------|
| OWASP LLM Top 10 | 10 mapped categories |
| OWASP MCP Top 10 | 10 mapped categories |
| OWASP Agentic Top 10 | 10 mapped categories |
| MITRE ATLAS | 65 mapped techniques |
| MITRE ATT&CK Enterprise | Official MITRE catalog via fetched ATT&CK data |
| NIST AI RMF 1.0 | 14 mapped subcategories |
| NIST CSF 2.0 | 14 mapped categories |
| NIST 800-53 Rev 5 | 29 mapped controls |
| FedRAMP Moderate | 25 mapped controls |
| ISO 27001:2022 | 9 controls |
| SOC 2 TSC | 9 mapped criteria |
| CIS Controls v8 | 10 mapped controls |
| EU AI Act | 6 articles |
| CMMC 2.0 Level 2 | 17 practices |

---

## Install & deploy

```bash
pip install agent-bom                        # CLI
docker run --rm agentbom/agent-bom agents    # Docker
```

| Mode | Command | Best for |
|------|---------|----------|
| CLI | `agent-bom agents` | Local audit |
| GitHub Action | `uses: msaad00/agent-bom@v0.75.11` | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom` | Isolated scans |
| MCP Server | `agent-bom mcp server` | Inside AI assistants |
| Runtime proxy | `agent-bom proxy` | MCP traffic enforcement |
| Shield SDK | `from agent_bom.shield import Shield` | In-process protection |
| Dashboard | `agent-bom serve` | API + Next.js UI (20 pages) |

<details>
<summary><b>GitHub Action</b></summary>

```yaml
- uses: msaad00/agent-bom@v0.75.11
  with:
    scan-type: scan
    severity-threshold: high
    upload-sarif: true
    enrich: true
    fail-on-kev: true
```

</details>

<details>
<summary><b>Install extras</b></summary>

| Extra | Command |
|-------|---------|
| Cloud providers | `pip install 'agent-bom[cloud]'` |
| MCP server | `pip install 'agent-bom[mcp-server]'` |
| REST API | `pip install 'agent-bom[api]'` |
| Dashboard | `pip install 'agent-bom[ui]'` |

</details>

<details>
<summary><b>Output formats (19)</b></summary>

JSON, SARIF, CycloneDX 1.6 (with ML BOM), SPDX 3.0, HTML, Graph JSON, Graph HTML, GraphML, Neo4j Cypher, JUnit XML, CSV, Markdown, Mermaid, SVG, Prometheus, Badge, OCSF, Attack Flow, plain text.

</details>

---

## MCP server

33 security tools available inside any MCP-compatible AI assistant:

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

Also on [Glama](https://glama.ai/mcp/servers/@msaad00/agent-bom), [Smithery](integrations/smithery.yaml), [MCP Registry](integrations/mcp-registry/server.json), and [OpenClaw](integrations/openclaw/SKILL.md).

---

## Trust & transparency

| When | What's sent | Where | Opt out |
|---|---|---|---|
| Default CVE lookups (`agents`, `scan`, `check`, `image`) | Package names + versions | OSV API | `--offline` |
| Floating version resolution | Package names, requested version/latest lookup | npm, PyPI, Go proxy | `--offline` |
| `--enrich` | CVE IDs | NVD, EPSS; KEV catalog download from CISA | Don't use `--enrich` |
| `--deps-dev` | Package names + versions | deps.dev | Don't use `--deps-dev` |
| `verify` | Package name + version | PyPI or npm integrity endpoints | Don't run `verify` |
| Optional push/integrations | Finding summaries or evidence bundles | Slack, Jira, Vanta, Drata | Don't pass those flags |

No source code, config contents, or credential values are sent. No telemetry or analytics. [Sigstore-signed](docs/PERMISSIONS.md) releases. See [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) and [PERMISSIONS.md](docs/PERMISSIONS.md) for the full trust model.

---

## Contributing

```bash
git clone https://github.com/msaad00/agent-bom.git && cd agent-bom
pip install -e ".[dev]"
pytest && ruff check src/
```

See [CONTRIBUTING.md](CONTRIBUTING.md) | [SECURITY.md](SECURITY.md) | [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md)

---

Apache 2.0 — [LICENSE](LICENSE)
