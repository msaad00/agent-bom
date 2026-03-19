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

<p align="center"><b>Your AI agent has a CVE. Which credentials leak?</b></p>

```
CVE-2025-1234  (CRITICAL · CVSS 9.8 · CISA KEV)
  |── better-sqlite3@9.0.0  (npm)
       |── sqlite-mcp  (MCP Server · unverified · root)
            |── Cursor IDE  (Agent · 4 servers · 12 tools)
            |── ANTHROPIC_KEY, DB_URL, AWS_SECRET  (Credentials exposed)
            |── query_db, read_file, write_file, run_shell  (Tools at risk)

 Fix: upgrade better-sqlite3 → 11.7.0
```

**agent-bom maps the blast radius**: CVE → package → MCP server → AI agent → credentials → tools. One command, zero config.

```bash
pip install agent-bom
agent-bom scan
```

<p align="center">
  <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/demo-v0.72.0.gif" alt="agent-bom scan demo" width="900" />
</p>

---

## What it does

Security scanner purpose-built for AI infrastructure and supply chain.

1. **Discovers** AI agents and MCP servers — auto-detects configs across Claude Desktop, Cursor, Windsurf, VS Code Copilot, and 26 more clients (30 total)
2. **Generates an AI BOM** — inventory of every agent, server, package, credential, and tool in your AI stack
3. **Scans for CVEs** — checks every dependency against OSV + NVD + GHSA + EPSS + CISA KEV
4. **Maps blast radius** — shows which agents, credentials, and tools each CVE can reach
5. **Enforces at runtime** — MCP proxy intercepts tool calls, detects rug pulls, blocks credential leaks

Also scans container images, filesystems, IaC files, and cloud infrastructure (AWS/Azure/GCP).

Read-only. Agentless. No secrets leave your machine.

---

## Quick start

```bash
pip install agent-bom                   # installs all 5 products
```

### agent-bom — BOM generation + vulnerability scanning
```bash
agent-bom scan                          # auto-detect agents + scan for CVEs
agent-bom check flask@2.0.0            # pre-install CVE gate
agent-bom image nginx:latest           # container image scan
agent-bom graph report.json -f graphml # dependency graph (GraphML/Neo4j/DOT)
agent-bom mcp inventory                # discover MCP agents + servers
```

### agent-shield — runtime protection
```bash
agent-shield proxy "npx @mcp/server-fs /tmp"   # MCP proxy with audit
agent-shield protect --shield                    # deep defense (7 detectors)
agent-shield run "npx @mcp/server-github"        # zero-config proxy launch
```

### agent-cloud — cloud infrastructure scanning
```bash
agent-cloud aws                         # AWS Bedrock/Lambda + CIS v3.0
agent-cloud azure                       # Azure AI Foundry + CIS v2.0
agent-cloud gcp                         # GCP Vertex AI + CIS v3.0
agent-cloud posture                     # unified cross-cloud summary
```

### agent-iac — IaC security
```bash
agent-iac scan Dockerfile k8s/ infra/main.tf    # 89 rules across 5 formats
agent-iac policy template                        # generate starter policy
```

### agent-claw — fleet governance
```bash
agent-claw serve                        # API server + dashboard
agent-claw fleet sync                   # discovery → fleet registry
agent-claw report analytics --days 30   # vulnerability trends
```

<details>
<summary><b>All commands by product</b></summary>

```
agent-bom:     scan, check, verify, image, fs, sbom, graph, diff, mcp, db, upgrade
agent-shield:  proxy, protect, run, guard, watch, audit, configure
agent-cloud:   aws, azure, gcp, snowflake, databricks, huggingface, ollama, posture
agent-iac:     scan, policy, validate
agent-claw:    fleet, serve, api, schedule, report, connectors
```

</details>

---

## Instruction file trust

AI agents run on instruction files — CLAUDE.md, .cursorrules, AGENTS.md. A malicious instruction file is a supply chain attack with full agent permissions.

```
agent-bom scan --skill-only

CLAUDE.md  →  SUSPICIOUS (high confidence)
  [CRITICAL] Credential/secret file access
             "cat ~/.aws/credentials" detected — reads secret files
  [HIGH]     Safety confirmation bypass
             "--dangerously-skip-permissions" found — disables all guardrails
  [HIGH]     Typosquatting risk: server name "filessystem" (→ filesystem)
```

---

## MCP server

33 scanning tools available inside any MCP-compatible AI assistant.

```bash
pip install 'agent-bom[mcp-server]'
agent-bom mcp server
```

```json
{
  "mcpServers": {
    "agent-bom": {
      "command": "agent-bom",
      "args": ["mcp", "server"]
    }
  }
}
```

Also on [Glama](https://glama.ai/mcp/servers/@msaad00/agent-bom), [Smithery](integrations/smithery.yaml), [MCP Registry](integrations/mcp-registry/server.json), and [OpenClaw](integrations/openclaw/SKILL.md).

---

## Install & deploy

```bash
pip install agent-bom                  # CLI
docker run --rm agentbom/agent-bom scan  # Docker (linux/amd64 + arm64)
```

| Mode | Command | Best for |
|------|---------|----------|
| CLI | `agent-bom scan` | Local audit |
| GitHub Action | `uses: msaad00/agent-bom@v0` | CI/CD + SARIF |
| Docker | `docker run agentbom/agent-bom scan` | Isolated scans |
| MCP Server | `agent-bom mcp server` | Inside any AI assistant |
| Runtime proxy | `agent-bom runtime proxy` | Enforce MCP traffic |
| Dashboard | `agent-bom serve` | API + Next.js UI |

<details>
<summary><b>GitHub Action</b></summary>

```yaml
- uses: msaad00/agent-bom@v0
  with:
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
| Cloud (all) | `pip install 'agent-bom[cloud]'` |
| MCP server | `pip install 'agent-bom[mcp-server]'` |
| REST API | `pip install 'agent-bom[api]'` |
| Dashboard | `pip install 'agent-bom[ui]'` |

</details>

---

## How it works

<p align="center">
  <picture>
    <source media="(prefers-color-scheme: dark)" srcset="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-dark.svg">
    <img src="https://raw.githubusercontent.com/msaad00/agent-bom/main/docs/images/scan-pipeline-light.svg" alt="Scan pipeline" width="800" />
  </picture>
</p>

1. **Discover** — auto-detect MCP configs, Docker images, K8s pods, cloud resources, model files
2. **Scan** — package names + versions sent to OSV.dev, NVD, EPSS, CISA KEV (no secrets leave your machine)
3. **Analyze** — blast radius mapping, tool poisoning detection, compliance tagging, posture scoring
4. **Report** — JSON, SARIF, CycloneDX 1.6, SPDX 3.0, HTML, JUnit XML, and more

<details>
<summary><b>What it scans</b></summary>

| Source | How |
|--------|-----|
| MCP configs | Auto-discover (30 clients + Docker Compose) |
| Docker images | Grype / Syft / Docker CLI fallback |
| Kubernetes | kubectl across namespaces |
| Cloud providers | AWS, Azure, GCP, Databricks, Snowflake |
| AI platforms | OpenAI, HuggingFace, W&B, MLflow, Ollama |
| IaC files | Dockerfile, K8s, Terraform, CloudFormation (82 rules) |
| Model files | 13 formats (.gguf, .safetensors, .pkl, ...) |
| Instruction files | CLAUDE.md, .cursorrules, AGENTS.md |
| Existing SBOMs | CycloneDX / SPDX import |
| 11 ecosystems | Python, Node.js, Go, Rust, Java, .NET, Ruby, PHP, Swift, Conda, MCP |

</details>

<details>
<summary><b>Output formats</b></summary>

JSON, SARIF, CycloneDX 1.6, SPDX 3.0, HTML, JUnit XML, CSV, Markdown, Mermaid, SVG, Graph HTML, Prometheus, Badge — 15 formats total.

```bash
agent-bom scan -f sarif -o results.sarif     # GitHub Security tab
agent-bom scan -f html -o report.html        # Interactive dashboard
agent-bom scan -f cyclonedx -o sbom.json     # CycloneDX 1.6
```

</details>

---

## Trust & transparency

| When | What's sent | Where | Opt out |
|---|---|---|---|
| `agent-bom scan` | Package names + versions only | OSV API | `--offline` |
| `--enrich` | CVE IDs only | NVD, EPSS, KEV APIs | Don't use `--enrich` |
| Everything else | **Nothing** | Nowhere | N/A |

No source code, no secrets, no telemetry ever leave your machine. Every release is [Sigstore-signed](docs/PERMISSIONS.md). See [SECURITY_ARCHITECTURE.md](docs/SECURITY_ARCHITECTURE.md) for the full trust model.

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

See [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) for full diagrams. New to MCP security? [docs/MCP_SECURITY_MODEL.md](docs/MCP_SECURITY_MODEL.md) explains attack vectors and how agent-bom addresses them.

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
