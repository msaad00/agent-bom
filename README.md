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
# AI infrastructure & MCP agents
agent-bom scan                          # auto-detect agents + scan for CVEs
agent-bom mcp                          # discover + scan MCP agents only
agent-bom check flask@2.0.0            # pre-install CVE gate
agent-bom runtime proxy "npx server"   # runtime enforcement

# Also scans traditional infrastructure
agent-bom image nginx:latest           # container image scan
agent-bom fs /mnt/vm-snapshot          # filesystem / VM scan
agent-bom iac Dockerfile k8s/          # IaC misconfigurations
agent-bom cloud aws                    # AWS posture + CIS benchmarks
```

<details>
<summary><b>All commands</b></summary>

```
Scanning:           scan, image, fs, iac, sbom, check, guard, verify
MCP & AI Agents:    mcp, cloud, run
Runtime:            runtime [proxy|protect|watch|audit|configure]
Reporting:          report [history|diff|rescan|analytics|dashboard], graph
Policy:             policy [template|apply]
Infrastructure:     serve, api, db, schedule, registry
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

32 scanning tools available inside any MCP-compatible AI assistant.

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
