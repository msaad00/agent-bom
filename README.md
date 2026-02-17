# agent-bom

[![CI](https://github.com/agent-bom/agent-bom/actions/workflows/ci.yml/badge.svg)](https://github.com/agent-bom/agent-bom/actions/workflows/ci.yml)
[![PyPI version](https://img.shields.io/pypi/v/agent-bom)](https://pypi.org/project/agent-bom/)
[![License](https://img.shields.io/badge/license-Apache%202.0-blue.svg)](LICENSE)
[![Docker Pulls](https://img.shields.io/docker/pulls/agentbom/agent-bom)](https://hub.docker.com/r/agentbom/agent-bom)

**AI Bill of Materials (AI-BOM) generator for AI agents and MCP servers.**

`agent-bom` maps the full trust chain from AI agent → MCP server → packages → known vulnerabilities, with **blast radius analysis**: *"If this package is compromised, which agents are affected, what credentials are exposed, and what tools can an attacker reach?"*

---

## Why agent-bom?

Existing tools scan for prompt injection or inventory AI models. **Nobody maps the full dependency chain from agent to vulnerability.**

Traditional SBOMs stop at the package layer. `agent-bom` goes deeper:

```
Agent (Claude Desktop)
  └── MCP Server (database-server)
        ├── Tool: query_database (read/write)
        ├── Credentials: DB_PASSWORD, API_KEY
        └── Packages:
              ├── express@4.18.2 ← CVE-2024-XXXX (HIGH)
              └── axios@1.6.0   ← CVE-2024-YYYY (CRITICAL)
                    ↑
                    Blast Radius: 3 agents, 2 credentials exposed, 5 tools reachable
```

A vulnerable package means every agent connected to that MCP server inherits the risk — credentials included.

---

## Install

```bash
pip install agent-bom
```

From source:

```bash
git clone https://github.com/agent-bom/agent-bom.git
cd agent-bom
pip install -e .
```

---

## Quick Start

| Command | What it does |
|---------|-------------|
| `agent-bom scan` | Discover agents + extract deps + scan for CVEs |
| `agent-bom scan --transitive` | Include transitive dependencies |
| `agent-bom scan --enrich` | Add NVD / EPSS / CISA KEV data |
| `agent-bom scan --project /path` | Scan a specific project directory |
| `agent-bom scan --config-dir /path` | Scan a custom agent config directory |
| `agent-bom scan --inventory agents.json` | Load agents from a manual inventory file |
| `agent-bom scan -f cyclonedx -o bom.json` | Export CycloneDX 1.6 BOM |
| `agent-bom scan -f json -o report.json` | Export JSON report |
| `agent-bom scan -f sarif -o bom.sarif` | Export SARIF for GitHub Security tab |
| `agent-bom scan -f json -o - \| jq .` | Pipe clean JSON to stdout |
| `agent-bom scan -q --fail-on-severity high` | CI gate — exit 1 if high+ vulns found |
| `agent-bom inventory` | List discovered agents (no vuln scan) |
| `agent-bom where` | Show where configs are looked up |

---

## Features

- **Auto-discovery** — Claude Desktop, Claude Code, Cursor, Windsurf, Cline, and project-level `.mcp.json`
- **Multi-ecosystem** — npm, pip, Go, Cargo (lock files + manifest files)
- **npx / uvx detection** — extracts package names from MCP server command definitions
- **Transitive resolution** — recursively resolves nested deps via npm and PyPI registries
- **Vulnerability scanning** — queries [OSV.dev](https://osv.dev) across all ecosystems
- **Enrichment** — NVD metadata, EPSS exploit probability, CISA KEV flags (`--enrich`)
- **Blast radius scoring** — contextual risk score based on agents, credentials, and tools in reach
- **Credential detection** — flags MCP servers exposing API keys, tokens, and secrets in env vars
- **Output formats** — rich console, JSON, CycloneDX 1.6, SARIF 2.1, plain text
- **CI/CD ready** — `--fail-on-severity`, `--quiet`, stdout piping (`-o -`)

---

## Supported Platforms

### Auto-discovered (local MCP clients)

| Client | macOS | Linux | Windows |
|--------|:-----:|:-----:|:-------:|
| Claude Desktop | ✅ | ✅ | ✅ |
| Claude Code | ✅ | ✅ | ✅ |
| Cursor | ✅ | ✅ | ✅ |
| Windsurf | ✅ | ✅ | ✅ |
| Cline | ✅ | ✅ | ✅ |

### Manual scan (any MCP config)

Use `--config-dir` or `--inventory` to scan any agent not listed above — including custom agents, OpenAI-based tools, LangChain apps, or anything that uses MCP servers.

### Cloud platforms (planned)

| Platform | Status | How it would work |
|----------|:------:|-------------------|
| Snowflake Cortex | Planned | Query `ACCOUNT_USAGE.QUERY_HISTORY` for `CREATE MCP SERVER` / `CREATE OR REPLACE AGENT` |
| AWS Bedrock Agents | Planned | List agents via Bedrock API, extract action group configs |
| Google Vertex AI | Planned | Discover agents + extensions via Vertex API |
| OpenAI Assistants | Planned | List assistants + tool definitions via OpenAI API |

### Package ecosystems scanned

| Ecosystem | Lock files | AI frameworks covered |
|-----------|-----------|----------------------|
| npm | `package-lock.json`, `package.json` | LangChain.js, Vercel AI SDK, etc. |
| pip | `requirements.txt`, `Pipfile.lock`, `pyproject.toml` | LangChain, LlamaIndex, transformers, openai, mistralai, etc. |
| Go | `go.sum` | — |
| Cargo | `Cargo.lock` | — |

AI framework packages (LangChain, transformers, openai, mistralai, etc.) are already scanned for CVEs like any other package. Future releases will add AI-specific risk analysis.

---

## Docker

```bash
docker run --rm \
  -v ~/.config:/root/.config:ro \
  -v $(pwd)/reports:/workspace/reports \
  ghcr.io/agent-bom/agent-bom:latest scan --enrich -o /workspace/reports/ai-bom.json
```

See [DEPLOYMENT.md](DEPLOYMENT.md) for CI/CD, Kubernetes, and remote scanning setups.

---

## Roadmap

**Cloud agent discovery:**
- [ ] Snowflake Cortex — scan `CREATE MCP SERVER` / `CREATE OR REPLACE AGENT` from query history
- [ ] AWS Bedrock — discover agents and action group configurations
- [ ] Google Vertex AI — discover agents and extensions
- [ ] OpenAI — scan assistant tool definitions

**Scanner capabilities:**
- [ ] Live MCP server introspection (enumerate tools/resources dynamically)
- [ ] Docker/container image scanning for MCP servers
- [ ] AI framework risk tagging (flag LangChain, transformers, etc. with AI-specific context)
- [ ] MCP registry scanning before installation

**Output & policy:**
- [x] SARIF 2.1 output for GitHub Security tab
- [ ] SPDX 3.0 output (AI-BOM profile)
- [ ] Policy engine ("no DB-credential server may have critical vulns")
- [ ] MITRE ATLAS mapping for AI/ML threats

---

## CI Integration

```yaml
# .github/workflows/ai-bom.yml
- name: Generate AI-BOM
  run: |
    pip install agent-bom
    agent-bom scan --inventory agents.json --fail-on-severity high -f sarif -o results.sarif

- name: Upload to GitHub Security
  uses: github/codeql-action/upload-sarif@v3
  with:
    sarif_file: results.sarif
```

---

## Contributing

Contributions welcome. See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
git clone https://github.com/agent-bom/agent-bom.git
cd agent-bom
pip install -e ".[dev]"
pytest && ruff check src/
```

---

## Security

To report a vulnerability, email **crewnycgiving@gmail.com**. See [SECURITY.md](SECURITY.md) for our responsible disclosure policy.

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

Built by [Wagdy Saad](https://linkedin.com/in/wagdy-saad) — Staff Security Engineer specializing in cloud security and AI agent security.

*Not affiliated with Anthropic, Cursor, or any MCP client vendor.*
