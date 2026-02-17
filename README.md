# agent-bom

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
- **Output formats** — rich console, JSON, CycloneDX 1.6

---

## Supported Clients

| Client | macOS | Linux | Windows |
|--------|:-----:|:-----:|:-------:|
| Claude Desktop | ✅ | ✅ | ✅ |
| Claude Code | ✅ | ✅ | ✅ |
| Cursor | ✅ | ✅ | ✅ |
| Windsurf | ✅ | ✅ | ✅ |
| Cline | ✅ | ✅ | ✅ |
| Custom / any agent | ✅ | ✅ | ✅ |

Use `--config-dir` or `--inventory` to scan any agent not on this list.

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

- [ ] Live MCP server introspection (enumerate tools dynamically)
- [ ] Docker/container image scanning for MCP servers
- [ ] SPDX 3.0 output (AI-BOM profile)
- [ ] Policy engine ("no DB-credential server may have critical vulns")
- [ ] MITRE ATLAS mapping for AI/ML threats
- [ ] MCP registry scanning before installation

---

## Contributing

Contributions welcome. See [GIT_WORKFLOW.md](GIT_WORKFLOW.md) for branching conventions.

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
