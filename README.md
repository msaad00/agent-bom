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
| `agent-bom scan` | Auto-discover agents + extract deps + scan for CVEs |
| `agent-bom scan --inventory agents.json` | Scan agents from a manual inventory file |
| `agent-bom scan --project /path` | Scan a specific project directory |
| `agent-bom scan --config-dir /path` | Scan a custom agent config directory |
| `agent-bom scan --transitive` | Include transitive dependencies |
| `agent-bom scan --transitive --max-depth 5` | Transitive resolution with custom depth |
| `agent-bom scan --enrich` | Add NVD / EPSS / CISA KEV data |
| `agent-bom scan --enrich --nvd-api-key KEY` | Enrich with higher NVD rate limits |
| `agent-bom scan --no-scan` | Inventory only — skip vulnerability scanning |
| `agent-bom scan --no-tree` | Skip dependency tree in console output |
| `agent-bom scan -f json -o report.json` | Export JSON report |
| `agent-bom scan -f cyclonedx -o bom.cdx.json` | Export CycloneDX 1.6 BOM |
| `agent-bom scan -f sarif -o bom.sarif` | Export SARIF for GitHub Security tab |
| `agent-bom scan -f text` | Plain text output (for grep/awk) |
| `agent-bom scan -f json -o - \| jq .` | Pipe clean JSON to stdout |
| `agent-bom scan -q --fail-on-severity high` | CI gate — exit 1 if high+ vulns found |
| `agent-bom inventory` | List discovered agents (no vuln scan) |
| `agent-bom inventory -c config.json` | Inventory a specific config file |
| `agent-bom validate agents.json` | Validate an inventory file against the schema |
| `agent-bom where` | Show where configs are looked up |

---

## How It Works

agent-bom operates in two modes: **auto-discovery** and **manual inventory**. Both are agentless — you bring the data, agent-bom scans and generates the BOM.

### Mode 1: Auto-discovery

When you run `agent-bom scan` with no arguments, it scans your machine for known MCP client configurations:

```bash
# Discover all local agents automatically
agent-bom scan

# Discover from a specific project directory
agent-bom scan --project /path/to/my-project
```

agent-bom looks for config files at known paths for each supported client (see `agent-bom where` for locations). It parses the `mcpServers` block in each config to find MCP server definitions.

### Mode 2: Manual inventory

For agents not auto-discovered — custom agents, production deployments, cloud platforms — provide a JSON inventory file:

```bash
agent-bom scan --inventory agents.json
```

**Inventory format** (`agents.json`):

```json
{
  "agents": [
    {
      "name": "my-production-agent",
      "agent_type": "custom",
      "config_path": "/opt/my-agent/config.json",
      "mcp_servers": [
        {
          "name": "database-server",
          "command": "npx",
          "args": ["-y", "@my-org/mcp-database-server"],
          "env": {
            "DATABASE_URL": "postgresql://...",
            "API_KEY": "sk-..."
          },
          "transport": "stdio",
          "tools": [
            {"name": "query_database", "description": "Execute SQL queries"},
            "list_tables"
          ],
          "packages": [
            {"name": "express", "version": "4.18.2", "ecosystem": "npm"},
            "axios@1.6.0"
          ]
        }
      ]
    }
  ]
}
```

| Field | Required | Description |
|-------|:--------:|-------------|
| `agents[].name` | yes | Agent identifier |
| `agents[].agent_type` | no | `claude-desktop`, `claude-code`, `cursor`, `windsurf`, `cline`, or `custom` (default: `custom`) |
| `agents[].config_path` | no | Where the agent config lives — can be a file path, ARN, Snowflake URI, etc. |
| `agents[].version` | no | Agent version string |
| `agents[].mcp_servers[].name` | yes | MCP server identifier |
| `agents[].mcp_servers[].command` | yes | Server command (`npx`, `uvx`, `python`, `node`, etc.) |
| `agents[].mcp_servers[].args` | no | Command arguments (array of strings) |
| `agents[].mcp_servers[].env` | no | Environment variables (object). Credential-like keys are flagged automatically |
| `agents[].mcp_servers[].transport` | no | `stdio` (default), `sse`, or `streamable-http` |
| `agents[].mcp_servers[].url` | no | Server URL (for SSE/HTTP transports) |
| `agents[].mcp_servers[].working_dir` | no | Server working directory (for lock file resolution) |
| `agents[].mcp_servers[].tools` | no | Pre-populated tool list — array of objects (`{"name", "description"}`) or strings |
| `agents[].mcp_servers[].packages` | no | Pre-known packages — array of objects (`{"name", "version", "ecosystem"}`) or `"name@version"` strings |

The inventory format mirrors what auto-discovery finds. Pre-populated packages are merged with any packages agent-bom discovers from lock files, so you can provide what you know and agent-bom fills in the rest.

**Validate before scanning:**

```bash
agent-bom validate agents.json   # exits 0 if valid, 1 with clear errors if not
```

**What you need for each scanning capability:**

| Capability | Required fields |
|-----------|----------------|
| Vulnerability scan | `mcp_servers[].packages[].name` + `.version` + `.ecosystem` |
| Credential detection | `mcp_servers[].env` (key names only — values never logged) |
| Blast radius analysis | Both packages and env above, plus `mcp_servers[].tools[]` |
| SARIF output (finding location) | `config_path` on agent or server |
| Supply chain traceability | `source` on agent or at file root |

**Mapping from platform-specific formats:**

| Your platform | Maps to |
|--------------|---------|
| Claude Desktop `mcpServers.X.command/args/env` | `mcp_servers[].command/args/env` |
| Cursor / VS Code `mcpServers.X` | Same — auto-discovered by `agent-bom scan` |
| Snowflake `CREATE MCP SERVER` tools YAML | `mcp_servers[].tools[]` + `mcp_servers[].packages[]` |
| AWS Bedrock `actionGroupName` / Lambda ARN | Agent name = group name, `config_path` = ARN, packages from Lambda deps |
| EC2 / VM with AI packages installed | `mcp_servers[].packages[]` with ecosystem = pypi/npm |
| OpenAI Assistant function tools | `mcp_servers[].tools[]` with name + description |

**Example inventories for different sources:**

- [examples/snowflake-inventory.json](examples/snowflake-inventory.json) — Snowflake Cortex agents with MCP servers and tools from query history
- [examples/cloud-inventory.json](examples/cloud-inventory.json) — AWS Bedrock agents and EC2-hosted ML pipelines with pre-known packages
- [schemas/inventory.schema.json](schemas/inventory.schema.json) — Full JSON Schema with field documentation

---

## Features

- **Auto-discovery** — Claude Desktop, Claude Code, Cursor, Windsurf, Cline, and project-level `.mcp.json`
- **Manual inventory** — scan any agent platform via `--inventory` JSON
- **Multi-ecosystem** — npm, pip, Go, Cargo (lock files + manifest files)
- **npx / uvx detection** — extracts package names from MCP server command definitions
- **Transitive resolution** — recursively resolves nested deps via npm and PyPI registries
- **Vulnerability scanning** — queries [OSV.dev](https://osv.dev) across all ecosystems
- **Enrichment** — NVD metadata, EPSS exploit probability, CISA KEV flags (`--enrich`)
- **Blast radius scoring** — contextual risk score based on agents, credentials, and tools in reach
- **Credential detection** — flags MCP servers exposing API keys, tokens, and secrets in env vars
- **Output formats** — rich console, JSON, CycloneDX 1.6, SARIF 2.1, plain text
- **CI/CD ready** — `--fail-on-severity`, `--quiet`, stdout piping (`-o -`), exit codes

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

### Manual scan (any platform)

Use `--inventory` to scan any agent not listed above — including custom agents, OpenAI-based tools, LangChain apps, or anything that uses MCP servers. See [Inventory format](#mode-2-manual-inventory) above.

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
  agentbom/agent-bom:latest scan --enrich -o /workspace/reports/ai-bom.json
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
