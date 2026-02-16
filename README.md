# agent-bom

**AI Bill of Materials (AI-BOM) generator for AI agents and MCP servers.**

`agent-bom` maps the full trust chain from AI agent → MCP server → packages → known vulnerabilities, with **blast radius analysis** that answers the question: *"If this package is compromised, which agents are affected, what credentials are exposed, and what tools can an attacker reach?"*

---

## Why agent-bom?

Existing tools scan MCP servers for prompt injection (Cisco MCP Scanner, mcp-scan) or inventory AI models and datasets (OWASP AIBOM Generator, Wiz AI-SPM). **Nobody maps the full dependency chain from agent to vulnerability.**

Traditional SBOMs stop at the package layer. `agent-bom` extends that to the **agent trust chain**:

```
Agent (Claude Desktop)
  └── MCP Server (database-server)
        ├── Tool: query_database (read/write)
        ├── Credentials: DB_PASSWORD, API_KEY
        └── Packages:
              ├── express@4.18.2 ← CVE-2024-XXXX (HIGH)
              ├── pg@8.11.0
              └── axios@1.6.0 ← CVE-2024-YYYY (CRITICAL)
                    ↑
                    Blast Radius: 3 agents, 2 credentials exposed, 5 tools reachable
```

A vulnerability in a package doesn't just mean "update this dependency." It means every agent connected to that MCP server inherits the risk — and if that server holds credentials, those credentials are in the blast radius.

---

## Features

- **Auto-discovery**: Finds MCP configurations for Claude Desktop, Claude Code, Cursor, Windsurf, Cline, and project-level configs
- **Multi-ecosystem parsing**: Extracts dependencies from npm (package-lock.json), pip (requirements.txt, Pipfile.lock, pyproject.toml), Go (go.sum), and Cargo (Cargo.lock)
- **npx/uvx detection**: Identifies packages from `npx`/`uvx` commands in MCP server configs
- **Transitive dependency resolution**: Recursively resolves nested dependencies for npx/uvx packages from npm and PyPI registries
- **Vulnerability scanning**: Queries [OSV.dev](https://osv.dev) for known CVEs across all ecosystems
- **Blast radius analysis**: Calculates contextual risk scores based on how many agents, credentials, and tools are in the vulnerability's reach
- **Credential detection**: Flags MCP servers with API keys, tokens, and secrets in environment variables
- **Multiple output formats**: Console (rich tables/trees), JSON, and CycloneDX 1.6 (SBOM standard)

---

## Installation

```bash
pip install agent-bom
```

Or install from source:

```bash
git clone https://github.com/wagdysaad/agent-bom.git
cd agent-bom
pip install -e .
```

---

## Quick Start

### Full scan (discover + extract + vuln scan)

```bash
agent-bom scan
```

### Inventory only (no vuln scan)

```bash
agent-bom inventory
```

### Scan a specific project

```bash
agent-bom scan --project /path/to/project
```

### Scan a specific config file

```bash
agent-bom inventory --config ~/.config/Claude/claude_desktop_config.json
```

### Export CycloneDX BOM

```bash
agent-bom scan --format cyclonedx --output agent-bom.cdx.json
```

### Export JSON report

```bash
agent-bom scan --format json --output report.json
```

### Enable transitive dependency scanning

```bash
agent-bom scan --transitive
```

This resolves nested dependencies for npx/uvx packages. For example, if your MCP server uses `npx @anthropic/server-filesystem`, it will:
1. Extract the top-level package (`@anthropic/server-filesystem`)
2. Query the npm registry for its dependencies
3. Recursively resolve all transitive dependencies
4. Scan all packages (direct + transitive) for vulnerabilities

Control the recursion depth (default: 3):

```bash
agent-bom scan --transitive --max-depth 5
```

### Show config locations

```bash
agent-bom where
```

---

## Output Examples

### Console (default)

```
🔍 Discovering MCP configurations...

  ✓ Found claude-desktop with 4 MCP server(s)
  ✓ Found cursor with 2 MCP server(s)

📦 Extracting package dependencies...

  ✓ database-server: 47 package(s) (npm)
  ✓ slack-bot: 23 package(s) (npm)

🛡️  Scanning for vulnerabilities...

  Scanning 62 unique packages across 2 agent(s)...
  ⚠ Found 5 vulnerabilities across 3 findings

┌─────────────────────────────────────────────────────────┐
│ AI-BOM Report                                           │
│ Generated: 2026-02-15 22:00:00 UTC                      │
│ agent-bom v0.1.0                                        │
└─────────────────────────────────────────────────────────┘

 Agents discovered   2
 MCP servers         6
 Total packages      70
 Vulnerabilities     5
 Critical findings   1

💥 Blast Radius Analysis

 Risk  Vuln ID            Package              Severity  Agents  Servers  Creds  Fix
 8.3   GHSA-xxxx-xxxx     axios@1.6.0          critical  3       2        2      1.7.4
 6.5   CVE-2024-1234      express@4.18.2       high      2       1        1      4.19.0
 4.0   CVE-2024-5678      lodash@4.17.20       medium    1       1        0      4.17.21
```

### CycloneDX

Exports a standards-compliant CycloneDX 1.6 BOM with:
- Agents as top-level `application` components
- MCP servers as intermediate `application` components
- Packages as `library` components with PURLs
- Full dependency graph (agent → server → packages)
- Vulnerability data with severity ratings and fix recommendations
- Custom properties for agent-bom metadata (credentials, transport type, tools)

---

## How It Works

1. **Discovery** — Auto-detects MCP client configs (Claude Desktop, Cursor, etc.) and project-level `.mcp.json` files
2. **Parsing** — For each MCP server, locates source directories and extracts package manifests (package.json, requirements.txt, etc.)
3. **Transitive Resolution** (optional) — For npx/uvx packages without local source, recursively queries npm/PyPI registries to resolve all nested dependencies
4. **Scanning** — Queries OSV.dev API to check every package version against known vulnerability databases (NVD, GitHub Advisory, etc.)
5. **Blast Radius** — Maps which agents connect to which servers, what credentials each server holds, and what tools are exposed — then scores each vulnerability by its total reach
6. **Reporting** — Outputs the full AI-BOM as a rich console tree, JSON report, or CycloneDX 1.6 BOM

---

## Supported MCP Clients

| Client | macOS | Linux | Windows |
|--------|-------|-------|---------|
| Claude Desktop | ✅ | ✅ | ✅ |
| Claude Code | ✅ | ✅ | ✅ |
| Cursor | ✅ | ✅ | ✅ |
| Windsurf | ✅ | ✅ | ✅ |
| Cline | ✅ | ✅ | ✅ |
| Project configs (.mcp.json) | ✅ | ✅ | ✅ |

---

## Roadmap

- [ ] **Live MCP introspection** — Connect to running MCP servers to enumerate tools and resources dynamically
- [ ] **Docker/container scanning** — Extract packages from container images used by MCP servers
- [ ] **SPDX 3.0 output** — AI-BOM profile support per Linux Foundation spec
- [ ] **GitHub Actions integration** — CI/CD gate that fails builds when new vulns are introduced
- [ ] **Policy engine** — Define rules like "no MCP server with DB credentials may have critical vulns"
- [ ] **Privilege analysis** — Map tool capabilities to data access scope
- [ ] **MITRE ATLAS mapping** — Map findings to MITRE ATLAS tactics for AI/ML threats
- [ ] **MCP registry scanning** — Scan MCP servers from public registries before installation

---

## Contributing

Contributions welcome! See [CONTRIBUTING.md](CONTRIBUTING.md) for guidelines.

```bash
# Development setup
git clone https://github.com/wagdysaad/agent-bom.git
cd agent-bom
pip install -e ".[dev]"

# Run tests
pytest

# Lint
ruff check src/
```

---

## License

Apache 2.0 — see [LICENSE](LICENSE).

---

## Author

Built by [Wagdy Saad](https://linkedin.com/in/wagdysaad) — Staff Security Engineer specializing in cloud security, AI agent security, and detection engineering.

---

*agent-bom is not affiliated with Anthropic, Cursor, or any MCP client vendor. It reads publicly documented configuration files to generate security inventories.*
