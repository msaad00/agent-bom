# Scanning & Discovery

## Auto-discovery

agent-bom discovers MCP clients and their configured servers by reading config files from 20 supported clients:

| Client | Config path |
|--------|------------|
| Claude Desktop | `~/Library/Application Support/Claude/claude_desktop_config.json` |
| Claude Code | `~/.claude/settings.json` |
| Cursor | `~/.cursor/mcp.json` |
| VS Code Copilot | `~/Library/Application Support/Code/User/mcp.json` |
| Windsurf | `~/.windsurf/mcp.json` |
| Cline | `~/Library/Application Support/Code/User/globalStorage/saoudrizwan.claude-dev/...` |
| Roo Code | `~/Library/Application Support/Code/User/globalStorage/rooveterinaryinc.roo-cline/...` |
| Codex CLI | `~/.codex/config.toml` |
| Gemini CLI | `~/.gemini/settings.json` |
| Goose | `~/.config/goose/config.yaml` |
| Cortex Code | `~/.snowflake/cortex/mcp.json` |
| Continue | `~/.continue/config.json` |
| Zed | `~/.config/zed/settings.json` |
| Amazon Q | VS Code globalStorage |
| JetBrains AI | `~/Library/Application Support/JetBrains/*/mcp.json` |
| Junie | `~/.junie/mcp/mcp.json` |
| OpenClaw | `~/.openclaw/openclaw.json` |
| Project-level | `.mcp.json`, `.vscode/mcp.json`, `.cursor/mcp.json` |

Linux paths use `~/.config/` equivalents.

## Vulnerability sources

| Source | Data |
|--------|------|
| [OSV](https://osv.dev) | Primary CVE database — covers PyPI, npm, Go, Maven, etc. |
| [NVD](https://nvd.nist.gov) | CVSS v4 base scores |
| [EPSS](https://www.first.org/epss/) | Exploit probability scores (0.0–1.0) |
| [CISA KEV](https://www.cisa.gov/known-exploited-vulnerabilities-catalog) | Known exploited vulnerabilities catalog |
| [GitHub Advisories](https://github.com/advisories) | Supplemental advisory data |
| Commercial vuln API | Optional enrichment when a vendor API token is configured |

## Credential exposure detection

Config files are parsed for server definitions. Environment variable **values** are automatically redacted — only key names are reported. Patterns detected:

- AWS keys (`AKIA...`)
- GitHub tokens (`ghp_`, `gho_`, `ghs_`)
- OpenAI / Anthropic API keys
- JWTs, bearer tokens
- Connection strings with embedded passwords
- Private keys (PEM headers)

## Container image scanning

```bash
agent-bom scan --image python:3.12-slim
```

Uses agent-bom's native image scanning pipeline to enumerate OS and language packages within container images.
