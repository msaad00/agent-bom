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
agent-bom image python:3.12-slim
```

Uses agent-bom's native image scanning pipeline to enumerate OS and language packages within container images.
The native parser reads Debian dpkg, Alpine apk, modern SQLite RPM databases,
and legacy RPM BerkeleyDB/NDB databases without requiring a scanner binary.
Malformed legacy RPM databases fail the scan instead of producing a clean
zero-package result.

The default OS result remains precision-first and reports distro-confirmed
advisories. To include unfixed, pending, no-DSA, and end-of-life distro
advisories for an exhaustive review, run:

```bash
AGENT_BOM_INCLUDE_UNFIXED=1 agent-bom image python:3.12-slim
```

The artifact is the same findings report with lower-confidence unfixed distro
rows included; review their match-confidence tier before using them as a CI
block. Language-package coverage is unaffected by this switch.

## IaC and cloud posture

Use `agent-bom iac` as the pre-cloud gate for Terraform, CloudFormation,
Kubernetes, Helm-rendered manifests, and Dockerfiles. Use `agent-bom
cis-benchmark` as the runtime posture check for deployed cloud state. The
combined workflow catches proposed misconfiguration before apply and drift
after deployment.

See [Cloud Posture and IaC Gates](cloud-posture.md) for the recommended lane
split and CI example.
