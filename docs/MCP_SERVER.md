# MCP Server — Connect agent-bom to AI Assistants

agent-bom exposes 33 security tools as an MCP server. Any MCP-compatible client
can connect and get vulnerability scanning, blast radius analysis, compliance
checks, and supply chain verification through natural conversation.

## Quick Start

### Claude Desktop / Claude Code

Add to your `claude_desktop_config.json` (macOS: `~/Library/Application Support/Claude/`):

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

Restart Claude Desktop. You can now ask: *"Scan my AI agents for vulnerabilities"*

### Cursor / Windsurf / VS Code

Add to your MCP settings (`.cursor/mcp.json` or equivalent):

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

### SSE Transport (Remote / Multi-Client)

```bash
agent-bom mcp server --sse --host 0.0.0.0 --port 8000
```

Connect any SSE-capable MCP client to `http://your-server:8000/sse`.

### Docker

```bash
docker run -it --rm \
  -v ~/.config:/root/.config:ro \
  agentbom/agent-bom:latest mcp server
```

## Tool Categories (33 tools)

| Category | Tools | What They Do |
|----------|-------|-------------|
| **Scan** | `scan_agents`, `scan_image`, `scan_filesystem`, `scan_sbom` | Discover agents, scan containers, filesystems, and existing SBOMs for CVEs |
| **Check** | `check_package`, `verify_package` | Pre-install CVE gate + supply chain provenance verification |
| **Blast Radius** | `blast_radius` | Map CVE → package → MCP server → agent → credentials → tools |
| **Registry** | `registry_lookup`, `batch_registry_scan` | Query 427+ MCP server security metadata |
| **Compliance** | `compliance_check`, `cis_benchmark` | Run OWASP, NIST, MITRE ATLAS, CIS checks |
| **Policy** | `evaluate_policy` | Apply custom or built-in security policies |
| **Inventory** | `inventory` | List agents/servers without CVE scanning |
| **Trust** | `trust_assessment` | Multi-category trust scoring for packages |
| **IaC** | `scan_terraform`, `scan_dockerfile`, `scan_helm` | Infrastructure-as-code security scanning |
| **Runtime** | `shield_status` | Runtime protection engine status |

## Example Conversations

**"Are my AI agents vulnerable?"**
> Agent-bom discovers your Claude Desktop, Cursor, and VS Code MCP configs,
> extracts all server packages, queries OSV/NVD for CVEs, and shows the
> blast radius chain.

**"Is it safe to install mcp-server-sqlite?"**
> Runs pre-install check: CVE scan, typosquat detection, OpenSSF Scorecard,
> license analysis, and supply chain provenance verification.

**"Show me my compliance posture"**
> Runs OWASP LLM Top 10, MITRE ATLAS, NIST AI RMF, and CIS benchmarks
> against your infrastructure. Returns per-framework pass/fail/warn.

## Security Model

- **Read-only**: Only List/Describe/Get operations. Zero write calls.
- **No credential storage**: Never stores, logs, or transmits your credentials.
- **No network exfiltration**: Scans local configs, queries public CVE databases.
- **Agentless**: No agents installed on targets.

## Resources

The server exposes one MCP resource:

- `registry://servers` — Browse the full 427+ server security metadata registry

## Prompts

Built-in prompts for common workflows:

- `security-scan` — Full agent + MCP server vulnerability scan
- `pre-install-check` — Check a package before installing
- `compliance-posture` — Multi-framework compliance assessment
