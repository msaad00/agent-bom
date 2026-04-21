# MCP Server — Connect agent-bom to AI Assistants

agent-bom exposes 36 security tools as an MCP server. Any MCP-compatible client
can connect and get vulnerability scanning, blast radius analysis, compliance
checks, and supply chain verification through natural conversation.

See also:

- [MCP client guides](MCP_CLIENT_GUIDES.md)
- [Claude Desktop / Claude Code guide](CLAUDE_INTEGRATION.md)
- [Cortex CoCo / Cortex Code guide](CORTEX_CODE.md)
- [Codex CLI guide](CODEX_CLI.md)
- [Runtime Monitoring](RUNTIME_MONITORING.md)

## Quick Start

### Claude Desktop

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

### Claude Code

If you already use the Claude CLI, add agent-bom directly:

```bash
claude mcp add agent-bom -- uvx agent-bom mcp server
```

Claude Code project-level MCP servers are also discovered from `~/.claude.json`.

### Cortex CoCo

Add to `~/.snowflake/cortex/mcp.json`:

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

CoCo can then call the same 36 `agent-bom` tools over MCP.

agent-bom also discovers Cortex auxiliary security files alongside `mcp.json`:

- `settings.json`
- `permissions.json`
- `hooks.json`

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

agent-bom discovers these MCP client config paths directly:

- Cursor: `~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json`
- Windsurf: `~/.windsurf/mcp.json`, `~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json`
- VS Code: `~/Library/Application Support/Code/User/mcp.json`, plus workspace `.vscode/mcp.json`

### Codex CLI

Add to `~/.codex/config.toml`:

```toml
[mcp_servers.agent-bom]
command = "uvx"
args = ["agent-bom", "mcp", "server"]
```

Codex uses TOML, so manual proxy wrapping is the right path when you want runtime inspection around a third-party server.

### SSE Transport (Remote / Multi-Client)

```bash
agent-bom mcp server --transport sse --host 0.0.0.0 --port 8000 --bearer-token "$AGENT_BOM_MCP_BEARER_TOKEN"
```

Connect any SSE-capable MCP client to `https://your-server/sse`.
For non-loopback SSE or Streamable HTTP binds, `agent-bom` now fails closed unless you set
`--bearer-token` / `AGENT_BOM_MCP_BEARER_TOKEN` or explicitly pass
`--allow-insecure-no-auth`. Keep TLS at your proxy or ingress for remote deployments.

### Docker

```bash
docker run -it --rm \
  -v ~/.config:/root/.config:ro \
  agentbom/agent-bom:latest mcp server
```

## Runtime proxy

Use the proxy when you want to inspect or enforce on MCP traffic between a client and a third-party server:

```bash
agent-bom proxy "npx @modelcontextprotocol/server-filesystem /workspace"
```

This keeps the real server behind `agent-bom` and enables runtime detectors for tool drift, credential leakage, injection patterns, sequence risk, and related policy decisions.

For JSON-configured clients like Claude Desktop or Cortex CoCo, use:

```bash
agent-bom proxy-configure --log-dir ~/.agent-bom/logs --detect-credentials
```

Add `--apply` to write the wrapped config back to compatible JSON MCP config files.

For IT-owned rollout across managed laptops, use:

```bash
agent-bom proxy-bootstrap \
  --bundle-dir ./endpoint-bundle \
  --control-plane-url https://agent-bom.example.com \
  --push-url https://agent-bom.example.com/v1/fleet/sync
```

`proxy-configure` is best for JSON MCP clients such as Claude Desktop, Cursor, Windsurf, and Cortex CoCo. TOML-based clients like Codex CLI need manual proxy wrapping.

## Tool Categories (36 tools)

| Category | Tools | What They Do |
|----------|-------|-------------|
| **Scan** | `scan`, `code_scan`, `vector_db_scan`, `gpu_infra_scan`, `ai_inventory_scan` | Discover agents, scan packages, code, vector stores, GPU infra, and AI usage |
| **Check** | `check`, `verify`, `marketplace_check`, `license_compliance_scan` | Pre-install CVE gate, integrity verification, marketplace trust, and license policy |
| **Blast Radius** | `blast_radius` | Map CVE → package → MCP server → agent → credentials → tools |
| **Registry** | `registry_lookup`, `inventory`, `where`, `fleet_scan` | Query the MCP registry, inspect discovery paths, and summarize fleet inventories |
| **Compliance** | `compliance`, `cis_benchmark`, `aisvs_benchmark` | Run OWASP, NIST, MITRE ATLAS, CIS, and AISVS-aligned posture checks |
| **Policy** | `policy_check`, `remediate` | Evaluate policies and generate guided remediation plans |
| **Inventory** | `inventory` | List agents/servers without CVE scanning |
| **Trust** | `marketplace_check`, `runtime_correlate`, `tool_risk_assessment` | Score package trust, correlate runtime usage, and assess live tool capability risk |
| **Skills** | `skill_scan`, `skill_verify`, `skill_trust` | Instruction-file trust, provenance, and tool-poisoning detection |
| **Graph / Runtime** | `context_graph`, `graph_export`, `runtime_correlate`, `tool_risk_assessment` | Visualize lateral movement, export graph data, and connect runtime logs to findings |
| **AI supply chain** | `dataset_card_scan`, `training_pipeline_scan`, `browser_extension_scan`, `model_provenance_scan`, `prompt_scan`, `model_file_scan`, `ingest_external_scan` | Scan AI artifacts, prompts, model files, browser extensions, and external scanner results |

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

The server exposes two MCP resources:

- `registry://servers` — Browse the full 427+ server security metadata registry
- `policy://template` — Default security policy template

## Prompts

Built-in prompts for common workflows:

- `security-scan` — Full agent + MCP server vulnerability scan
- `pre-install-check` — Check a package before installing
- `compliance-posture` — Multi-framework compliance assessment
