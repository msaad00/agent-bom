# MCP Client Guides

Use this page when you want the shortest path to wiring `agent-bom` into a specific MCP-capable client.

Two modes matter:

- `agent-bom mcp server`: expose `agent-bom` itself as a read-only MCP tool surface
- `agent-bom proxy`: wrap a third-party MCP server when you want runtime inspection and enforcement

## Which mode to use

| Goal | Use | Why |
|------|-----|-----|
| Ask an assistant to run `agent-bom` tools directly | `agent-bom mcp server` | Makes discovery, scan, blast-radius, compliance, and trust tools available in-chat |
| Inspect or block live MCP traffic to another server | `agent-bom proxy` | Adds inline JSON-RPC inspection, audit logs, and policy enforcement |
| Auto-wrap JSON-based stdio MCP configs | `agent-bom proxy-configure` | Rewrites eligible client configs so they point at the proxy wrapper |
| Generate managed endpoint rollout artifacts | `agent-bom proxy-bootstrap` | Writes shell/PowerShell bootstrap scripts plus fleet-sync artifacts for IT-owned rollout |

## Major clients

| Client | Primary config path(s) | Recommended setup | Notes |
|--------|-------------------------|-------------------|-------|
| Claude Desktop | macOS: `~/Library/Application Support/Claude/claude_desktop_config.json` Linux: `~/.config/Claude/claude_desktop_config.json` Windows: `~/AppData/Roaming/Claude/claude_desktop_config.json` | `agent-bom mcp server` or `uvx agent-bom mcp server` | Good fit for MCP server mode. Proxy wrapping works for JSON-configured stdio servers. |
| Claude Code | `~/.claude/settings.json`, `~/.claude.json` | `claude mcp add agent-bom -- uvx agent-bom mcp server` | `agent-bom` also discovers project-level MCP servers from `~/.claude.json`. |
| Cortex CoCo / Cortex Code | `~/.snowflake/cortex/mcp.json` plus `settings.json`, `permissions.json`, `hooks.json` in the same directory | `uvx agent-bom mcp server` in `mcp.json` | Best fit when you want both MCP discovery and Cortex-specific permission/hook audits. |
| Cursor | macOS: `~/Library/Application Support/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` Linux: `~/.config/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` Windows: `~/AppData/Roaming/Cursor/User/globalStorage/cursor.mcp/mcp.json`, `~/.cursor/mcp.json` | `agent-bom mcp server` | Cursor uses standard JSON MCP config, so `proxy-configure` can wrap eligible stdio servers. |
| Windsurf | macOS: `~/.windsurf/mcp.json`, `~/Library/Application Support/Windsurf/User/globalStorage/windsurf.mcp/mcp.json` Linux: `~/.windsurf/mcp.json` Windows: `~/.windsurf/mcp.json` | `agent-bom mcp server` | Same `mcpServers` JSON shape as Claude/Cursor. |
| Codex CLI | `~/.codex/config.toml` on macOS, Linux, and Windows | `agent-bom mcp server` via `[mcp_servers.agent-bom]` | Codex uses TOML, not JSON. `proxy-configure` does not rewrite TOML configs; wrap manually when needed. |
| Gemini CLI | `~/.gemini/settings.json` on macOS, Linux, and Windows | `agent-bom mcp server` | Uses standard JSON MCP config. |

## Config snippets

### JSON clients

Claude Desktop, Cortex CoCo, Cursor, Windsurf, and Gemini CLI all use JSON MCP config shapes that look like:

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

If `agent-bom` is already installed locally, you can replace `uvx` with:

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

### Codex CLI

Codex CLI uses TOML:

```toml
[mcp_servers.agent-bom]
command = "uvx"
args = ["agent-bom", "mcp", "server"]
```

For a manual proxy-wrapped third-party server in Codex:

```toml
[mcp_servers.filesystem]
command = "agent-bom"
args = ["proxy", "--log", "~/.agent-bom/logs/filesystem.jsonl", "--", "npx", "@modelcontextprotocol/server-filesystem", "/workspace"]
```

## Runtime proxy notes

- `agent-bom proxy` is best when the client talks to a third-party stdio server and you want runtime inspection.
- `agent-bom proxy-configure --apply` targets JSON MCP configs and can now stamp control-plane policy/audit settings into the wrapped proxy command.
- `agent-bom proxy-bootstrap --bundle-dir ./endpoint-bundle --control-plane-url https://agent-bom.example.com --push-url https://agent-bom.example.com/v1/fleet/sync` writes managed rollout artifacts for macOS/Linux and Windows without hand-editing JSON on every machine.
- stdio transports have no native HTTP header channel. When a client or upstream includes W3C trace context in JSON-RPC `_meta.traceparent`, `_meta.tracestate`, or `_meta.baggage`, the proxy preserves those fields and rehydrates them onto the paired response when the upstream does not echo them back.
- TOML clients like Codex CLI need manual proxy wrapping today.
- SSE / HTTP clients can use `agent-bom mcp server --transport sse --bearer-token "$AGENT_BOM_MCP_BEARER_TOKEN"` or `--transport streamable-http`.
- Non-loopback remote transports fail closed unless you configure `--bearer-token` / `AGENT_BOM_MCP_BEARER_TOKEN` or explicitly pass `--allow-insecure-no-auth`.
- Keep TLS at your ingress or reverse proxy for remote deployments.

## Next steps

- [Claude Desktop / Claude Code](CLAUDE_INTEGRATION.md)
- [Cortex CoCo / Cortex Code](CORTEX_CODE.md)
- [Codex CLI](CODEX_CLI.md)
- [MCP server mode](MCP_SERVER.md)
- [Runtime monitoring and proxy](RUNTIME_MONITORING.md)
