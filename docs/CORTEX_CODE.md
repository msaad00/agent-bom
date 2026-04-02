# Cortex CoCo / Cortex Code Integration

This guide covers the full `agent-bom` flow for Snowflake Cortex CoCo:

1. add `agent-bom` as an MCP server inside CoCo
2. scan CoCo MCP servers plus Cortex-specific config state
3. wrap third-party MCP servers with the runtime proxy when you want live inspection

## Use agent-bom as an MCP server

Config files discovered by `agent-bom`:

- `~/.snowflake/cortex/mcp.json`
- `~/.snowflake/cortex/settings.json`
- `~/.snowflake/cortex/permissions.json`
- `~/.snowflake/cortex/hooks.json`

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

Or, if `agent-bom` is already installed:

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

This makes the same 36 `agent-bom` MCP tools available in CoCo conversations.

## What agent-bom discovers for Cortex

`agent-bom` does more than read `mcp.json`. It also inspects:

- `~/.snowflake/cortex/settings.json`
- `~/.snowflake/cortex/permissions.json`
- `~/.snowflake/cortex/hooks.json`

That gives you Cortex-specific audit visibility that normal MCP discovery does not provide.

## Cortex-specific security checks

`agent-bom` audits:

- cached approvals in `permissions.json`
- high-risk tools approved persistently
- approvals without integrity hashes
- dangerous shell hook commands in `hooks.json`
- hooks that fire on all events
- hooks that exfiltrate to external URLs

## Scan Cortex environments directly

Use the CLI when you want an audit of the local CoCo setup:

```bash
agent-bom agents
agent-bom agents -p .
agent-bom skills scan .
```

This discovers CoCo MCP servers, package dependencies, exposed credential names, and auxiliary Cortex config findings.

## Runtime proxy for CoCo-connected MCP servers

When you want live inspection of third-party MCP traffic, wrap the real server:

```bash
agent-bom proxy "npx @modelcontextprotocol/server-filesystem /workspace"
```

Or auto-wrap eligible JSON MCP configs:

```bash
agent-bom proxy-configure --log-dir ~/.agent-bom/logs --detect-credentials --apply
```

That adds runtime monitoring for:

- tool drift
- credential leakage
- argument injection
- rate spikes
- suspicious sequences
- response cloaking
- vector/RAG injection

For cross-agent correlation across sessions, use the broader runtime protection engine with `agent-bom runtime protect --shield`.

## When to use MCP server vs proxy

- Use `agent-bom mcp server` when you want CoCo to call `agent-bom` tools directly.
- Use `agent-bom proxy` when CoCo should keep talking to a third-party MCP server, but you want live runtime inspection around that server.
- Use `agent-bom proxy-configure --apply` when you want to auto-wrap eligible JSON-configured stdio servers in Cortex MCP configs.

## Notes

- `agent-bom` does not need write access to the target MCP server to scan it.
- MCP server mode is read-only.
- Proxy mode is opt-in and is the path for runtime enforcement.
- See [MCP_CLIENT_GUIDES.md](MCP_CLIENT_GUIDES.md) for the broader client matrix, [MCP_SERVER.md](MCP_SERVER.md) for the MCP tool catalog, and [RUNTIME_MONITORING.md](RUNTIME_MONITORING.md) for deployment details.
