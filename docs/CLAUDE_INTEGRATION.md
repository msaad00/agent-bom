# Claude Desktop / Claude Code Integration

This guide covers the full `agent-bom` flow for Anthropic clients:

1. add `agent-bom` as an MCP server so Claude can call the scanner directly
2. scan Claude MCP configurations and project context
3. wrap third-party MCP servers with the runtime proxy when you want live enforcement

## Use agent-bom as an MCP server

### Claude Desktop

Add to your `claude_desktop_config.json`:

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

If you prefer not to install globally, use `uvx` instead:

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

### Claude Code

The quickest path is:

```bash
claude mcp add agent-bom -- uvx agent-bom mcp server
```

`agent-bom` also discovers Claude Code project MCP servers from `~/.claude.json`.

## What users get inside Claude

`agent-bom mcp server` exposes 36 read-only tools for:

- agent and MCP discovery
- package and registry checks
- blast radius analysis
- compliance evidence
- skills scanning and trust
- SBOM generation
- runtime and tool-risk queries

## Scan Claude environments directly

Use the CLI when you want a local audit instead of an MCP tool call:

```bash
agent-bom agents
agent-bom agents -p .
agent-bom skills scan .
```

This discovers Claude Desktop and Claude Code MCP configs, project-level instruction files, and the packages behind those MCP servers.

## Runtime proxy for Claude-connected MCP servers

When you want live inspection of third-party MCP traffic, wrap the real server:

```bash
agent-bom proxy "npx @modelcontextprotocol/server-filesystem /workspace"
```

For JSON-based configs, auto-wrap all eligible stdio servers:

```bash
agent-bom proxy-configure --log-dir ~/.agent-bom/logs --detect-credentials --apply
```

The proxy adds runtime inspection for:

- tool drift
- argument injection
- credential leakage
- rate spikes
- suspicious sequences
- response cloaking
- vector/RAG injection

For cross-agent correlation across sessions, use the broader runtime protection engine with `agent-bom runtime protect --shield`.

## Notes

- `agent-bom` is read-only in MCP server mode.
- Proxy mode is opt-in and wraps the target server command; it does not modify the server itself.
- Use [MCP_SERVER.md](MCP_SERVER.md) for the full MCP tool catalog and [RUNTIME_MONITORING.md](RUNTIME_MONITORING.md) for deployment and policy details.
