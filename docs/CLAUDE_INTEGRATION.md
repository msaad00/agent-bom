# Claude Desktop / Claude Code Integration

This guide covers the full `agent-bom` flow for Anthropic clients:

1. add `agent-bom` as an MCP server so Claude can call the scanner directly
2. scan Claude MCP configurations and project context
3. wrap third-party MCP servers with the runtime proxy when you want live enforcement

## Use agent-bom as an MCP server

### Claude Desktop

Config paths:

- macOS: `~/Library/Application Support/Claude/claude_desktop_config.json`
- Linux: `~/.config/Claude/claude_desktop_config.json`
- Windows: `~/AppData/Roaming/Claude/claude_desktop_config.json`

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

Config paths discovered by `agent-bom`:

- `~/.claude/settings.json`
- `~/.claude.json`

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

The JSON output from `agent-bom skills scan` and `agent-bom skills rescan` is versioned and schema-tagged so it can be consumed safely by automation and dashboards.

## Runtime proxy for Claude-connected MCP servers

When you want live inspection of third-party MCP traffic, wrap the real server:

```bash
agent-bom proxy "npx @modelcontextprotocol/server-filesystem /workspace"
```

For JSON-based configs, auto-wrap all eligible stdio servers:

```bash
agent-bom proxy-configure --log-dir ~/.agent-bom/logs --detect-credentials --apply
```

For enterprise-managed endpoint rollout, generate a packaged bootstrap bundle instead:

```bash
agent-bom proxy-bootstrap \
  --bundle-dir ./endpoint-bundle \
  --control-plane-url https://agent-bom.example.com \
  --push-url https://agent-bom.example.com/v1/fleet/sync
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

## When to use MCP server vs proxy

- Use `agent-bom mcp server` when you want Claude to call the scanner directly.
- Use `agent-bom proxy` when Claude should keep talking to a third-party MCP server, but you want inline runtime inspection and policy enforcement around that traffic.
- Use `agent-bom proxy-configure --apply` when you want to auto-wrap JSON-configured stdio servers in supported Claude config files.

## Notes

- `agent-bom` is read-only in MCP server mode.
- Proxy mode is opt-in and wraps the target server command; it does not modify the server itself.
- Use [MCP_CLIENT_GUIDES.md](MCP_CLIENT_GUIDES.md) for the broader MCP client matrix, [MCP_SERVER.md](MCP_SERVER.md) for the full MCP tool catalog, and [RUNTIME_MONITORING.md](RUNTIME_MONITORING.md) for deployment and policy details.
