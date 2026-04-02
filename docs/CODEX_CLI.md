# Codex CLI Integration

This guide covers `agent-bom` with OpenAI Codex CLI and other Codex-oriented local setups that use `~/.codex/config.toml`.

## Use agent-bom as an MCP server

Add this to `~/.codex/config.toml`:

```toml
[mcp_servers.agent-bom]
command = "uvx"
args = ["agent-bom", "mcp", "server"]
```

If `agent-bom` is already installed locally:

```toml
[mcp_servers.agent-bom]
command = "agent-bom"
args = ["mcp", "server"]
```

That makes the same 36 read-only `agent-bom` MCP tools available to Codex.

## What agent-bom discovers for Codex

`agent-bom agents` already discovers Codex MCP servers from:

- macOS: `~/.codex/config.toml`
- Linux: `~/.codex/config.toml`
- Windows: `~/.codex/config.toml`

Codex TOML configs can include:

- stdio MCP servers with `command` and `args`
- remote MCP endpoints with `url`
- bearer token env var references

`agent-bom` parses those and redacts credential-bearing env values in output.

## Scan Codex environments directly

Use the CLI when you want a local audit instead of an MCP tool call:

```bash
agent-bom agents
agent-bom agents -p .
agent-bom mcp inventory
```

## Runtime proxy for Codex-connected MCP servers

Codex uses TOML, so `agent-bom proxy-configure` does not auto-rewrite the config today. Wrap the target server manually:

```toml
[mcp_servers.filesystem]
command = "agent-bom"
args = ["proxy", "--log", "~/.agent-bom/logs/filesystem.jsonl", "--", "npx", "@modelcontextprotocol/server-filesystem", "/workspace"]
```

That gives you:

- tool drift detection
- argument and injection checks
- credential leak detection
- response inspection
- sequence and rate analysis

For deeper protection workflows beyond the lighter proxy path, use the broader runtime engine documented in [RUNTIME_MONITORING.md](RUNTIME_MONITORING.md).

## Notes

- `agent-bom mcp server` is read-only.
- `agent-bom proxy` is the runtime enforcement path.
- Codex TOML configs support both local stdio and remote URL-based MCP servers, but only stdio targets can be wrapped with the local proxy command pattern.
- See [MCP_CLIENT_GUIDES.md](MCP_CLIENT_GUIDES.md) for the broader client matrix.
