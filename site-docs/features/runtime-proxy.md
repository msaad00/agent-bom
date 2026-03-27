# Runtime Proxy

The `agent-bom proxy` command sits between MCP clients and servers, intercepting all JSON-RPC messages for real-time security enforcement.

## Architecture

```
MCP Client (Claude, Cursor, etc.)
    │
    ▼
agent-bom proxy  ←── policy.json
    │   ├── JSONL audit log
    │   └── Prometheus metrics (:8422)
    ▼
MCP Server (filesystem, postgres, etc.)
```

## Five detectors

| Detector | What it catches |
|----------|----------------|
| **Tool Drift** | Tools invoked at runtime not declared in `tools/list` (rug pull detection) |
| **Argument Analyzer** | Shell injection, path traversal, credential values in arguments |
| **Credential Leak** | API keys/tokens in tool call arguments or responses |
| **Rate Limiter** | Excessive calls per tool within a time window |
| **Sequence Analyzer** | Multi-step attack patterns (bulk exfiltration, recon + lateral movement) |

## Usage

```bash
# Basic audit logging
agent-bom proxy --log audit.jsonl \
  -- npx @modelcontextprotocol/server-filesystem /workspace

# With policy enforcement
agent-bom proxy \
  --policy policy.json \
  --log audit.jsonl \
  --block-undeclared \
  -- npx @modelcontextprotocol/server-filesystem /workspace
```

## Claude Desktop integration

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-bom",
      "args": [
        "proxy",
        "--log", "audit.jsonl",
        "--policy", "policy.json",
        "--block-undeclared",
        "--",
        "npx", "@modelcontextprotocol/server-filesystem", "/workspace"
      ]
    }
  }
}
```

## Prometheus metrics

The proxy exposes metrics on port 8422:

- `agent_bom_proxy_tool_calls_total` — calls per tool
- `agent_bom_proxy_blocked_total` — blocks by reason
- `agent_bom_proxy_latency_ms` — p50/p95 latency
- `agent_bom_proxy_replay_rejections_total` — replay attacks detected

See [Grafana Dashboard](../deployment/grafana.md) for pre-built visualization.
