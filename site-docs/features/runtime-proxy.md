# Runtime Proxy

The `agent-bom proxy` command sits between MCP clients and servers, intercepting all JSON-RPC messages for real-time security enforcement.

Important boundary:

- scanner mode is read-only
- MCP server mode is read-only
- proxy mode intentionally executes the wrapped stdio server or connects to the remote SSE/HTTP server so it can enforce policy on live traffic

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

# Recommended hardened proxy
agent-bom proxy \
  --policy policy.json \
  --log audit.jsonl \
  --detect-credentials \
  --block-undeclared \
  -- npx @modelcontextprotocol/server-filesystem /workspace
```

Recommended minimum hardening for developer workstations:

- `--log` for auditable JSONL records
- `--detect-credentials` to inspect responses for leaked secrets
- `--block-undeclared` to stop tools that were never declared in `tools/list`
- `--policy` when you want explicit allowlist/blocklist/read-only enforcement

## Audit JSONL example

The proxy writes one sanitized JSON object per line. Durable records keep the
safe policy and relationship fields needed for runtime correlation without
storing raw tool arguments or response bodies.

```jsonl
{"ts":"2026-05-08T18:56:05.635108+00:00","type":"tools/call","tool":"read_file","agent_id":"anonymous","tenant_id":"default","policy":"blocked","event_relationships":{"normalization_version":"1","source":"proxy_tool_call","targets":[{"type":"tool","id":"read_file","role":"invoked_tool","source_field":"tool"}],"resources":[{"type":"path","id":"<path:passwd>","role":"referenced_input","source_field":"path"}]},"prev_hash":"","record_hash_algorithm":"aes-cmac-128","record_hash":"be865de2cfeef8d0f1056cbc8b40ad36"}
```

At shutdown, the proxy appends a `proxy_summary` record with call counts,
blocked counts, latency, replay rejections, relay errors, and audit delivery
backlog fields. The complete field guide lives in
[`docs/RUNTIME_PROXY_AUDIT_JSONL.md`](https://github.com/msaad00/agent-bom/blob/main/docs/RUNTIME_PROXY_AUDIT_JSONL.md).

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
        "--detect-credentials",
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
