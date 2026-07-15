# Runtime Proxy

The `agent-bom proxy` command sits between MCP clients and servers, intercepting all JSON-RPC messages for real-time security enforcement.

Important boundary:

- scanner mode is read-only
- MCP server mode is read-mostly; Shield write actions require admin role, `shield:write` scope, and an audit reason
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

## 7 inline proxy detectors

| Detector | What it catches |
|----------|----------------|
| **ToolDriftDetector** | New, removed, or changed tools after the initial `tools/list` baseline |
| **ArgumentAnalyzer** | Shell injection, path traversal, SSRF targets, prompt injection, and credential values in arguments |
| **CredentialLeakDetector** | API keys, tokens, passwords, and PII in tool call arguments or responses |
| **RateLimitTracker** | Excessive calls per tool within a sliding time window |
| **SequenceAnalyzer** | Multi-step attack patterns such as bulk exfiltration and recon followed by lateral movement |
| **ResponseInspector** | Cloaking, SVG payloads, invisible characters, and response-side prompt injection |
| **VectorDBInjectionDetector** | Prompt injection from retrieved RAG or vector database chunks |

## Usage

```bash
# Basic audit and policy for one stdio server, without process containment.
agent-bom proxy --no-isolate --log audit.jsonl \
  -- npx @modelcontextprotocol/server-filesystem /workspace

# Process-contained stdio proxy. The sandbox image must contain the server
# runtime, such as Node for npx-based MCP servers.
agent-bom proxy \
  --sandbox-image ghcr.io/your-org/mcp-runtime:node20@sha256:<64-hex-digest> \
  --sandbox-image-pin-policy enforce \
  --sandbox-mount "$PWD:/workspace:ro" \
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
- `--sandbox-image` plus `--sandbox-image-pin-policy enforce` when you want
  Docker/Podman process containment for stdio MCP servers

Important containment limits:

- `--no-isolate` is audit and policy only; it does not contain the MCP server
  process.
- `--isolate` is the default for stdio proxy mode. For plain commands such as
  `npx ...`, isolation requires `--sandbox-image` or
  `AGENT_BOM_MCP_SANDBOX_IMAGE`.
- Existing `docker run ...` or `podman run ...` server commands can be hardened
  directly by the proxy; conflicting weaker flags such as host networking are
  stripped before launch.
- `--url` SSE/HTTP proxy mode and the shared gateway govern remote MCP traffic
  but do not containerize the upstream server.

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
        "--no-isolate",
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

## Trace correlation and LLM-observability connectors

Agents that already emit OpenTelemetry traces (or send them to an
LLM-observability platform) get first-class security correlation without extra
wiring.

### Per-span attack-path correlation

`POST /v1/traces/attack-paths` correlates a submitted OTLP trace against the
tenant's scan results and resolves **each vulnerable tool-call span** to the
exact attack path it hit — the precise reachable CVE, the credentials that path
exposes, the non-human identities that hold those credentials, and the blast
radius (affected agents, servers, risk score). This answers "span `abc123` is
the exact call that reached `CVE-2025-1234`", not just "`run_shell` was called
12 times". Correlation is performed in-memory; no raw span content is stored.

### Opt-in trace-content screening

By default the trace-ingest path (`POST /v1/traces`) parses span **metadata
only** and never reads or stores content, for privacy. Set
`AGENT_BOM_TRACE_CONTENT_SCREENING=1` (or pass `?screen_content=true`) to
additionally run Shield over ingested trace **content** and surface
prompt-injection, PII, and credential-leak findings on production traces. Raw
content is screened in-memory and never persisted — only the redacted detector,
severity, and span identity are surfaced.

### Native Langfuse / LangSmith connectors

`GET /v1/traces/connectors` lists the native trace-pull connectors, and
`POST /v1/traces/connectors/{provider}/pull` pulls traces directly from
**Langfuse** or **LangSmith** via their REST APIs — no OTLP re-wiring required.
Pulled traces feed the same parser, per-span correlation, and (opt-in) content
screening as pushed OTLP. Connector credentials are supplied per request (or
from the secret store), used for authentication only, and never logged.
