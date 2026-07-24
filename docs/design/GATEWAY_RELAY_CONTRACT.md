# Design: gateway pure-relay contract

**Status:** Phase 2 extract (Python reference). Optional Go sidecar is **not**
implemented here — see [ADR-009](../decisions/009-python-primary-go-sidecar-later.md)
and the Go-gate evidence in
[`docs/perf/gateway-relay-latency.md`](../perf/gateway-relay-latency.md)
(`gate_tripped=true` on 2026-07-23).

**Code:** [`src/agent_bom/runtime/gateway_relay_contract.py`](../../src/agent_bom/runtime/gateway_relay_contract.py)

## Why this exists

`gateway_server.py` mixes (a) auth / policy / firewall / budget / DLP and
(b) the HTTP JSON-RPC forward to upstream MCP servers. A future Go sidecar may
replace **only (b)** behind a stable contract owned by the Python control plane.
Policy evaluation stays in Python for v1 (in-process today; HTTP callback is an
allowed later shape).

## Surfaces

| Surface | Owner today | Sidecar-replaceable? |
|---------|-------------|----------------------|
| Listen `host:port`, `/healthz`, `/metrics`, `/mcp/{name}` | Python FastAPI gateway | No (orchestration) |
| Upstream registry (`upstreams.yaml` / discovery) | Python `UpstreamRegistry` | Snapshot JSON only |
| Policy / identity / firewall / budget / DLP | Python gateway | No (v1) |
| Pure JSON-RPC HTTP forward | `GatewayRelayTransport.forward` | **Yes** |
| Audit push to `/v1/proxy/audit` + runtime events | Python (`build_gateway_runtime_event`) | Sidecar may emit metadata-only hints |

## Listen / route contract (orchestration stays Python)

- Bind: `agent-bom gateway serve --bind HOST:PORT` (loopback may omit incoming
  bearer auth; non-loopback requires token / API keys / explicit insecure override).
- Client route: `POST /mcp/{server_name}` with a JSON-RPC body.
- Upstream URL comes from registry `name` → `url` (streamable-http only).
- Health: `GET /healthz`. Metrics: `GET /metrics` (Prometheus text).

## Pure relay request

After Python decides **ALLOW**, it builds a `RelayForwardRequest`:

```json
{
  "upstream": {
    "name": "echo",
    "url": "http://127.0.0.1:8100/mcp",
    "tenant_id": "",
    "private_network_approved": true
  },
  "message": {
    "jsonrpc": "2.0",
    "id": 1,
    "method": "tools/call",
    "params": {"name": "echo", "arguments": {}}
  },
  "headers": {
    "Authorization": "Bearer …"
  }
}
```

Rules:

1. Presence of the request means policy already allowed the call.
2. Max request/response body: **2 MiB** (`MAX_GATEWAY_RELAY_MESSAGE_BYTES`).
3. Transport: HTTP `POST` with `Content-Type: application/json`.
4. Private / loopback upstreams require `private_network_approved=true`
   (operator YAML); discovery-only entries stay public-only.
5. Failures (HTTP error, timeout, oversized body) raise to the orchestrator;
   the orchestrator maps them to circuit-breaker + audit outcomes
   (`upstream_error`, `upstream_timeout`, `circuit_open`).

## Pure relay response

```json
{
  "message": { "jsonrpc": "2.0", "id": 1, "result": { } },
  "upstream_name": "echo",
  "bytes_read": 123
}
```

Non-JSON upstream bodies are wrapped as
`{"jsonrpc":"2.0","id":…,"result":{"raw":"…"}}` so audit still fires.

## Audit

Durable events must stay metadata-only via
`agent_bom.runtime.gateway_events.build_gateway_runtime_event`.
`RelayAuditHint` is a sidecar-friendly sketch (`action`, `upstream`,
`tenant_id`, `outcome`, optional `tool` / `reason`) — no raw args/results.

## Fail-open / fail-closed

| Layer | Default | Notes |
|-------|---------|-------|
| Pure relay transport | fail-closed on HTTP/timeout/oversize | Raises; no silent empty success |
| Policy engine | fail-closed unless `AGENT_BOM_GATEWAY_FAIL_MODE=open` | Outside this contract |
| Missing agent identity | fail-closed on non-loopback | Outside this contract |

## Contract tests

`tests/test_gateway_relay_contract.py` exercises the Python reference
(`forward_jsonrpc_http` / `PythonHttpRelayTransport`) against the local mock
upstream and asserts Protocol compliance. A future Go binary must pass the same
behavioral checks (HTTP status, JSON-RPC result, oversize rejection).

## Non-goals

- No Go binary in this phase.
- No rewrite of stdio `proxy.py` or cloud connectors.
- No second product edition.
