# gateway-relay (Go sidecar spike)

Optional pure HTTP JSON-RPC forwarder for the agent-bom multi-MCP gateway
(ADR-009 / Phase 3). Policy, auth, and audit stay in the Python gateway; this
process only implements `POST /v1/forward` for an already-authorized
`RelayForwardRequest`.

## Run

```bash
cd runtime/gateway-relay
go test ./...
go run ./cmd/gateway-relay -listen 127.0.0.1:8091
```

Python gateway (feature-flagged, default off):

```bash
export AGENT_BOM_GATEWAY_RELAY_BACKEND=go
export AGENT_BOM_GATEWAY_RELAY_GO_URL=http://127.0.0.1:8091
agent-bom gateway serve --bind 127.0.0.1:8090 --upstreams upstreams.yaml
```

## Contract

See `docs/design/GATEWAY_RELAY_CONTRACT.md`. Max body: 2 MiB.
