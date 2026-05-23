# Go SDK Smoke

Run this against a live agent-bom API deployment to verify the Go
control-plane client can authenticate and read the first operational surfaces.

```bash
cd examples/go_sdk
AGENT_BOM_BASE_URL=http://127.0.0.1:8422 \
AGENT_BOM_API_KEY=dev-key \
go run ./control_plane_smoke.go
```

The smoke reads `/health`, `/v1/agent-bom/manifest`, and
`/v1/runtime/production-index`. It does not run local scans or write data.
