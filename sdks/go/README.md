# agent-bom Go SDK

The Go SDK is a lightweight control-plane client for stable agent-bom API
routes. It talks to an existing self-hosted API deployment; it does not embed a
scanner or duplicate CLI behavior.

```go
package main

import (
	"context"
	"fmt"

	agentbom "github.com/msaad00/agent-bom/sdks/go"
)

func main() {
	client, err := agentbom.NewClient(agentbom.Options{
		BaseURL:  "https://agent-bom.example.com",
		APIKey:   "...",
		TenantID: "default",
	})
	if err != nil {
		panic(err)
	}

	health, err := client.Health(context.Background())
	if err != nil {
		panic(err)
	}
	fmt.Println(health["status"])
}
```

## Covered Surfaces

- `GET /health`
- `GET /v1/findings`
- `POST /v1/findings/bulk`
- `GET /v1/graph/exposure-paths`
- `POST /v1/graph/should-i-deploy`
- `GET|POST /v1/datasets/{dataset_id}/versions`
- `GET /v1/datasets/{dataset_id}/versions/{version_id}`
- `GET|POST /v1/evaluations`
- `GET /v1/evaluations/{evaluation_id}`
- `GET /v1/agent-bom/manifest`
- `GET /v1/runtime/production-index`
- `GET /v1/intel/advisories/{advisory_id}`
- `POST /v1/intel/match`
- `GET /v1/intel/sources`

Configure either `APIKey` or `BearerToken`, not both. Tenant scope is sent as
`X-Agent-Bom-Tenant-ID` and, where the API accepts it, as `tenant_id`.

## Verify

```bash
cd sdks/go
go test ./...
```
