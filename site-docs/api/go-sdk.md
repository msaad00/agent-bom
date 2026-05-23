# Go Control-Plane Client

Use the Go SDK when services, CI workers, or agent runtimes need to read or
write stable agent-bom control-plane surfaces without shelling out to the CLI.

## Install

```bash
go get github.com/msaad00/agent-bom/sdks/go
```

## First Call

```go
package main

import (
	"context"
	"fmt"

	agentbom "github.com/msaad00/agent-bom/sdks/go"
)

func main() {
	client, err := agentbom.NewClient(agentbom.Options{
		BaseURL:  "https://agent-bom.internal",
		APIKey:   "agent-bom-api-key",
		TenantID: "tenant-a",
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

Run the packaged smoke example against a live API:

```bash
cd examples/go_sdk
AGENT_BOM_BASE_URL=http://127.0.0.1:8422 \
AGENT_BOM_API_KEY=dev-key \
go run ./control_plane_smoke.go
```

The client accepts either `APIKey` or `BearerToken`. `TenantID` is sent as
`X-Agent-Bom-Tenant-ID` and used as the default tenant scope for tenant-aware
methods.
