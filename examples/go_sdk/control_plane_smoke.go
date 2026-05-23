package main

import (
	"context"
	"fmt"
	"os"

	agentbom "github.com/msaad00/agent-bom/sdks/go"
)

func main() {
	baseURL := os.Getenv("AGENT_BOM_BASE_URL")
	if baseURL == "" {
		baseURL = "http://127.0.0.1:8422"
	}

	client, err := agentbom.NewClient(agentbom.Options{
		BaseURL:     baseURL,
		APIKey:      os.Getenv("AGENT_BOM_API_KEY"),
		BearerToken: os.Getenv("AGENT_BOM_BEARER_TOKEN"),
		TenantID:    os.Getenv("AGENT_BOM_TENANT_ID"),
	})
	if err != nil {
		panic(err)
	}

	ctx := context.Background()
	health, err := client.Health(ctx)
	if err != nil {
		panic(err)
	}
	manifest, err := client.AgentManifest(ctx, "")
	if err != nil {
		panic(err)
	}
	runtime, err := client.RuntimeProductionIndex(ctx, "")
	if err != nil {
		panic(err)
	}

	fmt.Printf("health=%v manifest_schema=%v runtime_schema=%v\n", health["status"], manifest["schema_version"], runtime["schema_version"])
}
