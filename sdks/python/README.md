# agent-bom Python SDK

The Python SDK is the packaged `agent_bom.AgentBomClient` control-plane client.
It talks to an existing agent-bom API deployment and keeps authentication and
tenant scope explicit.

```python
from agent_bom import AgentBomClient

client = AgentBomClient(
    base_url="https://agent-bom.example.com",
    api_key="...",
    tenant_id="default",
)

print(client.health())
print(client.exposure_paths(limit=5, min_risk=70))
print(client.runtime_production_index())
```

## Covered Surfaces

- `GET /health`
- `GET /v1/findings`
- `POST /v1/findings/bulk`
- `GET /v1/graph/exposure-paths`
- `POST /v1/graph/should-i-deploy`
- `GET|POST /v1/datasets/{dataset_id}/versions`
- `GET /v1/datasets/{dataset_id}/versions/{version_id}`
- `GET /v1/agent-bom/manifest`
- `GET /v1/runtime/production-index`
- `GET /v1/intel/advisories/{advisory_id}`
- `POST /v1/intel/match`
- `GET /v1/intel/sources`

Configure either `api_key` or `bearer_token`, not both. Tenant scope is sent as
`X-Agent-Bom-Tenant-ID` and, where the API accepts it, as the request
`tenant_id`.
