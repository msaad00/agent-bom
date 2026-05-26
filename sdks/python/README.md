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
print(client.should_i_deploy("flask@2.0.0", block_risk=80))
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

Configure either `api_key` or `bearer_token`, not both. Tenant scope is sent as
`X-Agent-Bom-Tenant-ID` and, where the API accepts it, as the request
`tenant_id`.

## Workflow Examples

```python
client.ingest_findings(
    [{"id": "finding-1", "severity": "high", "title": "Demo finding"}],
    source="external-scanner",
)

client.register_dataset_version(
    "training-set",
    version_id="2026-05-24",
    artifact_uri="s3://customer-owned-bucket/training-set.jsonl",
    digest="sha256:...",
)

versions = client.dataset_versions("training-set")
evaluation = client.register_evaluation_run(
    evaluation_id="eval-2026-05-25",
    dataset_id="training-set",
    dataset_version_id="2026-05-24",
    model="gpt-4.1-mini",
    prompt_hash="sha256:...",
    scores={"safety": 1.0, "faithfulness": 0.92},
)
decision = client.should_i_deploy("flask@2.0.0", block_risk=80)
```
