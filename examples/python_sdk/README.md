# Python SDK Examples

These examples show the packaged Python adoption path for services, notebooks,
and automation that need typed `agent-bom` evidence.

## Control-Plane Smoke

Start or point at an agent-bom API, then run:

```bash
AGENT_BOM_BASE_URL=http://127.0.0.1:8422 \
AGENT_BOM_API_KEY=dev-key \
AGENT_BOM_TENANT_ID=default \
python examples/python_sdk/control_plane_smoke.py
```

The script calls the same stable endpoints exposed by `AgentBomClient`:

- `/health`
- `/v1/agent-bom/manifest`
- `/v1/runtime/production-index`
- `/v1/intel/sources`

It prints one JSON envelope with status, schema versions, and intel source
count. It does not send scan artifacts or secret values.
