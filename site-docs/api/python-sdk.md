# Python API

Use the public Python API when another tool needs typed `agent-bom` results
without parsing terminal output, or when services and notebooks need a small
control-plane client for stable REST endpoints.

## Install

```bash
pip install agent-bom
```

Use the API extra when the same environment also starts a local control plane:

```bash
pip install 'agent-bom[api]'
```

## Local Scan Helpers

```python
from agent_bom import check, diff, scan
from agent_bom.sdk import inventory

report = scan(project=".", offline=True)
for finding in report.to_findings():
    print(finding.id, finding.severity)

package = check("requests@2.31.0", ecosystem="pypi", offline=True)
print(package.status, package.vulnerabilities)

fleet = inventory("fleet-inventory.json")
print(fleet.agent_count, fleet.package_count)

delta = diff("baseline.json", "current.json")
print(delta.summary)
```

The API delegates to the same scanner, inventory, and history-diff primitives
used elsewhere in the product. It is not a parallel scan engine.

## Control-Plane Client

```python
from agent_bom import AgentBomClient

with AgentBomClient(
    base_url="https://agent-bom.internal",
    api_key="agent-bom-api-key",
    tenant_id="tenant-a",
) as client:
    print(client.health()["status"])
    manifest = client.agent_manifest()
    runtime = client.runtime_production_index()
    intel = client.intel_sources()

print(manifest["schema_version"], runtime["schema_version"], len(intel.get("sources", [])))
```

Run the packaged smoke example against a live API:

```bash
AGENT_BOM_BASE_URL=http://127.0.0.1:8422 \
AGENT_BOM_API_KEY=dev-key \
python examples/python_sdk/control_plane_smoke.py
```

The client accepts either `api_key` or `bearer_token`. `tenant_id` is sent as
`X-Agent-Bom-Tenant-ID` and used as the default tenant scope for tenant-aware
methods.

::: agent_bom.sdk
