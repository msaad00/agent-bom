# Python API

`agent-bom` exposes a small public Python API for tools that want typed scan
results without shelling out to the CLI, plus a typed control-plane client for
stable REST endpoints. These surfaces are wrappers over shipped scanner,
inventory, diff, and API primitives; they are not parallel implementations.

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

## Control-Plane Client

Use `AgentBomClient` from services, notebooks, and automation that already have
an agent-bom API URL and token. The client keeps auth and tenant headers in one
place and exposes stable evidence endpoints without requiring callers to build
URLs manually.

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
    decision = client.should_i_deploy("flask@2.0.0", block_risk=80)

print(manifest["schema_version"], runtime["schema_version"], len(intel.get("sources", [])), decision["decision"])
```

For a smoke test against a running API:

```bash
AGENT_BOM_BASE_URL=http://127.0.0.1:8422 \
AGENT_BOM_API_KEY=dev-key \
python examples/python_sdk/control_plane_smoke.py
```

## Functions

| Function | Returns | Boundary |
|---|---|---|
| `scan(...)` | `agent_bom.models.AIBOMReport` | Runs the same local simple scan runner used by CLI scan-consuming commands. |
| `check(...)` | `PackageCheckResult` | Synchronous single-package vulnerability check. |
| `async_check(...)` | `PackageCheckResult` | Async single-package vulnerability check for applications already running an event loop. |
| `agent_bom.sdk.inventory(...)` | `InventoryResult` | Parses JSON, CSV, or NDJSON inventory using the canonical inventory loader. Kept under `agent_bom.sdk` to avoid shadowing the existing `agent_bom.inventory` module. |
| `diff(...)` | `DiffResult` | Diffs two agent-bom reports or SBOM documents using the history diff engine. |

## Client Methods

| Method | Endpoint | Use |
|---|---|---|
| `health()` | `GET /health` | API liveness and configured subsystem health. |
| `agent_manifest()` | `GET /v1/agent-bom/manifest` | Tenant-scoped agent, MCP server, tool, and credential-reference posture. |
| `runtime_production_index()` | `GET /v1/runtime/production-index` | Runtime traffic, policy, freshness, alert, and retention posture. |
| `exposure_paths()` | `GET /v1/graph/exposure-paths` | Graph-backed reachability and blast-radius paths. |
| `should_i_deploy(...)` | `POST /v1/graph/should-i-deploy` | Allow/warn/block deployment guidance from graph risk. |
| `list_findings(...)` | `GET /v1/findings` | Normalized findings with severity and pagination filters. |
| `ingest_findings(...)` | `POST /v1/findings/bulk` | Bulk finding ingest from external scanners or jobs. |
| `register_dataset_version(...)` | `POST /v1/datasets/{dataset_id}/versions` | Dataset artifact evidence registration. |
| `register_evaluation_run(...)` | `POST /v1/evaluations` | Evaluation run evidence linked to dataset versions, traces, models, and prompt hashes. |
| `evaluation_runs(...)` | `GET /v1/evaluations` | Tenant-scoped evaluation run listing with dataset filters. |
| `evaluation_run(...)` | `GET /v1/evaluations/{evaluation_id}` | One evaluation run record. |
| `intel_lookup(...)` | `GET /v1/intel/advisories/{advisory_id}` | Advisory lookup by CVE, GHSA, or OSV ID. |
| `intel_match(...)` | `POST /v1/intel/match` | Match package coordinates against local advisory intelligence. |
| `intel_sources()` | `GET /v1/intel/sources` | Source registry and freshness metadata. |

Common write and governance calls keep the payload in the first positional
argument:

```python
client.ingest_findings(
    [{"id": "finding-1", "severity": "high", "title": "External scanner finding"}],
    source="external-scanner",
)
client.register_dataset_version("training-set", version_id="2026-05-24")
client.register_evaluation_run(
    evaluation_id="eval-2026-05-25",
    dataset_id="training-set",
    dataset_version_id="2026-05-24",
    model="gpt-4.1-mini",
    prompt_hash="sha256:...",
    scores={"safety": 1.0},
)
client.should_i_deploy("flask@2.0.0", block_risk=80)
```

## Notes

- `check()` cannot be called from an already running event loop; use
  `async_check()` in async applications.
- `scan(config_path=...)` and `scan(project=...)` both define the local scan
  scope. Passing both is allowed only when they refer to the same path.
- The returned `AIBOMReport` uses the same typed dataclasses as the rest of the
  package, including `Finding`, `Asset`, `Package`, and `BlastRadius`.
- The control-plane client accepts either `api_key` or `bearer_token`, not both.
  `tenant_id` is sent as `X-Agent-Bom-Tenant-ID` and is also used as the
  default tenant query/body value for tenant-scoped methods.
