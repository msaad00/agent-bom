# Python API

`agent-bom` exposes a small public Python API for tools that want typed scan
results without shelling out to the CLI. The API is a wrapper over shipped
scanner, inventory, and diff primitives; it is not a separate scanner.

```python
from agent_bom import check, diff, inventory, scan

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

## Functions

| Function | Returns | Boundary |
|---|---|---|
| `scan(...)` | `agent_bom.models.AIBOMReport` | Runs the same local simple scan runner used by CLI scan-consuming commands. |
| `check(...)` | `PackageCheckResult` | Synchronous single-package vulnerability check. |
| `async_check(...)` | `PackageCheckResult` | Async single-package vulnerability check for applications already running an event loop. |
| `inventory(...)` | `InventoryResult` | Parses JSON, CSV, or NDJSON inventory using the canonical inventory loader. |
| `diff(...)` | `DiffResult` | Diffs two agent-bom reports or SBOM documents using the history diff engine. |

## Notes

- `check()` cannot be called from an already running event loop; use
  `async_check()` in async applications.
- `scan(config_path=...)` and `scan(project=...)` both define the local scan
  scope. Passing both is allowed only when they refer to the same path.
- The returned `AIBOMReport` uses the same typed dataclasses as the rest of the
  package, including `Finding`, `Asset`, `Package`, and `BlastRadius`.
