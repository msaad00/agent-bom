# Python API

Use the public Python API when another tool needs typed `agent-bom` results
without parsing terminal output.

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

The API delegates to the same scanner, inventory, and history-diff primitives
used elsewhere in the product. It is not a parallel scan engine.

::: agent_bom.sdk
