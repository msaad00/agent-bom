# Map existing warehouse evidence to a graph

Export the inventory and relationship rows already held in a warehouse, then map
the local JSON into the shared graph contract:

```bash
agent-bom ingest warehouse examples/warehouse-evidence/rows.json \
  --mapping examples/warehouse-evidence/mapping.json \
  --tenant acme -o warehouse-graph.json
```

The example is synthetic. The command reads two local files and creates a new,
private graph artifact. It requires no provider credentials and executes no SQL.
It does not overwrite an existing output, push to a control plane, collect new
inventory, or run a vulnerability scanner. Snowflake, Databricks, ClickHouse and
BigQuery are source labels for exported evidence, not authenticated connector
qualification or interchangeable graph storage backends.

## Mapping contract

`agent-bom.warehouse-mapping/v1` contains `provider`, `source_instance`, an aware
`exported_at` timestamp, and optional `nodes` / `edges` column maps. Column map
values are exact JSON property names; there are no expressions or executable
transforms. Unknown mapping options are rejected. The checked-in example maps
uppercase source columns to the graph's entity identity, kind, label and time.

The rows file contains exactly `nodes` and `edges` arrays. Every node requires a
unique source ID, a supported graph entity type, a label and a timezone-aware
observation time. Optional columns retain `cloud_provider`, `account_id`,
`organization_id`, `environment` and `repository` context. Every edge requires
source/target IDs present in that export, a supported relationship type and an
observation time. Duplicate IDs, duplicate relationships and dangling endpoints
are errors. Use account-qualified native IDs when multiple accounts share an
export; display labels are never identity keys.

Identity is case-sensitive and bound to the caller's explicit tenant, provider,
source instance and native ID. Labels, timestamps and input row order do not
change node identities. A snapshot records both input and mapping digests;
changing either produces a different snapshot. These unsigned local digests do
not authenticate the collector or prevent an operator from rewriting evidence.

Input is limited to 16 MiB per file and 20,000 combined node/edge rows. Oversized
input is rejected, rather than silently presented as a complete graph. Project
only required inventory columns when exporting; unused columns are not copied
to graph nodes, but the input itself still needs appropriate access controls.

## Evidence and next step

Node and relationship times come from source observations. Export time stays in
a separate receipt and does not make old evidence fresh. Imported topology is
`recorded`; runtime execution, effective permissions and collection coverage
remain unverified. Edges default to non-traversable. An explicit boolean
`traversable: true` records the source's claim that a relationship supports graph
traversal; it does not establish exploitation or successful access. Analysis
status separately discloses unknown source collection coverage.

A Python integration can load the artifact with the public shared graph model
and inspect recorded neighbors, preserve it in its chosen graph store, or pass it
to its own correlation workflow:

```python
import json
from pathlib import Path
from agent_bom.graph import UnifiedGraph

graph = UnifiedGraph.from_dict(json.loads(Path("warehouse-graph.json").read_text()))
print(graph.tenant_id, graph.scan_id, len(graph.nodes), len(graph.edges))
```

The local `--tenant` flag only labels this artifact; it grants no API access.
Authenticated control-plane writes must use the deployment's existing tenant
and authorization boundary. Direct evaluation inside a remote warehouse and
continuous source polling are not implemented by this command.
