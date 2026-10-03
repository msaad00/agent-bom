# Connected component investigation

From a source checkout, run the credential-free workflow proof:

```bash
uv run --extra api --extra mcp-server python scripts/prove_connected_bom.py --output-dir /tmp/connected-bom-example
```

Use a new output directory on each run. Existing evidence is preserved.
The script parses an isolated dependency manifest, scans Pillow 9.0.0 against
the bundled advisory fixture, changes the input to 10.0.1, and rescans it.
The pinned CVE-2023-4863 finding disappears from the second snapshot. Neither
version is installed and no deployment is changed. This is one regression
example, not a broad vulnerability-accuracy estimate or a clean verdict.

The output directory contains:

| Artifact | Inspect it for |
|---|---|
| `proof.json` | Input hashes, versions, snapshot generations, node/edge counts, measured runtime and limits |
| `before-component.json`, `after-component.json` | Exact component identity, paginated recorded relationships, finding IDs and source evidence |
| `before-controls.json`, `after-controls.json` | Linked modeled failed-check evidence, scope and explicit evaluation attributes |
| `before-graph.json`, `after-graph.json` | Repository/package hierarchy, synthetic cloud resources and a disconnected model |
| `rescan-diff.json` | The actual change between retained snapshots |
| `graph.db` | Persistent SQLite snapshots, readable after reopening the store |

AWS, Azure and GCP records deliberately share a display name and retain
different provider-native identities. Their topology and failed configuration
check are synthetic, with no cloud API calls or provider qualification implied.
The disconnected model has no invented relationships. The package rescan does
not repair the independent modeled cloud finding.

Next, inspect the same evidence through an MCP client's **graph** profile:

```bash
AGENT_BOM_GRAPH_DB=/tmp/connected-bom-example/graph.db \
AGENT_BOM_MCP_TENANT_ID=connected-bom-example \
uv run --extra api --extra mcp-server agent-bom mcp server --profile graph
```

Call `inventory_asset` with `asset_id="pkg:pypi:pillow@9.0.0"`,
`scan_id="connected-before"`, and `limit=1`. Continue with the returned
`next_cursor` and `snapshot_generation`. The JSON artifact is compared against
the shared REST inventory service by the script. The regression suite also
exercises authenticated HTTP and actual MCP stdio calls:

```bash
uv run --extra dev --extra api --extra mcp-server pytest -q tests/test_connected_bom_journey.py
```

For a deployed dashboard, use an authenticated reader bound to the
`connected-bom-example` tenant and this graph store. Select **Inventory →
component → Findings → Compliance** to retain exact component/snapshot scope.
Control mappings are not evaluated passes. Missing source detail, freshness,
and collection coverage remain explicit unknowns. See the
[deployment guide](../../docs/DEPLOY_QUICKSTART.md) for authentication and storage.

This small local workflow does not qualify enterprise scale, production
deployment, or independent attestation. Live-provider and performance evidence
must be collected separately. For modeled cross-source correlation and a live
local gateway allow/block proof, run the [reference evidence lab](../reference-evidence-lab/README.md).
