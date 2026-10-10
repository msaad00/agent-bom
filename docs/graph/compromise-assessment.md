# Direct compromise assessment contract

`agent_bom.graph.compromise` provides a read-only Python assessment for an
explicit control assumption on a graph snapshot. It classifies direct outgoing
relationships and recorded authorization requests. It does not yet have an
API, CLI, MCP tool or dashboard entry point, and does not search multi-hop
routes.

## Evaluate an authorized snapshot

An application must authorize the tenant, load and pin a snapshot, and retain
that revision with the result. The function checks the supplied tenant against
the graph; that equality check is not authentication or authorization.

```python
from datetime import datetime, timezone

from agent_bom.graph.compromise import CompromiseRequest, assess_direct_compromise

# graph is the application's already authorized, pinned UnifiedGraph.
result = assess_direct_compromise(
    graph,
    CompromiseRequest(root_node_id=selected_node_id, assume_control=True),
    tenant_id=authorized_tenant_id,
    at=datetime.now(timezone.utc),
)
assessment_json = result.model_dump_json(indent=2)
```

The artifact identifies the assumed node, scan, tenant, evaluation time,
relationship budget, evidence-age threshold and each recorded action's
principal, resource, timestamp, source edge and binding IDs. Use the edge and
snapshot references to inspect the original evidence before proposing a
permission or configuration change.

Finding roots also require `affected_node_id` and `assume_exploitation=True`.
The selected component must have a recorded `affects` or `vulnerable_to`
relationship with the finding. This is an explicit hypothetical exploitation
assumption; the finding is not an acting principal or proof of compromise.

## Interpretation

| Field or result | Meaning |
|---|---|
| `supported_at_collection` | A fresh, scoped recorded evaluator allow with source bindings supports that exact action at the recorded time. |
| `denied_at_collection` | A scoped recorded denial applies to that action at that time. Same-time denial takes precedence over an allow. |
| `unknown` | Missing, stale, invalid, conditional, mismatched or truncated evidence does not establish permission. |
| `observation` | A recorded runtime attempt, blocked attempt or failed attempt; no successful execution is inferred. |
| `current_access: not_evaluated` | No current provider permission check was performed. |
| `collection_coverage: unknown` | An empty result is not a clean bill of health. |
| `collector_independence: not_assessed` | The assessment does not authenticate imported receipts or prove independence from the assumed compromised actor. |

Only exact principal, provider, action and resource scope on direct
`can_access` or `has_permission` relationships can support an action. Native
grants alone, package dependencies, network exposure, identity trust and
cross-environment correlation are investigation context. They do not grant
permissions or make an identity session usable. Reverse dependency edges are
excluded, including reverse edges synthesized for bidirectional canvas
traversal.

The default budget is 128 outgoing relationships and a one-hour maximum
evidence age, bounded to 512 relationships and 24 hours. The assessment only
accepts an explicit fresh marker and valid timezone-aware timestamps; it does
not refresh evidence. Partial authority projections cannot hide a denial by
promoting their remaining allow receipts. Different observation times remain
separate records, with no inferred current verdict.

The classifier fails closed for permission support: uncertainty remains
unknown. It neither enforces access nor changes policies, graph state, cloud
resources or runtime behavior. Existing enforcement boundaries are unchanged.

## Verification

```bash
uv run pytest -q tests/graph/test_compromise.py \
  tests/test_graph_hop_authority.py tests/test_exposure_path_evidence_parity.py
```

The tests cover directional scope, action-specific denial, missing and stale
evidence, truncated receipts, finding assumptions, tenant mismatch, non-empty
graph evaluation and SQLite restart parity. They do not establish cloud
authorization, complete collection, detected persistence or escape, or
multi-hop movement between environments.
