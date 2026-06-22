# Graph Migration Note

The graph subsystem is mid-consolidation. This note tells newcomers which
implementation is the future and how the two sides bridge today, so new work
lands in the right place.

For the full graph contract (entity/edge coverage, accuracy guarantees, scaling
tiers, known gaps), see [`graph/CONTRACT.md`](graph/CONTRACT.md).

---

## The two graphs

| | Legacy / bridge | Canonical / target |
|---|---|---|
| Module | `src/agent_bom/context_graph.py` | `src/agent_bom/graph/` |
| Builds | An in-memory lateral-movement graph from raw scan JSON dicts | The `UnifiedGraph` from the serialized AIBOM report contract |
| Core types | local `NodeKind` / `EdgeKind` | `EntityType` / `RelationshipType` (`graph/types.py`) |
| Status | Still backs some CLI/API paths; **shrinking** | Where all new graph features belong |

`context_graph.py` answers "if Agent A is compromised, what else becomes
reachable?" over raw dicts (the same shape `output/attack_flow.py` consumes),
which is why it predates the unified model. It converts forward to the canonical
model via `to_unified_graph()`.

`graph/builder.py` ingests the JSON contract emitted by
`output.json_fmt.to_json()` and assembles the canonical inventory, finding,
runtime, and compliance entities used for current-state views, traversal,
attack paths, and temporal diffs.

---

## The bridge

`src/agent_bom/graph/compat.py` keeps the two sides aligned during the
migration. It holds the mapping dicts that convert legacy kinds onto the
canonical enums so nothing is silently dropped:

- `NODE_KIND_TO_ENTITY` — e.g. legacy `iam_role` → `EntityType.SERVICE_ACCOUNT`,
  so cloud/workload identity context survives conversion.
- `EDGE_KIND_TO_RELATIONSHIP` — e.g. legacy `attached_to` →
  `RelationshipType.MEMBER_OF`, so identity-membership edges are preserved.

---

## Direction of travel

- **Add new graph capabilities under `src/agent_bom/graph/`** — the
  `UnifiedGraph` (`graph/container.py`, `graph/node.py`, `graph/edge.py`,
  `graph/types.py`) plus overlays (`cnapp_overlay.py`, `nhi_overlay.py`,
  `governance_overlay.py`) and scoring (`attack_path_fusion.py`,
  `blast_reach.py`).
- **Treat `context_graph.py` as a bridge**, not a place to extend. When a path
  that still uses it gets touched, prefer moving it onto the canonical builder
  and the `compat.py` mappings rather than growing the legacy types.
- When you add a legacy kind that has no canonical mapping yet, add it to
  `compat.py` in the same change so conversion stays lossless.

The consolidation is intentional and in progress — this is not a fork, it is a
one-directional move from `context_graph.py` to `graph/builder.py`.
