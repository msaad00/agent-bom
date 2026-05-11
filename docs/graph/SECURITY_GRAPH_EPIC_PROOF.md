# Best-In-Class Graph Epic Closure Proof

This proof is the closure artifact for #2254. It records what is now guaranteed by the repo, where the deterministic evidence lives, and what remains outside the current guarantee.

## GitHub issue state

Verified on 2026-05-05 with `gh issue view`:

| Issue | State | Closed at | Proof surface |
|---|---:|---|---|
| #2255 typed schema codegen | CLOSED | 2026-05-05T01:51:44Z | Python graph enums in `src/agent_bom/graph/types.py`; generated UI schema in `ui/lib/graph-schema.generated.ts`; parity guard in `tests/test_graph_schema_ui_parity.py` |
| #2256 per-graph layouts | CLOSED | 2026-05-05T02:00:30Z | Layout hooks under `ui/lib/use-*-layout.ts`; dispatcher in `ui/lib/use-graph-layout.ts`; guard in `ui/tests/use-graph-layout.test.tsx` |
| #2257 LOD, aggregation, focus | CLOSED | 2026-05-05T03:46:51Z | LOD resolver in `ui/lib/lod-renderer.ts`; sibling cluster pills in `ui/components/lineage-nodes.tsx`; focused defaults in `ui/components/lineage-filter.tsx`; guards in `ui/tests/lod-renderer.test.ts` |
| #2258 filter algebra | CLOSED | 2026-05-05T03:34:46Z | Constraint propagation in `ui/lib/filter-algebra.ts`; guard in `ui/tests/filter-algebra.test.ts` |
| #2259 accuracy guards | CLOSED | 2026-05-05T03:25:33Z | Round-trip, edge-count, and graph payload snapshot guards in `tests/test_graph_roundtrip.py`, `tests/test_graph_edge_counts.py`, and `tests/test_graph_visual_snapshot.py` |
| #2260 graph contract docs | CLOSED | 2026-05-05T01:08:20Z | Operator/auditor contract in `docs/graph/CONTRACT.md` |
| #2261 two-bucket evidence | CLOSED | 2026-05-05T04:58:33Z | Redaction policy in `src/agent_bom/evidence/policy.py`; persistence-path guard in `tests/test_evidence_policy.py` |
| #2262 effective reach | CLOSED | 2026-05-05T04:58:33Z | Scoring in `src/agent_bom/effective_reach.py`; snapshots in `tests/fixtures/effective_reach_snapshots.json`; guard in `tests/test_effective_reach.py` |

## Current guarantees

### Schema codegen

The Python graph schema is the source of truth for entity types, relationship types, layouts, semantic layers, severities, and default graph filters. UI schema drift is guarded by `tests/test_graph_schema_ui_parity.py`, which compares the checked-in TypeScript schema against Python enums and defaults.

### Layouts

The graph layout dispatcher resolves UI aliases and canonical `GraphLayout` enum values to deterministic layout hooks:

| Surface | Default layout proof |
|---|---|
| Mesh/topology aliases | `topology` and `spawn-tree` resolve to Dagre directions in `ui/lib/use-graph-layout.ts` |
| Security graph | Force layout is a first-class dispatcher target |
| Lineage graph | `dagre-lr` is a first-class dispatcher target |
| Scan pipeline DAG | Sankey is a first-class dispatcher target |

`ui/tests/use-graph-layout.test.tsx` pins alias resolution and verifies radial, Dagre, Dagre-LR aliasing, and Sankey selection without a browser.

### LOD, aggregation, and focus

Readability is split into deterministic controls:

- Zoom levels resolve to `cluster`, `summary`, or `detail` bands in `ui/lib/lod-renderer.ts`.
- Low-zoom cluster rendering only activates when aggregation materially reduces node count, avoiding unlabeled dot fields.
- Sibling fan-outs render as cluster pills in `ui/components/lineage-nodes.tsx`.
- Relevant paths filters default to bounded hop depth and visible layers through `GraphFilterOptions` and `lineage-filter`.

`ui/tests/lod-renderer.test.ts` pins the zoom thresholds and the aggregation fallback.

### Filter algebra

Filters are not independent toggles. `ui/lib/filter-algebra.ts` applies severity, layer, agent, runtime mode, and relationship scope as a propagated constraint system, then returns valid next values for each filter dimension. `ui/tests/filter-algebra.test.ts` exercises the behavior on a synthetic graph with distinguishable inventory, attack, and runtime edges.

### Accuracy guards

The graph has three deterministic accuracy gates:

- Round-trip inventory subset guard: graph build must preserve structural inventory entities.
- Edge-count guard: `tests/fixtures/graph_edge_counts.json` pins the trimmed self-scan fixture with a 5% tolerance.
- Payload snapshot guard: `tests/fixtures/graph-snapshots/security-graph.json` pins graph payload schema, node IDs, edge triples, node-kind distribution, and edge-kind distribution.

Current checked-in payload snapshot:

- Schema: `agent-bom.graph-snapshot/v1`
- Nodes: 11
- Edges: 10
- Node kinds: `agent=1`, `server=8`, `vulnerability=2`
- Edge kinds: `uses=8`, `vulnerable_to=2`

This is intentionally a pure graph-payload guard. It catches dropped nodes, dropped edges, renamed kinds, swapped labels, and distribution drift without requiring Playwright, a live backend, or a browser.

### Two-bucket evidence

Evidence is classified before durable persistence:

- `safe_to_store`: package versions, lockfile source, exposed tool names, declared scopes, command names, hostnames, env var names, client/agent IDs, timestamps, status codes, trace IDs, severity and advisory metadata, and effective-reach fields.
- `replay_only`: raw prompts, tool inputs/outputs, full paths, full URLs, command args, request/response bodies, stdout/stderr, workspace content, and unknown keys.

`tests/test_evidence_policy.py` verifies classification, recursive redaction, persistence-path redaction, replay TTL cleanup, capture-replay opt-in, and badge state.

### Effective reach

Effective reach is a first-class graph signal and edge-adjacent rendering input. `tests/test_effective_reach.py` pins the core scenarios:

- Low reach: vulnerable package behind read-only search tool, no credential exposure, `green`, composite `27.4`.
- High reach: same class of package behind `run_shell`, visible `AWS_*`/GitHub env names, two reachable agents, `pulsing-red`, composite `100.0`.

The snapshot fixture records reachable agents, tools, credential names, CVSS, EPSS, KEV status, tool capability, credential visibility, breadth, band, and composite.

### Layout dispatcher

The merged dispatcher (#2292) is part of this closure proof because it removes per-surface layout drift. `resolveGraphLayoutKind()` maps canonical layout enum values and UI aliases to one concrete hook surface: `force`, `radial`, `dagre`, `dagre-lr`, or `sankey`.

## Honest limits

These limits do not block #2254 closure, but they define what this proof does not claim:

- The Python graph-payload snapshot is not a screenshot or pixel-diff test. It is stronger for graph-data regressions and intentionally does not prove CSS, canvas, or React Flow rendering.
- The checked-in self-scan fixture for accuracy gates is trimmed to 11 nodes and 10 edges. The epic's larger 244-node / 302-edge readability target is covered by deterministic UI algorithms and child issue closure, not by a live browser proof in this PR.
- Static graph edges are reachability and correlation claims, not causality claims. Runtime causality still requires proxy/gateway traces.
- Cross-cluster federation, cross-cloud trust relationships, multi-region asset stitching, and non-MCP agent collaboration remain out of contract per `docs/graph/CONTRACT.md`.

## Closure verdict

The proof is sufficient to close #2254: every child issue #2255-#2262 is closed, each acceptance area has a deterministic repo-backed proof surface, and the remaining limits are explicitly documented as non-blocking boundaries rather than missing child work.

Suggested PR body line:

```text
Closes #2254.
```

Validation command for this artifact:

```bash
python scripts/check_graph_epic_proof.py
```
