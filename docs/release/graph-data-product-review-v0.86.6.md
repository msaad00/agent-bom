# Graph and Data Product Review for v0.86.6

Date: 2026-05-12

This review exists because screenshot polish is only the visible symptom. The
graph product has to become a security investigation system: readable at first
paint, accurate against the canonical graph model, scalable for large estates,
and impressive without becoming a decorative canvas.

## Verdict

agent-bom already has strong graph ingredients:

- canonical graph schema with 18 entity types and 25 relationship types
- deterministic canonical node and edge IDs
- attack paths, blast radius, inventory, dependency review, lineage, mesh, and
  security graph views
- persisted graph stores for SQLite/Postgres plus API endpoints for snapshots,
  attack paths, paths, impact, search, node detail, diff, query, schema, and
  legends
- React Flow views with Dagre, radial, force, and Sankey layout helpers

The gap is not whether agent-bom has graphs. It does. The gap is that the
surfaces still feel like separate visualizations over related data instead of
one graph-backed security command language.

Target state: every graph surface should answer four questions immediately:

1. What is exposed?
2. Why does it matter?
3. What entities and relationships prove it?
4. What is the fix or containment step?

## Current Main Status

This document started as a design review. The main branch has since shipped a
large part of that plan, so the release narrative should separate delivered
capability from future graph-platform work.

Shipped on `main` after `v0.86.5`:

- **Time-versioned graph edges** — SQLite and Postgres edges carry
  `valid_from`, `valid_to`, confidence, provenance, source scan, and source run
  metadata, with `/v1/graph/edges/active` and `/v1/graph/edges/changes` API
  routes.
- **Measured graph benchmark evidence** — benchmark artifacts now report real
  measured API path timings while keeping synthetic-estate disclaimers explicit.
- **Large graph fallback hardening** — broad graph views have a defensive
  overview path instead of forcing every dense scene into the focused renderer.
- **API-native `ExposurePath` contract** — fix-first and attack-path APIs share
  a structured path shape for risk, hops, evidence, fix target, and provenance.
- **Toxic-combo projection** — compound risk conditions are represented as graph
  entities and relationships instead of living only in narrative summaries.
- **Renderer switch contract** — the UI can choose React Flow, large overview,
  or WebGL paths by graph size and focus state.
- **Semantic clusters** — package, CVE, agent, server, credential, tool, and
  source-family clusters reduce raw topology before rendering.
- **Postgres hot-path indexes** — graph search, node hydration, and attack-path
  SQL paths have explicit index coverage for the known slow paths.
- **Neptune backend lane** — the adapter boundary and optional enterprise graph
  backend design are documented; implementation remains optional and must not
  weaken the SQLite/Postgres defaults.

Release blockers and non-claims:

- Existing SQLite graph DBs must migrate time-versioned edge columns before
  `v0.86.6` can be tagged; otherwise existing `/v1/graph*` users can hit
  `OperationalError: no such column: valid_from`.
- A live Neptune deployment, production Neptune latency SLO, openCypher query
  endpoint, and 50k-node WebGL operations claim are not shipped claims in this
  review.
- SARIF, Markdown, and HTML outputs still need `ExposurePath` propagation before
  the path contract can be described as format-wide.

## External Benchmark

Public references do not disclose Wiz or CrowdStrike's exact browser graph
renderer. The public signal is about the data model and scale:

- AWS states that Wiz maps detected risks and the technology stack onto a Wiz
  Security Graph built on Amazon Neptune, with graph context used to prioritize
  risks and reveal actionable issues.
- AWS also reports that Wiz stores hundreds of billions of relationships and
  scans billions of cloud resources daily.
- CrowdStrike describes Threat Graph as a purpose-built graph database for
  cybersecurity and describes Asset Graph as a graph database for visibility
  across devices, users, accounts, applications, cloud workloads, OT, and more.
- Sigma.js is publicly documented as a WebGL graph renderer built on graphology.

References:

- https://aws.amazon.com/solutions/case-studies/wiz-neptune/
- https://www.crowdstrike.com/products/falcon-platform/threat-graph/
- https://www.crowdstrike.com/en-us/press-releases/crowdstrike-introduces-crowdstrike-asset-graph/
- https://v4.sigmajs.org/

## What Amazon Neptune Means For agent-bom

Amazon Neptune is AWS's managed graph database service. It is not a frontend
graph renderer. It is the backend layer that stores entities and relationships
as a queryable graph, supports graph query languages, and is built for highly
connected data such as identities, cloud resources, packages, findings,
credentials, tools, and attack paths.

For agent-bom, Neptune matters as an enterprise backend option, not as a
requirement:

- self-hosted default should remain Postgres/SQLite so local and customer-VPC
  deployments stay simple
- enterprise deployments can add a Neptune adapter for high-scale graph
  traversal and managed AWS operations
- the UI should not depend on Neptune directly; it should depend on stable API
  contracts such as `ExposurePath`, `Entity`, `Relationship`, `Finding`,
  `Evidence`, and `TimeRange`
- the same graph API should be able to read from Postgres today and Neptune or
  Neo4j later

The path to that level is realistic if agent-bom keeps the graph contract clean:
canonical IDs, typed relationships, evidence/provenance, temporal fields, and
query results that already look like security investigations instead of raw
database rows.

## Current Architecture

Backend data model:

- Python graph core: `src/agent_bom/graph/`
- canonical entities: `EntityType`
- canonical relationships: `RelationshipType`
- graph node contract: `UnifiedNode`
- graph edge contract: `UnifiedEdge`
- path contract: `AttackPath`
- graph API: `src/agent_bom/api/routes/graph.py`
- stores: `src/agent_bom/api/graph_store.py`,
  `src/agent_bom/api/postgres_graph.py`

Frontend graph model:

- TypeScript schema parity: `ui/lib/graph-schema.ts`
- generated schema: `ui/lib/graph-schema.generated.ts`
- React Flow adapter: `ui/lib/unified-graph-flow.ts`
- mesh graph adapter: `ui/lib/mesh-graph.ts`
- attack path helpers: `ui/lib/attack-paths.ts`
- renderers today: `@xyflow/react`, Dagre, radial, force, Sankey

Visible surfaces:

- `/security-graph`: fix-first attack path queue and selected path evidence
- `/graph`: lineage graph and investigation drilldown
- `/mesh`: agent/MCP/package/finding topology
- `/insights`: dependency and risk summaries
- `/scan?view=mesh`: scan-scoped mesh view
- dashboard: top paths and posture pressure

## Root Issues

### 1. The graph surfaces do not share one investigation model

`/security-graph`, `/mesh`, `/graph`, `/insights`, and dashboard attack cards
all expose related ideas, but each has its own shape and emphasis. This creates
drift:

- path ranking is not presented identically everywhere
- mesh focuses topology while security graph focuses paths
- lineage focuses root investigation
- dependency map focuses package inventory

Required fix: introduce a shared `ExposurePath` contract for UI and API:

```text
ExposurePath
├─ id
├─ rank
├─ risk_score
├─ severity
├─ source entity
├─ target finding
├─ hops: EntityRef[]
├─ edges: RelationshipRef[]
├─ affected_agents
├─ affected_servers
├─ reachable_tools
├─ exposed_credentials
├─ dependency_context
├─ evidence
├─ fix target
└─ provenance and timestamps
```

Every surface should use this contract for top path, path queue, focused graph,
evidence drawer, and screenshot capture.

### 2. React Flow is the wrong ceiling for large graph exploration

React Flow is good for path diagrams and interactive node cards. It is not the
right default renderer for thousands of visible nodes.

Keep React Flow for:

- selected attack path
- evidence-aware path sequence
- focused neighborhood investigation
- remediation and fix-first flows

Add WebGL for:

- environment-scale graph exploration
- high-density inventory visualization
- clusters and overview mode
- 5k+ visible nodes

Recommended renderer:

- `sigma` + `graphology`

Why:

- WebGL rendering in the browser
- graphology gives a real graph data structure
- better fit for large readable topology than React Flow
- easier to keep the UI in React/TypeScript than moving to a separate app

Cytoscape.js is useful for algorithms and layouts, but it should not be the
primary renderer. Use Cytoscape only if a specific layout or graph algorithm is
needed. Use 3D/Three.js only as an optional demo mode, not as the default
security operations surface.

### 3. We need semantic clusters, not more raw nodes

Security-vendor-grade graphs reduce complexity before rendering. Required
cluster types:

- tenant
- environment
- source/provider
- agent fleet
- MCP server
- package family
- CVE/finding family
- credential family
- tool capability

Cluster nodes must be accurate and reversible:

```text
cluster:package_family:pypi:cryptography
  count.packages
  count.findings
  max.severity
  max.risk_score
  has_kev
  affected_agents
  expandable_node_ids
```

The first graph view should show clusters and top paths, then expand on demand.

### 4. Edges need provenance and confidence in the UI

The backend has evidence fields on `UnifiedEdge`, but UI does not make edge
confidence/provenance first-class enough. Required edge display:

- relationship type
- direction
- traversable true/false
- first_seen / last_seen
- source scanner or API ingest source
- confidence
- evidence count
- stale/drift/new flags

This matters for Fortune 500 buyers because they will ask why a relationship is
trusted.

### 5. Time and diff need to be visual, not hidden

The schema has temporal fields. The product needs:

- new since last scan
- removed since last scan
- risk increased
- path appeared
- path resolved
- first_seen / last_seen per node and edge
- graph snapshot retention policy

This should be visible as overlays on `/security-graph`, `/graph`, and WebGL
overview mode.

## Recommended Stack

### Keep

- Python + FastAPI API layer
- current graph dataclasses and stores
- React + TypeScript + Next.js UI
- React Flow for focused path and evidence workflows
- Dagre/radial/Sankey as focused-layout options

### Add

- `sigma`
- `graphology`
- `graphology-layout-forceatlas2` or a worker-backed layout package
- Web Worker layout pipeline for large graphs
- shared `ExposurePath` TypeScript contract
- shared graph renderer switch:

```text
visible nodes <= 500       React Flow focused renderer
visible nodes 501-5,000    Sigma WebGL overview renderer
visible nodes > 5,000      clustered Sigma overview with expansion windows
```

### Optional Enterprise Backends

Default self-hosted path should stay Postgres/SQLite, but enterprise graph
adapters should be explicit:

- Neo4j: common enterprise graph query backend
- Amazon Neptune: closest public analog to Wiz's Security Graph stack
- ClickHouse: analytics/time-series pressure, not the traversal source of truth

Do not require Neptune/Neo4j for local-first or self-hosted adoption.

## UI Target

The security graph first screen should have:

- top exposed path, zoomed in and already selected
- path queue sorted by risk
- cluster summary strip
- graph canvas with focus mode and overview mode
- evidence drawer
- relationship legend
- filters for severity, KEV, EPSS, reachability, credentials, tools,
  environment, owner, tenant, source, entity type, relationship type
- one-click exports for JSON/SARIF/GraphML/Cypher/Mermaid

The first screenshot should show:

- selected path
- affected agents
- vulnerable package
- CVE/finding
- reachable tool or credential exposure
- fix version or containment step
- clear relationship labels or legend

It should not show:

- browser chrome
- duplicate dark/light theme shots
- huge empty canvas
- raw topology with no selected story

## PR Plan

### PR 1: Shared ExposurePath contract

Scope:

- add frontend shared `ExposurePath` model
- adapt `/security-graph`, `/mesh`, dashboard attack cards, and scan mesh to the
  same selected path shape
- keep backend API unchanged where possible by adapting existing `AttackPath`
  and `blast_radius`

Acceptance:

- one path ranking helper used across graph surfaces
- one card/strip component used across graph surfaces
- tests prove CVE/package/agent focus produces the same path across surfaces

### PR 2: Security graph command center redesign

Scope:

- selected path graph as first visual, not a full raw topology
- path queue as secondary list
- evidence drawer for selected nodes/edges
- cluster summary strip

Acceptance:

- first viewport answers what/why/fix/evidence
- selected path readable at README scale
- Playwright screenshot checks dark and light themes

### PR 3: Sigma/WebGL overview renderer

Scope:

- add `sigma`, `graphology`, and layout worker
- add `GraphRendererSwitch`
- render overview graph in WebGL when visible graph exceeds threshold
- preserve React Flow for focused path

Acceptance:

- 5k-node fixture renders without blank canvas
- zoom/pan/filter stays responsive
- selected path can be projected into overview mode
- no loss of node/edge labels in focused mode

### PR 4: Semantic clustering and summarization

Scope:

- cluster package families, CVEs, agents, environments, servers
- add cluster metadata to graph API or frontend adapter
- add expandable cluster windows

Acceptance:

- 10k+ entity fixture defaults to fewer than 500 rendered nodes
- cluster counts and max risk are accurate
- expansion preserves canonical node and edge IDs

### PR 5: Temporal graph overlays

Scope:

- add new/changed/removed overlays from graph diff
- path appeared/resolved cards
- first_seen/last_seen displayed in drawer

Acceptance:

- scan-to-scan diff visible in graph UI
- graph snapshot tests cover node, edge, and path changes

## Release Gate For Graph Claims

Before claiming vendor-grade graph quality:

- run graph API tests
- run UI graph tests and Playwright screenshot checks
- validate at least 5k nodes locally
- validate cluster reduction on 10k+ node fixture
- verify dark/light screenshot readability
- verify selected path export preserves canonical node and edge IDs
- document whether renderer is React Flow or Sigma for the captured surface

## Immediate Recommendation

Do not start with 3D. Start with:

1. shared `ExposurePath`
2. `/security-graph` command center redesign
3. Sigma/WebGL overview fallback

This gives the product the right security story first, then raises the visual
and scale ceiling without sacrificing readability.
