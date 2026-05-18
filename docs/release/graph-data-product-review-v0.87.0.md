# Graph and Data Product Review for v0.87.0

Date: 2026-05-15

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
- **Sigma/WebGL overview** — the WebGL overview path is wired through
  Sigma.js/graphology for broad graph scenes, while React Flow remains the
  focused investigation renderer.
- **Semantic clusters** — package, CVE, agent, server, credential, tool, and
  source-family clusters reduce raw topology before rendering.
- **Postgres hot-path indexes** — graph search, node hydration, and attack-path
  SQL paths have explicit index coverage for the known slow paths.
- **Legacy SQLite graph migration** — existing local graph DB files are upgraded
  in place before read paths query the time-versioned edge columns.
- **Identity graph depth** — the schema includes organization, account, role,
  policy, service principal, and federated identity nodes, with AWS IAM
  enrichment gated behind an explicit opt-in flag.
- **Headless MCP graph tools** — `exposure_paths` returns ranked investigation
  paths and `should_i_deploy` returns allow/warn/block deploy guidance from the
  same risk model.
- **Report propagation** — ExposurePath evidence is present in SARIF, Markdown,
  HTML, JSON, and MCP responses.
- **Neptune backend lane** — the adapter boundary and optional enterprise graph
  backend implementation are on `main`; it remains optional and must not weaken
  the SQLite/Postgres defaults.

Closed blockers and non-claims:

- The legacy SQLite graph DB migration blocker is closed. Existing graph DBs
  must still be smoke-tested during release because this path protects existing
  customer state.
- A live Neptune deployment, production Neptune latency SLO, openCypher query
  endpoint, and 50k-node WebGL operations claim are not shipped claims in this
  review.
- Sigma/WebGL is a shipped overview renderer path, not a claim that every
  browser session can interactively operate on unbounded graph sizes.
- AWS IAM enrichment is opt-in and read-only. It does not imply complete IAM
  coverage for every cloud provider or every AWS service role pattern.

## External Benchmark

Public reference signal for graph-backed cloud-security platforms focuses on
the data model and scale, not the browser renderer:

- Leading commercial cloud-security graph platforms publicly describe their
  security graphs as backed by managed graph databases (Amazon Neptune is one
  documented backend), with graph context used to prioritize risks and surface
  actionable issues.
- Public materials from those vendors describe storing hundreds of billions of
  relationships and scanning billions of cloud resources per day.
- Other endpoint and asset-graph platforms describe purpose-built graph
  databases for cybersecurity and asset visibility across devices, users,
  accounts, applications, cloud workloads, and OT.
- Sigma.js is publicly documented as a WebGL graph renderer built on
  graphology, and is the path agent-bom uses for the WebGL overview lane.

Reference:

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
- renderer switch: `ui/lib/graph-renderer-switch.ts`
- renderers today: `@xyflow/react` for focused investigation and
  `sigma`/`graphology` for WebGL overview scenes, with Dagre, radial, force,
  and Sankey layout helpers for focused views

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

Implemented fix: keep using the shared `ExposurePath` contract for UI, API,
reports, JSON, and MCP:

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

WebGL now covers the overview path for:

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

Cluster nodes must stay accurate and reversible:

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

The edge schema has temporal fields. The remaining product work is visual:

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
- Amazon Neptune: managed AWS graph backend used by leading commercial cloud-security graph platforms
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

## Delivery Status

### PR 1: Shared ExposurePath contract — shipped

Delivered scope:

- API-native `ExposurePath` contract shipped for fix-first and attack-path
  views.
- Dashboard and graph surfaces promote the path as the primary investigation
  brief.
- SARIF, Markdown, HTML, JSON, and MCP responses carry ExposurePath evidence.

Remaining guardrail:

- Keep the file-export and graph-endpoint shapes aligned before adding new
  fields.

### PR 2: Security graph command center redesign — shipped

Delivered scope:

- selected path and path queue are first-class dashboard and security graph
  objects
- semantic clusters and toxic-combo graph projection are available to reduce
  raw topology
- light-mode graph token fixes are shipped

Remaining guardrail:

- Published screenshots must be recaptured from packaged UI and real demo data
  before the release notes use the refreshed graph story.

### PR 3: Sigma/WebGL overview renderer — shipped as overview path

Delivered scope:

- `sigma` and `graphology` are installed and used for the overview path.
- `GraphRendererSwitch` selects React Flow, large overview, or WebGL based on
  graph shape and focus state.
- React Flow remains the focused path/evidence renderer.

Remaining guardrail:

- Do not market a 50k-node operational claim until a release artifact includes
  the measured browser proof.

### PR 4: Semantic clustering and summarization — shipped at API/model layer

Delivered scope:

- package, CVE, agent, server, credential, tool, and source-family clusters are
  emitted for graph consumers.
- Cluster metadata includes counts and risk rollups for reversible expansion.

Remaining guardrail:

- UI screenshots should prove the cluster rendering that public docs describe.

### PR 5: Temporal graph overlays — data layer shipped, visual overlays pending

Delivered scope:

- graph edges carry bitemporal fields, confidence, provenance, source scan ID,
  and source run ID
- active-edge and change-query API routes are available

Remaining work:

- Add explicit new/changed/resolved overlays in the graph UI before claiming a
  full temporal investigation workflow.

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
