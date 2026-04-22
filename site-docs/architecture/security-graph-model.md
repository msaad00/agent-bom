# Security Graph Model

Use this page when the question is not "how do I open the graph?" but "what is
this graph actually storing, how should I read it, and what stays true when the
snapshot gets large?"

`agent-bom` persists the graph as a **snapshot-oriented control-plane view**:

- **nodes** are canonical entities such as agents, MCP servers, tools,
  packages, credentials, containers, cloud resources, vulnerabilities, and
  misconfigurations
- **edges** are typed relationships such as `uses`, `depends_on`,
  `exposes_cred`, `affects`, `invoked`, and `lateral_path`
- **attack paths** are precomputed fix-first exploit chains derived from the
  persisted graph
- **interaction risks** are runtime-oriented overlays that highlight where
  agent behavior or shared control surfaces can expand blast radius

This is not a best-effort browser-only canvas. It is a persisted graph snapshot
loaded from the control plane.

## What a snapshot means

Each graph snapshot is identified by:

- `scan_id`
- `tenant_id`
- `created_at`

The snapshot captures:

- the nodes present at that scan/control-plane save point
- the edges between those nodes
- the derived attack paths and interaction risks for that saved graph
- aggregate counts used for graph headers, graph search, and UI summaries

The important operator rule is:

- **pagination changes the visible canvas**
- **pagination does not change what the snapshot is**

So when the graph page says `showing 1-500 of 3,200 nodes`, it is telling you
how much of the persisted graph is on the current page, not that the rest of
the graph disappeared.

## IDs, timestamps, and evidence

The graph uses stable identifiers wherever possible:

- agents use canonical agent IDs
- MCP servers use canonical server `stable_id`
- tools, resources, and packages use their own stable IDs
- graph nodes expose a `node_id` that the API and UI can round-trip

That means operators can talk about:

- one node across filters
- one snapshot across pages
- one server across repo scan, fleet sync, gateway discovery, and runtime

Time fields have specific meaning:

- `created_at` on the snapshot = when the graph snapshot was persisted
- `first_seen` on a node = earliest observed timestamp for that entity in the
  current correlated model
- `last_seen` on a node = latest observed timestamp for that entity in the
  current correlated model

Those are different concepts. A snapshot is a saved graph view; `first_seen` and
`last_seen` are entity lifecycle signals inside that view.

## What the graph is for

The graph is not meant to be a generic everything-map. It exists for three
operator jobs:

1. **blast radius**
   Follow package or configuration risk into agents, credentials, tools, and
   reachable runtime surfaces.
2. **inventory correlation**
   Show how repo, fleet, gateway, and runtime evidence point at the same MCP
   server or agent surface.
3. **fix-first triage**
   Let operators collapse many exposed paths with one change instead of chasing
   every finding separately.

## Reading the graph in the UI

The UI exposes three layers of interpretation:

1. **snapshot metadata**
   - scan ID
   - captured time
   - total nodes and edges
   - current page window
2. **topology filters**
   - focused vs expanded view
   - relationship scope
   - runtime/static scope
   - agent filters
   - severity filters
3. **node detail**
   - node ID
   - first seen / last seen
   - incoming / outgoing edges
   - sources and impact counts

That split is intentional:

- the header tells you what snapshot you are looking at
- the filters tell you how you are slicing it
- the detail panel tells you why one node matters

## Scale and readability

To keep the graph readable at larger sizes, `agent-bom` uses:

- persisted snapshots rather than only transient browser layouts
- paginated node windows
- precomputed attack paths for shortlist triage
- focused vs expanded topology modes
- relationship-scope filters
- node detail enrichment on demand

The operator workflow should be:

1. start with the focused graph or attack-path shortlist
2. narrow by agent, severity, or relationship scope
3. open node detail for IDs, timestamps, and impact
4. page or expand only when the current slice is too narrow

## Relationship categories

At a high level the graph separates:

- **inventory relationships**
  - hosts
  - uses
  - depends_on
  - provides_tool
  - exposes_cred
- **attack relationships**
  - affects
  - vulnerable_to
  - exploitable_via
  - remediates
  - lateral_path
- **runtime relationships**
  - invoked
  - accessed
  - delegated_to
- **governance relationships**
  - manages
  - owns
  - part_of
  - member_of

This is why the graph page has relationship-scope filters. The same snapshot can
be read as inventory, attack path, runtime context, or governance context
without pretending those are all the same edge type.

## What the graph is not

The graph is not:

- a replacement for the raw scan JSON
- a guarantee that every runtime event is persisted forever
- a substitute for the proxy or gateway itself
- a live network map of traffic that never entered the control plane

It is the persisted **operator model** that unifies inventory, findings,
runtime evidence, and remediation.
