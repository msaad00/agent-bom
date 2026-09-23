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
- **attack paths** are precomputed fix-first paths derived from the persisted
  graph, with an explicit reachability verdict and evidence basis
- **interaction risks** are analysis results over recorded configuration and
  runtime evidence; their presence alone does not establish observed activity

This is not a best-effort browser-only canvas. It is a persisted graph snapshot
loaded from the control plane.

## Reachability truth

Every path distinguishes executable evidence from investigation context:

- `confirmed` — complete, directed, provenance-backed hop receipts support the
  recorded path; this is not proof of successful execution or exploitation
- `likely` — package/dependency or observed graph evidence supports the path
- `unknown` — structural topology connects the entities, but executable reach
  has not been proven; these candidates stay below evidence-backed paths
- `unlikely` — graph or symbol evidence disproves reachability; the finding is
  retained as evidence but is not emitted as an exploit chain

Credential and tool exposure increase impact, not reachability. MITRE ATT&CK
and ATLAS enrich evidence-backed hops; their technique mappings never create a
hop or promote a structural candidate into an executable path.

## Reading Context Map evidence

Open **Context** for a completed scan, then select a relationship label to inspect
its source, target, and affected package. Repository and SBOM imports remain
static inventory in Repository/Lineage; they are not MCP agent configurations.
These links describe scan evidence:

- **Configured server** records an agent configuration, not an invocation.
- **Advertises tool** records a tool declaration, not successful execution.
- **Credential reference** records a configured name, not secret disclosure or use.
- **Package vulnerability** associates the finding with evidenced package owners,
  not every tool exposed by the server. Multiple package associations remain separate.

A connected path is an investigation lead. To establish what an agent touched,
inspect runtime receipts with matching agent/tool identities and recorded resources,
decisions, and outcomes. A blocked attempt is not successful access; missing resource
or outcome evidence remains unknown. Finding badges show related runtime activity,
not proof that vulnerable code executed. Existing snapshots need a new scan to
reflect corrected ownership correlations.

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

For the product and review rubric behind these jobs, see
[`docs/graph/SECURITY_GRAPH_UX_RUBRIC.md`](https://github.com/msaad00/agent-bom/blob/main/docs/graph/SECURITY_GRAPH_UX_RUBRIC.md).

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

### Inspecting one instance or path

Open **Investigation → Summary**, drill into an account or environment, then
choose **Inspect** on a package. Matching package names can represent different
instances: the row includes available image/workload context, and **Node ID**
reveals the canonical identifier used by the API. Missing context stays absent.

In **Attack Paths → List**, expand any hop to load up to 12 direct neighbors.
Outgoing and incoming groups retain the relationship labels; an access edge is
not automatically a dependency. Use **Traverse from this hop** for a focused
investigation, or **Retry neighbor lookup** after a failed request. A partial
response does not establish that a node has no other neighbors.

The queue distinguishes paths shown, unique paths loaded from both the occurrence
queue and priority cards, and the snapshot total. **Evidence priority** identifies
a priority-card score; **Queue score** identifies an occurrence-queue score.
Neither score establishes compromise.

New demo projections direct dependencies from a workload to its image and from
an image to its packages. This change does not rewrite existing saved snapshots; rebuild the demo
snapshot to see corrected projection semantics.

### Paging recorded relationships through the API

For a persisted canonical node, authenticated clients can request one bounded
relationship page without loading the whole neighborhood:

```bash
curl --get "$AGENT_BOM_API_URL/v1/graph/incident-edges" \
  --header "Authorization: Bearer $AGENT_BOM_API_KEY" \
  --data-urlencode "node_id=$NODE_ID" --data-urlencode "limit=24"
```

The response contains the seed, endpoint nodes, recorded edges, and `next_cursor`.
Reuse the returned `scan_id` and `snapshot_generation` on every node expansion.
Follow `next_cursor` with those values and the same node and direction; the
generation check prevents mixing graph data across a replaced snapshot.
`limit` counts relationships (1–100), so parallel edges can share a neighbor.
`in` and `out` filter recorded endpoints; they do not establish permission or
execution. Completeness covers the current recorded page, and totals stay unknown.
On a stale-cursor or generation-mismatch 400, discard the accumulated view and
restart from the first page; unsupported backends return 501.
This endpoint is independent of the existing dashboard neighbor lookup.

## Scale and readability

To keep the graph readable at larger sizes, `agent-bom` uses:

- persisted snapshots rather than only transient browser layouts
- paginated node windows
- precomputed attack paths for shortlist triage
- focused vs expanded topology modes
- relationship-scope filters
- node detail enrichment on demand
- an independent persisted-path fast lane, so full-estate fix guidance cannot
  delay the first ranked path
- semantic role chains in the queue (`agent → server → package → finding`)
  and bounded one-hop traversal for direct dependencies and dependents

The operator workflow should be:

1. start with the focused graph or attack-path shortlist
2. narrow by agent, severity, or relationship scope
3. expand a hop for bounded direct neighbors, or traverse from it into lineage
4. open node detail for IDs, timestamps, and impact
5. page or expand only when the current slice is too narrow

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


## Investigate an agent from Context

Context starts with a compact, one-hop neighborhood from the selected scan.
Select a node to inspect its relationships; **Show** adds up to four recorded
neighbors of one type. **Collapse added neighbors** rolls that expansion back.
**Focus here** changes the center, **Back** returns to the previous center, and
**Reset neighborhood** returns to the selected agent. Search a name or exact
identifier in **Find loaded entity** to locate an entity outside the current view.
Direction and hop depth are under **Advanced view**.

The canvas retains at most 24 nodes and 36 relationships, including a discovery
edge for every displayed neighbor. Counts and search cover the loaded scan
snapshot; they do not measure the whole estate. This view still loads its graph
snapshot before projecting the neighborhood. These display limits are not
server-side pagination or an end-to-end enterprise performance guarantee.
Labels appear for a selected or hovered node, selected relationship, or focused
path. Shared infrastructure is not evidence that agents communicated.

Source truncation is disclosed separately; expansion is client-side and does not
collect additional evidence. Permissions and execution remain unknown in this
static projection.

Select an agent and scan in Context, then choose **Investigate reach & permissions**.
The investigation retains that scope and presents recorded paths. Select a path,
then use its investigation questions:

- **Reach & connections** opens ordered permission receipts and bounded incoming/
  outgoing neighbor expansion. Other agents, tools and resources appear only
  when the selected snapshot records their relationships.
- **Assume compromise** adds an explicit analyst assumption. It inspects existing
  receipts from the agent onward; it does not execute calls or simulate a
  successful attack. Denial and blocking evidence remain visible.
- **CVE conditions** shows recorded advisory prerequisites separately from the
  local exploitability assessment. Missing prerequisites remain unrecorded.
- **Potential impact** identifies recorded resource context and evidence gaps;
  an impact category is not proof of an actual consequence.
- **Recorded activity** preserves exact agent identity in the trace explorer.
  The explorer retrieves a bounded sample per source; its records are not
  correlated to a scan merely because navigation carries that scan ID.

Runtime hop receipts expose recorded opaque event/trace references when present
on the matching runtime edge. Missing or placeholder references stay absent.
These references do not create an end-to-end trace lookup or prove exploitation.
