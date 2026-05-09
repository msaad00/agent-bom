# Security Graph UX Rubric

This rubric turns the product direction for `agent-bom` into a reviewable
standard. Use it when changing `/graph`, `/security-graph`, `/mesh`,
graph APIs, screenshots, or graph documentation.

The target is a security-operator graph, not a generic node canvas. It should
start with what to fix, explain why it matters, show the path to the impacted
asset, and let the operator expand context only when needed.

This is also the product standard for AI-infrastructure visibility. Graphs
should make agent, MCP, model, RAG, package, credential-reference, runtime,
cloud, container, GPU, and compliance relationships readable enough for a live
buyer proof. A graph is not acceptable because it is visually impressive; it is
acceptable when it is accurate, bounded, sentence-readable, and tied to a
decision.

## North Star

The graph should answer six questions without requiring the user to manually
decode a dense canvas:

1. What risky thing exists?
2. Which agent, user, service account, or workflow can trigger it?
3. Which MCP server, tool, package, model, dataset, or infrastructure layer is
   on the path?
4. What asset, credential, endpoint, tenant, or environment can it reach?
5. Was the path observed at runtime, statically inferred, or both?
6. What should be blocked, patched, isolated, monitored, or reviewed first?

For executive and portfolio views, the graph should also answer:

7. Where is risk concentrated across agents, applications, cloud accounts, and
   runtime paths?
8. What changed since the last scan or runtime window?
9. Which coverage gaps are known, not guessed?

## Product Maturity Targets

| Target | Minimum bar | Best-in-class bar |
|---|---|---|
| Default view | Opens below the operator's cognitive limit with clustering, focus, and search. | Opens on a fix-first queue with the most actionable path selected and the graph scoped around it. |
| Prioritisation | Severity is visible on nodes and findings. | Effective reach combines vulnerability severity, exploitability, known exploitation, tool capability, credential visibility, runtime evidence, agent breadth, and asset criticality. |
| Path readability | Edges have labels and the legend explains node types. | Paths are sentence-readable: vulnerable package -> MCP server -> tool -> agent/user -> credential/asset, with each hop's evidence tier visible. |
| Scale | Large snapshots use pagination, LOD, aggregation, and filters. | Large tenants navigate by saved scope, entity search, ranked attack paths, and expansion from one selected path rather than whole-tenant rendering. |
| Evidence | Node detail shows source metadata. | Every claim is marked as static scan, gateway/proxy runtime, imported evidence, or replay-only evidence, with retention tier shown. |
| Remediation | Findings link to generic fix guidance. | The UI shows the lowest-cost choke point: patch package, disable tool, rotate credential, narrow scope, block gateway rule, or isolate asset. |
| Safety | Redaction exists in backend policies. | Durable views only show safe-to-store evidence; replay-only fields are named but not persisted or displayed raw. |

## Graph Product Families

Each graph should declare its family in code, API responses, screenshots, and
docs. Do not reuse one renderer mode for all jobs if it makes the operator
infer the meaning.

| Family | First question | Default shape | Must show | Must not imply |
|---|---|---|---|---|
| Agent Mesh | Which agents share risky MCP infrastructure? | Selected agent or workload in the center, then shared MCP servers, tools, packages, credential env-var references, and findings. | Omitted counts, shared chokepoints, evidence source, affected agents. | Complete tenant inventory when nodes are capped or clustered. |
| Security Graph | What path should I break first? | Ranked attack path or selected finding neighborhood. | Remediation choke point, path reason, static vs runtime evidence, asset criticality. | Runtime causality when only static reachability exists. |
| Compliance Evidence Graph | Which findings support this control or evidence packet? | Finding -> framework/control -> evidence artifact. | Framework subset scope, evidence packet command, control count, export status. | Full-framework catalog coverage where mappings are curated. |
| AI Visibility Flow | Who used which AI app/model/provider and what was detected? | Bounded Sankey or layered flow: actor -> app -> agent/orchestrator -> model/provider -> policy detection. | Time window, event counts, policy detections, collector/source. | Secret values, conversation contents, or complete monitoring without collectors. |
| RAG/MCP Architecture | Where can prompt, retrieval, tool, and data risks enter? | Layered architecture: enterprise zone, application layer, MCP/runtime boundary, RAG/data layer, third-party services. | Boundary controls, monitored links, AI TTPs, runtime collection point. | Enforcement on links that have no proxy/gateway/sensor coverage. |
| Cloud/Container/GPU AI Infra | Which workload or identity exposes AI runtime infrastructure? | Layered asset map: cloud account -> workload/identity -> container -> package/model/GPU/data. | Owner, environment, identity, image/package findings, GPU/model provenance. | Cross-cloud trust or multi-region stitching beyond implemented graph edges. |
| Executive Portfolio | Where should leadership focus this week? | Rollup cards plus drill-down graph entry points. | KPIs, trending risk, breached SLA, coverage across scan/runtime/cloud surfaces. | Raw scanner completeness as business risk without normalization. |

## Visual Readability Rules

These rules are mandatory for screenshots, docs images, and shipped graph UI.

- The first frame must fit its text. Labels, counts, badges, and legends must
  not overflow cards, controls, chips, side panels, or graph nodes at the
  documented desktop and mobile widths.
- Dense views must use ranked subgraphs, clustering, pagination, or progressive
  expansion. Do not publish a whole-tenant graph that reads as edge spaghetti.
- Long names must use truncation plus detail-on-hover or side-panel expansion.
  Truncation must preserve the security-significant prefix or suffix where
  possible, such as CVE ID, package name, provider, environment, or credential
  env-var key.
- Edge thickness and color must encode one clear thing each. If thickness means
  event count, color should not also imply severity unless the legend makes the
  distinction obvious.
- Layouts should prefer layered flows when the relationship has direction:
  actor -> application -> agent/MCP host -> server/tool -> package/model/data
  -> finding/control. Free-force layouts are for exploratory neighborhoods,
  not default executive or screenshot views.
- Side panels should carry the detail load. The canvas should show enough to
  navigate; the side panel should show evidence, timestamps, policy decisions,
  raw IDs, and remediation.
- Every collapsed group must show `visible_count` and `omitted_count`, and the
  expansion control must make clear whether it expands the current scope or
  runs a new query.
- Every screenshot used in public docs must be checked for overlap, unreadable
  text, blank canvas regions, and misleading stale data before release.

## Evidence Fields

Graph APIs and UI view models should prefer explicit evidence fields over
display-only inference. When a field does not exist yet, the UI should omit the
claim or mark it unavailable.

| Field | Purpose |
|---|---|
| `evidence_source` | Names the scanner, runtime, import, or operator source. |
| `evidence_tier` | Separates static scan, runtime observed, imported, replay-only, and synthetic demo evidence. |
| `confidence` | Lets heuristics differ from exact parser/runtime evidence. |
| `first_seen`, `last_seen` | Supports change detection and investigation windows. |
| `runtime_trace_id` | Links runtime edges to proxy/gateway audit records. |
| `policy_decision`, `policy_rule_id` | Explains allow/block/audit decisions. |
| `safe_to_store` | Prevents replay-only or sensitive fields from leaking into durable views. |
| `visible_count`, `omitted_count` | Makes truncation honest. |
| `relationship_reason` | Makes each edge sentence-readable. |
| `asset_criticality`, `owner`, `environment` | Turns technical exposure into prioritised business risk. |
| `recommended_action` | Connects the graph to the fix queue. |

## Operator Skill Pattern

Graph work should support three repeatable operator lanes instead of forcing
every user through raw graph output.

| Lane | Scope | Output |
|---|---|---|
| Domain graph | One program or surface: MCP runtime, repo scanning, cloud AI infra, RAG/data, containers/GPU, compliance. | Accurate local findings, evidence, and drill-down. |
| Domain graph | A second surface that shares entities with the first, such as code scanning plus runtime tool calls. | Comparable findings and shared asset IDs. |
| Orchestrator view | Portfolio synthesis across domains. | KPIs, trend, SLA breach, concentration of risk, and a drill-down path into the underlying evidence. |

The orchestrator view must not invent new evidence. It summarizes evidence from
domain graphs and names which surfaces are missing.

## Required Graph Layers

Treat these as semantic layers even when the underlying code represents them
with existing entity types.

| Layer | Examples | Why it matters |
|---|---|---|
| User/application | human user, desktop app, IDE, CLI, API client, service account | Shows who or what can trigger the path. |
| Gateway/runtime boundary | API gateway, MCP gateway, proxy, policy decision, audit log, trace ID | Separates static possibility from runtime enforcement and observation. |
| Orchestration | agent, LangChain/LangGraph/CrewAI/AutoGen/custom runtime, planner, router | Explains how prompts, tools, memory, and delegation are coordinated. |
| RAG/data | vector DB, retriever, index, embedding model, source document, dataset | Shows sensitive context and data-flow reachability. |
| MCP/tool | MCP server, tool schema, command class, filesystem scope, network scope | This is the core agent attack surface. |
| Package/supply chain | package, transitive dependency, lockfile, container layer, malicious signal | Connects CVEs and provenance to exposed capability. |
| Model/inference | model, adapter, inference server, model gateway, cache | Captures model serving risk and provenance. |
| Infrastructure/asset | Kubernetes workload, host, GPU node, accelerator, cloud account, IAM role, endpoint, business asset | Shows what the agent path can actually impact. |
| Finding/governance | CVE, misconfiguration, policy violation, compliance control, owner | Turns the path into a fix queue and audit trail. |

## Interaction Rules

- The first screen must not be a whole-tenant hairball. It should open on a
  focused view, ranked path, or selected entity neighborhood.
- Relationship labels should be verbs an operator can read aloud: `uses`,
  `loads package`, `exposes tool`, `can reach`, `uses credential`, `invoked`,
  `blocked by`, `observed in trace`, `owns`, `part of`.
- Graph filters must reduce the visible graph and the available filter choices
  together. Selecting `severity=critical` should not leave impossible agent,
  layer, or relationship options active.
- Cluster pills must preserve context. Never collapse a multi-parent child if
  that would hide another path.
- Hover focus is for inspection; pinned focus is for investigation. Hover must
  not override a pinned node or selected attack path.
- Node detail should always show stable ID, type, semantic layer, evidence
  source, first/last seen where available, incoming/outgoing counts, and the
  next action.

## Review Checklist

Every graph or graph-adjacent PR should answer:

- Does the change make the default view more actionable or just add more
  objects to the canvas?
- Can an operator explain the selected path in one sentence?
- Are static, runtime, imported, and replay-only evidence clearly separated?
- Does the UI remain readable at the agent-bom self-scan size and at 1,000+
  nodes through filtering, pagination, or aggregation?
- Are backend enum/schema changes reflected in generated TypeScript and tests?
- Are screenshots and docs updated only when they reflect the packaged Next.js
  product, not an older prototype surface?

## Immediate Enhancement Backlog

1. **Fix-first graph cockpit.** Keep `/security-graph` centered on ranked
   attack paths and remediation choke points, with the canvas scoped to the
   selected path.
2. **Semantic layer legend.** Group node types by layer so the legend reads
   like an AI-system stack instead of a flat enum dump.
3. **Runtime evidence overlay.** Distinguish static reachability, observed
   invocation, blocked policy decision, replay-only trace, and safe-to-store
   evidence.
4. **Asset-criticality weighting.** Add environment, tenant, business asset,
   and owner criticality to effective reach so the same CVE is ranked
   differently in dev vs production.
5. **Remediation choke-point cards.** For each path, suggest the cheapest
   fix that breaks the most reachability: patch, disable tool, rotate
   credential, narrow egress, enforce gateway policy, or isolate workload.
6. **Screenshot refresh gate.** After graph UI changes land, refresh live
   product screenshots from the packaged Next.js dashboard and avoid replacing
   them with hand-built or stale prototype views.
