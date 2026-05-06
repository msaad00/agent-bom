# Security Graph UX Rubric

This rubric turns the product direction for `agent-bom` into a reviewable
standard. Use it when changing `/graph`, `/security-graph`, `/mesh`,
graph APIs, screenshots, or graph documentation.

The target is a security-operator graph, not a generic node canvas. It should
start with what to fix, explain why it matters, show the path to the impacted
asset, and let the operator expand context only when needed.

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
