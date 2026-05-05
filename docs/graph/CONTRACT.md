# Graph Contract

This is the single page that tells operators, auditors, and regulators what agent-bom's graph promises and what it does not. Guarantees that previously lived scattered across the README, [ARCHITECTURE.md](../ARCHITECTURE.md), and [SECURITY_ARCHITECTURE.md](../SECURITY_ARCHITECTURE.md) consolidate here.

The graph subsystem has one source of truth in code: enums in `src/agent_bom/graph/types.py`, the legacy builder in `src/agent_bom/context_graph.py`, and the unified bridge in `src/agent_bom/graph/`. Every name on this page maps 1:1 to those files.

---

## 1. Coverage

### Entity types

`EntityType` (`src/agent_bom/graph/types.py:8`) is a closed enum. Every node in the graph carries one of these values. The legacy `NodeKind` enum (`src/agent_bom/context_graph.py:57`) is a strict subset that the bridge in `to_unified_graph()` maps onto `EntityType`.

| Entity type | Producing scanner / module | Asset shape |
|---|---|---|
| `agent` | `discovery/__init__.py` (29 first-class MCP client surfaces) | One MCP host configuration: agent name, type, server list |
| `server` | `discovery/__init__.py`, `parsers/__init__.py` | One declared MCP server: command, transport, env, packages, tools |
| `package` | `parsers/__init__.py` (15 ecosystems) | One pinned dependency: ecosystem, name, version, source manifest |
| `tool` | `mcp_introspect.py`, `risk_analyzer.classify_mcp_tool` | One tool advertised by a server with classified capabilities (read / write / execute / network) |
| `model` | `cloud/`, model-card scanners | One model artifact: HuggingFace ID, local path, or cloud-served endpoint |
| `dataset` | `cloud/`, dataset discovery | One referenced dataset (cloud or local) |
| `container` | `image_scanner.py`, `filesystem.py` | One OCI image or unpacked filesystem |
| `cloud_resource` | `cloud/aws.py`, `cloud/azure.py`, `cloud/gcp.py` | One discovered cloud asset (workload identity target, bucket, key, etc.) |
| `vulnerability` | `scanners/__init__.py`, `enrichment.py` | One CVE / GHSA after OSV + NVD + EPSS + KEV enrichment |
| `misconfiguration` | `iac/`, `cis/` | One IaC / CIS rule violation |
| `credential` | `context_graph._is_credential_key` against MCP server `env` | One credential-shaped env key (no secret value stored) |
| `user` | SCIM ingest (`scim_provisioning.py`) | One identity from the customer IdP |
| `group` | SCIM ingest | One identity group |
| `service_account` | Cloud workload-identity discovery | One non-human principal |
| `provider`, `environment`, `fleet`, `cluster` | Fleet sync, cloud discovery | Organisational hierarchy nodes (no security state of their own) |
| `iam_role` (legacy `NodeKind` only) | Cloud agent metadata `cloud_principal` | Workload identity attached to an agent — bridged onto `EntityType.SERVICE_ACCOUNT` |

### Edge kinds

`RelationshipType` (`src/agent_bom/graph/types.py:40`) is a closed enum. The legacy `EdgeKind` (`src/agent_bom/context_graph.py:66`) maps onto it through `EDGE_KIND_TO_RELATIONSHIP`.

| Edge kind | Direction | Semantics | Emission rule |
|---|---|---|---|
| `hosts` | provider → agent | A provider account / subscription / project hosts an agent. | Emitted when cloud discovery records a parent provider. |
| `uses` | agent → server | The agent is configured to use this server. | Emitted for every server in `agent.mcp_servers`. |
| `depends_on` | server → package | The server has this package as a dependency. | Emitted for every package returned by the package parser. |
| `provides_tool` | server → tool | The server advertises this tool over MCP. | Emitted from `tools/list` introspection or static config. |
| `exposes_cred` | server → credential | The server's launch env carries a credential-shaped key. | Emitted only when `_is_credential_key(env_key)` returns true; the value is never stored. |
| `reaches_tool` | credential → tool | A credential is reachable by an executable tool on the same server. | Emitted only when both nodes share a server *and* the tool has the `execute` capability. |
| `serves_model` | server → model | The server fronts a model endpoint. | Emitted by cloud / HuggingFace / Ollama scanners. |
| `contains` | container → package | A container image contains this package. | Emitted by `image_scanner.py` / `filesystem.py`. |
| `affects` | vulnerability → package | The CVE affects this package version. | Emitted from OSV / GHSA advisory data. |
| `vulnerable_to` | server / package → vulnerability | The server (via its packages) is exposed to this CVE. | Emitted when a CVE in `blast_radius` lists the server in `affected_servers`. |
| `exploitable_via` | vulnerability → tool / credential | An exploitation path leads through this tool or credential. | Emitted by blast-radius propagation when a path exists. |
| `remediates` | fix_version → vulnerability | This fix version closes the CVE. | Emitted when the advisory carries a `fixed` version. |
| `triggers` | vulnerability → toxic_combination | The CVE participates in a toxic combination finding. | Emitted by toxic-combination detection. |
| `shares_server` | agent ↔ agent (bidirectional) | Two agents reference the same MCP server. | Emitted only when `len(unique_agents_for_server) >= 2`. |
| `shares_cred` (`shares_credential` legacy) | agent ↔ agent (bidirectional) | Two agents share a credential-shaped env key. | Emitted only when `len(unique_agents_for_credential) >= 2`. |
| `lateral_path` | agent → agent | Pre-computed lateral movement path. | Emitted by `find_lateral_paths()` BFS, bounded to depth 4 and 100 paths. |
| `manages` | user / team → agent / fleet | Identity ownership over a managed entity. | Emitted from SCIM + fleet metadata. |
| `owns` | org / team → environment / resource | Organisational ownership. | Emitted from fleet / cloud metadata. |
| `part_of` | agent → fleet, server → cluster | Hierarchy membership. | Emitted from fleet / cluster discovery. |
| `member_of` | user → group, package → dependency_group | Group membership. | Emitted from SCIM and dependency-group analysis. |
| `invoked` | agent → tool | Runtime tool invocation. | Emitted **only** by proxy / gateway runtime. Never emitted by static scans. |
| `accessed` | tool → resource | Runtime resource access. | Emitted **only** by proxy / gateway runtime. |
| `delegated_to` | agent → agent | Runtime delegation between agents. | Emitted **only** by proxy / gateway runtime. |
| `correlates_with` | local agent ↔ cloud agent | High-confidence cross-environment match. | Emitted only when cloud account/subscription/project + region + model ID all match (#1892). |
| `possibly_correlates_with` | local agent ↔ cloud agent | Partial cross-environment match. | Emitted on partial-key matches; never conflated with the strict path. |
| `attached_to` (legacy `EdgeKind`) | iam_role → agent | Workload identity correlation. | Bridged onto `member_of` in the unified graph. |

Edges carry `weight` and `evidence` (a metadata dict). Bidirectional edges (`shares_server`, `shares_cred`, `correlates_with`) are stored once but traversed both ways.

---

## 2. Accuracy guarantees

agent-bom's graph is a static analytical artifact derived from inventory plus canonical advisory feeds. The guarantees below are the ones we will defend in an audit.

- **Deterministic given the same inventory.** No machine-learning inference is on the graph build path. Given the same `agents_data` + `blast_data` input, `build_context_graph()` produces the same nodes and edges. Edge insertion is deduplicated by `(source, target, kind)` (`context_graph.py:108`), and serialisation is sorted where order would otherwise be implementation-defined.
- **Round-trip clean.** The graph is a projection of the inventory, not a parallel data store. `to_unified_graph()` accepts a `ContextGraph` and emits a `UnifiedGraph` whose node IDs and edge keys are stable. Projecting back to inventory matches the original — there are no graph-only entities invented by the builder.
- **Framework tags from canonical sources only.** Every framework tag attached to a vulnerability node comes from CISA KEV, OSV, NVD, EPSS, MITRE ATLAS, or MITRE ATT&CK. The bundled canonical metadata lives in `src/agent_bom/compliance_coverage.py`. agent-bom never invents a framework label, never derives one from heuristics, and never re-tags advisories from secondary aggregators.
- **No cross-tenant leakage.** Every `UnifiedGraph` carries a `tenant_id` (`context_graph.py:808`). Persistence enforces row-level security in Postgres, scoped by tenant, on every read and write path. A query for tenant A's graph cannot return tenant B's nodes or edges, regardless of API surface.
- **Untrusted external metadata is fenced.** Tool descriptions ingested from MCP `tools/list` are passed through `_untrusted_metadata_text()` (`context_graph.py:47`), control characters are stripped, length is bounded, and the field is marked `description_trust = "untrusted_external_mcp_metadata"`. Downstream consumers must treat that field as data, never as a label or instruction.

---

## 3. Scaling boundaries

The graph renderer ships explicit thresholds. Operators can override per-tenant; defaults match the table below.

| Node count `N` | Default behaviour | Why |
|---|---|---|
| `N ≤ 30` | Full graph render — every node and every edge in the canvas. | Pilot fleets; one screen, no aggregation needed. |
| `30 < N ≤ 100` | Focus mode default — start anchored at the highest-risk entity, expand on demand. | Mid-market scale; the canvas is still legible if the operator drives navigation. |
| `100 < N ≤ 300` | Sibling aggregation default — agents that share the same set of servers / credentials collapse into a single sibling cluster, expandable. | Avoids the hairball problem when many agents share infrastructure. |
| `N > 300` | Anchor required — the operator must pick an entity, and the renderer returns the 3-hop neighbourhood around it. | Beyond ~300 nodes, no force-directed layout in a browser stays interactive. Pagination + anchored neighbourhoods are how large tenants navigate. |

Operators reaching the 300-node boundary should pivot to scoped queries (`/v1/agents/mesh?anchor=…`), the blast-radius drilldown, or the snapshot + page + search workflow described in `site-docs/deployment/performance-and-sizing.md`. The graph is designed for investigation, not for "render the whole tenant in one canvas."

---

## 4. What we don't promise

These are the explicit non-promises. Reading them is how regulators understand the boundary of the contract.

- **No ML inference.** There is no model on the graph build path. Nodes and edges are deterministic functions of the inventory and the canonical advisory feeds. We do not predict edges, infer relationships from embeddings, or assign risk via a learned model.
- **No causality without explicit traces.** The static graph encodes correlation, not causation. `shares_server` and `shares_cred` mean "two agents reference the same name," not "agent A caused agent B to be compromised." Causal claims require runtime traces emitted by the proxy / gateway (`invoked`, `accessed`, `delegated_to`); without those, a path through the static graph is a *reachability* claim, not a *causality* claim.
- **No real-time updates without proxy or gateway runtime.** The static graph is a snapshot built from the last scan. New tool calls, new credential exposure during a session, and live agent-to-agent delegation are not visible until the proxy or gateway runtime ships them as runtime edges. Without a runtime in place, treat the graph as a point-in-time artifact.
- **No cross-tenant graph leakage.** Postgres row-level security enforces tenant scope on every graph read and write. A graph query authenticated as tenant A will never include nodes or edges that belong to tenant B, even when a shared upstream provider node would otherwise look common across tenants. This is enforced at the database, not at the application layer.
- **No completeness claim for every framework.** Framework tags are drawn from a curated subset, not the full source standard for every framework. See [ARCHITECTURE.md § Coverage per framework](../ARCHITECTURE.md#coverage-per-framework) for the per-framework control counts.

---

## 5. Re-baseline procedure

Issue #2259 ships a graph-edge accuracy CI gate that compares each scan's emitted edges against a snapshot fixture. When an intentional graph-shape change ships — a new entity type, a new edge kind, a corrected emission rule — the snapshot fixtures must be regenerated.

```bash
python scripts/rebaseline_graph_edges.py
```

This is the **only** correct way to refresh the snapshot. It is appropriate when:

- A new `EntityType` or `RelationshipType` is added to `src/agent_bom/graph/types.py` and wired through the bridge.
- An emission rule is intentionally changed (for example: `exposes_cred` now emits on additional env-key heuristics, or `shares_server` raises its minimum-agent threshold).
- A scanner upstream of the graph is repaired and starts producing additional nodes or edges that the snapshot must now reflect.

It is **never** appropriate to:

- Silence a regression that surfaced on a normal feature branch.
- "Refresh the baseline" because tests are red and the cause hasn't been investigated.
- Re-baseline on main without a corresponding code change that explains *why* the shape changed.

Every re-baseline must land in the same PR as the code change that motivated it. The PR description must call out which entities or edges shifted and why. Reviewers should reject re-baseline-only PRs — they hide regressions.

---

## 6. Coverage gaps

These are the shapes we do not model yet. They are documented here so operators do not assume coverage that does not exist.

- **Cross-cluster federation.** A multi-cluster Kubernetes fleet appears in the graph as multiple disjoint `cluster` subgraphs. Workloads that federate across clusters (KubeFed, Karmada, Argo CD ApplicationSets) are not stitched together — each cluster's nodes stay in their own component.
- **Cross-cloud trust relationships.** AWS ↔ GCP ↔ Azure cross-account trust (assume-role chains across providers, GCP workload-identity-federation pointing at AWS, Azure-AD federated apps trusting Okta) is not represented as a graph edge. Provider-internal trust (one AWS account → another AWS account) is captured; cross-provider trust is not.
- **Real-time tool-call traces.** `invoked`, `accessed`, and `delegated_to` edges live in the proxy / gateway audit log only. The static graph does not back-fill them from audit logs after the fact. To investigate a runtime path, query the audit log directly; the graph view of runtime traffic is forward-only from the moment proxy / gateway runtime is enabled.
- **Multi-region cloud asset stitching.** Cloud resources discovered in different regions for the same account currently show as separate `cloud_resource` nodes. Region-aware deduplication (one logical resource that spans multiple regions, e.g. a global S3 bucket) is partial.
- **Agent-to-agent runtime collaboration outside MCP.** Agents that talk over non-MCP transports (custom RPC, message queues, direct HTTP between LLM frontends) are invisible to the static graph. They surface only when a runtime in the path emits `delegated_to` edges.
- **Identity provider chains.** SCIM ingest models the customer's primary IdP. Federated chains (Okta → Azure AD → AWS IAM Identity Center) collapse into the entry point's `user` and `group` nodes; the upstream IdP graph is not modelled.

These gaps are tracked as roadmap work. None of them block the guarantees in §2.
