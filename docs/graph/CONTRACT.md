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
| `container` | `image.py`, `cloud/container_sbom.py`, `filesystem.py` | One OCI image or unpacked filesystem |
| `cloud_resource` | `cloud/aws.py`, `cloud/azure.py`, `cloud/gcp.py` | One discovered cloud asset (workload identity target, bucket, key, etc.) |
| `vulnerability` | `scanners/__init__.py`, `enrichment.py` | One CVE / GHSA after OSV + NVD + EPSS + KEV enrichment |
| `misconfiguration` | `iac/`, `cis/` | One IaC / CIS rule violation |
| `credential` | `context_graph._is_credential_key` against MCP server `env` | One credential-shaped env key (no secret value stored) |
| `user` | SCIM ingest (`api/routes/scim.py`) | One identity from the customer IdP |
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
| `contains` | container → package | A container image contains this package. | Emitted by `image.py`, `cloud/container_sbom.py`, and `filesystem.py`. |
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

### Provider authorization receipts

Azure/GCP authorization evaluation emits `can_access` edges only for an explicit
`allow` result. Each `evidence.authorization_decisions` record
keeps the evaluated principal, concrete action, resource, decision, provider,
matched binding IDs, and source observation time together. Multiple allowed
actions on the same edge retain separate records through graph aggregation,
SQLite/Postgres persistence, and the graph API. Top-level compatibility fields
such as `action` are omitted when the records disagree; the union of binding
IDs does not authorize every action under every binding.

Identity-attachment actions (`iam.serviceAccounts.actAs` and
`Microsoft.ManagedIdentity/userAssignedIdentities/assign/action`) retain their
allowed-action receipts on a **nontraversable** `can_access` edge to the target
identity. These permissions alone do not establish an impersonated session or
inherit the target's access. The edge records `authority_effect=identity_attachment`
and the missing workload-control, attachment, and credential-access context;
analysis is `limited` with `identity_attachment_requires_workload_context`.
See [Google's service-account permission semantics](https://docs.cloud.google.com/iam/docs/service-account-permissions)
and [Azure's managed-identity assignment prerequisites](https://learn.microsoft.com/en-us/entra/identity/managed-identities-azure-resources/how-to-configure-managed-identities).

Rebuild or rescan older snapshots that contain `assumes` edges derived from
these attachment permissions. Historical snapshots are not rewritten on read;
rolling back to an older binary restores the earlier derivation behavior.

These receipts describe the evaluator's result for the collected snapshot.
They do not establish that an action executed, that data was affected, or that
the grant is still valid now. Conditional, denied, stale, and incomplete inputs
remain subject to the evaluator's fail-closed behavior. This receipt list
currently retains allowed decisions, not the complete policy evaluation trace.
Derived permission overlays and specialized path responses must not be assumed
to expose this action detail merely because the source edge contains it.

Existing snapshots may contain only a single legacy action receipt. Reading or
merging that record cannot recover actions previously discarded; collect fresh
authorization evidence and rebuild the snapshot to obtain the full retained
set of evaluated allowed actions. Missing legacy principal or observation fields
remain unknown.

### AWS policy conditions

AWS identity-policy evaluation retains supported string/ARN set qualifiers:
`ForAllValues` requires each supplied request value to match the policy;
`ForAnyValue` requires one. Negated operators compare each request value against
all policy values before applying the set qualifier. See the
[AWS condition-operator reference](https://docs.aws.amazon.com/IAM/latest/UserGuide/reference_policies_elements_condition_operators.html).
Missing request context remains unknown, including for `IfExists` and `Null`:
this contract does not carry proof that a key was absent from a complete AWS
request. An explicitly supplied empty value set is distinct. Malformed conditions make their policy incomplete instead of
becoming unconditional grants. A valid explicit deny retains precedence.

This evaluator does not establish a complete AWS effective-permission verdict:
unsupported operators, missing session context, permissions boundaries, SCPs
and resource policies need their own evidence. Rebuild snapshots after changing
policy evidence or upgrading the evaluator; existing derived snapshots are not
rewritten by a read request.

### Derived permission witnesses

Newly built `has_permission` edges include `evidence.permission_derivation`.
Its ordered `source_edge_ids` reference the actual access, group-membership, or
assume/inheritance relationships in the same `source_scan_id`. The
`grant_edge_id` identifies the original access edge and its action receipts;
`grant_principal_id` remains the original role, group, or direct principal.
Inheriting that graph connection does not relabel the source's policy decision
as a directly evaluated grant for the requesting identity.

The overlay retains one deterministic shortest witness for each grant and
access class, with at most 16 witnesses per derived edge and six principal
transfer hops. It does not enumerate every alternate route or reevaluate policy
provider policy conditions or session restrictions. A witness cap marks the
edge's derivation `truncated`; an unvisited frontier at the depth limit or a
witness cap marks the snapshot analysis `limited`. Cycles alone do not mark a
walk incomplete. Consumers must resolve source references within the same
tenant and snapshot, and show an evidence gap when a source edge is unavailable
in a bounded response. Old snapshots require rebuilding to gain these witnesses.

New permission derivation excludes source edges that are deleted, not yet valid,
expired, or have invalid validity windows. It evaluates at UTC now by default;
a historical build must pass its evaluation time explicitly. Each witness uses
the intersection of its source windows; overlapping alternate witnesses may
extend the resulting interval. This preserves recorded graph validity, not a
fresh provider authorization decision. Existing snapshots and derived edges are
not retroactively rewritten; rebuild them to apply these checks.

### Managed-identity governance scope

The live governance overlay connects a managed identity to an exact agent node
ID when available, otherwise to one unambiguous agent label. Duplicate labels
remain unlinked. This is a registered binding, not evidence of an authenticated
session. Expired or invalid identities do not acquire traversable tool scope;
JIT scope requires a live identity and an active grant within its recorded time
window. Pending, revoked, future, or expired grants do not establish access.

A matching unconditional deny leaves a context-only scope edge with
`authorization_state=explicit_deny`. Applicable conditional policies require
request context and use `context_required`; unavailable or capped policy
collection uses `policy_evidence_unavailable`. These edges are non-traversable
and do not generate governance access paths. Policy IDs and required context
survive edge serialization. `recorded_scope` means the collected scope has no
such unresolved policy guard; it does not prove a successful tool call or data
access. Runtime enforcement is unchanged by this graph qualification.

---

## Evidence truth dimensions

The versioned `SecurityDimensions` contract keeps six questions independent:

| Dimension | Question | Value when not assessed |
|---|---|---|
| Exposure | Is there an entry point, credential, or tool exposure? | `status=unavailable`; no inferred `false` |
| Reachability | Is a directed, traversable path supported by evidence? | `verdict=null`; never copied from exposure |
| Exploitability | Do the vulnerability and execution conditions permit exploitation? | `verdict=null`; never copied from risk |
| Likelihood | What bounded probability model applies as of a stated time? | `probability=null`; never a risk score |
| Impact | Which technical or business assets could be affected? | empty facts with an explicit reason code |
| Risk | What versioned method combines named input dimensions? | `score=null`; never an unavailable zero |

Each asserted fact references an `EvidenceProvenance` receipt. Its `basis`
(`observed`, `runtime_observed`, `inferred`, or `modeled`) is separate from its
collection `status` (`complete`, `partial`, `unavailable`, or `failed`).
Freshness is evaluated against an explicit `evaluated_at` timestamp and validity
window; process time is not consulted during model validation.

`EvidenceCompletenessLedger` records collection, normalization, catalog lookup,
persistence, graph-join, and analysis coverage by component. An empty ledger is
`unavailable`, any relevant failed entry makes it `failed`, and any other
relevant incomplete entry makes it `partial`. Counts and reason codes describe
only what the producing component reported; they do not fabricate a clean or
complete state.

These contracts are additive foundations. Existing finding, graph, and endpoint
payloads retain their current serialization until their producers can populate
every field honestly and their migrations are independently tested.

---

## 2. Accuracy guarantees

agent-bom's graph is a static analytical artifact derived from inventory plus canonical advisory feeds. The guarantees below are the ones we will defend in an audit.

- **Deterministic given the same inventory.** No machine-learning inference is on the graph build path. Given the same `agents_data` + `blast_data` input, `build_context_graph()` produces the same nodes and edges. Edge insertion is deduplicated by `(source, target, kind)` (`context_graph.py:108`), and serialisation is sorted where order would otherwise be implementation-defined.
- **Round-trip clean.** The graph is a projection of the inventory, not a parallel data store. `to_unified_graph()` accepts a `ContextGraph` and emits a `UnifiedGraph` whose node IDs and edge keys are stable. Projecting back to inventory matches the original — there are no graph-only entities invented by the builder.
- **Framework tags from canonical sources only.** Every framework tag attached to a vulnerability node comes from CISA KEV, OSV, NVD, EPSS, MITRE ATLAS, or MITRE ATT&CK. The bundled canonical metadata lives in `src/agent_bom/compliance_coverage.py`. agent-bom never invents a framework label, never derives one from heuristics, and never re-tags advisories from secondary aggregators.
- **No cross-tenant leakage.** Every `UnifiedGraph` carries a `tenant_id` (`context_graph.py:808`). Persistence enforces row-level security in Postgres, scoped by tenant, on every read and write path. A query for tenant A's graph cannot return tenant B's nodes or edges, regardless of API surface.
- **Untrusted external metadata is fenced.** Tool descriptions ingested from MCP `tools/list` are passed through `_untrusted_metadata_text()` (`context_graph.py:47`), control characters are stripped, length is bounded, and the field is marked `description_trust = "untrusted_external_mcp_metadata"`. Downstream consumers must treat that field as data, never as a label or instruction.
- **Alternative graph backends must preserve this contract first.** SQLite and Postgres are the shipped graph persistence backends today. Any future backend, including the proposed Neptune lane, must preserve stable IDs, tenant predicates, snapshot semantics, bounded traversal, audit behavior, and explicit unsupported-operation errors before it can be documented as supported.

---

### Snowflake historical access receipts

Snowflake ACCESS_HISTORY observations collapse into one `ACCESSED` edge per user
and object while retaining distinct `access_receipts`. Each receipt keeps its
query ID/time, recorded query role (empty when unavailable), account, object,
columns, base objects and source array. A query that reads and writes the same
object retains both observations. `READ` and `WRITE` describe the source arrays;
they do not infer a SELECT/INSERT/UPDATE statement, current permission, or rows
changed. See [Snowflake ACCESS_HISTORY](https://docs.snowflake.com/en/sql-reference/account-usage/access_history).

Graph JSON and persisted edge evidence retain these records without combining
one query's role with another query's action. Historical access does not establish
an exact agent/session binding or current authorization; data impact remains
unknown. Collection is bounded by the configured lookback and the collector's
1,000-query limit, and source visibility/latency still apply.

## 3. Scaling boundaries

The graph renderer ships deterministic focused and expanded modes. Operators can override per-tenant; defaults match the table below.

| Mode / size | Default behaviour | Why |
|---|---|---|
| Relevant paths default | 2-hop neighbourhood, 50-node page size, high-severity vulnerable scope, sibling fan-outs of 5+ collapsed into expandable cluster pills. | Starts every investigation readable, even on dense self-scans. |
| Ranked path queue | Persisted paths load independently from full-estate fix guidance; the response includes only consecutive path edges. Direct neighbors load on demand with a 12-node fan-out cap. | Produces a fast, evidence-minimal first view without hiding broader topology or implying unrelated edges prove the selected path. |
| Expanded mode | 3-hop neighbourhood, 250-node page size, sibling fan-outs of 20+ collapsed. | Lets operators widen context deliberately without turning the first view into a whole-tenant canvas. |
| Zoomed out | Level-of-detail renderer swaps detail cards for summary cards and cluster bubbles below the zoom thresholds. | Dense snapshots stay navigable instead of turning into unreadable labels. |
| Large overview | Visible pages at or above 500 nodes or 1,200 edges switch from React Flow to a limited 2D canvas overview. The overview draws up to 3,000 high-signal nodes and 6,000 high-signal edges; search, filters, selected-node detail, and reachability drill-ins remain server-backed. | Keeps broad estate pages from blanking or stalling while preserving React Flow for bounded investigations. |

Operators reaching large-snapshot scale should pivot to scoped queries, security-graph attack paths, the blast-radius drilldown, or the snapshot + page + search workflow described in `site-docs/deployment/performance-and-sizing.md`. The large overview is intentionally not a full React Flow replacement: it supports pan, zoom, node selection, and high-level topology, but not node cards, minimap, or path highlighting. The graph is designed for investigation, not for "render the whole tenant in one canvas."

---

## 4. What we don't promise

These are the explicit non-promises. Reading them is how regulators understand the boundary of the contract.

- **No ML inference.** There is no model on the graph build path. Nodes and edges are deterministic functions of the inventory and the canonical advisory feeds. We do not predict edges, infer relationships from embeddings, or assign risk via a learned model.
- **No causality without explicit traces.** The static graph encodes correlation, not causation. `shares_server` and `shares_cred` mean "two agents reference the same name," not "agent A caused agent B to be compromised." Causal claims require runtime traces emitted by the proxy / gateway (`invoked`, `accessed`, `delegated_to`); without those, a path through the static graph is a *reachability* claim, not a *causality* claim.
- **No real-time updates without proxy or gateway runtime.** The static graph is a snapshot built from the last scan. New tool calls, new credential exposure during a session, and live agent-to-agent delegation are not visible until the proxy or gateway runtime ships them as runtime edges. Without a runtime in place, treat the graph as a point-in-time artifact.
- **No cross-tenant graph leakage.** Postgres row-level security enforces tenant scope on every graph read and write. A graph query authenticated as tenant A will never include nodes or edges that belong to tenant B, even when a shared upstream provider node would otherwise look common across tenants. This is enforced at the database, not at the application layer.
- **No completeness claim for every framework.** Framework tags are drawn from a curated subset, not the full source standard for every framework. See [ARCHITECTURE.md § Coverage per framework](../ARCHITECTURE.md#coverage-per-framework) for the per-framework control counts.
- **No exhaustive centrality.** Bottleneck ranking is *approximate* betweenness: shortest-path traversals from a bounded, deterministic sample of source nodes (50–200, scaled to graph size, drawn by fixed stride over sorted node ids so the answer never depends on insertion order). Every response carries `sampled_sources` and `total_nodes`, and nodes no sampled path crossed are omitted rather than reported at score `0.0`. Treat the ranking as a strong signal, not a proof that no other choke point exists.
- **No complete answer from a bounded load.** When a snapshot is loaded under a node budget, every projection of it — filtered views, the typed inventory / attack-path / lateral-movement / compliance / runtime views, the estate roll-up and its drill-downs — reports `completeness.truncated` with the reason(s) that applied and the pre-truncation estate total (`total_nodes_source` on roll-up summaries, `stats.total_nodes_source` on graph responses). A filter cannot make truncation untrue: the nodes that were never read might have matched.

### Proposed scenarios are not observed evidence

The Investigation Canvas can save a bounded architecture delta against one
exact `base_scan_id` and compare `Current`, `Proposed`, and `Difference` over
the same canonical entity and relationship taxonomy. This is a design tool,
not a second scanner:

- `Current` is the immutable persisted scan snapshot.
- `Proposed` is a server-authored overlay whose additions are labeled
  `evidence_state=proposed`, `observed=false`, and `deployed=false`.
- `Difference` names additions, removals, posture changes, and observed paths
  touched by the proposal. A touched path is not reported as eliminated or
  remediated.

Scenarios are tenant-scoped, revisioned, and pinned. The comparison endpoint
does not fall forward to the latest snapshot when the base is missing or the
selected snapshot differs; it returns an explicit unavailable state. Scenario
operations never write into observed graph tables, findings, SARIF, runtime
enforcement, or materialized attack paths. Only a later scan can verify that a
proposed state was deployed and establish its findings or paths.

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

## Correlated runtime identity and path proof

Correlation manifests and edge receipts identify the join contract as
`runtime-occurrence.v2`. Container occurrences join only when an authoritative
runtime identifier and its provider and account, cluster, or host scope match
within the requesting tenant. Kubernetes pod identifiers additionally require
container names. Missing identity stays specific to the source snapshot. Image
digests remain artifact metadata; reusing an image does not join deployment
permissions.

Historical receipts remain stored. Correlated edges without the current identity
version require recomputation before they can support a verified path. Run a new
correlation using the original source snapshots; correlating an already merged
legacy output does not recover the original occurrence boundaries or upgrade
its receipts. Existing snapshots remain available for inspection and rollback.

A verified path requires a complete recorded analysis and one ordered receipt
for every hop, matching the source, target, and relationship. Receipts must be
directed, traversable, fresh, untruncated, backed by source references and recorded
relationship provenance, and use the current correlation identity contract.
Incomplete or historical evidence remains unavailable for verification. API and
MCP exposure projections also check the matching directed topology. Page-size
limits on the path queue do not certify or invalidate an individual hop receipt.

MITRE mappings describe potential techniques supported by matching directed,
traversable edges. Their `evidence_basis` preserves observed, inferred, or modeled
provenance; absent provenance leaves confidence unavailable. A mapped technique
is not evidence that an attacker used it.

Attack-path campaigns expose `priority_score` with
`priority_method: structural_path_rank.v1` for structural prioritization.
`exploitability` and `expected_risk_reduction` remain nullable, each with its own
`*_evidence` status and references. Historical numeric values without supporting
assessment metadata become unavailable; priority is not a substitute for either
quantity. Finding severity is displayed separately from path priority.

Exposure-path projections use the maximum known vulnerability/misconfiguration
severity, independently of asset priority. Missing finding severity remains
unknown, including when a high-priority asset is present. API and MCP legacy
`reachability: confirmed` labels are downgraded to unknown when the current
evidence dimensions cannot support that verdict. Projection qualification does
not rewrite stored path receipts.

### Inspect recorded authorization

In a selected hop, open **Recorded authority** to inspect an evaluator's action,
principal, resource, observation time and matched binding IDs together. The same
optional `hopEvidence[].authority` object is retained by exposure REST responses,
MCP, the graph-paths JSON command and the Python/TypeScript clients. No permission
is re-evaluated in the browser. Missing legacy principal, resource or observation
time remains `null` and appears as **Not recorded**.

A derived permission can instead supply ordered source-edge IDs, the original
grant principal, source snapshot and grant edge. These are selected shortest
structural witnesses per grant/access type, not an exhaustive path set or an
inferred action scope. They do not establish successful execution.

Snowflake object grants are separate `native_grants` receipts. Each retains its
recorded privilege, account, role, object FQN and object type; a native grant is
not an evaluator `allow` decision. Multiple privileges on one relationship remain
separate records. Unknown legacy scope stays null, and grants do not establish
active session roles, required database/schema usage, masking or row-policy effects.

Projection retains at most 16 action receipts, 16 native grants and 16 witnesses, with at most
seven source relationships per witness. Invalid or oversized records are omitted
with explicit reason codes and `status: partial`; valid neighboring records stay
inspectable. Each action receipt accepts at most 16 binding IDs. Arbitrary policy
bodies, tool output and credential fields are excluded. The UI shows four records
per page in a bounded list and treats all identifiers as inert text.

These are historical records, not proof of current access. Conditions, explicit
denies, expiry and revocation still require a fresh evaluation in the relevant
context. Existing path snapshots are not rewritten: rescan or rebuild the derived
snapshot from source edges to populate the new projection. No database migration
is required. Older readers ignore the optional object; retained snapshots remain
available for rollback.

### Inspect a selected path's evidence

Use `agent-bom graph-paths exposure --api-url "$AGENT_BOM_API_URL" --format json`
with the control plane's provisioned authentication. The response includes a
`hopEvidence` array alongside `evidenceDimensions`. Continue with the returned
cursor to keep the same tenant, snapshot, and risk filter. In the dashboard,
select the path, expand its evidence disclosure, then select one hop to inspect
its receipt. The filter searches the loaded path; it does not run a new traversal.

| Receipt field | Interpretation |
|---|---|
| `source_snapshot_ids` | Recorded source snapshots, displayed as inert identifiers. The inspector does not fetch or execute locators. |
| `freshness`, `relationship_provenance`, `correlation_identity_status` | Independent qualifications; missing or mismatched receipts remain unavailable. |
| `runtime_observed_state` | Whether an invocation or blocked attempt was observed; this is not proof of effective permission. |
| `runtime_outcome` | `blocked`, `failed`, or `unknown`. An allowed invocation and a mixed aggregate leave the downstream outcome unknown. |
| `direction`, `traversable` | Eligibility for graph traversal, separate from successful execution. |

A blocked receipt or an aggregate in which every observed attempt failed cannot
support confirmed downstream reachability. A CVSS network attack vector, KEV
entry, EPSS score, or a bare exploitability label does not supply an
exploitability assessment. An assessment must satisfy the existing evidence
contract, including references; its status and limitations remain visible.

The hop projection excludes unclassified receipt fields. Older snapshots need
no database migration: receipts use the existing JSON storage, and missing
outcomes project as unknown. Projection does not change historical rows. To
refresh an assessment, collect new source evidence and correlate a new snapshot;
a display change or a proposed fix is not remediation verification. Preserve
old snapshots for comparison. A rollback to an evaluator that ignores negative
outcomes can restore overstated labels; do not treat those labels as proof.

Permission overlays exclude context-only access, membership, and delegation
links from newly derived authority. This does not reconstruct missing action or
policy-condition evidence. Previously persisted derived edges remain historical
records; rebuild from source evidence to obtain the corrected derivation.

Exposure pages retrieve relationships between their selected node IDs. Other
incident-edge queries retain their existing behavior. Response limits and cursor
continuation still apply; a small rendered page does not establish full-estate
coverage. The inspector renders at most eight relationship rows at once and
keeps the original hop positions when filtering.

Node IDs containing slashes (filesystem findings and scoped package identifiers)
use `GET /v1/graph/node-context?node_id=...` and
`GET /v1/graph/node-neighbors?node_id=...`. These authenticated query aliases
preserve the complete ID without URL-path decoding ambiguities. Existing
single-segment node routes remain supported.


### Campaign verification and graph remediation

Run `agent-bom campaigns list --format json`, then use the returned campaign ID
and version with `agent-bom campaigns verify CAMPAIGN_ID --version VERSION`.
Both commands use the control plane's configured authentication. Verification
checks original finding identities even if advisory enrichment moved them to
another remediation group, plus current replacement findings in the original
group. `remaining_count` counts distinct matches; it can exceed the baseline
member count when new affected instances appear.

A complete 90-day findings window is not a fresh scan receipt for the original
target scope. With no matching findings, verification returns HTTP 409 with
`outcome: unavailable_evidence` and
`retry_state: awaiting_fresh_scope_evidence`; workflow state remains unchanged.
The MCP workflow preserves these fields and the dashboard displays the reason.
No absence-based `verified_fixed` result is issued, including from older cached
success responses. Existing saved workflow states are not rewritten.

Collect the same target scope again and inspect its new graph snapshot for
remaining and alternate routes. A proposed edge removal changes only a scenario;
it does not revoke provider access, trigger a rescan, or verify remediation.
The campaign endpoint currently does not bind baseline/rescan coverage receipts
or evaluate alternate graph paths, so it cannot certify access revocation from
that comparison. Retain those source receipts and compare the new snapshot's
qualified hop evidence before deciding whether more remediation is needed.
