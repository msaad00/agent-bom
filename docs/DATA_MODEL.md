# Data model atlas

One source of truth for the canonical agent-bom data model and how every
field flows from `models.py` dataclasses → DB schemas → output formats →
graph taxonomy. Use this when you need to know:

- which dataclass field becomes which DB column
- which output format includes a given finding attribute
- how the graph taxonomy maps onto the canonical model
- which fields are populated by which scan type

If you change a dataclass field, **update this doc in the same PR**. It
is wired into the docs site so drift produces a visible regression.

---

## 1. Canonical in-memory model (`src/agent_bom/models.py`)

The canonical model is dataclass-based, strongly typed, and is the
single source of truth that every other surface serializes from.

| Class | Purpose | Key fields |
|---|---|---|
| `Severity` enum | Severity ladder | `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`, `NONE`, `UNKNOWN` |
| `AgentType` enum | Discovered agent kind | `CURSOR`, `CLAUDE_DESKTOP`, `CLAUDE_CODE`, `CODEX`, `WINDSURF`, `CORTEX`, `CONTINUE`, `ZED`, `KIRO`, … |
| `TransportType` enum | MCP transport | `STDIO`, `HTTP`, `SSE`, `WEBSOCKET` |
| `ServerSurface` enum | Where the MCP server runs | `LOCAL`, `CONTAINER_IMAGE`, `IN_CLUSTER`, `CLOUD_HOSTED` |
| `AgentStatus` enum | Lifecycle state | `DISCOVERED`, `APPROVED`, `QUARANTINED`, `RETIRED` |
| `Vulnerability` | One CVE/OSV/GHSA advisory | `id`, `summary`, `severity`, `cvss_score`, `epss_score`, `is_kev`, `cwe_ids`, `aliases`, `vex_status`, `compliance_tags`, `advisory_sources` |
| `PackageOccurrence` | Where a package was found in a container layer | `layer_index`, `layer_id`, `package_path`, `dockerfile_instruction` |
| `Package` | One dependency or OS package | `name`, `version`, `ecosystem`, `purl`, `vulnerabilities`, `is_direct`, `dependency_depth`, `license`, `scorecard_score` |
| `MCPTool` | A tool exposed by an MCP server | `name`, `description`, `input_schema`, `output_schema`, `dangerous`, `network`, `filesystem`, `risk_level` |
| `MCPResource` | A resource exposed by an MCP server | `uri`, `name`, `description`, `mime_type` |
| `PermissionProfile` | What an MCP server can touch | `can_read_files`, `can_write_files`, `can_execute_commands`, `network_access`, `requires_credentials` |
| `MCPServer` | One discovered server | `name`, `command`, `transport`, `surface`, `packages`, `tools`, `resources`, `permissions`, `verified`, `runs_as_root`, `env` |
| `Agent` | One discovered agent | `name`, `agent_type`, `source`, `mcp_servers`, `config_path`, `version`, `metadata` |
| `BlastRadius` | The chain CVE → package → server → agent → credentials → tools | `vulnerability`, `package`, `affected_servers`, `affected_agents`, `exposed_credentials`, `exposed_tools`, `risk_score`, `compliance_tags`, `*_tags` (15 framework-specific tag fields) |
| `AIBOMReport` | Top-level scan output | `scan_id`, `agents`, `blast_radius`, `summary`, `framework_catalogs`, `scan_sources`, `tenant_id` |

### Compliance tag fields on `BlastRadius`

These are the lookup keys the report endpoint and dashboards use to map
a finding to a control. Adding a framework means adding a tag field
here AND a tag-population step in the relevant scanner / enricher.

| Field | Framework |
|---|---|
| `owasp_tags` | OWASP LLM Top 10 |
| `owasp_mcp_tags` | OWASP MCP Top 10 |
| `owasp_agentic_tags` | OWASP Agentic Top 10 |
| `atlas_tags` | MITRE ATLAS |
| `nist_ai_rmf_tags` | NIST AI RMF |
| `nist_csf_tags` | NIST CSF |
| `nist_800_53_tags` | NIST 800-53 |
| `iso_27001_tags` | ISO 27001 |
| `soc2_tags` | SOC 2 |
| `cis_tags` | CIS Controls |
| `cmmc_tags` | CMMC |
| `fedramp_tags` | FedRAMP |
| `eu_ai_act_tags` | EU AI Act |
| `pci_dss_tags` | PCI DSS |

---

## 2. Finding model (`src/agent_bom/finding.py`)

Used for unified findings outside the SCA / blast-radius path
(secrets, IaC misconfigs, K8s posture, cloud misconfigs).

| Class | Purpose |
|---|---|
| `FindingType` enum | `vulnerability`, `secret`, `misconfiguration`, `policy_violation`, `runtime_event` |
| `FindingSource` enum | Which scanner produced it (`osv`, `ghsa`, `iac`, `secrets`, `cloud_aws`, `runtime_proxy`, …) |
| `Asset` | Target of a finding (file, package, cloud resource, K8s resource, container image) |
| `Finding` | The finding itself — `id`, `type`, `source`, `severity`, `title`, `description`, `asset`, `evidence`, `remediation`, `compliance_tags` |

---

## 3. Graph taxonomy (`src/agent_bom/graph/types.py`)

The unified graph projects the canonical model into a node/edge form
used for blast-radius traversal, dashboards, and OCSF export.

### Entity types (18)

`AGENT`, `SERVER`, `PACKAGE`, `TOOL`, `MODEL`, `DATASET`, `CONTAINER`,
`CLOUD_RESOURCE`, `VULNERABILITY`, `MISCONFIGURATION`, `CREDENTIAL`,
`USER`, `GROUP`, `SERVICE_ACCOUNT`, `PROVIDER`, `ENVIRONMENT`, `FLEET`,
`CLUSTER`.

### Relationship types (24)

| Group | Relationships | Direction |
|---|---|---|
| Composition | `HOSTS`, `USES`, `DEPENDS_ON`, `PROVIDES_TOOL`, `EXPOSES_CRED`, `SERVES_MODEL`, `CONTAINS` | source → target |
| Risk | `AFFECTS`, `VULNERABLE_TO`, `EXPLOITABLE_VIA`, `REMEDIATES`, `TRIGGERS` | mostly bidirectional |
| Lateral movement | `SHARES_SERVER`, `SHARES_CRED`, `LATERAL_PATH` | symmetric |
| Ownership | `MANAGES`, `OWNS`, `PART_OF`, `MEMBER_OF` | hierarchical |
| Runtime | `INVOKED`, `ACCESSED`, `DELEGATED_TO` | source → target, time-stamped |

`EXPLOITABLE_VIA` is a capability-impact edge from a vulnerability to a
tool when the affected package is connected to the MCP server that provides
that tool. Because package-to-function call stacks are not always observable,
the edge evidence records `mapping_method` and `confidence`; conservative
server-scope mappings must not be presented as exact function-level proof.

### Canonical class → graph node mapping

| Canonical class | EntityType | Node id pattern |
|---|---|---|
| `Agent` | `AGENT` | `agent:{name}` |
| `MCPServer` | `SERVER` | `server:{name}` |
| `Package` | `PACKAGE` | `pkg:{ecosystem}/{name}@{version}` |
| `MCPTool` | `TOOL` | `tool:{server_name}/{tool_name}` |
| `Vulnerability` | `VULNERABILITY` | `vuln:{id}` |
| Credentials (env keys) | `CREDENTIAL` | `cred:{server_name}/{key}` |
| Cloud findings | `CLOUD_RESOURCE` / `MISCONFIGURATION` | `cloud:{provider}/{resource_id}` |
| Container layers | `CONTAINER` | `container:{image_ref}` |

The mapping lives in `src/agent_bom/graph/builder.py`. If a new
entity type is added to the enum, the builder must learn to emit it
or the dashboard will silently miss it.

---

## 4. Persistence layers

Four backends, one canonical model. Each store enforces tenant
isolation either via a `tenant_id` column (Postgres / ClickHouse /
Snowflake) or via per-tenant SQLite paths.

For the operator-facing logical entity → store/table contract, see
[`site-docs/deployment/control-plane-data-model.md`](../site-docs/deployment/control-plane-data-model.md).

### SQLite — `src/agent_bom/db/schema.py`

Single-file local store. Used for the offline vuln DB and the
single-node `agent-bom serve` deployment.

| Table | Purpose | Tenant-scoped? |
|---|---|---|
| `vulns`, `affected`, `epss_scores`, `kev_entries` | Bundled offline OSV/EPSS/KEV catalog | n/a (read-only catalog) |
| `jobs` | Scan job state | yes (per-tenant SQLite path or in-row column) |
| `fleet_agents` | Fleet inventory | yes |
| `gateway_policies` | Gateway policy rules | yes |
| `policy_audit_log` | Gateway policy mutation audit | yes |
| `sources` | Source registry | yes |
| `audit_log` | HMAC-chained audit | yes (in `details.tenant_id`) |
| `idempotency_keys` | idempotent write tracking | yes |
| `api_rate_limits` | shared runtime rate-limit state | yes |

### Postgres — `src/agent_bom/api/postgres_store.py`

Primary transactional control plane. Per-tenant filters on every
list/put plus session-scoped `app.current_tenant` for RLS.

| Table | Source dataclass | Notes |
|---|---|---|
| `scan_jobs` | `ScanJob` (api/models.py) | global `job_id` PK + tenant column (`team_id` / `tenant_id`) |
| `cis_benchmark_checks` | CIS benchmark JSON blobs normalized via `analytics_contract.build_cis_benchmark_check_rows` | indexed cloud/status/priority remediation rows for `/v1/cis/checks`; backfilled by `scripts/migrations/backfill_cis_benchmark_checks.py` |
| `fleet_agents` | `FleetAgent` (api/fleet_store.py) | trust score + lifecycle state |
| `api_keys` | `ApiKey` (api/auth.py) | scrypt hashes, expiry, role, tenant |
| `exceptions` | `Exception` (api/exceptions.py) | suppression workflow |
| `gateway_policies` + `policy_audit_log` | `GatewayPolicy` | RBAC-gated mutations, tenant-native reads |
| `scan_schedules` | `ScanSchedule` (api/schedule_store.py) | cron-driven |
| `audit_log` | `AuditEntry` (api/audit_log.py) | HMAC-chained, tamper-evident |
| `trend_history` | aggregated severity counts | for `/v1/trends` |
| `graph_nodes`, `graph_edges`, `graph_snapshots`, `attack_paths`, `interaction_risks`, `graph_filter_presets` | `UnifiedGraph` family | per-scan snapshots + delta alerts |
| `osv_cache` | OSV API response cache | TTL-bounded |
| `api_rate_limits` | Sliding-window rate limit state | per-tenant bucket key |

### ClickHouse — `src/agent_bom/cloud/clickhouse.py`

OLAP-only. Append-only analytics for trends, runtime events, posture.
This is not a transactional control-plane replacement.

| Table | Source dataclass | tenant_id |
|---|---|---|
| `vulnerability_scans` | `BlastRadius` flattened | yes (#1501) |
| `runtime_events` | runtime detector output | yes (#1501) |
| `posture_scores` | analytics_contract.posture_snapshots | yes (#1501) |
| `scan_metadata` | analytics_contract.scan_metadata | yes (#1501) |
| `fleet_agents` | `FleetAgent` snapshot | yes (native) |
| `compliance_controls` | per-control measurement | yes (#1501) |
| `cis_benchmark_checks` | normalized cloud CIS check rows + remediation | yes |
| `audit_events` | `AuditEntry` denormalized | yes (native) |

Every `query_*` method on the analytics store accepts `tenant_id` and
injects a `WHERE tenant_id = '<scope>'` predicate. Absent `tenant_id`
is deliberately cross-tenant and reserved for admin surfaces.

### Snowflake — `src/agent_bom/api/snowflake_store.py`

Warehouse-native deployment for governance-heavy customers. Today it
persists `scan_jobs`, `fleet_agents`, `gateway_policies`, and
`policy_audit_log` with Snowflake-specific column types. It also supports
`scan_schedules` and `exceptions`, so the warehouse-native contract is
broader than the original jobs/fleet/policy slice. It is not yet at full
control-plane parity:

- no source registry persistence
- no API-key / RBAC persistence
- no graph persistence
- no trend/baseline persistence
- no full `audit_log` transactional replacement

For the operator-facing backend matrix and current parity boundaries, see
`site-docs/deployment/backend-parity.md`.

### Deployment-context posture contract — `GET /v1/posture/counts`

This endpoint is the lightweight capability contract used by the UI to
adapt navigation and deployment-specific surfaces without fetching full
scan payloads. It must be derived from **tenant-scoped state only**:
completed scan jobs, fleet inventory, and gateway policy/audit stores.

| Field | Meaning | Source |
|---|---|---|
| `deployment_mode` | `local`, `fleet`, `cluster`, or `hybrid` | derived from the booleans below |
| `has_local_scan` | direct/local scan evidence exists | `scan_sources` + MCP/agent context |
| `has_fleet_ingest` | governed fleet inventory exists | fleet store |
| `has_cluster_scan` | cluster/GPU/K8s evidence exists | `scan_sources` + fleet agent environment |
| `has_ci_cd_scan` | CI/CD workflow scanning exists | `scan_sources` (`github_actions`) |
| `has_mesh` | mesh/topology views are meaningful | fleet + MCP/agent/runtime evidence |
| `has_gateway` | central gateway policy plane is configured | policy store |
| `has_proxy` | proxy/runtime enforcement evidence exists | policy audit + runtime signals |
| `has_traces` | trace/timeline views are meaningful | runtime correlation/session graph |
| `has_registry` | image/SBOM/registry-oriented scans exist | `scan_sources` |

If a new scan mode or deployment surface is added, update this table in
the same PR as the route and nav change.

### Graph/cache hot-path indexes

The Postgres graph and cache backends are tuned for the query shapes
the UI and API actually execute:

| Table | Query shape | Required indexes |
|---|---|---|
| `graph_nodes` | tenant + snapshot search ordered by severity/risk | `idx_pg_graph_nodes_scan`, `idx_pg_graph_nodes_scan_order` |
| `graph_edges` | neighbor expansion by source/target in one snapshot | `idx_pg_graph_edges_scan`, `idx_pg_graph_edges_scan_source`, `idx_pg_graph_edges_scan_target` |
| `attack_paths` | fix-first path lists ordered by composite risk | `idx_pg_attack_paths_scan`, `idx_pg_attack_paths_scan_risk` |
| `graph_snapshots` | latest/previous snapshot lookup | `idx_pg_graph_snapshots_recent` |
| `osv_cache` | TTL cleanup and expiry sweeps | `idx_cache_age` |

Any new backend should preserve these access patterns or document the
replacement plan explicitly.

---

## 5. Output formats (`src/agent_bom/output/`)

18 formats, all derived from `AIBOMReport`. The conversion contract is
**lossy in one direction**: every format strips fields it cannot
represent, but the canonical report keeps everything.

| Format | Module | What it includes | What it drops |
|---|---|---|---|
| JSON | `json_fmt.py` | Full report, lossless | nothing |
| SARIF 2.1 | `sarif.py` | Findings, locations, fix recommendations | runtime trace, fleet membership |
| CycloneDX 1.6 (+ ML BOM) | `cyclonedx_fmt.py` | Components, vulnerabilities, services, ML-BOM `model` blocks | dashboard-only attributes |
| SPDX 3.0 | `spdx_fmt.py` | Packages, relationships, licenses | runtime + agent context |
| HTML | `html.py` | Interactive dashboard view | suitable for emailed PDF |
| Graph JSON | `graph_export.py` | `UnifiedGraph` nodes/edges/paths | textual narratives |
| Graph HTML | `graph.py` | Cytoscape-rendered graph | — |
| GraphML | `graph_export.py` | XML graph for analysis tools | — |
| Neo4j Cypher | `graph_export.py` | `CREATE` statements | — |
| JUnit XML | `junit.py` | Findings as test failures (CI gating) | severity-below-threshold drops |
| CSV | `csv_fmt.py` | One finding per row | nested objects flattened |
| Markdown | `markdown.py` | Human-readable report | tables only |
| Mermaid | `mermaid.py` | Blast-radius graph as Mermaid | layout details |
| SVG | `svg.py` | Static graph render | interactivity |
| Prometheus | `prometheus.py` | Severity counts as gauges | finding details |
| Badge | `badge.py` | shields.io badge | everything except status |
| Attack Flow | `attack_flow.py` | MITRE Attack Flow JSON | non-attack-path nodes |
| Plain text | `__init__.py` | Console summary | everything except top-line stats |
| **OCSF** (event delivery) | `ocsf.py` | Findings as OCSF events for SIEM / security-lake | Used for streaming, not as a `-f ocsf` report option |

---

## 6. Per-scan-type populated-fields matrix

Different scan types populate different subsets of `AIBOMReport`. A
field empty for scan type X is intentional, not a bug.

| Scan type | `agents` | `blast_radius` | `mcp_servers` | `iac_findings` | `cloud_findings` | `secret_findings` |
|---|:---:|:---:|:---:|:---:|:---:|:---:|
| `agents` (default) | ✅ | ✅ | ✅ | — | — | optional `--secrets` |
| `image` | synthetic single agent | ✅ | n/a | — | — | optional |
| `iac` | — | — | — | ✅ | optional `--k8s-live` | — |
| `cloud aws/gcp/azure/snowflake` | — | — | — | — | ✅ | — |
| `secrets` | — | — | — | — | — | ✅ |
| `proxy` (runtime) | — | streaming events | n/a | — | — | — |
| `check` (single package) | — | one BlastRadius row | — | — | — | — |

When a consumer asserts on a field that should be populated for the
scan type, refer to this table first.

---

## 7. Trust + tenancy invariants

These hold across every layer. If you change them, this doc must
change in the same PR.

1. **Tenant propagation** — `request.state.tenant_id` is set by
   `APIKeyMiddleware` from the resolved API key, OIDC claim, or SAML
   assertion. Every store accepts it as a kwarg or context-var; every
   query enforces a filter.
2. **Audit chain** — `AuditEntry` carries `prev_signature` and
   `hmac_signature`. Tampering with any field breaks the chain on the
   next `verify_integrity` call.
3. **Signed exports** — `/v1/audit/export` and
   `/v1/compliance/{framework}/report` both ship
   `X-Agent-Bom-*-Signature` headers so the bundle is verifiable
   off-server with the operator's HMAC key.
4. **Read-only by default** — the scanner never writes configs, never
   executes MCP servers, never persists credential values. Outbound
   network calls are limited to the package metadata, version
   resolution, and CVE enrichment endpoints documented in the README
   trust table.
5. **Tenant_id default value** — `"default"`. Used only when no
   middleware ran (CLI, single-tenant deployments). Never a sentinel
   for missing data.

---

## 8. Pointers

- README sections that reference these flows: `## How a scan moves through the system`, `## Deploy in your own AWS / EKS`, `## Trust & transparency`, `## Compliance`
- Architecture deep-dive: [site-docs/architecture/how-agent-bom-works.md](../site-docs/architecture/how-agent-bom-works.md)
- Canonical vs OCSF: [site-docs/architecture/canonical-vs-ocsf.md](../site-docs/architecture/canonical-vs-ocsf.md)
- Data ingestion modes: [site-docs/architecture/data-ingestion-and-security.md](../site-docs/architecture/data-ingestion-and-security.md)
- Governance and retention evidence: [docs/DATA_GOVERNANCE_RETENTION.md](DATA_GOVERNANCE_RETENTION.md)
- Capture protocol for screenshots: [docs/CAPTURE.md](CAPTURE.md)
- Visual language for diagrams: [docs/VISUAL_LANGUAGE.md](VISUAL_LANGUAGE.md)
