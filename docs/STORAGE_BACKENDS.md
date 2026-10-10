# Storage backends and support tiers

agent-bom can persist control-plane state to several engines. They do not
carry the same evidence, so each one has a support tier. The tier is declared
in code (`src/agent_bom/storage/tiers.py`), logged at control-plane startup,
and shown by `agent-bom doctor`.

## Support matrix

| Backend | Tier | Use | Tenant-isolation evidence |
|---|---|---|---|
| PostgreSQL | **supported** | System of record for self-hosted servers, including multi-replica and multi-tenant deployments | Forced row-level security plus application tenant predicates; startup refuses a role that can bypass RLS (`_preflight_postgres_tenant_isolation` in `api/server.py`). Tests: `tests/test_postgres_rls_backstop_parity.py`, `tests/test_rls_superuser_guard.py`, `tests/test_storage_sql.py`, `tests/test_cross_tenant_leakage.py` |
| SQLite | **supported** | Local CLI, single-node and pilot control planes | Application tenant predicates on every read and write; shared SQL with Postgres in `api/storage/` ([architecture boundaries](ARCHITECTURE_BOUNDARIES.md)). Tests: `tests/test_storage_sql.py`, `tests/test_store_tenant_backstop.py`, `tests/test_*_tenant_boundary.py` |
| In-memory | supported for local use only | Default when no database is configured; not durable | Process-local; lost on restart |
| ClickHouse | **analytics sink** | Optional OLAP mirror for traces, proxy audit and scan analytics. Never the system of record for jobs, fleet, policy, audit or graph state | Tenant column on every row and tenant predicate on every scoped query, tested against a mocked client: `tests/test_clickhouse_tenant_isolation.py` |
| Snowflake (control-plane stores) | **experimental** | Selected job, fleet, policy, schedule and exception stores when `SNOWFLAKE_ACCOUNT` is set; used by the [Snowflake Native App](snowflake-native-app/INSTALL.md) | Application tenant predicates plus a row access policy (`agent_bom_tenant_isolation`) attached to tenant tables. The policy admits every row until `agent_bom_tenant_access` role mappings are populated, so the application filter is the effective boundary by default. Both are verified only as rendered SQL against mocked connections (`tests/test_snowflake_stores.py`); there is no live cross-tenant test. **Tenant isolation is not proven.** |
| Neptune (graph) | **experimental** | Graph store when `AGENT_BOM_GRAPH_BACKEND=neptune` and `AGENT_BOM_EXPERIMENTAL_NEPTUNE_GRAPH=1` | Tenant property on vertices and edges, tested against a mocked Gremlin client (`tests/test_neptune_graph_store.py`). **Tenant isolation is not proven.** Generation-owned push persistence is rejected ([architecture](ARCHITECTURE.md)) |

Snowflake warehouse-native discovery and governance routes (Cortex, query
history, account inventory) read from Snowflake as a data source. They are not
covered by this table, which is about where agent-bom stores its own state.

## How the active backend is selected

Precedence mirrors the API startup wiring:

| Component | Order |
|---|---|
| Control plane (jobs, fleet, policy, …) | `SNOWFLAKE_ACCOUNT` → `AGENT_BOM_GRAPH_BACKEND=neptune` (jobs stay in memory) → `AGENT_BOM_POSTGRES_URL` or a Postgres URL in `AGENT_BOM_DB` → SQLite file in `AGENT_BOM_DB` → in-memory |
| Graph | `AGENT_BOM_GRAPH_BACKEND=neptune` → Postgres → SQLite |
| Analytics | `AGENT_BOM_ANALYTICS_BACKEND=clickhouse`, or `AGENT_BOM_CLICKHOUSE_URL` with the backend unset or `auto` |

## Startup behavior

- **Supported backends and the ClickHouse sink:** no storage-tier log line.
- **Experimental backend (default, advisory):** the API logs one `WARNING`
  that names each experimental backend and component, its tier, and this page.
  The log record carries a `context` object
  (`event=storage_tier_experimental`) for JSON log pipelines. When the
  deployment looks multi-tenant (`AGENT_BOM_REQUIRE_TENANT_BOUNDARY=1`,
  `AGENT_BOM_CONTROL_PLANE_REPLICAS` greater than 1, or
  `AGENT_BOM_OIDC_TENANT_PROVIDERS_JSON` set), the warning states that tenant
  isolation for that backend is not proven. Startup continues, so existing
  deployments, including the Snowflake Native App, keep working.
- **Strict mode (opt-in):** set `AGENT_BOM_REQUIRE_SUPPORTED_STORAGE=1` and the
  API refuses to start when an experimental backend is selected. An invalid
  value for this variable also refuses startup instead of being ignored.

Check the effective tiers without starting the API:

```bash
agent-bom doctor --offline
agent-bom --agent-mode doctor --offline   # JSON; see data.platform
```

Experimental rows show as warnings and count toward the doctor warning total.

## Migrating to PostgreSQL

1. Provision PostgreSQL and run the control-plane migrations with the
   maintenance role. Configure the restricted application role in
   `AGENT_BOM_POSTGRES_URL` ([enterprise deployment](ENTERPRISE_DEPLOYMENT.md)).
2. **From SQLite:** import evidence registries with the operator-controlled,
   dry-run-first import in
   [operations/sqlite-registry-import.md](operations/sqlite-registry-import.md).
3. **From Snowflake or Neptune:** there is no automated migration. Unset
   `SNOWFLAKE_ACCOUNT` (control-plane stores) or `AGENT_BOM_GRAPH_BACKEND`
   (graph) for the API process, then re-run scans and fleet sync so jobs,
   inventory and graph snapshots are rebuilt in PostgreSQL. Export any
   Snowflake-held policy or exception records you need to keep before switching.
4. Set `AGENT_BOM_REQUIRE_SUPPORTED_STORAGE=1` so a later configuration change
   cannot silently reintroduce an experimental backend.
5. Run `agent-bom doctor` and confirm every storage row reads `supported` or
   `analytics sink`.

ClickHouse can stay configured alongside PostgreSQL as the analytics sink.

See also: [backend parity by route](../site-docs/deployment/backend-parity.md).
