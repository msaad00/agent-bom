# Data Governance, Retention, and Tenant Deletion Evidence

This page maps the self-hosted `agent-bom` data lifecycle to the code paths,
API endpoints, tests, and operator responsibilities that support privacy,
retention, and tenant-deletion reviews.

It is evidence for self-hosted deployments. It is not a hosted-service DPA,
subprocessor list, legal retention schedule, or customer-support access policy.
Those controls remain operator-owned unless a managed service is explicitly
launched.

## Data Classification

| Class | Examples | Storage surfaces | Owner | Default handling |
|---|---|---|---|---|
| Customer operational data | scan jobs, fleet agents, graph snapshots, gateway policies, scan schedules, sources, exceptions, tenant quota overrides | SQLite, Postgres, Snowflake-supported slices, graph store | operator / tenant | tenant-scoped read, export, and delete paths |
| Security evidence | HMAC-chained audit events, policy audit log, compliance export metadata | audit store, policy store, compliance bundles | operator | retained for integrity evidence; not deleted by normal scan cleanup |
| Derived analytics | ClickHouse posture rows, vulnerability trends, runtime events, CIS benchmark rows | ClickHouse analytics store | operator | append-oriented analytics with backend TTL policy |
| Dependency and advisory cache | OSV/NVD/EPSS/KEV enrichment cache, scan cache, package metadata cache | local cache files under the configured agent-bom cache directory | operator | TTL and max-entry bounded cache |
| Secret material | API-key hashes, trusted-proxy attestation secret, audit HMAC secret, OIDC/SAML/SCIM secrets | env vars, external secret manager, or configured control-plane stores | operator | values are not exported by tenant-data export; source credentials are redacted |
| Exported evidence | audit exports, compliance bundles, SARIF, CycloneDX/SPDX, JSON reports | caller-selected output path or downstream evidence store | operator / recipient | retention determined by the evidence repository, bucket policy, or ticketing system |
| Transient runtime data | active scan workers, proxy pending calls, request rate buckets, browser sessions | process memory and short-lived local state | operator | expires through runtime TTLs or process lifecycle |

## Retention Knobs

| Data class | Control | Default | Code path |
|---|---|---|---|
| API scan jobs | `AGENT_BOM_API_JOB_TTL` | `3600` seconds | `src/agent_bom/config.py`, `src/agent_bom/api/server.py`, store `cleanup_expired()` |
| Retained scan jobs per tenant | `AGENT_BOM_API_MAX_RETAINED_JOBS_PER_TENANT` | `500` | `src/agent_bom/config.py`, `src/agent_bom/api/tenant_quota.py` |
| Scan cache | `AGENT_BOM_SCAN_CACHE`, `AGENT_BOM_SCAN_CACHE_MAX_ENTRIES` | local cache, `100000` entries | `src/agent_bom/scan_cache.py`, `src/agent_bom/config.py` |
| Enrichment cache | `AGENT_BOM_ENRICHMENT_TTL`, `AGENT_BOM_ENRICHMENT_MAX_CACHE` | `604800` seconds, `10000` entries | `src/agent_bom/enrichment.py`, `src/agent_bom/config.py` |
| AI enrichment cache | `AGENT_BOM_AI_CACHE_MAX` | `1000` entries | `src/agent_bom/ai_enrich.py`, `src/agent_bom/config.py` |
| API keys | `AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS`, `AGENT_BOM_API_KEY_MAX_TTL_SECONDS` | 30 days, 90 days | `src/agent_bom/api/auth.py` |
| SAML relay state | `AGENT_BOM_SAML_RELAY_STATE_TTL_SECONDS` | `300` seconds | `src/agent_bom/api/routes/enterprise.py` |
| SAML session | `AGENT_BOM_SAML_SESSION_TTL_SECONDS` | `3600` seconds | `src/agent_bom/api/saml.py` |
| Compliance bundle links | `AGENT_BOM_COMPLIANCE_BUNDLE_TTL_SECONDS` | `86400` seconds | `src/agent_bom/api/routes/compliance.py` |
| Audit HMAC posture | `AGENT_BOM_AUDIT_HMAC_KEY`, `AGENT_BOM_REQUIRE_AUDIT_HMAC`, rotation metadata env vars | self-hosted operator supplied | `src/agent_bom/api/audit_log.py` |
| ClickHouse analytics TTL | table TTL clauses | 2 years for analytics tables | `src/agent_bom/cloud/clickhouse.py` |

Backup retention, object lock, legal hold, and immutable evidence archive
windows are not set by the application. They belong in the operator's database,
bucket, and backup policy.

## Tenant Data Export

Endpoint:

```text
GET /v1/tenant/{tenant_id}/data?include_records=false
GET /v1/tenant/{tenant_id}/data?include_records=true&record_limit=500
```

Authorization:

| Requirement | Evidence |
|---|---|
| Admin role | `src/agent_bom/api/middleware.py` role rule for `GET /v1/tenant/` |
| `privacy.data:read` scope | `src/agent_bom/api/middleware.py` scope rule |
| Same authenticated tenant | `src/agent_bom/api/routes/privacy.py::_require_same_tenant` |
| Export audit event | `privacy.tenant_export` via `log_action()` |

The export inventory includes counts for scan jobs, fleet agents, gateway
policies, scan schedules, sources, exceptions, graph snapshots, tenant quota
overrides, audit log entries, and policy audit entries. When record export is
requested, source credentials and source configs are redacted.

Example evidence shape:

```json
{
  "tenant_id": "tenant-a",
  "counts": {
    "jobs": 12,
    "fleet_agents": 4,
    "gateway_policies": 3,
    "scan_schedules": 2,
    "sources": 2,
    "exceptions": 1,
    "graph_snapshots": 10,
    "tenant_quota_overrides": 1,
    "audit_log_entries_retained": 31,
    "policy_audit_entries_retained": 8
  },
  "retention": {
    "audit_log": "retained_immutable_hmac_chain",
    "policy_audit_log": "retained_for_security_evidence",
    "api_keys": "retained_manage_with_api_key_lifecycle"
  }
}
```

## Tenant Data Deletion

Endpoint:

```text
DELETE /v1/tenant/{tenant_id}/data?dry_run=true
DELETE /v1/tenant/{tenant_id}/data?dry_run=false&confirm_tenant_id={tenant_id}
```

Deletion is dry-run by default. A final delete requires
`confirm_tenant_id` to exactly match the normalized tenant id.

Authorization:

| Requirement | Evidence |
|---|---|
| Admin role | `src/agent_bom/api/middleware.py` role rule for `DELETE /v1/tenant/` |
| `privacy.data:delete` scope | `src/agent_bom/api/middleware.py` scope rule |
| Same authenticated tenant | `src/agent_bom/api/routes/privacy.py::_require_same_tenant` |
| Dry-run audit event | `privacy.tenant_delete_dry_run` |
| Final-delete audit event | `privacy.tenant_delete` |

Final delete removes tenant-scoped operational records from the configured
stores for scan jobs, fleet agents, gateway policies, schedules, sources,
exceptions, tenant quota overrides, and graph rows. The response reports both
deleted counts and remaining counts so the operator can attach before/after
evidence to a ticket.

Example dry-run response:

```json
{
  "tenant_id": "tenant-a",
  "dry_run": true,
  "would_delete": {
    "jobs": 12,
    "fleet_agents": 4,
    "graph_snapshots": 10
  },
  "retention": {
    "audit_log": "retained_immutable_hmac_chain"
  }
}
```

Example final-delete response:

```json
{
  "tenant_id": "tenant-a",
  "dry_run": false,
  "deleted": {
    "jobs": 12,
    "fleet_agents": 4,
    "gateway_policies": 3,
    "scan_schedules": 2,
    "sources": 2,
    "exceptions": 1,
    "tenant_quota_overrides": 1,
    "graph_rows": 41
  },
  "remaining": {
    "jobs": 0,
    "fleet_agents": 0,
    "graph_snapshots": 0
  }
}
```

## Regression Tests

| Control | Test evidence |
|---|---|
| Export is tenant-scoped and redacts source secrets | `tests/test_api_privacy.py::test_tenant_data_export_is_tenant_scoped_and_redacts_source_secrets` |
| HTTP endpoint requires authenticated admin access | `tests/test_api_privacy.py::test_tenant_data_http_endpoint_requires_authenticated_admin` |
| Cross-tenant export is rejected | `tests/test_api_privacy.py::test_tenant_data_export_rejects_cross_tenant_access` |
| Delete defaults to dry-run | `tests/test_api_privacy.py::test_tenant_data_delete_defaults_to_dry_run` |
| Final delete requires exact confirmation | `tests/test_api_privacy.py::test_tenant_data_delete_requires_exact_confirmation` |
| Final delete removes only the authenticated tenant | `tests/test_api_privacy.py::test_tenant_data_delete_removes_only_authenticated_tenant` |
| Graph tenant delete removes all graph row families | `tests/test_api_privacy.py::test_sqlite_graph_store_delete_tenant_removes_graph_rows` |
| Middleware maps tenant-data routes to privacy scopes | `tests/test_api_operator_policy.py` |
| Cross-tenant leakage guardrails | `tests/test_api_cross_tenant_matrix.py`, `tests/test_cross_tenant_leakage.py` |

## Operator Caveats

- Signed audit and compliance exports are evidence records. Normal tenant
  deletion does not rewrite evidence already exported to external systems.
- Immutable backups, object-lock buckets, warehouse snapshots, and legal holds
  can retain deleted tenant data until the operator's retention window expires.
- API-key hashes and audit-chain metadata may remain where required for
  security evidence and non-repudiation. Rotate or revoke active credentials
  before final tenant deletion.
- Downstream SIEM, ticketing, GRC, and data-lake integrations must run their
  own deletion or retention workflow after agent-bom exports data to them.
- Self-hosted operators own DPA language, legal basis, regional residency,
  support-access approvals, and subprocessor review.

## Evidence Collection Checklist

For a tenant lifecycle ticket, attach:

1. The authenticated export response before deletion.
2. The dry-run delete response.
3. The final delete response with `confirm_tenant_id`.
4. The tenant-scoped audit export containing `privacy.tenant_export`,
   `privacy.tenant_delete_dry_run`, and `privacy.tenant_delete`.
5. Backup or object-lock retention notes from the operator's infrastructure.
6. Any downstream deletion receipts from SIEM, GRC, ticketing, or data-lake
   systems that received agent-bom exports.
