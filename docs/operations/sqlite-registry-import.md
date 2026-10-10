# Import SQLite evidence registries into Postgres

Configure and migrate the Postgres control plane before starting API replicas.
`AGENT_BOM_POSTGRES_URL` takes precedence; a Postgres URL in `AGENT_BOM_DB` selects
the same backend and role validation. An unavailable configured backend fails
initialization instead of choosing local or process memory storage.

Migration `20261007_01` adds shared webhook subscriptions, dataset versions,
evaluation runs, drift incidents, MCP observations, external issue mappings,
Skills runs and KSPM posture. Every table has a tenant-leading key, forced row
level security, and grants for the restricted application and maintenance roles.
Existing export schedules, compliance, access reviews and runtime evidence use
their existing adapters.

## Recover existing SQLite evidence

Stop writes to the source registry and preserve the SQLite file and any `-wal`
and `-shm` companions. Do not rename, delete or automatically migrate files that
were accidentally created from a database configuration. Take a reviewed backup
before running this operator-controlled import.

Create a private tenant mapping, including every source tenant explicitly:

```json
{"old-tenant": "approved-tenant"}
```

The command uses the configured restricted Postgres application credentials.
The source opens read-only and is never initialized, upgraded or deleted.
Run a dry run first; select each table to import explicitly:

```bash
python -m agent_bom.api.storage.registry_import \
  --source /secure/recovery/control-plane.db \
  --tenant-map /secure/recovery/tenant-map.json \
  --table dataset_versions --table evaluation_runs
```

The JSON receipt includes selected tables, row counts, conflict counts and a
SHA-256 digest of the mapped source snapshot. It contains no source payloads,
credentials or filesystem paths. Inspect and retain this receipt privately.
Then repeat the same command with `--apply` and retain the resulting receipt.
Identical rows are unchanged on repeats. A differing existing row, conflicting
secondary identity, or inconsistent source identity prevents the transaction
from committing; reconcile evidence explicitly before retrying. Exit status 2
means a conflict; other errors exit 1 with sanitized diagnostics.

Supported table names are `webhook_subscriptions`, `dataset_versions`,
`evaluation_runs`, `drift_incidents`, `mcp_observations`, `issue_mappings`,
`skills_scan_run`, `kspm_cluster_posture`, `credential_refs`, `sources`,
`scan_schedules`, `access_review_campaigns`, `access_review_items`,
`runtime_observations`, `runtime_sessions`, `fleet_agents`, `fleet_endpoints`,
`gateway_policies`, `exceptions`, `scim_users` and `scim_groups`. The `compliance_hub` selection
restores the complete seven-table compliance snapshot as one group.

Scan finding snapshots (`scan_snapshot_jobs`, `scan_snapshot_rows`) are derived
from scan jobs and are not imported. After the jobs are restored, rebuild them
with `python -m agent_bom.api.scan_snapshot backfill --tenant <tenant_id>`.

Select both access-review tables together. Campaign counts must match their
items; existing decisions require their original actor and timestamp. Source
credential references must already exist in the same target tenant or be included
in the import. Disabled sources, paused schedules and retired credentials retain
their state. Imported decisions do not execute revocation or create approvals.

Select both runtime tables together. Recovery requires complete metadata-only
observations that reproduce the recorded session summary. Pruned histories,
raw tool payloads and differing target sessions require explicit reconciliation;
the command refuses to infer missing history. Runtime recovery bypasses retention
pruning during the transaction, preserving the selected evidence. Normal runtime
writes subsequently apply the configured retention policy.

Fleet agents and endpoint records retain lifecycle and observation timestamps. Gateway
policies retain their enabled state. Waivers retain original approval, revocation,
expiry, and decision actors; recovery never approves or reactivates a waiver.
The selected destination tenant must already be provisioned.

Select both SCIM tables together. User deactivation, group membership, roles and
original timestamps are preserved. Every membership must resolve in the selected
tenant snapshot. The destination identity population must be empty or identical;
recovery refuses to merge extra identities or infer missing memberships.

Compliance recovery requires the current SQLite schema, complete lifecycle
observations, valid ledger/reference links and consistent ingestion counters.
It preserves resolved/suppressed states, timestamps, payload references and the
source evidence revision. It does not perform a new scan or reconcile absent
findings. Stable finding identifiers remain unchanged; Postgres allocates fresh
internal ledger ordinals and remaps their current-finding pointers. Those
sequence allocations can advance during dry-run even though all evidence rows
roll back. The target tenant hub must be empty or identical. Merging existing
hub evidence, merging source tenants, or upgrading older source files requires
an explicit compatibility procedure and is refused by this command.

Use a maintenance window and pause source, schedule, runtime and webhook workers.
For the canonical control-plane stores, both dry-run and apply stage owner-validated
writes under table locks; dry-run rolls all target changes back. No external job,
webhook or review action is replayed. This command rejects unsupported tables,
including signed audit history, idempotency fences, graph and trend snapshots,
tenant score configuration, retention overrides and quota overrides. Preserve
those source files and their compatibility metadata; this command does not
provide recovery for those stores. Do not replay signed history through normal
write APIs or generate replacement signatures. An audit recovery procedure must
preserve the exact signed bytes, original chain and independent checkpoints;
a missing checkpoint or truncated source is missing evidence. Do not replay
idempotency records as operations or drop fences to make a retry succeed.

## Verification and rollback

Use the API under each target tenant to verify imported evidence and retain the
receipt with the source backup. A successful apply verifies every target row
inside the committing transaction. A rollback of the application binary does
not remove these tables; migration downgrade deliberately refuses to discard
evidence. Restore a reviewed backup if database rollback is required. Older
binaries that still select memory or SQLite will not read the imported rows.
