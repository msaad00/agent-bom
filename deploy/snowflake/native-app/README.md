# agent-bom for Snowflake

This provider-preview package defines API/UI containers, consumer permission
callbacks, and read-only reference bindings for Snowflake. Binding objects does
not automatically ingest their data. Advisory-feed references remain unbound
until explicitly approved.

**Native App scan dispatch is unavailable; the scanner lifecycle is unsupported.**
Authenticated installation, service readiness, reference binding, and a completed
scan with persisted findings remain unverified. Use this package to validate the
installation contract, not as evidence of a production-ready scanning deployment.

## Persistent evidence (single instance)

Fresh installations reserve a customer-account 4 GiB encrypted SPCS block volume
for the API only. `AGENT_BOM_DB` and `AGENT_BOM_GRAPH_DB` point to
`/var/lib/agent-bom/control-plane.db`. This is a SQLite companion for graph,
connection, and other local control-plane stores, **not Snowflake graph-store
parity**. Keep `MIN_INSTANCES = MAX_INSTANCES = 1`; replicas do not share a volume.
The existing Snowflake-backed job/fleet/policy stores remain separate.

The Native-only image prepares just the mount directory, clears supplementary
groups, then starts the API as UID/GID 10001. It refuses an absent mount, failed
privilege drop, or unwritable state. A private audit signing key is created once
on that volume and reused on restart. Backups contain both evidence and this
key: protect them together; this does not provide independent off-volume
attestation. The general Snowpark image is unchanged.

API authentication remains required. Snowflake service endpoint permissions
and its injected SQL OAuth token do not replace API authentication. Configure a
supported API authentication mechanism before starting the service; no anonymous
or insecure override is included. Authenticated Native installation remains an
operator acceptance check, not a completed deployment proof.

### Upgrade, backup, and restart checks

[Snowflake block volumes](https://docs.snowflake.com/en/developer-guide/snowpark-container-services/block-storage-volume)
survive service upgrade and suspend/resume. Dropping/replacing a service deletes
its volume; automatic deletion snapshots have finite retention. Do not use a
stage mount for SQLite/WAL. Quiesce writers and flush the database before taking
a snapshot; verify restore in a separate installation before destructive work.

Existing services cannot acquire a new block volume through `ALTER SERVICE`.
This package does not silently drop/recreate them or migrate existing ephemeral
files. Export existing evidence before retirement, create a new service with the
persistent specification, and import/rescan through supported authenticated
interfaces. Preserve the original until tenant-scoped records and audit integrity
are verified. A JSON report import is not a full database/audit-chain restore.
Volume size/encryption are fixed after service creation; plan capacity and backup
retention before installation.

Local verification (requires Docker; no Snowflake mutation):

```bash
docker build -f deploy/docker/Dockerfile.native-app -t agent-bom:native-persistence-contract .
AGENT_BOM_TEST_NATIVE_IMAGE=agent-bom:native-persistence-contract uv run pytest -q tests/test_native_app_persistence.py
```

This checks non-root execution, authenticated API enforcement, tenant graph
isolation, and audit verification after replacing a container on the same local
volume. A real consumer-account block mount, suspend/resume, upgrade, snapshot
restore, and completed authenticated scan still require live validation.

## Required privileges

- `CREATE COMPUTE POOL` creates one bounded `CPU_X64_XS` pool for the app.
- Services are created in the app-owned schema; no global `CREATE SERVICE` privilege is requested.
- `BIND SERVICE ENDPOINT` exposes the app's declared API and UI endpoints.
- Customer table references request `SELECT`; stage references request `READ`.

The app does not request `MANAGE GRANTS`, write access to customer tables, or a
general account/database grant.

Service containers authenticate with Snowflake's injected, rotating OAuth
token file. The app does not request a user password or private key.

## Configure after install

1. Bind only the cloud, IAM, vulnerability, log, and artifact objects the app
   should read.
2. Approve the requested compute-pool and endpoint privileges. The grant callback then creates API/UI resources. `core.health_check()` reports configuration flags, not live service health.
3. Leave advisory external access integrations unbound for an air-gapped install,
   or approve the named feeds before enabling the scanner service.
4. Native App scan dispatch is currently unavailable. Use an authenticated external `agent-bom scan --snowflake -f json -o snowflake-report.json` invocation to produce a local report; it is not automatically ingested into this app.

## Procedures

- `core.health_check()` reports configured service and advisory-egress flags.
- `core.trigger_scan()` raises an explicit unsupported-dispatch error without creating a job.
- `core.enable_scanner_service()` creates the default-off scanner after all
  advisory-feed integrations are bound.
- `core.enable_mcp_runtime_service(token, expires_at)` creates the default-off MCP service
  with a user-provisioned bearer token of at least 32 characters and an absolute
  timezone-aware expiry within one hour. Calling it again suspends the service
  and applies the replacement token and deadline; explicitly resume afterward.
  Agent-Bom does not issue tokens or automatically rotate them.

## Verify the installation

```sql
CALL core.health_check();
SHOW SERVICES IN APPLICATION agent_bom;
SHOW GRANTS TO APPLICATION ROLE app_user;
```

Expected after consumer privilege approval: the API/UI service exists; scanner and MCP
services are disabled; advisory egress is disabled.

The scanner spec is an unsupported one-shot prototype: it has no persistent job
dispatcher or result ingestion, and its declared HTTP readiness endpoint is not
served by the CLI. Do not enable it as a production scanning service.
Authenticated consumer installation, service readiness, reference binding, and a
completed scan with persisted findings remain required before claiming Native
App deployment readiness. Package validation alone does not establish these.
