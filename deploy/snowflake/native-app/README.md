# agent-bom for Snowflake

This provider-preview package defines API/UI containers, consumer permission
callbacks, and read-only reference bindings for Snowflake. Binding objects does
not automatically ingest their data. Advisory-feed references remain unbound
until explicitly approved.

**Native App scan dispatch is unavailable; the scanner lifecycle is unsupported.**
Authenticated installation, service readiness, reference binding, and a completed
scan with persisted findings remain unverified. Use this package to validate the
installation contract, not as evidence of a production-ready scanning deployment.

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
