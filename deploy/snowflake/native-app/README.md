# agent-bom for Snowflake

agent-bom inventories and governs AI, MCP, identity, vulnerability, and cloud
security evidence inside the consumer's Snowflake account. Customer data stays
in that account. Outbound advisory feeds are disabled until the consumer binds
the corresponding external access integrations and enables the scanner.

## Required privileges

- `CREATE COMPUTE POOL` creates one bounded `CPU_X64_XS` pool for the app.
- `CREATE SERVICE` creates the API and dashboard service.
- `BIND SERVICE ENDPOINT` exposes the app's declared API and UI endpoints.
- Customer table references request `SELECT`; stage references request `READ`.

The app does not request `MANAGE GRANTS`, write access to customer tables, or a
general account/database grant.

Service containers authenticate with Snowflake's injected, rotating OAuth
token file. The app does not request a user password or private key.

## Configure after install

1. Bind only the cloud, IAM, vulnerability, log, and artifact objects the app
   should read.
2. Open the app UI and call `core.health_check()` to confirm the default posture.
3. Leave advisory external access integrations unbound for an air-gapped install,
   or approve the named feeds before enabling the scanner service.
4. Run `CALL core.trigger_scan()` for the first read-only scan.

## Procedures

- `core.health_check()` reports service and advisory-egress state.
- `core.trigger_scan()` starts a read-only evidence scan.
- `core.enable_scanner_service()` creates the default-off scanner after all
  advisory-feed integrations are bound.
- `core.enable_mcp_runtime_service(token)` creates the default-off MCP service
  with an operator-supplied bearer token of at least 32 characters.

## Verify the installation

```sql
CALL core.health_check();
SHOW SERVICES IN APPLICATION agent_bom;
SHOW GRANTS TO APPLICATION ROLE app_user;
```

Expected immediately after install: the API/UI service exists; scanner and MCP
services are disabled; advisory egress is disabled.
