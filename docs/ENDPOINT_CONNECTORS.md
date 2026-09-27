# Jamf and CrowdStrike Falcon endpoint inventory

Use **Connections → Endpoints** to save a read-only connection, sync a
bounded batch, and inspect device evidence. Admin access is required to configure,
rotate, disable, associate or sync; authenticated readers can inspect inventory.
Saving a connection does not collect inventory. Secrets use the control plane's
existing encrypted connection store and are never returned. Configure
`AGENT_BOM_CONNECTIONS_KEY` (or its supported managed-key provider) before connecting.
Keep the same key available to every API/MCP replica. Docker secrets and Helm
secret/environment injection use the existing connection-encryption configuration.

| Provider | Grant | Credential destination | Collected evidence |
| --- | --- | --- | --- |
| Jamf Pro 11.32 API contract | Read Computers | Exact HTTPS instance under `jamfcloud.com` | Computer ID, UDID/management ID, management state, OS version, FileVault coverage, inventory report time |
| CrowdStrike Falcon | Hosts: Read | Explicit US1, US2, EU1, USGOV1 or USGOV2 API origin | Customer CID + host ID, OS version, reporting sensor, reduced-functionality status, last seen |

Jamf uses `/api/v1/oauth/token` and `/api/v4/computers-inventory` with GENERAL
and OPERATING_SYSTEM sections. Older Jamf token/inventory endpoints, on-premises
custom domains and the Platform Gateway are not this contract. Falcon uses
`/oauth2/token`, `/devices/queries/devices-scroll/v1`, then
`/devices/entities/devices/v2`. Host-detail CID must match the configured account.
Credentials need no containment, device write, policy write or administrator grants.
Redirects and ambient HTTP proxies are disabled; TLS verification stays enabled.

## CLI: connection → collection → evidence

Create a non-secret `jamf.json`:

```json
{
  "name": "Managed Macs",
  "provider": "jamf",
  "account_id": "example.jamfcloud.com",
  "jamf_url": "https://example.jamfcloud.com",
  "client_id": "your-api-client-id"
}
```

Inject the vendor secret into an environment variable using your secret manager,
then use the authenticated control-plane API:

```bash
agent-bom connect endpoints create --config jamf.json --secret-env JAMF_CLIENT_SECRET
agent-bom connect endpoints list
agent-bom connect endpoints sync CONNECTION_ID
agent-bom connect endpoints devices CONNECTION_ID --limit 100 --offset 0 > devices.json
```

Commands accept the existing `--api-url`, `--api-key` / `--bearer-token`, and
`--tenant` API options. Use HTTPS outside loopback. For Falcon use
`provider: "crowdstrike"`, `account_id: "<32-character CID without checksum>"`,
`region: "us1"` (or your region), and omit `jamf_url`.

`sync` exits **2** for partial/failed collection and **0** only for a completed
collection. Repeat to resume; use `--restart` after inventory drift or to request
an explicit new collection. Falcon offsets expire after two minutes: stale offsets
start a new run while retaining the previous run and its receipts. Collection is
paginated evidence, not a transactionally consistent vendor snapshot.

The JSON artifact contains canonical device IDs, provider observation time,
collection time, freshness, scope, the collection denominator and recent receipts.
It is endpoint evidence, not an AI SBOM, CVE scan, compliance certification, or
proof that installed software executed. Missing, malformed, stale and future-dated
observations cannot satisfy posture requirements. A healthy Falcon sensor does
**not** establish organizational policy compliance; `compliant` remains unknown.

## API, MCP and agent associations

- `POST /v1/endpoint-connectors`: encrypted connection creation; tenant comes from authentication.
- `GET /v1/endpoint-connectors`: connections and latest collection status.
- `PATCH /v1/endpoint-connectors/{id}`: rotate `client_secret` or set `enabled`.
- `POST /v1/endpoint-connectors/{id}/sync`: `{ "restart": false, "max_pages": 5 }`.
- `GET /v1/endpoint-connectors/{id}/devices?limit=100&offset=0`: bounded evidence page.
- `PUT /v1/endpoint-connectors/devices/{device_id}/agent-binding`: exact existing
  fleet `agent_id` and `active` flag, verified within the authenticated tenant.

The Connections evidence view links operator-recorded agent associations to the
existing agent detail, MCP/package composition and finding views. These links are
explicit assertions, never hostname matches or execution observations. Device IDs
include tenant, provider and account scope. Existing deployment wrappers and
already-fetched generic posture ingestion remain supported. The old Falcon JSON
normalizer now also leaves policy compliance unknown; policies that previously
relied on `status=normal` to authorize access must supply real compliance evidence.

```bash
agent-bom connect endpoints bind-agent DEVICE_ID FLEET_AGENT_ID
agent-bom connect endpoints bind-agent DEVICE_ID FLEET_AGENT_ID --retire
agent-bom connect endpoints update CONNECTION_ID --disabled
agent-bom connect endpoints update CONNECTION_ID --enabled --secret-env FALCON_CLIENT_SECRET
agent-bom mcp server --profile cloud
```

The `cloud`/`full` MCP profiles expose `endpoint_inventory`; an empty connection ID
lists available connections. `full` additionally exposes `endpoint_sync`, which
requires the authenticated admin operator and `connectors:write` scope. Neither MCP
tool accepts a vendor secret or caller-selected vendor URL. CLI, API, UI and MCP
all call the same service; there is no second vendor collection implementation.

Access-policy enrichment for canonical `endpoint-…` IDs reads current durable
connector evidence and re-evaluates age on every decision. Disabled connections,
missing devices in the current run and stale evidence fail closed. A device ID is
not hardware attestation: authenticate the device-to-principal binding separately.

## Persistence, bounded work and recovery

SQLite is single-node durable. Postgres shares connections, checkpoints and device
records across replicas with forced tenant RLS. Apply Alembic migrations before
starting upgraded Postgres services. Persist the database and encryption key with
your deployment's normal backup/restore path. Losing the key prevents decryption;
there is no plaintext fallback. Open a connection’s settings to disable a connection to stop future collection and
posture use while retaining inspectable evidence; rotate credentials in Connections.

A page's devices, receipt and next cursor commit together. Competing workers use
an expiring lease and owner check; a stale worker cannot commit after takeover.
Successful resume retains earlier failure receipts. Receipts have no application
update/delete grants in the Postgres migration. They are operational evidence,
not an independent tamper-proof audit archive against a database administrator.

Limits: at most 100 connections/tenant, 100 recorded agent associations/device,
100 hosts/page, 20 pages/request, 100,000 devices/run, an 8 MiB
response cap and a 100-second provider budget. Retries are bounded; long throttles
surface as collection gaps for a later attempt. Normal UI batches request 5 pages.
A partial collection never reports missing devices as clean or silently reuses a
previous run. Changing totals, duplicate IDs, omitted details and wrong account
IDs stop cursor advancement. Inspect the recent receipts, repair the grant or
credential, then resume or start fresh. Retention cleanup requires an operator's
export/retention procedure; automatic downgrade does not erase endpoint evidence.

Provider contract references:
[Jamf client credentials](https://developer.jamf.com/jamf-pro/docs/client-credentials),
[Jamf v4 inventory](https://developer.jamf.com/jamf-pro/reference/get_v4-computers-inventory),
[Falcon Hosts](https://developer.crowdstrike.com/api-reference/collections/hosts/),
[Falcon regions](https://developer.crowdstrike.com/sdks/python/configuration/).
