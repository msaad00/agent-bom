# Design: Connections and Sources pane

**Status:** lock-in taxonomy for the dashboard Connections hub and related
ingest/export surfaces. Describes what already ships and how rows should be
grouped — not a roadmap or GTM plan.

**Canonical UI merge:** [`ui/lib/connections-sources.ts`](../../ui/lib/connections-sources.ts)
unifies `/v1/cloud/connections` and `/v1/sources` into one table (cloud row
wins on name collision). Operator onboarding for cloud grants lives in
[`docs/CLOUD_CONNECT.md`](../CLOUD_CONNECT.md) (§1c + Practical enable path).

## Connector taxonomy

Use these product nouns when extending the pane, API kinds, or docs. They are
capability classes, not vendor product names.

| Class | Meaning | Primary surface today |
|-------|---------|------------------------|
| `cloud_account` | One brokered cloud target (AWS account, Azure subscription, GCP project, Snowflake account). Default `inventory_scope=account`. | Connections wizard + `POST /v1/cloud/connections` |
| `org_fanout` | Same connection row with `inventory_scope=organization` — `/scan` fans members via the management credential. StackSet (or equivalent) still deploys member roles. Distinct from Helm Job/CLI `scanner.cloud.*.orgInventory` / `allSubscriptions` / `allProjects`. | Connections row field; see CLOUD_CONNECT §1c |
| `runtime_mcp` | MCP proxy / gateway runtimes and MCP config scans as first-class sources. | `/v1/sources` kinds `runtime.proxy`, `runtime.gateway`, `scan.mcp_config`; Runtime UI |
| `endpoint_fleet` | Endpoint / agent inventory pushed into the tenant fleet registry. | `POST /v1/fleet/sync` — [`docs/SESSION_FLOWS.md`](../SESSION_FLOWS.md) (Fleet sync) |
| `evidence_ingest` | Push of scan results, artifacts, traces, or fleet sync into the control plane without a live cloud assume. | `/v1/sources` ingest kinds (`ingest.fleet_sync`, `ingest.trace_push`, `ingest.result_push`, `ingest.artifact_import`); OCSF ingest at the wire boundary |
| `findings_export` | Outbound findings / events to customer-owned sinks (SIEM, lake, OTLP). Not a “connection” row — an integration / export path. | SIEM connectors + OCSF projection; report / delta export |

Display categories in the hub (`cloud` / `code` / `ai` / `data` / `runtime` /
`ingest`) are the UI filter chips mapped from `SourceKind` in
`connections-sources.ts`. Prefer extending that map over inventing a parallel
taxonomy in React.

## Related existing paths (point, do not duplicate)

| Concern | Where |
|---------|--------|
| Cloud grant + org gate + scheduler / continuous | [`docs/CLOUD_CONNECT.md`](../CLOUD_CONNECT.md) |
| SIEM push / OCSF wire formats | [`site-docs/deployment/siem-integration.md`](../../site-docs/deployment/siem-integration.md), [`docs/OCSF_BOUNDARY.md`](../OCSF_BOUNDARY.md) |
| OTEL as operator telemetry + trace ingest | [`docs/PRODUCT_BRIEF.md`](../PRODUCT_BRIEF.md) (Observability and OTEL); site-docs deployment overview |
| Fleet sync contract | [`docs/SESSION_FLOWS.md`](../SESSION_FLOWS.md) |
| Posture change event collector (queue → CP) | [`docs/design/EVENT_COLLECTOR_CONTRACT.md`](EVENT_COLLECTOR_CONTRACT.md) |
| Unified table rules | [`ui/lib/connections-sources.ts`](../../ui/lib/connections-sources.ts) |

## Non-goals

- Replacing SIEM, warehouse, or observability products — we export / ingest at
  the boundary; we do not host customer SIEM storage.
- Treating Helm CronJob `orgInventory` as the Connections org control — Job/CLI
  flags stay separate from `inventory_scope` on the row.
- Collapsing runtime MCP, fleet endpoints, and cloud accounts into one backend
  table — the hub is a **display** merge; persistence stays split.
- Private strategy, parity scorecards, or named third-party product comparisons
  in this tree.
- Claiming continuous CSPM without scheduler opt-in + (for mid-interval drain)
  a configured provider event queue.

## Operator read of the pane

1. Cloud rows come from Connections (richer status, scan cadence, org scope).
2. Non-cloud sources come from `/v1/sources` with kind labels from
   `sourceKindLabel`.
3. Dedup: a `scan.cloud` / `connector.cloud_read_only` source with the same
   display name as a cloud connection is dropped so the account appears once.
4. Schedules attach by source id count — cloud recurrence is still the
   Connections scheduler + `scan_interval_minutes` intersection documented in
   CLOUD_CONNECT.
