# Posture Event Streaming

This document is the repo-facing contract for issue #2597.

Current shipped posture delivery includes pull workflows and the first
push-delivery primitive:

- scan report files: SARIF, SBOM, HTML, JSON, graph exports
- REST API routes for findings, normalized bulk finding ingest, graph, audit,
  posture, and runtime state
- MCP tools for agent pull workflows, including `exposure_paths` and
  `should_i_deploy`
- selected SIEM/export guidance and OCSF projections
- `agent_bom.posture_streaming.WebhookOutbox`, a tenant-scoped SQLite outbox
  for signed webhook delivery with idempotency, retry metadata,
  private-network destination opt-in, and dead-letter state
- graph delta webhook routing through the same outbox when
  `AGENT_BOM_GRAPH_DELTA_WEBHOOK` and
  `AGENT_BOM_GRAPH_DELTA_WEBHOOK_SIGNING_SECRET` are configured
- REST outbox observability at `GET /v1/posture/webhooks/outbox`,
  `GET /v1/posture/webhooks/outbox/stats`, and
  `POST /v1/posture/webhooks/outbox/{row_id}/retry`
- opt-in cloud posture event consumers:
  AWS CloudTrail/EventBridge→SQS, Azure Activity Log/Event Grid→Storage Queue,
  and GCP Cloud Asset/Audit Log→Pub/Sub. These are bounded re-evaluation lanes
  for connected cloud accounts, not a managed streaming service.

The shipped webhook outbox core does not create hidden egress. Operators must
provide an explicit `WebhookDestination` and delivery function. Managed
connector packages for Kafka, EventBridge, Pub/Sub, Event Hub, Kinesis, and
Firehose remain roadmap work until adapter code and tests land.

## Event Envelope

Posture push connectors should emit:

| Field | Purpose |
|---|---|
| `event_id` | idempotent delivery key |
| `tenant_id` | tenant owner |
| `event_type` | finding, exposure path, skill verdict, deploy decision, runtime policy decision, or audit integrity event |
| `created_at` | source or enqueue timestamp |
| `source` | scan/API/MCP/proxy/gateway/importer |
| `severity` | normalized severity where applicable |
| `risk_score` | path or finding risk score where applicable |
| `entity_refs` | related graph/source/package/agent/cloud/IAM IDs |
| `exposure_path_id` | linked path ID when present |
| `payload` | canonical agent-bom object |
| `ocsf` | OCSF projection when available in higher-level adapters |
| `audit_ref` | audit-chain pointer or verification metadata when available |
| `schema_version` | connector schema version |

Current reserved event types include `graph.delta`, `runtime.alert`,
`runtime.policy_decision`, `intel.published`, `intel.matched_inventory`, and
`intel.exploitation_changed`. The intel event names are reserved for future
adapters; they are not a shipped intel API or feed registry.

## Graph Delta Webhooks

Graph delta alerts no longer use immediate generic webhook POST dispatch from
environment-only configuration. When a graph delta webhook is configured, the
runtime queues one signed `graph.delta` posture event per alert into the
webhook outbox. Delivery workers then use the existing signed headers,
idempotency key, retry, and dead-letter behavior. If a webhook URL is set
without a signing secret, no webhook event is queued and the dispatch metadata
includes a configuration error. OCSF export metadata is still returned.

Slack delta notifications remain an explicit best-effort notification channel;
they are separate from the durable generic webhook path.

## Delivery Order

1. Generic webhook outbox core with signed HTTPS POST headers, retry metadata,
   dead-letter state, and idempotent `event_id` delivery. Shipped in
   `agent_bom.posture_streaming`.
2. Outbox observability API for tenant-scoped status, stats, dead-letter
   inspection, and explicit admin retry. Shipped in the REST API.
3. OCSF envelope shared by all connector adapters.
4. Kafka connector for enterprise posture-event sinks covering findings,
   `ExposurePath` changes, skill verdicts, deploy decisions, and audit deltas.
5. AWS CloudTrail/EventBridge→SQS posture re-evaluation for connected accounts.
   Shipped as an opt-in bounded consumer.
6. Azure Activity Log/Event Grid→Storage Queue and GCP Cloud Asset/Audit
   Log→Pub/Sub posture re-evaluation for connected accounts. Shipped as opt-in
   bounded consumers.
7. General EventBridge/Pub/Sub/Event Hub connector packages for posture-event
   delivery. Roadmap: these are broader sink/source adapters, not the same as
   the provider-specific posture re-evaluation lanes above.
8. Kinesis/Firehose as a later AWS high-volume adapter for customers that
   already centralize telemetry there.
9. MCP posture subscription tool backed by the same replay contract.

Do not document Kafka, generic EventBridge/Pub/Sub/Event Hub connector
packages, Kinesis, Firehose, or MCP posture subscriptions as shipped until their
adapters and tests land. The current claim is: posture/event streaming has a
signed webhook outbox core; connected cloud posture has opt-in AWS/Azure/GCP
event consumers that re-evaluate affected resources; Kafka-style sinks and
general event connector packages remain roadmap.
