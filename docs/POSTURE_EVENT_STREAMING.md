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
- REST outbox observability at `GET /v1/posture/webhooks/outbox`,
  `GET /v1/posture/webhooks/outbox/stats`, and
  `POST /v1/posture/webhooks/outbox/{row_id}/retry`

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

## Delivery Order

1. Generic webhook outbox core with signed HTTPS POST headers, retry metadata,
   dead-letter state, and idempotent `event_id` delivery. Shipped in
   `agent_bom.posture_streaming`.
2. Outbox observability API for tenant-scoped status, stats, dead-letter
   inspection, and explicit admin retry. Shipped in the REST API.
3. OCSF envelope shared by all connector adapters.
4. Kafka connector for enterprise posture-event sinks covering findings,
   `ExposurePath` changes, skill verdicts, deploy decisions, and audit deltas.
5. AWS EventBridge plus S3/SQS CloudTrail ingestion for cloud activity
   evidence.
6. GCP Pub/Sub plus Azure Event Hub/Event Grid for multi-cloud parity.
7. Kinesis/Firehose as a later AWS high-volume adapter for customers that
   already centralize telemetry there.
8. MCP posture subscription tool backed by the same replay contract.

Do not document Kafka, EventBridge, Pub/Sub, Event Hub, Kinesis, Firehose, or
MCP posture subscriptions as shipped until their adapters and tests land. The
current claim is: posture/event streaming has a signed webhook outbox core;
Kafka-style sinks are next; AWS cloud-log ingestion should start with
CloudTrail S3/SQS and EventBridge. Kinesis is a later adapter, not a release
blocker.
