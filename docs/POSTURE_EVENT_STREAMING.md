# Posture Event Streaming

This document is the repo-facing contract for issue #2597.

Current shipped posture delivery is pull-first:

- scan report files: SARIF, SBOM, HTML, JSON, graph exports
- REST API routes for findings, normalized bulk finding ingest, graph, audit,
  posture, and runtime state
- MCP tools for agent pull workflows, including `exposure_paths` and
  `should_i_deploy`
- selected SIEM/export guidance and OCSF projections

Push connectors are roadmap work until a PR adds the outbox, delivery, and
retry implementation.

## Event Envelope

Posture push connectors should emit:

| Field | Purpose |
|---|---|
| `event_id` | idempotent delivery key |
| `tenant_id` | tenant owner |
| `event_type` | finding, exposure path, skill verdict, deploy decision, runtime policy decision, or audit integrity event |
| `occurred_at` | source timestamp |
| `observed_at` | connector timestamp |
| `source` | scan/API/MCP/proxy/gateway/importer |
| `severity` | normalized severity where applicable |
| `risk_score` | path or finding risk score where applicable |
| `entity_refs` | related graph/source/package/agent/cloud/IAM IDs |
| `exposure_path_id` | linked path ID when present |
| `payload` | canonical agent-bom object |
| `ocsf` | OCSF projection when available |
| `audit_ref` | audit-chain pointer or verification metadata |
| `schema_version` | connector schema version |

## Delivery Order

1. Generic webhook outbox with signed HTTPS POST, retry, dead-letter handling,
   and idempotent `event_id` delivery.
2. OCSF envelope shared by all connector adapters.
3. Kafka connector for enterprise posture-event sinks covering findings,
   `ExposurePath` changes, skill verdicts, deploy decisions, and audit deltas.
4. AWS EventBridge plus S3/SQS CloudTrail ingestion for cloud activity
   evidence.
5. GCP Pub/Sub plus Azure Event Hub/Event Grid for multi-cloud parity.
6. Kinesis/Firehose as a later AWS high-volume adapter for customers that
   already centralize telemetry there.
7. MCP posture subscription tool backed by the same replay contract.

Do not document webhook outbox, Kafka, EventBridge, Pub/Sub, Event Hub,
Kinesis, Firehose, or MCP posture subscriptions as shipped until their adapters
and tests land. The current claim is: posture/event streaming is planned via
webhook outbox and Kafka-style sinks; AWS cloud-log ingestion should start with
CloudTrail S3/SQS and EventBridge. Kinesis is a later adapter, not a release
blocker.
