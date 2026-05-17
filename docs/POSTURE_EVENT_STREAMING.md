# Posture Event Streaming

This document is the repo-facing contract for issue #2597.

Current shipped posture delivery is pull-first:

- scan report files: SARIF, SBOM, HTML, JSON, graph exports
- REST API routes for findings, graph, audit, posture, and runtime state
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

1. Webhook outbox with signed HTTPS POST.
2. OCSF envelope shared by all connector adapters.
3. Kafka/Pulsar/EventBridge adapters as optional extras.
4. MCP posture subscription tool backed by the same replay contract.

Do not document Kafka, Pulsar, EventBridge, or MCP posture subscriptions as
shipped until their adapters and tests land.
