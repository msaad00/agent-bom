# Posture Event Streaming

`agent-bom` already produces security evidence through reports, API routes,
MCP tools, audit records, and selected SIEM/export paths. It also ships the
first push-delivery primitive: a signed webhook outbox core for posture events.
This page separates shipped primitives from connector roadmap work so release
claims stay precise.

## Current State

Shipped today:

- SARIF, SBOM, HTML, JSON, and graph exports from scans
- OCSF projection helpers for findings where the canonical event maps cleanly
- `/v1/proxy/audit` and audit-chain verification for runtime events
- SIEM integration guidance for supported export paths
- `exposure_paths` and `should_i_deploy` MCP tools for agent pull workflows
- `agent_bom.posture_streaming.WebhookOutbox` for tenant-scoped, idempotent,
  signed webhook deliveries with retry and dead-letter metadata

Not shipped today:

- managed posture-event streaming service
- Kafka, EventBridge, Pub/Sub, Event Hub, Kinesis, or Firehose connector package
- long-lived `subscribe_posture_changes` MCP tool
- guaranteed production streaming SLO

## Connector Contract

Every posture event connector should preserve the same envelope so downstream
systems do not need per-connector parsers.

| Field | Meaning |
|---|---|
| `event_id` | stable UUID for idempotency |
| `tenant_id` | tenant that owns the event |
| `event_type` | `finding.created`, `finding.updated`, `exposure_path.created`, `skill.verdict`, `deploy.decision`, `runtime.policy_decision`, or `audit.integrity` |
| `created_at` | source event or enqueue timestamp |
| `source` | scan, API route, MCP tool, proxy, gateway, or importer that produced the event |
| `severity` | normalized severity where applicable |
| `risk_score` | numeric risk score where applicable |
| `entity_refs` | related package, source, agent, cloud, IAM, MCP, skill, or graph IDs |
| `exposure_path_id` | linked `ExposurePath` ID when the event is path-backed |
| `payload` | canonical `agent-bom` object |
| `ocsf` | OCSF projection when the event maps cleanly |
| `audit_ref` | audit-chain pointer or verification metadata where available |
| `schema_version` | connector event schema version |

The canonical `agent-bom` payload remains authoritative. OCSF is a projection
for SIEM/security-lake interoperability, not a replacement for the graph model.

## Delivery Modes

| Mode | Status | First proof | Notes |
|---|---|---|---|
| Pull by API | shipped | `GET /v1/findings`, `POST /v1/findings/bulk`, `/v1/graph*`, `/v1/audit*` | works for dashboards, SIEM jobs, agent runtimes, and custom collectors |
| Pull by MCP | shipped | `exposure_paths`, `should_i_deploy` | best for AI agents and coding assistants |
| Webhook outbox core | shipped | `agent_bom.posture_streaming.WebhookOutbox` | operator-provided sender performs explicit HTTPS POST; no hidden egress |
| Webhook outbox observability | shipped | `GET /v1/posture/webhooks/outbox` | tenant-scoped status, stats, dead-letter inspection, admin retry |
| Kafka | roadmap | topic-per-tenant or topic with tenant key | first enterprise stream sink for posture events |
| AWS EventBridge + CloudTrail S3/SQS | roadmap | customer account event bus or S3/SQS trail feed | first AWS cloud activity evidence lane |
| GCP Pub/Sub + Azure Event Hub/Event Grid | roadmap | customer-owned cloud event transports | multi-cloud parity after AWS |
| Kinesis/Firehose | roadmap | customer stream or delivery stream | later AWS high-volume adapter, not a release blocker |
| Long-lived MCP subscription | roadmap | `subscribe_posture_changes` | agent-native stream; needs backpressure and replay contract |

## Reliability Rules

Push connectors should be fail-closed for configuration and fail-safe for
delivery:

- reject missing tenant IDs, unsigned destinations, and private-network
  destinations unless explicitly allowed by operator policy
- persist an outbox record before first delivery attempt
- use `event_id` for idempotent retries
- record delivery status, attempt count, and final failure reason
- expose dead-letter records through API and audit logs
- never include raw secret values in payloads
- preserve `audit_ref` so the downstream event can be tied back to the
  customer-owned evidence chain

## Security Boundary

Operators own destination credentials, webhook signing keys, Kafka credentials,
EventBridge role grants, retention, and downstream access control.

`agent-bom` should only store references to those credentials through the
credential-reference model, not raw destination secrets.

## Implementation Slices

1. **Webhook outbox core** — tenant-scoped table, signed delivery headers,
   retry policy metadata, dead-letter state, private-network destination
   opt-in, and tests. Shipped in `agent_bom.posture_streaming`.
2. **Webhook outbox observability API** — tenant-scoped status and stats,
   dead-letter inspection, and explicit admin retry.
3. **OCSF event envelope** — shared serializer for findings, exposure paths,
   deploy decisions, skill verdicts, runtime policy decisions, and audit
   integrity events.
4. **Kafka connector** — enterprise stream sink for findings, exposure paths,
   skill verdicts, deploy decisions, and audit deltas.
5. **Cloud activity ingestion** — AWS EventBridge plus CloudTrail S3/SQS first,
   then GCP Pub/Sub and Azure Event Hub/Event Grid.
6. **High-volume AWS adapter** — Kinesis/Firehose for customers that already
   centralize telemetry there.
7. **Agent subscription** — MCP `subscribe_posture_changes` backed by the same
   outbox/replay contract.

Each slice should ship with a first command, an artifact, and a verification
path before release docs describe it as available.
