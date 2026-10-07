# v1 Contracts

These schemas describe the stable agent-bom payload families used across CLI,
API, dashboard, graph, fleet, audit, and compliance evidence surfaces.

Compatibility policy:

- Additive optional fields are allowed in v1.
- Required fields, enum meanings, IDs, timestamps, tenant IDs, and scan IDs are
  compatibility anchors.
- Removing a required field, changing field meaning, or changing ID semantics
  requires a v2 schema.
- Consumers should ignore unknown fields and preserve known IDs when storing or
  transforming payloads.

Published schemas:

- `agent-mode-envelope.schema.json` - machine-readable CLI envelope returned
  by `--agent-mode` for assistant and automation callers.
- `scan-report.schema.json` - top-level AI-BOM JSON scan output.
- `graph-export.schema.json` - graph nodes, edges, and materialized attack
  paths. HTTP dependency exports include authenticated tenant and job scope,
  canonical `entity_type`/`relationship` fields, and retained `kind` aliases.
  Relationship evidence retains its existing object form; the schema also
  accepts legacy receipt arrays. Scan reports validate the `result` inside the
  HTTP job envelope, not the envelope itself.
- `fleet-snapshot.schema.json` - tenant/fleet agent posture rows from `GET /v1/fleet/agents`.
  `agent_name` retains the existing `name` field as an additive alias. `last_seen`
  is the latest recorded scan or discovery timestamp, and is null when neither
  is available; edits to a registry row do not imply a new observation.
- `finding-feedback.schema.json` - tenant finding feedback and suppression
  lifecycle records.
- `audit-export.schema.json` - signed audit export envelope returned by
  `GET /v1/audit/export`, including `filters`, `integrity`, and audit-entry
  `hmac_signature` / `prev_signature` chain fields.
- `evidence.schema.json` - procurement/compliance evidence record.
