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

- `scan-report.schema.json` - top-level AI-BOM JSON scan output.
- `graph-export.schema.json` - graph nodes, edges, and materialized attack
  paths.
- `fleet-snapshot.schema.json` - tenant/fleet agent posture rows.
- `finding-feedback.schema.json` - tenant finding feedback and suppression
  lifecycle records.
- `audit-export.schema.json` - signed audit export envelope.
- `evidence.schema.json` - procurement/compliance evidence record.
