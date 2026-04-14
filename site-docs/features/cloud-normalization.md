# Cloud Normalization

Agent BOM keeps cloud ingestion accurate by separating three layers:

1. Raw provider payloads from AWS, Azure, GCP, Databricks, and other sources
2. A canonical `agent-bom` normalization layer
3. Optional downstream projections such as OCSF

The product does not force every cloud response into OCSF first. It preserves
source-specific semantics, normalizes them into stable envelopes for the rest
of the product, and projects to OCSF only where that mapping is accurate.

## Canonical envelopes

The current canonical cloud envelopes are additive metadata attached to
discovered assets and emitted through JSON output. They give the CLI, API, UI,
graphs, and future exports a stable internal contract without discarding
provider-specific evidence.

### `cloud_origin`

Identity and provenance for the cloud asset:

- `provider`
- `service`
- `resource_type`
- `resource_id`
- `resource_name`
- `location`
- scoped identifiers such as `account_id`, `subscription_id`, or `project_id`
- constrained `raw_identity` fields for debugging and mapping verification

### `cloud_state`

Normalized lifecycle state for the asset:

- `lifecycle_state`
- `raw_state`
- `state_source`

This lets the product distinguish canonical status from provider-specific state
strings without losing the original value.

### `cloud_timestamps`

Normalized timestamps for asset lifecycle history:

- `created_at`
- `updated_at`
- `sources`

Timestamps are normalized to UTC ISO-8601 so downstream graph, timeline, and
history features do not need to guess provider formats.

### `cloud_principal`

Execution identity or attached principal where the provider exposes one:

- `principal_type`
- `principal_id`
- `principal_name`
- `tenant_id`
- `source_field`
- constrained `raw_identity`

This helps preserve the relationship between a resource and the principal it
runs as, without forcing every provider into a single vendor-specific schema.

## Why this layer exists

Cloud providers do not agree on:

- field names
- nested response shapes
- lifecycle enums
- timestamp formats
- identity semantics

The normalization layer prevents those differences from leaking into every
product surface.

## Relationship to OCSF

OCSF is optional and sits downstream of the canonical model:

- raw cloud payload in
- source-specific adapter
- canonical `agent-bom` envelope
- optional OCSF projection

If OCSF does not fit a provider-specific concept cleanly, Agent BOM keeps the
canonical field or extension instead of forcing a bad mapping.

## Persistence and history

Canonical cloud metadata supports current-state and historical views:

- `first_seen` and `last_seen` stay in the product model
- lifecycle changes remain queryable over time
- deactivated or disappeared entities can remain visible in history even when
  they no longer appear in the latest inventory

The design goal is persistent truth plus derived views, not transient
recomputation of every cloud shape on every page load.
