# Canonical Model vs OCSF

`agent-bom` is **canonical-model first**, not OCSF-first.

That means the product works in two modes without changing its core behavior:

- native `agent-bom` mode for scans, UI, graphs, remediation, compliance, and history
- optional OCSF projection for interoperability, SIEM delivery, and security-lake workflows

## The contract

Every ingestion path should follow the same sequence:

1. capture the raw source payload
2. parse it with a source-specific adapter
3. normalize it into the `agent-bom` canonical model
4. project it into OCSF only where the mapping is accurate
5. preserve vendor or AI-specific extension fields where OCSF does not fit

This avoids two common failures:

- forcing different vendors into a misleading shared schema too early
- locking the product to OCSF gaps or version churn

## What users actually choose

Users should not need to choose OCSF to use the product.

The default path is native `agent-bom`:

- CLI scans run against source-native data
- the API serves canonical product objects
- the dashboard and graphs use canonical product objects
- remediation, compliance, and timelines use canonical product objects

Users choose OCSF only at the interoperability boundary:

- SIEM/syslog delivery
- downstream security-lake export
- integrations that explicitly want OCSF classes, categories, and event shapes

## Source-native in, canonical inside, OCSF out

Different providers and tools do not share the same payload shape.

Each source has its own:

- field names
- nested JSON structure
- lifecycle and status enums
- identifier model
- timestamp format and timezone behavior
- actor and target semantics
- pagination and partial-response patterns

Because of that, `agent-bom` should not flatten directly into OCSF on ingestion.

Instead:

- raw payload is the source of evidence
- canonical `agent-bom` fields are the source of product truth
- OCSF is a projection for interoperability

## What the canonical model owns

The canonical model should stay authoritative for:

- stable internal IDs
- `first_seen` / `last_seen`
- lifecycle state
- remediation ranking
- blast-radius relationships
- compliance mapping
- graph relationships
- timeline and snapshot history
- source-specific metadata envelopes such as:
  - `cloud_origin`
  - `cloud_state`
  - `cloud_timestamps`
  - `cloud_principal`

These fields should remain useful even if a customer never exports OCSF.

## What OCSF owns

OCSF should be treated as a derived interoperability layer.

Use it for:

- SIEM event delivery
- security-lake interoperability
- standardized category/class/type labeling where it clearly applies

Do not make it the only internal representation of:

- AI-specific entities
- MCP runtime semantics
- vendor-specific lifecycle/state semantics
- cloud identity/resource relationships that need provider-native fidelity

## Graphs and storage

The graph and graph stores already carry OCSF-aligned classification fields such as:

- `category_uid`
- `class_uid`
- `type_uid`
- `severity_id`

Those should be treated as **derived classification metadata**, not the sole source of truth.

The primary graph truth remains:

- canonical node identity
- canonical relationships
- canonical timestamps and lifecycle
- canonical attributes and source metadata

## Persistence vs on-demand derivation

The product should **persist truth** and **derive views**.

Persist:

- canonical entities and findings
- stable IDs
- `first_seen` / `last_seen`
- lifecycle status
- snapshots and history
- audit trails

Derive on demand:

- filtered graph slices
- scorecards
- export formats
- OCSF projections
- report-specific formatting

This keeps the product scalable without losing historical accuracy.

## Historical entities and deactivation

If a user, service account, workload, or cloud asset disappears from the latest inventory:

- it should not disappear from history
- it should retain its stable ID
- it should keep `first_seen` and `last_seen`
- its lifecycle or status should explain whether it is active, inactive, deleted, or unknown

That is required for:

- timelines
- drift analysis
- graph replay
- auditability

## Human-in-the-loop and action safety

The data model and the action model are different concerns.

The product can normalize and correlate automatically, while still requiring approval for actions such as:

- creating or updating tickets
- mutating cloud or runtime policy
- writing to files
- invoking shells or subprocesses
- calling external connectors with side effects

Best practice:

- read-only by default
- explicit capability grants
- approval gates for destructive operations
- auditable policy and skills versions
- preserved source evidence for every normalized object

## Practical rule for new integrations

When adding a new vendor, cloud, or tool integration:

1. verify the real raw payload first
2. preserve source identity fields needed for audit and debugging
3. normalize into canonical `agent-bom` fields
4. add fixture tests for raw payloads and enums
5. add OCSF mapping only where the mapping is defensible

If a field does not fit OCSF cleanly:

- keep it as canonical metadata or an explicit extension
- do not discard it
- do not force a misleading OCSF field

## Summary

The design rule is simple:

- **raw source payload** for evidence
- **canonical `agent-bom` model** for product behavior
- **optional OCSF projection** for interoperability

That keeps the product:

- accurate
- interoperable
- scalable
- auditable
- not locked to one schema
