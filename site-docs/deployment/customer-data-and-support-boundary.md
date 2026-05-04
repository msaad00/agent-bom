# Customer Data and Support Boundary

> **You do not need to read this unless** procurement / security is
> reviewing the self-hosted trust boundary, or you are answering
> "can the agent-bom maintainers see our data?" For the related
> least-privilege contract see
> [Data Access Boundaries](data-access-boundaries.md).

This page defines the default self-hosted trust boundary for `agent-bom`.

The short version:

- customer findings, runtime events, audit, fleet, graph, and tenant data stay
  in customer-controlled infrastructure by default
- customer operators can review their own tenant-scoped logs, audit, and events
  through the UI and API when their role allows it
- `agent-bom` maintainers do **not** get silent access to customer content in
  self-hosted deployments
- outbound telemetry and support sharing are explicit operator choices, not
  hidden defaults

## What customer users can see

For an authenticated user inside the customer tenant, the normal control-plane
experience can include:

- audit trail and auth/debug history
- scan jobs and scan results
- findings, graph, remediation, and compliance state
- fleet inventory and MCP provenance
- proxy and gateway audit, alerts, and runtime health
- traces and pushed runtime results where those paths are enabled

That access is still role-scoped:

- `viewer` stays read-only
- `analyst` can run and review operational workflows
- `admin` can manage keys, policies, and other protected control-plane actions

The UI may hide or disable actions for clarity, but the API remains the source
of truth for what each role is allowed to read or mutate.

## What stays customer-owned by default

In the self-hosted model, these data classes stay in the customer's own control
plane and storage tier unless the operator explicitly exports them elsewhere:

- findings and remediation state
- runtime events and runtime audit
- fleet inventory and endpoint posture
- graph nodes, edges, and correlated evidence
- tenant-scoped auth and audit history
- generated reports and compliance exports

## Credential and PII evidence boundaries

`agent-bom` distinguishes between finding a risk and collecting the sensitive
value that caused it.

For MCP and agent configuration inventory, the scanner records credential-like
environment variable names such as `OPENAI_API_KEY` or `DATABASE_URL`. It does
not read the environment variable value.

For an explicit project secret scan, the scanner reads files inside the chosen
scope so it can classify likely hardcoded credentials or PII. Findings do not
store the matched value or a prefix of the matched value. They keep only the
relative file path, line number, finding type, severity, and a redacted evidence
label such as `[CREDENTIAL_REDACTED]`.

`agent-bom` does not use discovered credentials to call providers, validate
whether a token is live, or enrich findings. Any live-secret validation should
be a separate operator-approved workflow with its own network, audit, and
retention boundary.

That is true whether the customer keeps the data in:

- Postgres
- ClickHouse
- S3
- Snowflake
- OTEL / SIEM destinations they control

## What `agent-bom` maintainers do not see by default

In self-hosted deployments, `agent-bom` maintainers should not see customer
tenant content by default.

That includes:

- findings payloads
- prompts or tool arguments
- audit contents
- fleet inventories
- tenant business data
- credential-backed configuration details

Self-hosted means the customer operates the control plane and owns the data
plane. There is no silent vendor backhaul.

## Minimal product-health telemetry

If a customer later wants to share narrow product-health telemetry, the safest
default is a minimal, opt-in set such as:

- auth success or failure counts
- error classes and crash reports
- request IDs and trace IDs
- anonymized session IDs
- product version and deployment mode
- component health and route-level latency classes

This is product-health telemetry, not customer content telemetry.

## Self-hosted boundary vs provider operations

This page describes the self-hosted default:

- customer operators use the product inside their own infra
- customer tenants see their own data by role
- `agent-bom` maintainers do not silently inherit access

That is intentionally different from a future provider-style or MSSP operating
model where one operator plane serves many customer organizations. If that
product track expands later, it should still preserve explicit access,
auditable support flows, and least-privilege defaults instead of weakening the
self-hosted trust boundary described here.

## Optional exports and interoperability

`agent-bom` is designed so the customer can send their own data to the systems
they already trust.

Common export paths include:

- OTEL collectors
- Splunk
- Elastic
- Datadog
- Snowflake
- ClickHouse
- customer-managed archive and evidence stores

Those exports are customer-controlled integrations. They are not hidden vendor
telemetry.

## Support access and support bundles

The safe support model is:

- support access is explicit
- support sharing is revocable
- support access is auditable
- support data is customer-selected

Today the product already supports a redaction-friendly support bundle flow in
the UI help surface. That gives operators a copyable bundle for debugging and
bug reports without sending hidden telemetry automatically.

Operators can also inspect the code-generated trust contract through
`agent-bom trust --format json` and `GET /v1/auth/policy`. Both surfaces expose
the same credential, network, storage, auth, SCIM tenant, and export
boundaries. The same contract covers connector, plugin, skill, and role
boundaries: agentless read-only connectors by default, operator-scoped
plugin/skill execution, and least-privilege RBAC for every control-plane action.

If a customer needs deeper support later, the recommended model is:

- customer-generated support bundle
- explicit export to the destination they choose
- time-bounded break-glass access only when the operator approves it

## One-sentence policy

`Customers own their findings, audit, runtime events, fleet data, and exports; agent-bom owners should only see minimal product-health telemetry when the customer explicitly opts in or shares support data.`
