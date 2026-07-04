# SIEM Integration

> **You do not need to read this unless** you are wiring `agent-bom`
> events into a SIEM or security lake (Splunk, Elastic, Snowflake,
> generic OCSF). The product runs end-to-end without OCSF; this page is
> the boundary contract.

Agent BOM can push events downstream in two formats:

- `raw`: the canonical `agent-bom` event shape
- `ocsf`: a standardized OCSF projection for SIEM or security-lake workflows

The product is not a SIEM and does not require OCSF to function. OCSF is an
interoperability layer at the boundary.

## Inbound OCSF ingest

If your SIEM or security lake already emits OCSF events, Agent BOM can ingest
them through the control plane without changing its internal data model.

- endpoint: `POST /v1/ocsf/ingest`
- auth + tenant scope: same as other analyst-scoped observability ingest routes
- accepted payloads:
  - a single OCSF event object
  - a JSON array of OCSF event objects
  - `{ "events": [...] }`
- current normalization target: canonical runtime-event analytics plus one
  signed audit record per ingest batch

The design rule stays the same:

- OCSF comes in at the interoperability boundary
- Agent BOM normalizes it onto canonical internal event fields
- audit, dashboards, and tenant scoping remain canonical-model first

Example:

```bash
curl -X POST https://agent-bom.example.com/v1/ocsf/ingest \
  -H "Authorization: Bearer $AGENT_BOM_API_KEY" \
  -H "Content-Type: application/json" \
  -d '{
    "events": [
      {
        "class_uid": 2004,
        "class_name": "Detection Finding",
        "severity_id": 4,
        "message": "Prompt injection detected",
        "time": 1746033600000,
        "finding_info": {
          "uid": "finding-1",
          "types": ["prompt_injection"]
        },
        "resources": [{"name": "github-mcp"}],
        "metadata": {"product": {"name": "splunk"}}
      }
    ]
  }'
```

This path is intentionally narrow:

- it does not replace the native scan or proxy ingest paths
- it does not make OCSF the internal source of truth
- it gives existing OCSF-based security programs a clean way to feed Agent BOM
  without losing tenant scoping or auditability

## Choosing `raw` vs `ocsf`

Use `raw` when:

- you want full Agent BOM fidelity
- your destination can ingest custom JSON cleanly
- you need vendor-specific or AI-specific fields that do not fit OCSF well

Use `ocsf` when:

- your downstream platform expects standardized event semantics
- you want easier alignment to existing SIEM pipelines
- the destination benefits from OCSF `category_uid`, `class_uid`, and
  standardized detection finding structure

## Example: Splunk with raw events

Use the canonical event shape when you want to keep Agent BOM-native fields in
the pipeline.

```bash
agent-bom agents \
  --siem splunk \
  --siem-url https://splunk.example.com:8088/services/collector \
  --siem-token "$SPLUNK_HEC_TOKEN" \
  --siem-index agent-bom \
  --siem-format raw
```

This preserves Agent BOM-native details such as blast-radius context, canonical
resource envelopes, and product-specific metadata without wrapping them into an
OCSF Detection Finding.

## Example: Syslog / enterprise SIEM with OCSF

Use OCSF when the downstream system expects normalized security events.

```bash
agent-bom agents \
  --siem datadog \
  --siem-url tls://siem.example.com:6514 \
  --siem-token "$SIEM_TOKEN" \
  --siem-format ocsf
```

This projects the canonical finding/event into an OCSF-compatible envelope
before delivery.

## Example: Elasticsearch or OpenSearch

Either mode can work:

- choose `raw` for maximum product fidelity
- choose `ocsf` if you want a more standardized event schema

```bash
agent-bom fs . \
  --siem elasticsearch \
  --siem-url https://search.example.com \
  --siem-token "$ES_API_KEY" \
  --siem-index agent-bom-findings \
  --siem-format raw
```

## Design rules

Agent BOM follows these rules for SIEM delivery:

1. Canonical `agent-bom` data model stays primary
2. OCSF is optional and derived
3. Raw vendor/source semantics are not discarded just to fit a standard
4. If a field does not map cleanly to OCSF, Agent BOM keeps it as native data
   or an extension field

This avoids lock-in in both directions:

- customers are not forced into OCSF to use the product
- customers who want OCSF still get a clean interoperability path

## Finding delta-stream export (control plane)

When the compliance hub ingests findings (`POST /v1/findings/bulk` or
compliance format ingest), operators can push **only what changed** to a SIEM
or data-lake sink instead of re-listing the full hub on every poll.

Enable on the control plane:

```bash
export AGENT_BOM_DELTA_STREAM_ENABLED=1
export AGENT_BOM_DELTA_STREAM_URL=https://siem.example.com/hooks/agent-bom-deltas
export AGENT_BOM_DELTA_STREAM_FORMAT=ndjson   # or ocsf
export AGENT_BOM_DELTA_STREAM_AUTH_SCHEME=Bearer
export AGENT_BOM_DELTA_STREAM_AUTH_TOKEN="$SIEM_TOKEN"
```

Each ingest batch emits a delta payload with:

- `new` — canonical id first seen in current state for the ingest source
- `changed` — severity, CVSS, reach score, or status materially changed
- `resolved` — open finding absent from a reconcile-absent batch

Watermarks are stored per `(tenant_id, destination_id)` so retries and
multi-replica control planes do not double-send the same batch. Delivery rides
the hardened `agent_bom.delivery` client (retries, DLQ, circuit breaker,
idempotency keys).

First command → artifact → next step:

1. Enable the env vars above and restart the control plane.
2. POST a bulk ingest with `reconcile_absent: true` when you want resolved events.
3. Inspect delivery logs / your sink for `finding_delta_batch` payloads tagged
   with `batch_id` and `observed_at`.
4. See `docs/operations/ENV_VARS.md` for the full variable reference.
