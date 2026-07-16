# Observability Metrics Catalog

Prometheus scrape endpoint: `GET /metrics` on the control-plane API
(unauthenticated by design — same as `/healthz`). The endpoint renders
Prometheus text format v0.0.4.

Scrape config example (Prometheus):

```yaml
scrape_configs:
  - job_name: agent-bom-api
    scrape_interval: 30s
    static_configs:
      - targets: ["agent-bom-api.agent-bom.svc.cluster.local:8080"]
```

All counter series are process-local; they reset on pod restart. Pair them
with a `increase()` or `rate()` query over a 5–15 min window rather than
reading raw counts. Gauges reflect the live state at scrape time.

The Helm chart ships a `PrometheusRule` and a Grafana dashboard
`ConfigMap` under `deploy/helm/agent-bom/templates/`; the dashboard is
pre-wired to the series below.

---

## Fleet

| Metric | Type | Description | Watch for |
|---|---|---|---|
| `agent_bom_fleet_total` | gauge | Total agents registered in the fleet store | Sudden drop = fleet sync pipeline broken |
| `agent_bom_fleet_quarantined` | gauge | Agents in `quarantined` lifecycle state | > 5% of fleet = investigate policy drift |

## Authentication

| Metric | Type | Labels | Description |
|---|---|---|---|
| `agent_bom_auth_failures_total` | counter | `reason` ∈ {missing_key, invalid_key, expired_token, forbidden_origin, ...} | Rejected authentication attempts by reason |
| `agent_bom_oidc_decode_failures_total` | counter | — | OIDC JWT decode or verification failures |

**SLO sketch:** `rate(agent_bom_auth_failures_total{reason="invalid_key"}[5m]) > 5`
is a credential-spray signal. Page on sustained > 10/min.

## Rate limiting

| Metric | Type | Labels | Description |
|---|---|---|---|
| `agent_bom_rate_limit_hits_total` | counter | `bucket` ∈ {global, tenant, gateway_source_agent, ingress, fleet_sync} | Requests rejected by a rate limiter |

**SLO sketch:** `rate(agent_bom_rate_limit_hits_total{bucket="tenant"}[5m]) > 1`
for a single tenant for > 10 min means the tenant is mis-configured or
hostile — alert the operator.

## Compliance evidence

| Metric | Type | Labels | Description |
|---|---|---|---|
| `agent_bom_compliance_exports_total` | counter | `algorithm` ∈ {Ed25519, HMAC-SHA256} | Compliance evidence bundles exported by signing algorithm |
| `agent_bom_compliance_export_bytes_total` | counter | `framework` ∈ {owasp_llm_top10, soc2, fedramp, ...} | Total bytes of compliance bundles served, by framework |

**SLO sketch:** For an auditor-distributable deployment, alert on
`agent_bom_compliance_exports_total{algorithm="HMAC-SHA256"} > 0` — it
means someone forgot to configure `AGENT_BOM_COMPLIANCE_ED25519_PRIVATE_KEY_PEM`.

## Scans

| Metric | Type | Labels | Description |
|---|---|---|---|
| `agent_bom_scan_completions_total` | counter | `status` ∈ {done, failed, cancelled} | Completed scans by final status |

**SLO sketch:** `rate(agent_bom_scan_completions_total{status="failed"}[15m]) /
rate(agent_bom_scan_completions_total[15m]) > 0.1` — failure rate above
10% over 15 min means the scan pipeline is degraded.

---

## Tracing (OpenTelemetry)

Tracing is configured by `AGENT_BOM_OTEL_TRACES_ENDPOINT`. Optional
collector authentication headers can be passed with
`AGENT_BOM_OTEL_TRACES_HEADERS` as comma-separated `key=value` pairs. When
configured, FastAPI, gateway, graph, and MCP proxy spans are exported over
OTLP/HTTP through `src/agent_bom/api/tracing.py`. Recommended exporters:

- **Local / self-hosted:** OTel Collector → Jaeger, Tempo, or any
  OTLP-compatible sink.
- **AWS:** ADOT collector → CloudWatch / X-Ray.
- **Langfuse-compatible:** point `AGENT_BOM_OTEL_TRACES_ENDPOINT` at the
  Langfuse OTLP/HTTP traces endpoint and set `AGENT_BOM_OTEL_TRACES_HEADERS`
  for Basic auth plus ingestion headers. agent-bom emits redaction-safe
  `langfuse.*` attributes on runtime proxy and gateway spans, but Langfuse
  scores, dataset replay, and native trace import remain roadmap work until
  code and tests land for those paths.

Correlate traces with audit entries via the `trace_id` field written to
every `compliance.report_exported` audit entry.

## Audit-event OTLP log export

The tamper-evident governance/NHI-lifecycle audit chain
(`src/agent_bom/api/governance_audit_log.py`) can also be exported as OTLP
**logs** (distinct from the trace spans above) to any OTLP/HTTP collector. Set
`AGENT_BOM_OTEL_LOGS_ENDPOINT` (the collector's logs endpoint, e.g.
`https://collector.example.com/v1/logs`) and optional
`AGENT_BOM_OTEL_LOGS_HEADERS` (comma-separated `key=value` collector-auth
pairs). When configured, every audit record appended by the lifecycle-cleanup
loop (JIT-grant expiry, dormant-identity auto-revoke, token-rotation-due) is
emitted as an OTLP `LogRecord` through `src/agent_bom/siem/otlp_logs.py`:

- **Severity** escalates to `WARN` for revocation/enforcement actions and stays
  `INFO` for routine notices.
- **Attributes** carry `governance.tenant_id`, `governance.actor`,
  `governance.action`, `governance.target_type`/`target_id`, before/after state,
  and the chain `governance.record_hash` (so a consumer can attribute and verify
  per tenant). The free-form record `detail` is deliberately **not** exported, so
  a caller-supplied secret can never leave the process.
- **Batched + non-blocking:** a `BatchLogRecordProcessor` flushes on a background
  thread, so export never blocks the request or cleanup path. The endpoint is
  validated against the outbound URL policy (private/loopback egress is refused
  unless explicitly opened). Requires the `otel` extra; a graceful no-op
  otherwise.

`GET /health` reports the export state under `tracing.otlp_logs_export`
(`disabled` / `pending` / `configured`) so operators can confirm whether audit
logs are merely available or actively exported.

## Device posture (EDR/MDM) → conditional-access ABAC

EDR (endpoint detection & response) and MDM (mobile device management) systems
own device managed/compliant/encrypted ground truth. `POST /v1/device-posture`
ingests those signals — `source` selects the normalizer (`generic` for the
canonical shape, or a vendor field-mapping such as `crowdstrike` / `intune`) and
`payload` is the source's already-fetched JSON. This is read-only and agentless:
no vendor credential is stored here. Normalized, tenant-scoped
`DeviceSignal`s (`src/agent_bom/device_posture.py`) feed the
`require_device_managed` / `require_device_compliant` /
`require_device_disk_encrypted` conditions on a conditional-access policy, which
fail closed for an unknown or non-compliant device. `GET /v1/device-posture/{id}`
returns the latest stored signal for a device.

## Runtime Production Index

`GET /v1/runtime/production-index` returns the security equivalent of a
production AI gateway usage view for proxy and gateway traffic. It is
tenant-scoped and metadata-only by construction:

- tool-call volume, allowed/blocked counts, block rate, top tools, and latency
- policy decision counts and gateway action counts
- runtime alert severity and detector summaries
- active proxy/gateway sources and sessions
- freshness for the latest metrics and alerts
- retention posture for runtime evidence classes

The endpoint does **not** return raw prompts, raw tool arguments, raw tool
responses, credential values, or unredacted screenshots. Its retention posture
uses four explicit modes:

| Mode | Meaning |
|---|---|
| `audit_full` | Operator-controlled local JSONL or downstream SIEM retention; not returned by the production index |
| `redacted` | Safe-to-store runtime alerts after sanitizer and evidence-tier redaction |
| `metadata_only` | Counts, tool names, detector names, source IDs, and trace/session references |
| `no_persist` | Raw prompts, raw arguments, raw responses, credential values, and unredacted screenshots |

Use this endpoint when you need to answer "which agents and MCP servers are
active, what is being blocked, and what evidence is retained?" without turning
the runtime surface into a generic model billing dashboard.

## Audit log integrity

Audit-chain integrity is not a metric — it's verified on every
evidence bundle via `audit_log_integrity.verified` / `.tampered` inside
the signed body. A non-zero `tampered` count in any bundle is a P0
incident. Mirror this into a daily cron alert:

```bash
curl -s https://agent-bom.example.com/v1/compliance/soc2/report \
  | jq -e '.audit_log_integrity.tampered == 0' \
  || alert "audit log tamper detected"
```

---

## Adding a new metric

1. Add a counter/gauge to `src/agent_bom/api/metrics.py`.
2. Record it wherever the event fires (import is O(1); no hot-path overhead).
3. Extend `render_prometheus_lines()` to emit it.
4. Document it here — metrics with no doc are metrics the on-call won't trust.

Keep metric names under `agent_bom_*`, snake_case, Prometheus-idiomatic
(`_total` suffix on counters, `_bytes` / `_seconds` for units).
