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
| `agent_bom_rate_limit_hits_total` | counter | `bucket` ∈ {global, tenant, ingress, fleet_sync} | Requests rejected by a rate limiter |

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

Tracing is configured by `OTEL_EXPORTER_OTLP_ENDPOINT` and
`AGENT_BOM_OTEL_ENABLED=1`. When on, every FastAPI request emits a trace
via the middleware in `src/agent_bom/api/tracing.py`. Recommended
exporters:

- **Local / self-hosted:** OTel Collector → Jaeger, Tempo, or any
  OTLP-compatible sink.
- **AWS:** ADOT collector → CloudWatch / X-Ray.

Correlate traces with audit entries via the `trace_id` field written to
every `compliance.report_exported` audit entry.

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
