# Grafana Dashboard

`agent-bom` ships a pre-built Grafana dashboard for visualizing Prometheus
metrics from the API and proxy.

## Manual import

1. Go to **Dashboards > Import** in Grafana
2. Upload `deploy/grafana/grafana-agent-bom.json`
3. Select your Prometheus data source
4. Click **Import**

## Helm-packaged dashboard

If you are using the packaged control plane, enable:

```yaml
controlPlane:
  enabled: true
  observability:
    grafanaDashboard:
      enabled: true
```

The chart renders a `ConfigMap` with `grafana_dashboard=1` so a Grafana
sidecar or operator can pick it up automatically.

## Panels

| Row | What you see |
|-----|-------------|
| **Overview** | Total vulns, Critical, High, Agents, MCP Servers, Packages |
| **Severity** | Donut chart + trend lines over time |
| **Risk** | KEV findings, Fixable %, Credentials exposed, Proxy stats |
| **Blast Radius** | Top 15 blast radius scores, Top 15 EPSS probabilities |
| **Agent Detail** | Vulns by agent (table), Credentials by agent (bar) |
| **Proxy Runtime** | Call rate, Block reasons (donut), Latency p50/p95 |
| **Proxy Detail** | Calls per tool, CVSS distribution, Message rate, Replay rejections |

## Data sources

### Scan metrics

Push scan results to Prometheus via Pushgateway:

```bash
agent-bom scan --push-gateway http://pushgateway:9091
```

### Proxy metrics

Scrape the proxy's `/metrics` endpoint:

```yaml
# prometheus.yml
scrape_configs:
  - job_name: agent-bom-proxy
    static_configs:
      - targets: ['localhost:8422']
```

Or use Kubernetes annotations for auto-discovery:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8422"
  prometheus.io/path: "/metrics"
```

## Requirements

- Grafana 10+
- Prometheus data source with agent-bom metrics
- For the packaged path, a Grafana sidecar or operator that watches dashboard `ConfigMap`s
