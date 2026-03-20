# Grafana Dashboard

Pre-built Grafana dashboard for agent-bom Prometheus metrics.

## Import

1. In Grafana, go to **Dashboards → Import**
2. Upload `grafana-agent-bom.json` or paste its contents
3. Select your Prometheus data source
4. Click **Import**

## Panels

| Row | Panels |
|-----|--------|
| **Overview** | Total vulns, Critical, High, Agents, MCP Servers, Packages |
| **Severity** | Donut chart (severity distribution), Trend lines (over time) |
| **Risk** | KEV findings, Fixable %, Credentials exposed, Proxy uptime/blocked/total |
| **Blast Radius** | Top 15 blast radius scores, Top 15 EPSS probabilities |
| **Agent Detail** | Vulns by agent (table), Credentials by agent (bar) |
| **Proxy Runtime** | Call rate, Block reasons (donut), Latency p50/p95 |
| **Proxy Detail** | Calls per tool (table), CVSS distribution, Message rate, Replay rejections |

## Metrics Sources

- **Scan metrics** — Push via `agent-bom agents --push-gateway http://pushgateway:9091`
- **Proxy metrics** — Scraped from `agent-bom proxy --metrics-port 8422` at `/metrics`

## Requirements

- Grafana 10+
- Prometheus data source with agent-bom metrics
