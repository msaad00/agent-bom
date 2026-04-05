# Runtime Monitoring — Deployment Guide

agent-bom includes a runtime security proxy (`agent-bom proxy`) that sits between MCP clients and servers, intercepting JSON-RPC messages in real time. This guide covers sidecar deployment, detector configuration, enforcement modes, and alert routing.

## What the Runtime Proxy Does

The proxy interposes on the stdio channel between an MCP client (Claude Desktop, Cursor, VS Code, etc.) and an MCP server. Every JSON-RPC message passes through the proxy, which:

1. **Logs** every `tools/call` invocation to a JSONL audit trail
2. **Detects** anomalous or dangerous tool usage via seven inline detectors
3. **Enforces** policy rules — optionally blocking tool calls that violate policy
4. **Tracks** declared vs. actual tool usage (drift detection)
5. **Measures** latency, call counts, and blocked-call metrics

### Seven Inline Detectors

| Detector | What it catches | Default mode |
|---|---|---|
| **Tool drift** | Tools invoked at runtime that were not declared in the `tools/list` response. Indicates a server exposing undeclared capabilities. | Log |
| **Argument analysis** | Tool call arguments that match blocked regex patterns defined in policy (e.g., path traversal, SQL injection payloads). | Log |
| **Credential leak** | Arguments containing patterns that look like API keys, tokens, passwords, or connection strings being passed to tools. | Log |
| **Rate limiting** | Abnormal call frequency for a single tool within a time window — detects runaway loops or abuse. | Log |
| **Sequence analysis** | Suspicious sequences of tool calls (e.g., `list_files` followed by `read_file` on every file, or `exec` after `write_file`). | Log |
| **Response inspection** | Cloaking, invisible Unicode, SVG/script payloads, and poisoned response content. | Log |
| **Vector DB injection** | Retrieved prompt chunks or vector-backed content attempting to coerce downstream tools or agents. | Log |

---

## Sidecar Deployment

### Docker

Build the slim runtime image:

```bash
docker build -f deploy/docker/Dockerfile.runtime -t agent-bom-runtime .
```

The maintained runtime image now builds from the checked-out `agent-bom` source tree,
not from a separately downloaded PyPI artifact, so the runtime sidecar stays aligned
with the repo revision you are deploying.

Run as a wrapper around any MCP server:

```bash
docker run --rm \
  -v $(pwd)/audit-logs:/var/log/agent-bom \
  agent-bom-runtime \
  --log /var/log/agent-bom/audit.jsonl \
  --block-undeclared \
  -- npx -y @modelcontextprotocol/server-filesystem /workspace
```

### Docker Compose

Use the provided `deploy/docker-compose.runtime.yml` for a complete sidecar example:

```bash
docker compose -f deploy/docker-compose.runtime.yml up
```

This starts:
- A filesystem MCP server (`npx @modelcontextprotocol/server-filesystem`)
- The agent-bom proxy sidecar intercepting all traffic
- Audit logs written to `./audit-logs/audit.jsonl` on the host

### Kubernetes

Deploy the proxy as a sidecar container in the same pod as your MCP server:

```yaml
apiVersion: apps/v1
kind: Deployment
metadata:
  name: mcp-server
spec:
  replicas: 1
  selector:
    matchLabels:
      app: mcp-server
  template:
    metadata:
      labels:
        app: mcp-server
    spec:
      containers:
        # MCP server container
        - name: mcp-server
          image: node:20-slim
          command: ["npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"]
          volumeMounts:
            - name: workspace
              mountPath: /workspace

        # agent-bom runtime proxy sidecar
        - name: agent-bom-proxy
          image: agent-bom-runtime:latest
          args:
            - "--log"
            - "/var/log/agent-bom/audit.jsonl"
            - "--block-undeclared"
            - "--"
            - "npx"
            - "-y"
            - "@modelcontextprotocol/server-filesystem"
            - "/workspace"
          volumeMounts:
            - name: audit-logs
              mountPath: /var/log/agent-bom
            - name: workspace
              mountPath: /workspace

      volumes:
        - name: workspace
          emptyDir: {}
        - name: audit-logs
          persistentVolumeClaim:
            claimName: audit-logs-pvc
```

For production Kubernetes deployments, mount the policy file from a ConfigMap:

```yaml
volumes:
  - name: policy
    configMap:
      name: agent-bom-policy
```

```yaml
# In the proxy container:
volumeMounts:
  - name: policy
    mountPath: /etc/agent-bom/policy.json
    subPath: policy.json
```

Then add `--policy /etc/agent-bom/policy.json` to the proxy args.

---

## Log vs Enforce Mode

The proxy supports two operational modes:

### Log mode (default)

All tool calls are allowed through. Every invocation is recorded in the JSONL audit log with full metadata (tool name, truncated arguments, timestamp). Use this mode to build a baseline of normal behavior before enabling enforcement.

```bash
agent-bom proxy --log audit.jsonl -- npx @mcp/server-filesystem /workspace
```

For Claude Desktop, Claude Code, and Cortex JSON configs, you can auto-wrap eligible stdio servers:

```bash
agent-bom proxy-configure --log-dir ~/.agent-bom/logs --detect-credentials
```

Add `--apply` to persist the wrapped config entries.

If you need cross-agent correlation and the broader 8-detector runtime engine, use `agent-bom runtime protect --shield` alongside or upstream of the proxy pipeline.

### Enforce mode

Add `--block-undeclared` and/or `--policy policy.json` to actively block tool calls:

```bash
agent-bom proxy \
  --log audit.jsonl \
  --policy policy.json \
  --block-undeclared \
  -- npx @mcp/server-filesystem /workspace
```

Blocked calls receive a JSON-RPC error response (`code: -32600`) and are recorded in the audit log with `"policy": "blocked"` and the reason.

---

## Alert Routing

### Audit JSONL

Every tool call is appended to the JSONL log file as a single-line JSON object:

```json
{"ts": "2026-02-26T12:00:00Z", "type": "tools/call", "tool": "read_file", "args": {"path": "/etc/passwd"}, "policy": "blocked", "reason": "Argument 'path' matches blocked pattern '/etc/(passwd|shadow)'"}
```

When the proxy shuts down, it writes a summary record:

```json
{"ts": "2026-02-26T12:05:00Z", "type": "proxy_summary", "uptime_seconds": 300.0, "total_tool_calls": 42, "total_blocked": 3, "calls_by_tool": {"read_file": 30, "write_file": 12}, "blocked_by_reason": {"policy": 2, "undeclared": 1}, "latency": {"min_ms": 1.2, "max_ms": 450.0, "avg_ms": 23.5, "p50_ms": 15.0, "p95_ms": 120.0, "count": 42}, "messages_client_to_server": 50, "messages_server_to_client": 48}
```

### Webhook Alerts

Use the `agent-bom watch` command alongside the proxy to route alerts to Slack, Teams, or PagerDuty:

```bash
# In one terminal: run the proxy
agent-bom proxy --log audit.jsonl -- npx @mcp/server-filesystem /workspace

# In another terminal: watch the audit log and send alerts
agent-bom watch --webhook https://hooks.slack.com/services/T.../B.../xxx --log alerts.jsonl
```

---

## Detector Descriptions

### Tool Drift

Compares the set of tools declared in the server's `tools/list` response against actual `tools/call` invocations. If a tool is called that was never declared, the proxy flags it as drift. This catches servers that expose hidden capabilities not visible during initial handshake.

Enable blocking with `--block-undeclared`.

### Argument Analysis

Evaluates tool call arguments against regex patterns defined in a policy file. Common patterns include path traversal (`../../etc/passwd`), SQL injection payloads, and shell metacharacters. Each policy rule specifies an `arg_pattern` map of argument name to regex.

### Credential Leak

Scans tool call arguments for patterns that resemble secrets: API keys (prefixed strings like `sk-`, `ghp_`, `AKIA`), bearer tokens, connection strings with embedded passwords, and base64-encoded credentials. Prevents AI agents from inadvertently passing secrets to MCP tools.

### Rate Limiting

Tracks call frequency per tool within a sliding time window. Detects runaway loops where an AI agent repeatedly calls the same tool (e.g., `exec` or `write_file`) in rapid succession, which may indicate a prompt injection driving automated actions.

### Sequence Analysis

Analyzes the order of tool calls to detect suspicious multi-step patterns. For example: `list_directory` followed by `read_file` on every discovered file (bulk exfiltration), or `write_file` followed by `exec` (code injection + execution).

### Response Inspection

Scans tool responses for cloaking tricks, invisible Unicode, SVG/script payloads, and other content that tries to smuggle instructions back into the agent.

### Vector DB Injection

Detects prompt-coercion or poisoning patterns from retrieval-backed tools and escalates them when the response clearly comes from vector or RAG-like sources.

## Configuration Examples

### Basic audit logging

```bash
agent-bom proxy --log /var/log/agent-bom/audit.jsonl \
  -- npx @modelcontextprotocol/server-filesystem /workspace
```

### Enforce with policy file

```bash
agent-bom proxy \
  --policy policy.json \
  --log /var/log/agent-bom/audit.jsonl \
  --block-undeclared \
  -- npx @modelcontextprotocol/server-filesystem /workspace
```

### Policy file example

```json
{
  "rules": [
    {
      "id": "block-sensitive-paths",
      "action": "block",
      "arg_pattern": {
        "path": "(/etc/(passwd|shadow|sudoers)|/root/\\.ssh)"
      }
    },
    {
      "id": "block-exec-tools",
      "action": "block",
      "block_tools": ["exec", "run_command", "shell"]
    },
    {
      "id": "block-sql-injection",
      "action": "block",
      "arg_pattern": {
        "query": "(DROP\\s+TABLE|DELETE\\s+FROM|UNION\\s+SELECT|;\\s*--)"
      }
    }
  ]
}
```

### Claude Desktop configuration

Point Claude Desktop at the proxy instead of the raw MCP server:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "agent-bom",
      "args": [
        "proxy",
        "--log", "/var/log/agent-bom/audit.jsonl",
        "--policy", "/etc/agent-bom/policy.json",
        "--block-undeclared",
        "--",
        "npx", "@modelcontextprotocol/server-filesystem", "/workspace"
      ]
    }
  }
}
```

### Docker sidecar in Claude Desktop

Use the runtime container directly from Claude Desktop:

```json
{
  "mcpServers": {
    "filesystem": {
      "command": "docker",
      "args": [
        "run", "--rm", "-i",
        "-v", "./workspace:/workspace",
        "-v", "./audit-logs:/var/log/agent-bom",
        "agent-bom-runtime:latest",
        "--log", "/var/log/agent-bom/audit.jsonl",
        "--block-undeclared",
        "--",
        "npx", "-y", "@modelcontextprotocol/server-filesystem", "/workspace"
      ]
    }
  }
}
```

---

## Kubernetes Deployment Manifests

Pre-built K8s manifests are available in `deploy/k8s/`:

| Manifest | Purpose |
|----------|---------|
| `namespace.yaml` | Creates the `agent-bom` namespace |
| `rbac.yaml` | ServiceAccount + ClusterRole (pod/namespace read) + ClusterRoleBinding |
| `cronjob.yaml` | Scheduled vulnerability scan every 6 hours across all namespaces |
| `daemonset.yaml` | Runtime protection monitor on every node via `agent-bom protect --mode http` |
| `sidecar-example.yaml` | MCP server + agent-bom proxy sidecar deployment example |

### Quick start

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/cronjob.yaml
```

To enable runtime monitoring on all nodes:

```bash
kubectl apply -f deploy/k8s/daemonset.yaml
```

---

## Helm Chart

A Helm chart is provided in `deploy/helm/agent-bom/` for customizable deployments:

```bash
# Install with defaults (scheduled scanner only)
helm install agent-bom deploy/helm/agent-bom/ -n agent-bom --create-namespace

# Enable runtime monitoring DaemonSet
helm install agent-bom deploy/helm/agent-bom/ -n agent-bom --create-namespace \
  --set monitor.enabled=true

# Enable Prometheus scraping for the runtime monitor
helm install agent-bom deploy/helm/agent-bom/ -n agent-bom --create-namespace \
  --set monitor.enabled=true \
  --set monitor.serviceMonitor.enabled=true

# Custom scan schedule (every 2 hours)
helm install agent-bom deploy/helm/agent-bom/ -n agent-bom --create-namespace \
  --set scanner.schedule="0 */2 * * *"
```

### Key values

| Value | Default | Description |
|-------|---------|-------------|
| `scanner.enabled` | `true` | Deploy the CronJob scanner |
| `scanner.schedule` | `0 */6 * * *` | Cron schedule for scans |
| `scanner.allNamespaces` | `true` | Scan all namespaces |
| `monitor.enabled` | `false` | Deploy the DaemonSet runtime monitor |
| `monitor.port` | `8423` | HTTP port for the protect endpoint |
| `monitor.service.enabled` | `true` | Expose the monitor DaemonSet through a ClusterIP Service when enabled |
| `monitor.serviceMonitor.enabled` | `false` | Create a Prometheus Operator ServiceMonitor that scrapes `/metrics` |
| `monitor.ingress.enabled` | `false` | Create an Ingress for the monitor Service when remote access is needed |
| `networkPolicy.allowDns` | `true` | Allow outbound DNS resolution on TCP/UDP 53 |
| `networkPolicy.allowWeb` | `true` | Allow outbound TCP web traffic for registry/API access |
| `networkPolicy.webPorts` | `[80, 443]` | TCP ports permitted when `allowWeb` is enabled |
| `networkPolicy.additionalEgress` | `[]` | Extra egress rules for stricter or more specialized environments |
| `pdb.enabled` | `false` | Create a PodDisruptionBudget for the runtime monitor pods |
| `rbac.create` | `true` | Create the cluster-scoped read RBAC needed for pod and namespace discovery |

When the monitor is enabled, the chart now wires:
- `livenessProbe` on `/status`
- `readinessProbe` on `/status`
- `startupProbe` on `/status`
- optional Prometheus scraping on `/metrics`
- optional `Ingress` for the monitor Service
- optional `PodDisruptionBudget` for voluntary-eviction safety

The chart's default `NetworkPolicy` also avoids unrestricted outbound traffic. By default it permits:
- DNS resolution on TCP/UDP 53
- outbound TCP 80/443 for package registries, APIs, and control-plane calls

Use `networkPolicy.additionalEgress` to add tighter environment-specific rules without editing templates.

The chart RBAC is intentionally cluster-scoped today because the monitor and scanner read both pods and namespaces. It is focused cluster-read access rather than a richer workload-specific RBAC partitioning story.

---

## Sidecar Injection

To run the agent-bom proxy as a sidecar alongside your MCP server pod, see `deploy/k8s/sidecar-example.yaml`. The sidecar:

- Intercepts all JSON-RPC traffic between client and server
- Logs tool calls to `/var/log/agent-bom/audit.jsonl`
- Detects credential leaks and blocks undeclared tools
- Exposes Prometheus metrics on port 8422

Apply the example:

```bash
kubectl apply -f deploy/k8s/sidecar-example.yaml
```

---

## Prometheus Metrics

The proxy exposes Prometheus-compatible metrics on port 8422 (configurable via `--metrics-port`):

```bash
agent-bom proxy --metrics-port 8422 --log audit.jsonl -- npx @mcp/server-filesystem /workspace
```

### Metrics endpoint

`GET http://localhost:8422/metrics` returns:

```
agent_bom_proxy_tool_calls_total{tool="read_file"} 42
agent_bom_proxy_blocked_total{reason="policy"} 3
agent_bom_proxy_uptime_seconds 300.5
agent_bom_proxy_total_tool_calls 45
agent_bom_proxy_total_blocked 3
agent_bom_proxy_latency_ms{quantile="0.5"} 15.0
agent_bom_proxy_latency_ms{quantile="0.95"} 120.0
agent_bom_proxy_replay_rejections_total 0
agent_bom_proxy_messages_total{direction="client_to_server"} 50
agent_bom_proxy_messages_total{direction="server_to_client"} 48
```

### Prometheus scrape config

The sidecar example includes Prometheus annotations for auto-discovery:

```yaml
annotations:
  prometheus.io/scrape: "true"
  prometheus.io/port: "8422"
  prometheus.io/path: "/metrics"
```

To disable metrics, set `--metrics-port 0`.

### Grafana dashboard

A pre-built Grafana dashboard is available at [`deploy/grafana/grafana-agent-bom.json`](../deploy/grafana/grafana-agent-bom.json). Import it into Grafana (Dashboards > Import) to get:

- Severity distribution (donut + trend lines)
- Top blast radius scores and EPSS probabilities
- Per-agent vulnerability and credential exposure tables
- Proxy runtime panels (call rate, block reasons, latency p50/p95, replay rejections)

See [`deploy/grafana/README.md`](../deploy/grafana/README.md) for setup details.
