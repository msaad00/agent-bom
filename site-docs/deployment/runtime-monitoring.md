# Runtime Monitoring

For the full runtime monitoring deployment guide, see the [dedicated doc](https://github.com/msaad00/agent-bom/blob/main/docs/RUNTIME_MONITORING.md).

## Overview

The runtime proxy (`agent-bom proxy`) intercepts MCP JSON-RPC messages between client and server, providing:

- JSONL audit logging of all tool calls
- 7-detector anomaly engine (tool drift, argument analysis, credential leak, rate limiting, sequence analysis, response inspector, vector DB injection)
- Policy enforcement with block/allow rules
- Prometheus metrics on port 8422
- Optional visual leak detection for image and screenshot responses

## Deployment modes

| Mode | Command | Use case |
|------|---------|----------|
| Local sidecar | `agent-bom proxy -- npx server` | Dev/testing |
| Docker sidecar | See [Docker](docker.md) | Production |
| K8s sidecar | See [Kubernetes](kubernetes.md) | Fleet |
| Optional node-wide monitor | Helm `monitor.enabled=true` | Broad runtime coverage only when a team explicitly accepts a DaemonSet |
| Config watcher | `agent-bom watch` | Drift alerting |

The node-wide monitor is:

- optional
- off by default
- not required for scan/discovery, fleet, gateway, or selected sidecar proxy rollout
- the highest-trust runtime shape, so it should be enabled only when the operator wants per-node runtime coverage

## Alert routing

The `watch` command supports webhook alerts to:

- Slack
- Microsoft Teams
- PagerDuty
- Custom webhook URLs

```bash
agent-bom watch --webhook-url https://hooks.slack.com/... --watch-interval 60
```

## Operator guides

- [Visual Leak Detection](visual-leak-detection.md)
- [Worker and Scheduler Concurrency](worker-and-scheduler-concurrency.md)
- [Gateway Auto-Discovery From the Control Plane](gateway-auto-discovery.md)
