# Kubernetes Deployment

## Pre-built manifests

Located in `deploy/k8s/`:

| Manifest | Purpose |
|----------|---------|
| `namespace.yaml` | `agent-bom` namespace |
| `rbac.yaml` | ServiceAccount + ClusterRole (pod/namespace read) |
| `cronjob.yaml` | Scheduled scan every 6 hours |
| `daemonset.yaml` | Runtime protection on every node |
| `sidecar-example.yaml` | Proxy sidecar alongside an MCP server |

## Quick start

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/cronjob.yaml
```

## Helm chart

```bash
# Install with defaults
helm install agent-bom deploy/helm/agent-bom/ \
  -n agent-bom --create-namespace

# Enable runtime monitoring
helm install agent-bom deploy/helm/agent-bom/ \
  -n agent-bom --create-namespace \
  --set monitor.enabled=true

# Custom schedule
helm install agent-bom deploy/helm/agent-bom/ \
  -n agent-bom --create-namespace \
  --set scanner.schedule="0 */2 * * *"
```

### Key values

| Value | Default | Description |
|-------|---------|-------------|
| `scanner.enabled` | `true` | Deploy CronJob scanner |
| `scanner.schedule` | `0 */6 * * *` | Cron schedule |
| `scanner.allNamespaces` | `true` | Scan all namespaces |
| `scanner.extraArgs` | `[]` | Add scan flags like `--k8s-mcp`, `--enforce`, or `--introspect` |
| `scanner.env` | `[]` | Extra environment variables for the scanner CronJob |
| `monitor.enabled` | `false` | Deploy DaemonSet monitor |
| `monitor.port` | `8423` | HTTP port for protect endpoint |
| `rbac.create` | `true` | Create RBAC resources |
| `serviceAccount.annotations` | `{}` | Attach provider-specific identity such as AWS IRSA |
