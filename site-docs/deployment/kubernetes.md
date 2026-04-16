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
| `proxy-sidecar-pilot.yaml` | Focused EKS pilot sidecar pattern for selected MCP workloads |

Those static manifests are still the scanner/runtime path.

If you want the packaged API + dashboard control plane, use the Helm chart
described below.

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

# Package the API + UI control plane
helm install agent-bom deploy/helm/agent-bom/ \
  -n agent-bom --create-namespace \
  --set controlPlane.enabled=true \
  --set controlPlane.ingress.enabled=true

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
| `controlPlane.enabled` | `false` | Package API + dashboard Deployments and Services |
| `controlPlane.ingress.enabled` | `false` | Add same-origin ingress routing for UI + API |
| `controlPlane.ui.env` | `NEXT_PUBLIC_API_URL=\"\"` | Blank by default so the browser uses same-origin paths |
| `networkPolicy.restrictIngress` | `false` | Keep ingress open unless you explicitly provide ingress policy rules |
| `rbac.create` | `true` | Create RBAC resources |
| `serviceAccount.annotations` | `{}` | Attach provider-specific identity such as AWS IRSA |

For the full control-plane topology and secret wiring, see
[Packaged API + UI Control Plane](control-plane-helm.md).

For the narrower MCP and agents pilot, see
[Focused EKS MCP Pilot](eks-mcp-pilot.md).
