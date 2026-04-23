# Kubernetes Deployment

If you still need to choose a rollout path, start with
[Deployment Overview](overview.md). This page is Kubernetes reference material
for teams that already know they want raw manifests or direct chart controls.

## Pre-built manifests

Located in `deploy/k8s/`:

| Manifest | Purpose |
|----------|---------|
| `namespace.yaml` | `agent-bom` namespace |
| `rbac.yaml` | ServiceAccount + ClusterRole (pod/namespace read) |
| `cronjob.yaml` | Scheduled scan every 6 hours |
| `daemonset.yaml` | Optional node-wide runtime monitor |
| `sidecar-example.yaml` | Proxy sidecar alongside an MCP server |
| `proxy-sidecar-pilot.yaml` | Focused EKS pilot sidecar pattern for selected MCP workloads |

Those static manifests are still the scanner/runtime path.

The packaged Helm chart now also ships an optional mutating webhook for the
HTTP/SSE sidecar path:

- enable `sidecarInjection.enabled=true`
- opt in an entire namespace with label `agent-bom.io/proxy-inject=enabled`
- or opt in a single workload with pod label `agent-bom.io/proxy=true`
- declare the local MCP target with annotation `agent-bom.io/mcp-url` or
  `agent-bom.io/mcp-port`

If you want the packaged API + dashboard control plane, use the Helm chart
described below.

## Runtime boundary

`agent-bom` now has two distinct Kubernetes security surfaces:

- manifest hardening
  - `agent-bom iac k8s/`
  - scans YAML/Helm content in Git or on disk
- live cluster posture
  - `agent-bom iac . --k8s-live --k8s-all-namespaces`
  - inspects runtime state through `kubectl`
  - covers live pod health, live RBAC drift, and namespace NetworkPolicy coverage

The live path is intentionally scoped. It does not claim full admission-policy,
service-mesh, or arbitrary controller-state analysis.

## Quick start

```bash
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac.yaml
kubectl apply -f deploy/k8s/cronjob.yaml

# Inspect live cluster posture through kubectl
agent-bom iac . --k8s-live --k8s-all-namespaces
```

## Helm chart

```bash
# Install with defaults
helm install agent-bom deploy/helm/agent-bom/ \
  -n agent-bom --create-namespace

# Enable the optional node-wide runtime monitor
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
| `monitor.enabled` | `false` | Deploy the optional node-wide monitor DaemonSet |
| `monitor.port` | `8423` | HTTP port for protect endpoint |
| `monitor.serviceAccount.create` | `true` | Create a dedicated monitor service account instead of reusing the shared chart identity |
| `controlPlane.enabled` | `false` | Package API + dashboard Deployments and Services |
| `controlPlane.ingress.enabled` | `false` | Add same-origin ingress routing for UI + API |
| `controlPlane.ui.env` | `NEXT_PUBLIC_API_URL=\"\"` | Blank by default so the browser uses same-origin paths |
| `sidecarInjection.enabled` | `false` | Package the cert-manager-backed mutating webhook for proxy sidecar auto-injection |
| `networkPolicy.restrictIngress` | `true` | Deny ingress by default; add explicit ingress policy rules for allowed callers |
| `rbac.create` | `true` | Create RBAC resources |
| `serviceAccount.annotations` | `{}` | Attach provider-specific identity such as AWS IRSA |

For the full control-plane topology and secret wiring, see
[Packaged API + UI Control Plane](control-plane-helm.md).

Use the monitor only when you explicitly want node-wide runtime coverage. The
default secure path remains:

- agentless scans
- fleet sync
- gateway for shared remote MCPs
- selected sidecar proxies where inline enforcement matters

For the narrower MCP and agents pilot, see
[Focused EKS MCP Pilot](eks-mcp-pilot.md).

For employee laptops and workstations that should sync into the same control
plane, see [Endpoint Fleet](endpoint-fleet.md).
