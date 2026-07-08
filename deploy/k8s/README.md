# agent-bom on Kubernetes (raw manifests)

Plain `kubectl apply` manifests for running agent-bom on any Kubernetes cluster
without Helm. They cover the two honest deployment lanes: **scheduled scanning**
and **inline runtime enforcement** of MCP traffic.

> Prefer Helm for the full control plane (API + dashboard + gateway + Postgres).
> See [`deploy/helm/agent-bom`](../helm/agent-bom) and the
> [Kubernetes deployment guide](../../site-docs/deployment/kubernetes.md). These
> raw manifests are the lightweight, dependency-free alternative for the scanner
> and proxy-sidecar paths.

## Files

| File | Kind | Purpose |
| --- | --- | --- |
| `namespace.yaml` | Namespace | Creates the `agent-bom` namespace with Pod Security Admission set to **restricted** (`enforce`/`audit`/`warn`). Apply first. |
| `rbac.yaml` | ServiceAccount + ClusterRole + ClusterRoleBinding | A `agent-bom` service account bound to a **read-only** ClusterRole (`get`/`list`/`watch` on `pods` and `namespaces`). Nothing here can mutate cluster state. |
| `cronjob.yaml` | CronJob | Runs `agent-bom scan --k8s -A` every 6 hours and writes JSON to a mounted `/output` volume. Hardened pod (non-root, read-only rootfs, all capabilities dropped). |
| `daemonset.yaml` | DaemonSet | Runs `agent-bom protect --mode http` on every node as a runtime monitor, exposing the protect endpoint on port `8423` with liveness/readiness probes on `/status`. |
| `sidecar-example.yaml` | Deployment | Reference: the agent-bom proxy as a sidecar to an MCP server. The proxy intercepts JSON-RPC traffic, logs tool calls, detects credential leaks, and enforces policy. Prometheus scrape annotations on port `8422`. |
| `proxy-sidecar-pilot.yaml` | Namespace + ConfigMap + Service + Deployment | Focused MCP pilot: adds the proxy sidecar only to selected workloads, with an inline `policy.json` ConfigMap (deny exec/destructive tools, block secret paths, deny unknown egress, rate-limit). This is the recommended runtime-enforcement path for EKS today. |

## Apply

Namespace and RBAC first, then whichever lane you need:

```bash
# Namespace (restricted PSA) + read-only RBAC
kubectl apply -f deploy/k8s/namespace.yaml
kubectl apply -f deploy/k8s/rbac.yaml

# Scheduled scanning
kubectl apply -f deploy/k8s/cronjob.yaml

# Runtime monitoring on every node
kubectl apply -f deploy/k8s/daemonset.yaml
```

For inline MCP enforcement, edit the sample workload image/command in
`proxy-sidecar-pilot.yaml` (or `sidecar-example.yaml`) to point at your own MCP
server, then apply it:

```bash
kubectl apply -f deploy/k8s/proxy-sidecar-pilot.yaml
```

## Security posture

- **Read-only cluster access.** The bundled ClusterRole grants only
  `get`/`list`/`watch` on `pods` and `namespaces`. The scanner and monitor
  cannot change anything in your cluster.
- **Hardened pods.** Every workload runs as non-root (`runAsUser: 1000`) with a
  read-only root filesystem, `allowPrivilegeEscalation: false`, and all Linux
  capabilities dropped. The DaemonSet also disables the automounted
  service-account token.
- **Restricted namespace.** `namespace.yaml` enforces the Kubernetes
  `restricted` Pod Security Standard, so misconfigured pods are rejected at
  admission.
- **No long-lived secrets in the manifests.** Runtime credentials (registry,
  push tokens, provider keys) are supplied out-of-band as Kubernetes Secrets or
  environment references — never baked into these files.

The container image tags in these manifests are pinned to the current release
and are bumped automatically by `scripts/bump-version.py`; pin them to a digest
for production if you need immutable rollouts.

## Related docs

- [Kubernetes deployment guide](../../site-docs/deployment/kubernetes.md)
- [Vanilla EKS quickstart](../../site-docs/deployment/eks-vanilla-quickstart.md)
- [EKS MCP runtime pilot](../../site-docs/deployment/eks-mcp-pilot.md)
- [Runtime monitoring](../../site-docs/deployment/runtime-monitoring.md)
- [Helm chart](../helm/agent-bom)
