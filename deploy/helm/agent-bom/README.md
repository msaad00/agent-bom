# agent-bom Helm chart

Helm packaging for `agent-bom` in your Kubernetes cluster — scheduled scanner
jobs, optional runtime monitor, and (when enabled) the self-hosted API +
dashboard control plane.

## Default render is scanner-only

`controlPlane.enabled` defaults to **`false`**. A plain `helm install` deploys
the scanner CronJob and supporting RBAC only. The API, dashboard, gateway,
proxy, firewall, MCP server mode, and Postgres wiring stay off until you opt in.

For the full platform (browse findings in the UI, hit the REST API, enforce
runtime policy), install with:

```bash
helm upgrade --install agent-bom . \
  -n agent-bom --create-namespace \
  --set controlPlane.enabled=true
```

Without that flag, Helm succeeds quietly and only scanner pieces land in the
cluster. See the `controlPlane:` block in `values.yaml` for every subcomponent
the flag toggles.

## Quick start

From a checked-out repo (chart path `deploy/helm/agent-bom/`):

```bash
# Scanner CronJob only (default)
helm upgrade --install agent-bom deploy/helm/agent-bom \
  -n agent-bom --create-namespace

# API + UI control plane
helm upgrade --install agent-bom deploy/helm/agent-bom \
  -n agent-bom --create-namespace \
  --set controlPlane.enabled=true \
  --set controlPlane.ingress.enabled=true

# Custom scan schedule
helm upgrade --install agent-bom deploy/helm/agent-bom \
  -n agent-bom --create-namespace \
  --set scanner.schedule="0 */2 * * *"
```

## Shipped profiles

Production-ready value overlays live in [`examples/`](examples/README.md).
Validate every profile locally:

```bash
python scripts/validate_helm_profiles.py
```

Install a named profile in one command:

```bash
python scripts/install_helm_profile.py focused-pilot --print-command
python scripts/install_helm_profile.py focused-pilot
```

| Profile | Starting file | Use when |
|---|---|---|
| `focused-pilot` | `examples/eks-mcp-pilot-values.yaml` | Narrow EKS pilot with control plane |
| `eks-vanilla` | `examples/eks-vanilla-values.yaml` | EKS + Postgres + IRSA, no mesh/ESO |
| `production` | `examples/eks-production-values.yaml` | Postgres + ExternalSecrets + autoscaling |
| `sqlite-pilot` | `examples/eks-control-plane-sqlite-pilot-values.yaml` | Short-lived demo without Postgres |

Full profile matrix: [`examples/README.md`](examples/README.md).

## Key values

| Value | Default | Description |
|---|---|---|
| `scanner.enabled` | `true` | Deploy CronJob scanner |
| `scanner.schedule` | `0 */6 * * *` | Cron schedule |
| `scanner.allNamespaces` | `true` | Scan all namespaces |
| `controlPlane.enabled` | `false` | Package API + dashboard Deployments |
| `controlPlane.ingress.enabled` | `false` | Same-origin ingress for UI + API |
| `monitor.enabled` | `false` | Optional node-wide runtime monitor |
| `sidecarInjection.enabled` | `false` | Mutating webhook for proxy sidecars |
| `networkPolicy.restrictIngress` | `true` | Deny ingress unless rules allow |

Canonical env-var reference: [`docs/operations/ENV_VARS.md`](../../../docs/operations/ENV_VARS.md).

## Further reading

- [Packaged API + UI control plane](https://msaad00.github.io/agent-bom/deployment/control-plane-helm/) — topology, secrets, ingress
- [Kubernetes deployment](https://msaad00.github.io/agent-bom/deployment/kubernetes/) — raw manifests vs Helm
- [Deployment overview](https://msaad00.github.io/agent-bom/deployment/overview/) — choose laptop, compose, EKS, or Snowflake path
- [Vanilla EKS quickstart](https://msaad00.github.io/agent-bom/deployment/eks-vanilla-quickstart/) — paved production rollout
