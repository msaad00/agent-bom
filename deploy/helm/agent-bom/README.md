# agent-bom Helm chart

Helm packaging for `agent-bom` in your Kubernetes cluster — scheduled scanner
jobs, optional runtime monitor, and (when enabled) the self-hosted API +
dashboard control plane.

## Default render is scanner-only

`controlPlane.enabled` defaults to **`false`**. A plain `helm install` deploys
the scanner CronJob and supporting RBAC only. The API, dashboard, gateway,
proxy, firewall, MCP server mode, and Postgres wiring stay off until you opt in.

For the full platform (browse findings in the UI, hit the REST API, enforce
runtime policy), start from a shipped profile. Profiles provide the required
Postgres secret wiring and deployment-specific egress/ingress rules:

```bash
python scripts/install_helm_profile.py focused-pilot --print-command
python scripts/install_helm_profile.py focused-pilot
```

The chart does not provision Postgres. A direct `--set controlPlane.enabled=true`
install must supply `AGENT_BOM_POSTGRES_URL` through `controlPlane.api.envFrom`
or `controlPlane.migrations.env`; otherwise template validation fails before
Helm creates a partial control plane.

Without that flag, Helm succeeds quietly and only scanner pieces land in the
cluster. See the `controlPlane:` block in `values.yaml` for every subcomponent
the flag toggles.

## Quick start

From a checked-out repo (chart path `deploy/helm/agent-bom/`):

```bash
# Scanner CronJob only (default)
helm upgrade --install agent-bom deploy/helm/agent-bom \
  -n agent-bom --create-namespace

# API + UI control plane (use a shipped profile; it includes Postgres wiring)
python scripts/install_helm_profile.py focused-pilot

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

## Cloud-SDK collector image

The scheduled cloud scan runs a dedicated **collector image**
(`agentbom/agent-bom-collector`, built from
[`deploy/docker/Dockerfile.collector`](../../docker/Dockerfile.collector)) that
ships the provider SDK layer — boto3, the Azure management SDKs, the Google
Cloud SDKs, and the Snowflake connector — separately from the control-plane
image. This lets the fast-moving SDK layer be rebuilt and re-tagged on its own
cadence: a daily CI job (`refresh-collector-latest`) rebuilds
`agent-bom-collector:latest` to absorb newer provider-SDK wheels within the
pinned floors **without** a control-plane version bump. The collector keeps the
BYOC trust boundary intact — a direct, read-only, least-privilege link to the
customer's cloud, with no external MCP in the credential/data path.

The SDK versions come from the cloud provider extras in `pyproject.toml` (the
single source of truth the [cloud-SDK drift gate](../../../scripts/check_cloud_sdk_drift.py)
enforces); the image never re-declares them. To pin a newer SDK-only build
between control-plane releases:

```bash
helm upgrade agent-bom agent-bom/agent-bom \
  --reuse-values --set collectorImage.tag=<sdk-only-build>
```

`collectorImage` mirrors the `image`/`uiImage`/`runtimeImage` block convention; a
blank `collectorImage.tag` falls back to `image.tag`.

## Key values

| Value | Default | Description |
|---|---|---|
| `scanner.enabled` | `true` | Deploy CronJob scanner |
| `scanner.schedule` | `0 */6 * * *` | Cron schedule |
| `scanner.allNamespaces` | `true` | Scan all namespaces |
| `scanner.cloud.aws.orgInventory` | `false` | Job/CLI only → `AGENT_BOM_AWS_ORG_INVENTORY`. Connections org fan-out uses `inventory_scope=organization` on the connection row, not this value. |
| `scanner.cloud.azure.allSubscriptions` | `false` | Job/CLI only → `AGENT_BOM_AZURE_ALL_SUBSCRIPTIONS` (same Connections vs Job split as `orgInventory`) |
| `scanner.cloud.gcp.allProjects` | `false` | Job/CLI only → `AGENT_BOM_GCP_ALL_PROJECTS` (same Connections vs Job split as `orgInventory`) |
| `controlPlane.connectionsScheduler.enabled` | `false` | Injects `AGENT_BOM_CONNECTIONS_SCHEDULER=1` on the API; still requires per-connection `scan_interval_minutes` |
| `collectorImage.repository` | `agentbom/agent-bom-collector` | Cloud-SDK collector image the scan CronJob runs |
| `collectorImage.tag` | release version | Collector tag — override to bump the SDK layer independently of the control plane; blank falls back to `image.tag` |
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
