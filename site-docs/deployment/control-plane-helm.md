# Packaged API + UI Control Plane

`agent-bom` now ships a Helm-packaged control plane for teams that want the API
and dashboard inside their own Kubernetes environment instead of running custom
Deployment manifests by hand.

This is the right path when you want:

- the API and UI in your own cluster
- same-origin browser traffic through your own ingress
- Postgres, ClickHouse, OIDC, and secrets kept in your own environment
- the scanner CronJob and optional runtime monitor packaged alongside the
  control plane

## What the chart deploys

When you set `controlPlane.enabled=true`, the Helm chart can package:

- API Deployment + Service
- UI Deployment + Service
- same-origin Ingress that routes API paths to the API service and `/` to the UI
- scanner CronJob
- optional runtime monitor DaemonSet

```mermaid
flowchart LR
    A[Browser] --> B[Ingress]
    B -->|/| C[agent-bom-ui Service]
    B -->|/v1 /health /docs /ws| D[agent-bom-api Service]
    D --> E[(Postgres)]
    D --> F[(ClickHouse optional)]
    G[Scanner CronJob] --> D
    H[OIDC / API key auth] --> D
```

## Same-origin default

The UI runtime contract from `#1452` is what makes this honest.

By default the chart leaves `NEXT_PUBLIC_API_URL` blank in the UI pod, so the
browser uses relative paths:

- `/v1/*`
- `/health`
- `/docs`
- `/redoc`
- `/openapi.json`
- `/ws/*`

The packaged ingress routes those paths to the API service and everything else
to the UI service. That means:

- one hostname
- no CORS setup for the default path
- no UI image rebuild per environment

If you want cross-origin instead, set `controlPlane.ui.env` so
`NEXT_PUBLIC_API_URL` points at the API host you own.

## Secure-by-default boundaries

The chart packages the control plane, but it does not quietly weaken the
runtime model.

- API and UI pods run with `automountServiceAccountToken: false`
- the discovery service account and IRSA path stay attached to the scanner
- the API still refuses non-loopback startup without `AGENT_BOM_API_KEY`,
  OIDC, or an explicit insecure override
- same-origin ingress avoids default CORS sprawl
- network policy stays enabled, with configurable ingress restrictions

## Minimal values example

Create a Secret with the database URL and auth settings you actually use:

```bash
kubectl create secret generic agent-bom-control-plane \
  -n agent-bom \
  --from-literal=AGENT_BOM_POSTGRES_URL='postgresql://agent_bom:...@postgres-rw:5432/agent_bom' \
  --from-literal=AGENT_BOM_API_KEY='replace-me'
```

Then install with a values file like:

```yaml
controlPlane:
  enabled: true
  api:
    envFrom:
      - secretRef:
          name: agent-bom-control-plane
  ingress:
    enabled: true
    className: nginx
    hosts:
      - host: agent-bom.internal.example.com

scanner:
  enabled: true
  allNamespaces: true

serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::123456789012:role/agent-bom-discovery
```

Install:

```bash
helm install agent-bom deploy/helm/agent-bom \
  -n agent-bom --create-namespace \
  -f values.agent-bom.yaml
```

## What you still own

This is a real packaged control plane, but not a magic managed service.

You still own:

- Postgres and optional ClickHouse
- ingress controller and TLS
- OIDC provider configuration or API key secret management
- HPA, topology spread, and cluster-specific scaling policy
- operator runbooks and load testing

## Production guidance

- keep `controlPlane.api.replicas` and `controlPlane.ui.replicas` at `2+`
- use `Postgres`, not SQLite
- keep same-origin ingress unless you have a strong reason not to
- use `envFrom` / Secrets for `AGENT_BOM_POSTGRES_URL`, API keys, OIDC issuer,
  audience, and audit HMAC settings
- enable PDBs when you are running multi-replica workloads

## Current boundary

The chart now packages the control plane honestly, but it still does not claim:

- a bundled Postgres subchart
- built-in autoscaling or benchmarked throughput guarantees
- completed auth hardening beyond the currently shipped server contract

Those are the next operator-hardening layers, not hidden assumptions.
