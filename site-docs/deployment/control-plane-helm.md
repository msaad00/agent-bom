# Packaged API + UI Control Plane

`agent-bom` now ships a Helm-packaged control plane for teams that want the API
and dashboard inside their own Kubernetes environment instead of running custom
Deployment manifests by hand.

This is the right path when you want:

- the API and UI in your own cluster
- same-origin browser traffic through your own ingress
- Postgres, ClickHouse, SSO, and secrets kept in your own environment
- the scanner CronJob and optional runtime monitor packaged alongside the
  control plane
- production operator defaults without pretending there is a managed vendor plane

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
    H[OIDC or SAML / API key auth] --> D
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
  OIDC, SAML-issued session keys, or an explicit insecure override
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

## Production defaults example

For the stronger self-hosted operator path, start from:

- [deploy/helm/agent-bom/examples/eks-production-values.yaml](/Users/mohamedsaad/Desktop/Agent-Bom/deploy/helm/agent-bom/examples/eks-production-values.yaml)
- [Performance, Sizing, and Benchmarks](performance-and-sizing.md)

That example adds:

- `HPA` for API and UI
- `HPA` scale-down stabilization
- topology spread across zones and nodes
- preferred pod anti-affinity for API and UI replicas
- optional control-plane `PriorityClass`
- fail-closed shared rate limiting when the Postgres-backed limiter is unavailable
- `cert-manager` ingress annotations and TLS wiring
- `external-secrets` integration for the control-plane secrets, including split refresh cadence for DB vs auth/HMAC material
- packaged `PrometheusRule` alerts for API error rate, scanner failures, OIDC decode failures, and proxy audit backlog
- packaged Grafana dashboard `ConfigMap` for clusters that already watch dashboard config
- packaged Postgres backup `CronJob` that runs `pg_dump` and uploads to S3 through IRSA with SSE or KMS
- restricted ingress defaults for the chart network policy

## What you still own

This is a real packaged control plane, but not a magic managed service.

You still own:

- Postgres and optional ClickHouse
- ingress controller and TLS
- OIDC or SAML IdP configuration, or API key secret management
- cluster-specific autoscaling thresholds and failure-domain policy
- operator runbooks and load testing

## Production guidance

- keep `controlPlane.api.replicas` and `controlPlane.ui.replicas` at `2+`
- use `Postgres`, not SQLite
- run Alembic for long-lived Postgres control planes:
  - `alembic -c deploy/supabase/postgres/alembic.ini upgrade head`
  - existing `init.sql` databases should be stamped once with `20260416_01`
- enable the control-plane HPAs before higher-volume rollout
- use anti-affinity and a control-plane `PriorityClass` when you expect node pressure
- enable topology spread when you run multi-AZ EKS
- keep same-origin ingress unless you have a strong reason not to
- use `envFrom` / Secrets for `AGENT_BOM_POSTGRES_URL`, API keys, OIDC issuer,
  audience, optional required nonce, SAML IdP/SP metadata values, and audit
  HMAC settings
- enforce API key lifetime policy with `AGENT_BOM_API_KEY_DEFAULT_TTL_SECONDS`
  and `AGENT_BOM_API_KEY_MAX_TTL_SECONDS`; admin key replacement uses
  `POST /v1/auth/keys/{key_id}/rotate` so rotation stays explicit and audited
- split fast-rotating auth secrets from slower DB config with `controlPlane.externalSecrets.secrets[]`
  so `AGENT_BOM_OIDC_*`, `AGENT_BOM_SAML_*`, and `AGENT_BOM_AUDIT_HMAC_KEY`
  can refresh at `5m`
  while `AGENT_BOM_POSTGRES_URL` stays at `1h`
- set `AGENT_BOM_REQUIRE_SHARED_RATE_LIMIT=1` for multi-replica production
  control planes so the API refuses to start if the shared limiter backend is unavailable
- enable `controlPlane.observability.prometheusRule.enabled=true` when the cluster already runs Prometheus Operator
- enable `controlPlane.observability.grafanaDashboard.enabled=true` when Grafana watches dashboard `ConfigMap`s
- enable `controlPlane.backup.enabled=true` only after setting a real S3 bucket, prefix, and IRSA-backed upload permissions
- set `controlPlane.backup.destination.bucketRegion` to the actual region of your backup bucket; the production example intentionally uses `REPLACE_ME_BUCKET_REGION`
- `controlPlane.backup.destination.region` remains as a backward-compatible fallback for older values files
- keep `controlPlane.backup.destination.encryption.enabled=true`; the default is `AES256`, and production should set `mode=aws:kms` with a dedicated `kmsKeyId`
- restore drills should use [`deploy/ops/restore-postgres-backup.sh`](../../deploy/ops/restore-postgres-backup.sh):
  `./deploy/ops/restore-postgres-backup.sh s3://bucket/key.dump "$AGENT_BOM_POSTGRES_URL" REPLACE_ME_BUCKET_REGION`
- expose `GET /v1/auth/saml/metadata` to your IdP admins and keep
  `POST /v1/auth/saml/login` behind the same ingress hostname as the API
- enable PDBs when you are running multi-replica workloads

## Current boundary

The chart now packages the control plane honestly, but it still does not claim:

- a bundled Postgres subchart
- benchmarked throughput guarantees
- completed auth hardening beyond the currently shipped server contract

Those are the next operator-hardening layers, not hidden assumptions.
