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

## Enterprise deployment topology

Everything agent-bom ships runs inside one trust boundary — the customer's
VPC, EKS account, or self-managed cluster. The only arrows that cross that
boundary are OIDC (inbound, terminated at ingress) and policy-audited MCP
upstream calls (outbound). Enrichment to OSV/NVD is optional and
allow-listable.

| Layer | Lives in | Scales via | Talks to |
|---|---|---|---|
| **Ingress + auth** | ALB / Istio Gateway + OIDC | — | Corporate IdP (Okta / Entra / Google) |
| **MCP traffic plane** | `gateway` + `proxy` Deployments | HPA + PDB | Remote MCPs, `/v1/proxy/audit` |
| **Control plane** | `api`, `ui`, `jobs`, `backup` (Helm) | HPA + CronJob | Data plane, OTEL, Prometheus |
| **Data plane** | Customer-owned Postgres (+ optional ClickHouse, S3) | Operator-managed | — |
| **Platform glue** | ExternalSecrets, ServiceMonitor, OTEL collector | Operator-managed | AWS Secrets Manager / Vault / Grafana |

```mermaid
flowchart LR
    subgraph outside["Outside customer trust boundary"]
      dev["Developer laptop<br/>Claude Desktop · Cursor · Claude Code"]
      gh["GitHub<br/>Actions runner"]
      osv["OSV / NVD / GHSA<br/>optional egress, allow-listable"]
      mcp_saas["Remote MCPs<br/>SaaS + partner tools"]
      idp["Corporate IdP<br/>Okta · Entra · Google"]
    end

    subgraph vpc["Customer VPC / EKS account — single trust boundary"]
      ingress["Ingress + TLS<br/>ALB / Istio Gateway"]

      subgraph cp["Control plane — Helm chart: agent-bom"]
        api["API + UI<br/>2× Deployment + HPA + PDB"]
        gw["MCP gateway<br/>Deployment + HPA<br/>agent-bom gateway serve"]
        px["MCP proxy sidecar<br/>stdio · SSE · HTTP<br/>sidecar or laptop wrapper"]
        jobs["Scan + ingest workers<br/>CronJob + Job"]
        backup["Backup CronJob<br/>pg_dump → S3"]
      end

      subgraph glue["Platform integration"]
        es["ExternalSecrets<br/>AWS SM / Vault"]
        otel["OTEL collector<br/>traces + metrics"]
        prom["Prometheus<br/>ServiceMonitor"]
      end

      subgraph dataplane["Data plane in your account"]
        pg["Postgres / Supabase<br/>jobs · fleet · graph · audit"]
        ch["ClickHouse (optional)<br/>analytics + long-retention"]
        s3["S3 (optional)<br/>backups + SBOM archive"]
      end
    end

    idp -. OIDC .-> ingress
    ingress --> api
    ingress --> gw

    dev -->|MCP JSON-RPC| px
    px -->|audited relay| gw
    gw -->|policy + audit| mcp_saas
    gw -->|/v1/proxy/audit| api

    gh -->|SARIF + findings| api

    jobs --> api
    api --> pg
    api -. optional .-> ch
    backup --> s3

    api -. optional egress .-> osv

    es --> api
    es --> gw
    api --> otel
    gw --> otel
    api --> prom
    gw --> prom
```

*Everything in the boundary runs in your account. Only OIDC (inbound) and
MCP upstream calls (outbound, policy-audited) cross it.*

### How an MCP call actually flows

1. Developer client (Claude Desktop / Cursor / Claude Code) speaks MCP
   JSON-RPC to the local `agent-bom proxy` (stdio or SSE).
2. The proxy inspects and audits the call, enforces policy, then relays to
   the central `agent-bom gateway` inside your cluster.
3. The gateway applies shared policy, records the audit event to
   `/v1/proxy/audit`, and forwards to the remote MCP upstream.
4. Responses flow back on the same path; screenshot/image responses run
   through the `VisualLeakDetector` for OCR-based redaction before the
   developer sees them.
5. Every hop emits OTEL spans with a W3C trace context, so a single trace
   ties developer → proxy → gateway → remote MCP → back.

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
- multi-replica API deployments now require a PostgreSQL-backed shared rate-limit
  store; the chart exports the replica floor and the API fails closed instead of
  silently falling back to process-local limits
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
      eks.amazonaws.com/role-arn: arn:aws:iam::REPLACE_ME_ACCOUNT_ID:role/REPLACE_ME_AGENT_BOM_DISCOVERY_ROLE

serviceAccount:
  annotations:
    eks.amazonaws.com/role-arn: arn:aws:iam::REPLACE_ME_ACCOUNT_ID:role/REPLACE_ME_AGENT_BOM_DISCOVERY_ROLE
```

The chart supports component-specific service-account overrides for scanner, gateway, and backup jobs. If you omit the component-specific annotations, they inherit the shared `serviceAccount.annotations` block.

Install:

```bash
helm install agent-bom oci://ghcr.io/msaad00/charts/agent-bom \
  --version 0.79.0 \
  -n agent-bom --create-namespace \
  -f values.agent-bom.yaml
```

## Single-node SQLite pilot preset

For a fast in-cluster pilot without external Postgres, use the shipped
single-node preset:

- [eks-control-plane-sqlite-pilot-values.yaml](https://github.com/msaad00/agent-bom/blob/main/deploy/helm/agent-bom/examples/eks-control-plane-sqlite-pilot-values.yaml)

Create the auth secret and a small PVC first:

```bash
kubectl create secret generic agent-bom-control-plane \
  -n agent-bom \
  --from-literal=AGENT_BOM_API_KEY='replace-me'

kubectl apply -n agent-bom -f - <<'EOF'
apiVersion: v1
kind: PersistentVolumeClaim
metadata:
  name: agent-bom-sqlite-pilot
spec:
  accessModes: ["ReadWriteOnce"]
  resources:
    requests:
      storage: 10Gi
EOF
```

Then install:

```bash
helm install agent-bom oci://ghcr.io/msaad00/charts/agent-bom \
  --version 0.79.0 \
  -n agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-control-plane-sqlite-pilot-values.yaml
```

This preset is intentionally single-node only: one API pod, one UI pod, PVC-backed
SQLite state, no HPA, no PDB, and no multi-replica availability claims.

## Production defaults example

For the stronger self-hosted operator path, start from:

- [eks-production-values.yaml](https://github.com/msaad00/agent-bom/blob/main/deploy/helm/agent-bom/examples/eks-production-values.yaml)
- [Performance, Sizing, and Benchmarks](performance-and-sizing.md)

That example adds:

- `HPA` for API and UI
- `ServiceMonitor` enabled in the production preset so `/metrics` is scraped when Prometheus Operator is present
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
- dedicated service-account hooks for gateway and backup jobs, inheriting the scanner IRSA annotations unless you override them
- restricted ingress defaults for the chart network policy

For clusters that already standardize on a service mesh and policy controller,
start from:

- [eks-istio-kyverno-values.yaml](https://github.com/msaad00/agent-bom/blob/main/deploy/helm/agent-bom/examples/eks-istio-kyverno-values.yaml)

That example adds:

- packaged Istio `PeerAuthentication` for strict mTLS on `agent-bom` pods
- packaged Istio `AuthorizationPolicy` that keeps same-namespace traffic and explicitly whitelisted ingress namespaces
- packaged namespaced Kyverno `Policy` that enforces the same restricted pod contract already used by the chart

This is intentionally an opt-in hardening layer. It composes with the chart's
existing `NetworkPolicy`, PSS-restricted pod settings, anti-affinity, and HPA
defaults instead of replacing them.

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
- tune Postgres-backed control planes explicitly with
  `AGENT_BOM_POSTGRES_POOL_MIN_SIZE`, `AGENT_BOM_POSTGRES_POOL_MAX_SIZE`,
  `AGENT_BOM_POSTGRES_CONNECT_TIMEOUT_SECONDS`, and
  `AGENT_BOM_POSTGRES_STATEMENT_TIMEOUT_MS`
- enable `controlPlane.observability.prometheusRule.enabled=true` when the cluster already runs Prometheus Operator
- keep `monitor.enabled=true` and `monitor.serviceMonitor.enabled=true` in the production preset unless your platform team has a different scrape contract
- enable `controlPlane.observability.grafanaDashboard.enabled=true` when Grafana watches dashboard `ConfigMap`s
- enable `controlPlane.backup.enabled=true` only after setting a real S3 bucket, prefix, and IRSA-backed upload permissions
- enable `controlPlane.serviceMesh.enabled=true` only when the control-plane namespace is already part of your Istio data plane
- keep `controlPlane.serviceMesh.istio.authorizationPolicy.allowedNamespaces` explicit; the packaged example allows `ingress-nginx` and `istio-system`, but production should match your real ingress path
- enable `controlPlane.policyController.enabled=true` only when Kyverno is already installed cluster-wide; the chart packages the namespaced policy, not the controller itself
- set `controlPlane.backup.destination.bucketRegion` to the actual region of your backup bucket; the production example intentionally uses `REPLACE_ME_BUCKET_REGION`
- `controlPlane.backup.destination.region` remains as a backward-compatible fallback for older values files
- keep `controlPlane.backup.destination.encryption.enabled=true`; the default is `AES256`, and production should set `mode=aws:kms` with a dedicated `kmsKeyId`
- restore drills should use [`deploy/ops/restore-postgres-backup.sh`](https://github.com/msaad00/agent-bom/blob/main/deploy/ops/restore-postgres-backup.sh):
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
