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
- a clean split between the API/runtime image and the standalone UI image

## What the chart deploys

When you set `controlPlane.enabled=true`, the Helm chart can package:

- API Deployment + Service
- UI Deployment + Service
- same-origin Ingress that routes API paths to the API service and `/` to the UI
- scanner CronJob
- optional runtime monitor DaemonSet

The image split is intentional:

- `agentbom/agent-bom` runs the API, scanner jobs, gateway, proxy-related
  entrypoints, and other non-browser workloads
- `agentbom/agent-bom-ui` runs the standalone browser UI that sits behind the
  same ingress or a separate UI service

## Enterprise deployment topology

Use two diagrams, not one overloaded graph:

- **deployment topology** for what the Helm install actually puts in your
  environment
- **runtime MCP flow** for how proxy, gateway, API, and upstream MCP traffic
  interact

Everything agent-bom ships runs inside one trust boundary: the customer's VPC,
EKS account, or self-managed cluster. The normal cross-boundary paths are
inbound OIDC and outbound, policy-audited MCP upstream calls. Enrichment to
OSV/NVD is optional and allow-listable.

| Layer | Lives in | Scales via | Talks to |
|---|---|---|---|
| **Ingress + auth** | ALB / Istio Gateway + OIDC | — | Corporate IdP (Okta / Entra / Google) |
| **Runtime MCP plane** | `gateway` + selected `proxy` sidecars / local wrappers | HPA + PDB | Remote MCPs, `/v1/proxy/audit` |
| **Control plane** | `api`, `ui`, `jobs`, `backup` (Helm) | HPA + CronJob | Data plane, OTEL, Prometheus |
| **Data plane** | Customer-owned Postgres (+ optional ClickHouse, S3) | Operator-managed | — |
| **Platform glue** | ExternalSecrets, ServiceMonitor, OTEL collector | Operator-managed | AWS Secrets Manager / Vault / Grafana |

```mermaid
flowchart TB
    classDef ext  fill:#0b1220,stroke:#475569,color:#cbd5e1,stroke-dasharray:3 3
    classDef edge fill:#111827,stroke:#38bdf8,color:#e0f2fe
    classDef ctrl fill:#0f172a,stroke:#6366f1,color:#e0e7ff
    classDef run  fill:#0f172a,stroke:#10b981,color:#d1fae5
    classDef data fill:#0f172a,stroke:#f59e0b,color:#fef3c7
    classDef ops  fill:#0f172a,stroke:#64748b,color:#cbd5e1

    Browser["Browser operators"]:::ext
    IdP["Corporate IdP"]:::ext
    CI["CI + scheduled scans"]:::ext
    Remote["Remote MCPs"]:::ext
    Intel["OSV / NVD / GHSA<br/>optional enrichment"]:::ext

    subgraph Customer["Customer VPC / EKS / self-managed cluster"]
      direction TB
      Ingress["Ingress + TLS"]:::edge

      subgraph Control["Control plane"]
        direction LR
        UI["UI<br/>same-origin browser app"]:::ctrl
        API["API<br/>auth · findings · fleet · audit"]:::ctrl
        Jobs["Workers<br/>CronJob / Job"]:::ctrl
        Backup["Backup job"]:::ctrl
      end

      subgraph Runtime["Runtime MCP plane"]
        direction LR
        Proxy["Proxy<br/>sidecar or laptop wrapper"]:::run
        Gateway["Gateway<br/>agent-bom gateway serve"]:::run
      end

      subgraph Data["Customer-owned data"]
        direction LR
        PG[("Postgres / Supabase")]:::data
        CH[("ClickHouse optional")]:::data
        S3[("S3 optional")]:::data
      end

      subgraph Platform["Platform services"]
        direction LR
        Secrets["ExternalSecrets / IRSA / Vault"]:::ops
        Obs["OTEL + Prometheus"]:::ops
      end
    end

    Browser --> Ingress
    IdP -. OIDC .-> Ingress
    Ingress --> UI
    UI -->|same-origin API calls| API
    CI --> Jobs
    Jobs -->|results + inventory| API
    Proxy -->|audited relay| Gateway
    Gateway -->|POST /v1/proxy/audit| API
    Gateway -->|policy-audited upstream| Remote
    API --> PG
    API -. optional analytics .-> CH
    Backup --> S3
    Secrets --> API
    Secrets --> Gateway
    API --> Obs
    Gateway --> Obs
    API -. optional egress .-> Intel
```

*Deployment truth: the UI is not the collector. The browser drives workflows,
the API owns control-plane state, workers do scans, and proxy plus gateway
handle runtime MCP traffic. For the role split, see the [Self-Hosted Product
Architecture](../architecture/self-hosted-product-architecture.md).*

### MCP proxy and gateway runtime flow

```mermaid
sequenceDiagram
    participant Client as Developer or workload client
    participant Proxy as agent-bom proxy
    participant Gateway as agent-bom gateway
    participant API as Control-plane API
    participant Remote as Remote MCP
    participant Store as Postgres / audit store

    Client->>Proxy: MCP JSON-RPC (stdio / SSE / HTTP)
    Proxy->>Proxy: local policy + runtime checks
    Proxy->>Gateway: audited relay
    Gateway->>API: policy fetch / POST /v1/proxy/audit
    Gateway->>Remote: upstream MCP call
    Remote-->>Gateway: MCP response
    Gateway-->>Proxy: response + shared policy result
    Proxy->>Proxy: optional VLD / OCR redaction
    Proxy-->>Client: safe response
    API->>Store: persist audit, findings, graph links
```

1. The client talks to a local or sidecar `agent-bom proxy`.
2. The proxy applies local runtime checks and relays to the central
   `agent-bom gateway`.
3. The gateway evaluates shared policy, records audit to `/v1/proxy/audit`,
   then calls the remote MCP upstream.
4. The response returns on the same path; image responses can run through the
   visual leak detector before the client sees them.
5. The API persists audit, findings, and graph links for the UI, exports, and
   compliance surfaces.

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
  --version 0.80.1 \
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
  --version 0.80.1 \
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
