# Helm Example Profiles

These files are the canonical packaged deployment profiles for the `agent-bom`
Helm chart. They are meant to reduce day-0 decision sprawl, not create a new
product split.

## Shipped profiles

| Profile | File | Intended use |
|---|---|---|
| `sqlite-pilot` | `eks-control-plane-sqlite-pilot-values.yaml` | Single-node packaged demo or short-lived pilot where Postgres is not ready yet |
| `focused-pilot` | `eks-mcp-pilot-values.yaml` | Narrow EKS pilot with control plane, scanner, and tightened ingress |
| `enterprise-demo` | `eks-mcp-pilot-values.yaml` + `eks-enterprise-demo-overlay.yaml` | Focused pilot plus scheduled AWS estate inventory (IRSA, `AGENT_BOM_AWS_INVENTORY=1`) |
| `byo-postgres` | `byo-postgres-values.yaml` | Overlay for operator-owned Postgres-compatible databases, including Snowflake Postgres candidates |
| `production` | `eks-production-values.yaml` | Postgres-backed production EKS rollout with autoscaling, backup, and ExternalSecrets |
| `keda-autoscaling` | `eks-production-values.yaml` + `eks-keda-values.yaml` + `gateway-upstreams.example.yaml` | Production overlay with KEDA-backed API and gateway autoscaling |
| `eks-vanilla` | `eks-vanilla-values.yaml` | Postgres-backed production EKS rollout with ALB, IRSA, Kubernetes Secrets, and no service mesh / ESO / cert-manager requirement |
| `mesh-hardening` | `eks-istio-kyverno-values.yaml` | Overlay for Istio mTLS/authz and Kyverno policy-controller packaging |
| `collector-mtls` | `collector-mtls-values.yaml` | Scanner fleet-sync push with client TLS + delegated control-plane mTLS posture env |
| `oidc-discovery-shim` | `eks-mcp-pilot-values.yaml` + `gateway-upstreams.example.yaml` + `oidc-discovery-shim-values.yaml` | Gateway-hosted `/.well-known/openid-configuration` for legacy IdPs (MCP OAuth interop) |
| `snowflake-backend` | `eks-snowflake-values.yaml` | Overlay for Snowflake governance and selected store parity, not a claim of full control-plane replacement |
| `gateway-runtime` | `eks-mcp-pilot-values.yaml` + `gateway-upstreams.example.yaml` | Focused pilot plus central gateway rendering for shared MCP relay/policy |
| `control-plane-identity` | `control-plane-identity-values.yaml` | Keyless control-plane cloud identity (EKS IRSA / EC2-ECS instance role / AKS + GKE workload identity) that assumes read-only connect roles — zero static keys. See `docs/DEPLOY_PLATFORM.md` "Connect your cloud (zero keys)" |

## Validate the shipped profiles

With Helm installed:

```bash
python scripts/validate_helm_profiles.py
```

List the profile names without rendering:

```bash
python scripts/validate_helm_profiles.py --list
```

Render only one profile:

```bash
python scripts/validate_helm_profiles.py --profile focused-pilot
```

## Install a shipped profile in one command

Print the exact Helm command for a profile:

```bash
python scripts/install_helm_profile.py focused-pilot --print-command
```

Run the packaged focused EKS pilot profile directly:

```bash
python scripts/install_helm_profile.py focused-pilot
```

Append your own values file or targeted overrides without forking the shipped profile:

```bash
python scripts/install_helm_profile.py production \
  --values ./my-prod-overrides.yaml \
  --set controlPlane.ingress.hosts[0].host=agent-bom.acme.internal
```

## Control-plane secrets (create these before `helm install`)

No chart template renders the control-plane Secrets — you create them
out-of-band from a real secret manager (External Secrets Operator, SOPS, AWS
Secrets Manager, CI store) and keep the populated files out of git. A profile
whose `controlPlane.api.envFrom` references a Secret that does not exist leaves
the API/UI pods in `CreateContainerConfigError`, and the multi-replica profiles
additionally fail closed at boot when the browser-session / audit keys are
absent. Two example manifests document every key:

- `postgres-secret.example.yaml` → `agent-bom-control-plane-db`
  (`AGENT_BOM_POSTGRES_URL`). Used by the split-Secret profiles (`eks-vanilla`).
- `control-plane-auth-secret.example.yaml` → the auth/session keys
  (`AGENT_BOM_BROWSER_SESSION_SIGNING_KEY`, `AGENT_BOM_AUDIT_HMAC_KEY`,
  `AGENT_BOM_CONNECTIONS_KEY`, `AGENT_BOM_API_KEYS`, and — for the combined
  single-Secret profiles — `AGENT_BOM_POSTGRES_URL`). It carries one block per
  profile; copy the block matching your profile.

Generate the placeholder values with:

```bash
openssl rand -hex 32   # AGENT_BOM_BROWSER_SESSION_SIGNING_KEY, AGENT_BOM_AUDIT_HMAC_KEY
openssl rand -hex 24   # AGENT_BOM_API_KEYS key (append ":admin")
python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"  # AGENT_BOM_CONNECTIONS_KEY
```

Which keys each profile requires, and its first-run login posture:

| Profile | Secret(s) `envFrom` references | Required keys | First-run login |
|---|---|---|---|
| `focused-pilot` (`eks-mcp-pilot`) | `agent-bom-control-plane` (combined) | `AGENT_BOM_POSTGRES_URL`, `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY` (replicas 2), `AGENT_BOM_CONNECTIONS_KEY`, `AGENT_BOM_API_KEYS` | Seeded `AGENT_BOM_API_KEYS` admin key |
| `eks-vanilla` | `agent-bom-control-plane-db` + `agent-bom-control-plane-auth` | db: `AGENT_BOM_POSTGRES_URL`; auth: `AGENT_BOM_BROWSER_SESSION_SIGNING_KEY` (replicas 2), `AGENT_BOM_AUDIT_HMAC_KEY` (`REQUIRE_AUDIT_HMAC=1`), `AGENT_BOM_CONNECTIONS_KEY`, `AGENT_BOM_API_KEYS` | Seeded `AGENT_BOM_API_KEYS` admin key |
| `sqlite-pilot` | `agent-bom-control-plane` (demo) | `AGENT_BOM_CONNECTIONS_KEY` only (sqlite, replicas 1) | Anonymous — the profile sets a **visible, demo-only** `AGENT_BOM_ALLOW_UNAUTHENTICATED_API=1` (viewer role). Not for production |

Swap `AGENT_BOM_API_KEYS` for the OIDC block
(`AGENT_BOM_OIDC_ISSUER` / `AGENT_BOM_OIDC_CLIENT_ID` /
`AGENT_BOM_OIDC_REDIRECT_URI` / `AGENT_BOM_OIDC_CLIENT_SECRET`) on the API env
when an IdP is available. Session cookies are marked `Secure` automatically on
the clustered/production profiles (replicas > 1), so no cookie flag is needed;
the sqlite demo intentionally leaves it off so login works over plain HTTP.

## Operator guidance

- The chart intentionally does not install a Postgres subchart. Production
  profiles consume an operator-managed database through
  `AGENT_BOM_POSTGRES_URL`, either from External Secrets Operator
  (`production`) or a Kubernetes Secret (`eks-vanilla`).
- Use `byo-postgres-values.yaml` as an overlay when the platform team provides
  a Postgres-compatible database such as RDS/Aurora Postgres, Cloud SQL for
  PostgreSQL, Azure Database for PostgreSQL, Supabase, Crunchy/EDB, or
  Snowflake Postgres. Treat new providers as smoke-test required until API,
  graph, fleet, policy, audit, and backup/restore posture are verified.
- For Kubernetes Secrets without External Secrets Operator, start from
  `postgres-secret.example.yaml`, create the real secret out-of-band, and keep
  the credential out of values files and git.
- Start with `focused-pilot` for the narrow customer EKS story.
- Use `sqlite-pilot` only for demos or single-node packaged pilots.
- Move to `eks-vanilla` when you run EKS with ALB, IRSA, RDS/Postgres, and
  Kubernetes Secrets but not Istio, External Secrets Operator, or cert-manager.
- Move to `production` when you also run External Secrets and cert-manager.
- Treat `mesh-hardening` and `snowflake-backend` as overlays, not separate products.
- Treat `snowflake-backend` as a warehouse-native deployment mode with explicit parity boundaries, not the default production path.
- Gateway remains an optional runtime surface layered onto the control plane, not a mandatory chokepoint.
- Graph snapshot retention defaults to ``AGENT_BOM_GRAPH_RETENTION_DAYS`` (180). Per-tenant
  windows can be set with ``AGENT_BOM_GRAPH_RETENTION_OVERRIDES`` JSON on the API deployment or
  persisted in the control-plane tenant retention store. Local analytics and runtime observations
  are capped on write with ``AGENT_BOM_ANALYTICS_MAX_EVENTS``; on-disk CLI history uses
  ``AGENT_BOM_HISTORY_MAX_REPORTS``.
