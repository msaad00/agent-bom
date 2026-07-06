# agent-bom deployment runbook

Operator runbook for multicloud collectors, cross-cloud federation, and
post-install onboarding. Complements [`docs/DEPLOY_QUICKSTART.md`](../docs/DEPLOY_QUICKSTART.md).

---

## Quick entry

```bash
scripts/deploy/install.sh list
scripts/deploy/install.sh pilot                    # local proof
scripts/deploy/install.sh eks --create-cluster     # AWS production path
scripts/deploy/install.sh connect aws              # read-only account onboarding
scripts/deploy/install.sh onboard --url URL --api-key KEY
```

---

## Control-plane + collector seam

```
  control plane (you run)          collector / connect (read-only in customer cloud)
  ───────────────────────          ─────────────────────────────────────────────
  API + UI + Postgres + graph  ←── IAM / RBAC / SA roles (connect-* Terraform)
  fleet ingest /v1/fleet/sync
  POST /v1/cloud/connections
```

The control plane is the same Helm chart / Docker images everywhere. Collectors
are read-only principals minted by `deploy/terraform/connect-*`.

---

## Per-cloud collector starting points

| Cloud | Connect module | Helm collector overlay |
|-------|----------------|------------------------|
| AWS | `deploy/terraform/connect-aws` | `eks-collector-irsa-values.yaml` |
| Azure | `deploy/terraform/connect-azure` | `aks-collector-workload-identity-values.yaml` |
| GCP | `deploy/terraform/connect-gcp` | `gke-collector-workload-identity-values.yaml` |
| Snowflake | `deploy/terraform/connect-snowflake` | key-pair Secret in `multicloud-collector-values.yaml` |
| All four | apply each connect module | `multicloud-collector-values.yaml` |

Enable inventory in Helm:

```yaml
scanner:
  enabled: true
  cloud:
    enabled: true
    aws:   { inventory: true }
    azure: { inventory: true }
    gcp:   { inventory: true }
    snowflake: { inventory: true, account: "...", user: "...", keySecretName: "..." }
```

Or per-provider env flags — see [`docs/CLOUD_CONNECT.md`](../docs/CLOUD_CONNECT.md).

---

## Cross-cloud federation

`multicloud-collector-values.yaml` runs **one CronJob on EKS** and reaches AWS +
GCP + Azure + Snowflake. Two supported patterns:

### Pattern A — Single-cloud collectors (simplest)

Run a collector **native to each cloud** with that cloud's workload identity:

1. EKS + `eks-collector-irsa-values.yaml` → AWS inventory
2. AKS + `aks-collector-workload-identity-values.yaml` → Azure inventory
3. GKE + `gke-collector-workload-identity-values.yaml` → GCP inventory
4. Snowflake key-pair Secret on whichever cluster runs the Snowflake scan job

Each collector pushes to the same control plane (`AGENT_BOM_PUSH_URL` or API
cloud connection scans). **Recommended for production.**

### Pattern B — Multicloud CronJob on EKS (advanced)

One pod on EKS with:

- **AWS:** IRSA role (`eks.amazonaws.com/role-arn`)
- **GCP:** Workload Identity Federation — `connect-gcp` README § workload identity pool trusting the EKS OIDC issuer; annotate SA with `iam.gke.io/gcp-service-account`
- **Azure:** Federated credential on the EKS OIDC issuer → `azure.workload.identity/client-id` annotation
- **Snowflake:** PEM key in Kubernetes Secret (no cloud WI); passphrase via optional Secret

Prereqs:

1. EKS OIDC provider enabled on the cluster
2. `connect-gcp` / `connect-azure` federation configured to trust that issuer
3. `multicloud-collector-values.yaml` values filled with real ARNs/client IDs
4. NetworkPolicy egress allowed to cloud APIs + Snowflake

If federation is not configured, use Pattern A.

---

## Post-install onboarding checklist

1. **Health** — `GET /healthz` returns 200
2. **Auth** — API key or OIDC; non-loopback fails closed without auth
3. **Connect** — at least one `connect-*` module applied; register via API or Helm
4. **Scan** — `POST /v1/scan` or wait for CronJob; findings appear in Queue
5. **Fleet** — `proxy-bootstrap` bundle on a pilot workstation; `POST /v1/fleet/sync` succeeds
6. **Graph** — non-empty nodes after connect + fleet
7. **Smoke** — `scripts/pilot-verify.sh <url> <key>` or `scripts/release_smoke.sh`

---

## Snowflake lanes

| Lane | When | Doc |
|------|------|-----|
| Self-hosted POV | API/UI in customer K8s/VM; Snowflake read-only | `site-docs/deployment/snowflake-pov.md` |
| Native App + SPCS | In-account install; scanner/MCP runtime opt-in | `docs/snowflake-native-app/INSTALL.md` |
| Warehouse backend | Export findings to Snowflake tables | `snowflake-backend` Helm profile |

---

## Teardown

```bash
scripts/deploy/teardown-eks-reference.sh    # EKS reference install
helm uninstall agent-bom -n agent-bom        # Helm-only
cd deploy/terraform/connect-aws && terraform destroy   # per connect module
```

---

## Related

- [`docs/DEPLOY_QUICKSTART.md`](../docs/DEPLOY_QUICKSTART.md)
- [`docs/DEPLOY_PLATFORM.md`](../docs/DEPLOY_PLATFORM.md)
- [`deploy/terraform/README.md`](terraform/README.md)
- [`deploy/helm/agent-bom/examples/README.md`](helm/agent-bom/examples/README.md)
