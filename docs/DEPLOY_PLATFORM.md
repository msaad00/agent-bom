# Deploy agent-bom anywhere

> **Quickstart:** [`DEPLOY_QUICKSTART.md`](DEPLOY_QUICKSTART.md) — one script,
> connect-and-scan onboarding (deploy → connect accounts → inventory → scans).
> Run `scripts/deploy/install.sh list` from the repo root.

agent-bom is one product with one control plane (API + UI) and a stateless
scanner. You can run that control plane wherever you want it — on a laptop, on
your own Kubernetes cluster, or as a hosted service where you operate the
control plane and customers connect read-only. This guide covers all three
tiers, each with the exact command.

## Deployment doc set

This page is the docs-tree hub for deployment. Each sibling owns one job:

| Doc | Purpose |
|---|---|
| [`site-docs/deployment/overview.md`](../site-docs/deployment/overview.md) | Canonical deployment chooser (published site) |
| [`DEPLOY_QUICKSTART.md`](DEPLOY_QUICKSTART.md) | Connect-and-scan onboarding — deploy → connect → inventory → scan |
| [`DEPLOYMENT.md`](DEPLOYMENT.md) | Deployment and scalability architecture reference |
| [`ENTERPRISE_DEPLOYMENT.md`](ENTERPRISE_DEPLOYMENT.md) | Org-wide rollout — endpoints to cloud, container/image choices |

## Posture, in one breath

Across every tier the posture is the same:

- **Read-only on your cloud.** The scanner inventories accounts with read-only
  roles (`SecurityAudit` / `ViewOnlyAccess`). It never mutates your resources.
- **Keyless where possible.** Cloud access is via assumable roles bound to OIDC
  / IRSA, not long-lived keys. Secrets live in your secret manager and are
  referenced, never minted into Terraform state or kubeconfigs on disk.
- **Your data stays in your control plane.** The only writable infrastructure
  is the platform's own Postgres, backup bucket, and secret containers — all in
  your account.

## The control-plane / collector seam

The product is built around a single architectural seam:

```
   control plane  ──────────────  collector / connect
   (API + UI + Postgres + graph)   (read-only cloud roles)
   you always run this             points at the cloud you scan
```

This seam is what makes "deploy anywhere" work. The **control plane** is the
same chart/image in all three tiers. The **collector side** is just read-only
connect roles (`deploy/terraform/connect-*`). In the hosted tier the control
plane runs in one account and connected clouds apply a read-only connect role
pointing back to it; in the self-hosted tiers both sides live in your account.

---

## Tier 1 — Self-hosted anywhere (laptop / VM, fastest)

API + UI + Postgres with Docker Compose. Best for trying the full product, a
single-team pilot, or an air-gapped VM.

**Step 1 — generate the mounted secret files first.** `docker compose up`
hard-fails with a bare "secret file not found" if you skip this:

```bash
make secrets            # writes deploy/secrets/* (idempotent)
# equivalent: python scripts/deploy/hosted_poc_preflight.py --write-secret --skip-compose
```

**Step 2 — bring the stack up:**

```bash
cp .env.example .env    # ports / non-secret URL only
make fullstack-up       # == docker compose -f deploy/docker-compose.fullstack.yml up --build -d
```

Prefer to write the secret files by hand? Generate all six with `openssl` /
Fernet as documented in [`deploy/secrets/README.md`](../deploy/secrets/README.md),
`chmod 0400` them, then run the compose command above.

Postgres and control-plane secrets are Docker secret files only — never `.env`
or compose env. The API connects as `agent_bom_app` (DML-only), not the image
bootstrap role.

Then open:

- Dashboard → <http://localhost:3000>
- API docs → <http://localhost:8422/docs>

To point at a managed Postgres instead of the bundled one, set a password-free
`AGENT_BOM_POSTGRES_URL` (app role only) plus
`AGENT_BOM_POSTGRES_PASSWORD_FILE`, and remove the `postgres` service:

```bash
AGENT_BOM_POSTGRES_URL=postgresql://agent_bom_app@db.example.com:5432/agent_bom \
AGENT_BOM_POSTGRES_PASSWORD_FILE=/run/secrets/postgres_app_password \
  docker compose -f deploy/docker-compose.fullstack.yml up api ui
```

For a production-shaped single host (Docker secrets, internal-only Postgres,
split networks) use `deploy/docker-compose.platform.yml`.

---

## Tier 2 — Kubernetes / EKS

### Option A — one `terraform apply` (EKS, recommended)

The [`platform-eks`](../deploy/terraform/platform-eks/) root module stands up
the full platform in a single apply: it provisions (or references) an EKS
cluster, calls the `aws/baseline` module for RDS + IRSA + S3 backups + Secrets
Manager, and `helm_release`s the control-plane chart wired to those outputs.
Optionally it also mints the read-only connect role the scanner assumes.

```bash
cd deploy/terraform/platform-eks
cp terraform.tfvars.example terraform.tfvars   # set region, domain, cluster mode
terraform init
terraform apply

terraform output how_to_reach_it
```

Two modes, selected by one variable:

| `create_cluster` | You provide | Module provisions |
|------------------|-------------|-------------------|
| `true` | `region` | VPC + EKS + node group + RDS/IRSA/S3/Secrets + Helm |
| `false` | `cluster_name`, `vpc_id`, `private_subnet_ids` | RDS/IRSA/S3/Secrets + Helm onto your existing cluster |

Set `create_aws_connect_role = true` to also create the keyless, read-only role
the scanner uses to inventory the AWS account. See the
[module README](../deploy/terraform/platform-eks/README.md) for prerequisites
(ingress controller, cert-manager, External Secrets Operator) and the full
variable/output reference.

### Option B — Helm onto a cluster you already manage

If you manage cluster provisioning yourself (any Kubernetes, not just EKS),
install the chart directly:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  --values deploy/helm/agent-bom/examples/eks-production-values.yaml
```

The [`examples/`](../deploy/helm/agent-bom/examples/) directory ships values for
EKS, AKS, GKE, BYO-Postgres, SQLite pilots, collector-only workloads, and more.
On AWS you can still run `aws/baseline` on its own for RDS/IRSA/S3/Secrets and
feed its `helm_values_hint` output into your values file.

**Schema migrations:** for Helm installs against Postgres, the chart's
`pre-install,pre-upgrade` hook runs Alembic automatically
(`controlPlane.migrations.enabled`, on by default). A normal `helm upgrade`
does not require a manual `alembic upgrade head`. See
[Control-Plane Helm — migration contract](../site-docs/deployment/control-plane-helm.md)
for the one-time `init.sql` stamp path and the non-Helm override.

---

## Tier 3 — Operator-hosted / gated POC

The operator-hosted tier is the same control plane chart, operated centrally,
with invited customers connecting read-only across the control-plane /
collector seam:

1. **You run the control plane** — deploy the chart (Tier 2) in your account,
   behind your ingress and identity provider. For customer-0 and design
   partners, keep access invite-only with operator-minted tenants and keys.
2. **Customers connect read-only** — each customer applies a connect module
   (`deploy/terraform/connect-aws`, `connect-azure`, `connect-gcp`,
   `connect-snowflake`) that mints a read-only role trusting your hosted
   scanner principal:

   ```bash
   cd deploy/terraform/connect-aws
   terraform apply \
     -var 'trusted_principal_arns=["arn:aws:iam::<your-hosted-account>:role/agent-bom-scanner"]'

   terraform output role_arn               # hand this to the hosted control plane
   terraform output -raw external_id       # confused-deputy guard
   ```

3. **The scanner assumes the role** — your control plane inventories the
   customer account using only that read-only role. No keys leave the customer
   account; no customer data is mutated.

This is the same primitive used by `create_aws_connect_role` in the EKS module,
just pointed at a hosted scanner instead of a local one.

Start with the smaller hosted POC runbook for invite-only hosted evaluations:
[`HOSTED_POC.md`](HOSTED_POC.md). The recommended first proof is one AWS VM
behind HTTPS with
`deploy/docker-compose.hosted-poc.yml` layered on top of the platform compose
so Caddy is the only public listener. The Snowflake Native App lane remains an
enterprise customer-owned install path.

---

## Connect your cloud (zero keys)

Once the control plane is up (any tier above), connecting an account is four
steps and **never** involves a static access key or your laptop's base identity.
The control plane reads a customer cloud by **assuming that account's read-only
role** (`sts:AssumeRole` + ExternalId); it only needs its own workload identity
to make that call. That identity is provisioned automatically by the deploy.

**(a) Deploy the control plane — it gets a keyless identity automatically.**

| Target | Control-plane identity (keyless) | Provisioned by |
|--------|----------------------------------|----------------|
| EKS | IRSA role on the scanner/control-plane ServiceAccount | `platform-eks` / `aws/baseline` (`scanner_role_arn`) |
| Self-managed k8s on EC2 / ECS | Node instance profile / ECS task role (AWS SDK default chain) | your node/task role — grant it `sts:AssumeRole` on the connect roles |
| AKS | Azure workload identity federated to the pod SA | `connect-azure` + Helm `cloud.azure.clientId/tenantId` |
| GKE | GCP Workload Identity; the KSA impersonates the read-only SA | `connect-gcp` + Helm `cloud.gcp.impersonateSa` |

On EKS the scanner IRSA role is minted with a least-privilege `sts:AssumeRole`
policy scoped to the connection-role name pattern (`agent-bom-readonly*` /
`abom-readonly*`) so it can assume those roles in **any** target account —
`aws/baseline` variable `connect_role_arns`. Narrow it to explicit ARNs, or set
`[]` to disable cross-account assume.

**(b) Read the control plane's identity ARN — this is what target accounts trust.**

```bash
# EKS one-apply
terraform -chdir=deploy/terraform/platform-eks output -raw scanner_role_arn
# aws/baseline standalone
terraform -chdir=deploy/terraform/aws/baseline output -raw scanner_role_arn
```

For EC2/ECS it is the node instance-profile / ECS task role ARN; for AKS/GCP it
is the workload-identity principal your `connect-azure` / `connect-gcp` apply
prints. This is the value the read-only role in each target account will trust.

**(c) In each target account, create the read-only role trusting THAT identity + ExternalId.**

One account (Terraform or the 1-click CloudFormation Launch Stack the wizard
generates):

```bash
cd deploy/terraform/connect-aws
terraform apply -var 'trusted_principal_arns=["<CONTROL_PLANE_IDENTITY_ARN>"]'
terraform output role_arn               # hand to the wizard
terraform output -raw external_id       # confused-deputy guard
```

All accounts at once — the AWS Organizations **StackSet** with auto-deploy, so
new accounts enroll automatically (never account-by-account):

```bash
aws cloudformation create-stack-set \
  --stack-set-name agent-bom-readonly \
  --template-body file://deploy/cloudformation/agent-bom-readonly-role.yaml \
  --permission-model SERVICE_MANAGED \
  --auto-deployment Enabled=true,RetainStacksOnAccountRemoval=false \
  --capabilities CAPABILITY_NAMED_IAM \
  --parameters ParameterKey=ExternalId,ParameterValue="$EXTERNAL_ID" \
               ParameterKey=TrustedPrincipalArn,ParameterValue="<CONTROL_PLANE_IDENTITY_ARN>"
```

See [`deploy/cloudformation/README.md`](../deploy/cloudformation/README.md) for
the full StackSet flow, and [`connect-*`](../deploy/terraform/) for the Azure
management-group and GCP org/folder equivalents.

**(d) Connect in the UI.** Open **Connections**, paste the `role_arn` +
`ExternalId`, and scan. The control plane assumes the role with short-lived STS
— no key ever leaves the target account, nothing is mutated.

> **Zero-key throughout.** The one exception to workload identity is Snowflake,
> which has no cloud workload identity and uses key-pair (never password) auth
> supplied via a Secret reference. Everything else is keyless. The
> laptop/local-credential path (`aws sso login`, `az login`,
> `gcloud auth application-default login`) exists for **dev only** — never wire a
> personal base identity into a running control plane.

Full read-only contract (what is read, why it stays least-privilege) lives in
[`CLOUD_CONNECT.md`](CLOUD_CONNECT.md); the identity model is in
[`SECURITY_ARCHITECTURE.md` § Control-plane identity](SECURITY_ARCHITECTURE.md#control-plane-identity).

## Choosing a tier

| Need | Tier |
|------|------|
| Fastest look at the full product | 1 — Docker Compose |
| Single team / air-gapped VM | 1 — Docker Compose (or `docker-compose.platform.yml`) |
| Production on AWS, one command | 2A — `platform-eks` Terraform |
| Production on an existing/any cluster | 2B — Helm |
| Invite-only hosted design partner or customer-0 | 3 — Operator-hosted + connect roles |
| Gated customer-0 demo link | [`HOSTED_POC.md`](HOSTED_POC.md) |

## Related

- [`DEPLOY_QUICKSTART.md`](DEPLOY_QUICKSTART.md) — unified install script + onboarding
- [`deploy/RUNBOOK.md`](../deploy/RUNBOOK.md) — multicloud collector federation
- [`platform-eks` module](../deploy/terraform/platform-eks/README.md) — one-apply EKS
- [`aws/baseline` module](../deploy/terraform/aws/baseline/README.md) — RDS/IRSA/S3/Secrets
- [`connect-*` modules](../deploy/terraform/) — read-only cloud connect roles
- [Helm chart](../deploy/helm/agent-bom/) — control-plane chart + examples
- [`DEPLOYMENT.md`](DEPLOYMENT.md) — deployment & scalability architecture reference
