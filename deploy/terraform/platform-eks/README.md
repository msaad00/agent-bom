# platform-eks — staged agent-bom control plane on EKS

The module stands up the full self-hosted agent-bom platform on AWS EKS after
the operator creates three dedicated Secrets Manager entries. Terraform never
reads those values: External Secrets syncs them into Kubernetes, a readiness
barrier waits for all targets, the RDS master runs migrations, and only then do
the API and maintenance paths start.

```
pre-populate Secrets Manager
   │
terraform apply
   ├─ (optional) minimal EKS cluster + VPC      terraform-aws-modules/{vpc,eks}
   ├─ baseline                                  ../aws/baseline  (RDS · IRSA · S3)
   ├─ secret sync + readiness barrier           External Secrets Operator
   ├─ admin migration                           RDS-managed master credential
   ├─ control plane (API + UI + maintenance)    helm_release of ../../helm/agent-bom
   └─ (optional) read-only connect role         ../connect-aws   (keyless scanner trust)
```

The application, maintenance, and migration identities are intentionally
separate. The API receives only the `agent_bom_app`,
`agent_bom_maintenance`, and auth Secrets. The backup job receives only the
maintenance Secret. The RDS-managed master credential is exposed only to the
one-shot migration Job as `ALEMBIC_DATABASE_URL`. Every generated DSN URL-encodes
its username and password before interpolation.

This is the **Kubernetes/EKS tier** of the [deploy-anywhere
guide](../../../docs/DEPLOY_PLATFORM.md). For a laptop/VM run use the
[full-stack compose](../../docker-compose.fullstack.yml); to install onto a
cluster you already manage, use [Helm directly](../../helm/agent-bom).

## What it does NOT do

- It does **not** grant write access to your cloud. The only writable
  infrastructure is the platform's own control-plane database, backup bucket,
  and Secrets Manager containers. The optional connect role is read-only
  (`SecurityAudit` + optional `ViewOnlyAccess`).
- It does **not** write long-lived cluster credentials to disk or state. The
  `kubernetes`/`helm` providers authenticate with an `aws eks get-token` exec
  plugin (keyless). The AWS CLI must be on `PATH`.
- It does **not** create or populate runtime/auth secret containers. Their names
  are Terraform inputs; their values stay in Secrets Manager and never enter
  Terraform state.

## Two cluster modes

| Mode | `create_cluster` | You provide | Module provisions |
|------|------------------|-------------|-------------------|
| Provision | `true` | region, secret names, then the cluster-first ESO/store bootstrap | VPC + EKS + node group + everything below |
| Reference | `false` | secret names, existing ESO/store, `cluster_name`, VPC/subnets, and an explicit DB source SG or CIDR | baseline + Helm + (optional) connect role |

## Prerequisites

- Terraform >= 1.5, AWS CLI on `PATH`, `kubectl`.
- AWS credentials with permission to create the resources in scope.
- For ingress: an ingress controller (e.g. nginx) and, for TLS, cert-manager
  already installed on the cluster. Set `domain` + `ingress_annotations`.
- External Secrets Operator and a `ClusterSecretStore` named
  `aws-secrets-manager`. Its AWS identity needs `secretsmanager:GetSecretValue`
  and `secretsmanager:DescribeSecret` for the three operator-managed secrets and
  the RDS-managed master secret.

For `create_cluster=true`, bootstrap the cluster before the full apply because
those prerequisites cannot exist until EKS exists:

```bash
terraform apply -target=module.vpc -target=module.eks
aws eks update-kubeconfig --name "$CLUSTER_NAME" --region "$AWS_REGION"
# Install External Secrets Operator and the aws-secrets-manager
# ClusterSecretStore using your platform team's maintained manifests.
```

For an existing cluster, install or verify the same prerequisites before the
first apply. In either mode, set
`external_secrets_prerequisites_ready=true` only after the operator and store
are healthy; the secret-sync release otherwise fails before rendering any
workload.

## Secure bootstrap order

1. Create three JSON secrets in AWS Secrets Manager:

   - `app_db_secret_name`: `username=agent_bom_app` plus a generated password.
   - `maintenance_db_secret_name`: `username=agent_bom_maintenance` plus a
     different generated password.
   - `auth_secret_name`: the production `AGENT_BOM_*` auth/session values. At
     minimum follow
     [`control-plane-auth-secret.example.yaml`](../../helm/agent-bom/examples/control-plane-auth-secret.example.yaml)
     for the browser-session, audit HMAC, connections, and admin API-key keys.

   Use `aws secretsmanager create-secret --secret-string file://...` with
   operator-readable files rather than putting secret values in
   `terraform.tfvars` or command-line arguments.

2. Put only those three secret names in `terraform.tfvars`, set a non-secret
   `runtime_credentials_generation` (start at `"1"`), acknowledge the verified
   External Secrets prerequisites, then run `terraform apply`. The module provisions RDS and the cluster resources,
   installs a sync-only Helm release, and waits until all four ExternalSecrets
   (`app`, `maintenance`, RDS `admin`, and `auth`) report `Ready` and their
   target Kubernetes Secrets exist.

3. After the barrier passes, the workload release runs the forward migration
   with the RDS master plus the two runtime credentials. The migration creates
   or validates the fixed least-privilege roles and idempotently reconciles
   their passwords on every install or upgrade;
   the API and backup workloads start only after it succeeds. A missing,
   malformed, or unreconciled secret fails the apply before workloads start. Auth
   payload validation remains fail-closed at API readiness.

### Coordinated secret rotation

The platform ExternalSecrets use `refreshPolicy: OnChange`; changing a remote
value alone does not create a database/Kubernetes credential mismatch. Update
the app, maintenance, and/or auth value in Secrets Manager, increment
`runtime_credentials_generation`, and run `terraform apply`. The generation
forces reconciliation, the barrier waits for the new target annotations, the
admin migration Job reconciles both fixed Postgres role passwords, and only
then does Helm roll the API/UI pods. Never rotate the runtime database Secrets
by changing their values without advancing this generation.

The RDS-managed migration/admin password rotates independently. Every full
platform apply generates a non-secret admin reconciliation nonce, forces only
that ExternalSecret to read the current `AWSCURRENT` value, and waits for the
nonce on the target Secret before the migration hook runs. Terraform never
reads or stores the master secret value.

The created-cluster mode authorizes the managed node-group security group to
reach RDS on port 5432 automatically. For an existing cluster, set
`db_allowed_security_group_ids` to the security groups attached to the pods or
nodes that run the control plane, or set `db_allowed_cidr_blocks` when the CNI
uses a stable private source CIDR. The module refuses to deploy an unreachable
RDS instance when neither source is supplied.

## Usage

```bash
cd deploy/terraform/platform-eks
cp terraform.tfvars.example terraform.tfvars   # edit region/domain/mode
terraform init
terraform apply

# Reach it
terraform output how_to_reach_it
terraform output ui_url
```

## Key variables

| Variable | Default | Purpose |
|----------|---------|---------|
| `region` | — | AWS region (required) |
| `create_cluster` | `false` | Provision a minimal cluster vs reference an existing one |
| `cluster_name` | `agent-bom-platform` | Cluster to create or reference |
| `node_instance_types` / `node_*_size` | `m6i.large`, 2/2/4 | Managed node-group sizing (provision mode) |
| `vpc_id` / `private_subnet_ids` | — | Existing network (reference mode) |
| `db_instance_class` / `db_allocated_storage` / `db_multi_az` | `db.t4g.medium` / 100 / `true` | Control-plane Postgres sizing |
| `db_allowed_security_group_ids` / `db_allowed_cidr_blocks` | `[]` / `[]` | Extra RDS ingress sources; one is required for referenced clusters |
| `app_db_secret_name` | — | Existing `agent_bom_app` username/password JSON secret (required) |
| `maintenance_db_secret_name` | — | Existing `agent_bom_maintenance` username/password JSON secret (required and distinct) |
| `auth_secret_name` | — | Existing JSON secret of production `AGENT_BOM_*` auth keys (required and distinct) |
| `runtime_credentials_generation` | — | Required non-secret rotation marker; increment with any referenced secret-value change |
| `external_secrets_prerequisites_ready` | `false` | Explicit acknowledgement that ESO and the named ClusterSecretStore are healthy |
| `domain` | `""` | Public hostname for the UI/API ingress; empty = no ingress, use port-forward |
| `image_tag` | `""` | Override the API/UI image tag (empty = chart default) |
| `extra_helm_values` | `""` | Raw YAML merged last into the Helm release |
| `create_aws_connect_role` | `false` | Mint the read-only role the scanner assumes (same-account) |
| `connect_role_arns` | `["arn:aws:iam::*:role/agent-bom-readonly*", "arn:aws:iam::*:role/abom-readonly*"]` | Read-only connection roles the scanner IRSA role may `sts:AssumeRole` **cross-account** (org fan-out / hosted connect). Least-privilege: only `sts:AssumeRole`, scoped to these ARNs. Set `[]` to disable |
| `report_export_bucket` | `""` | Existing S3 bucket for async report export. When set, mints a dedicated API IRSA role (least-privilege `s3:` on that bucket only), wires it onto the API service account, and turns on S3 export. Empty = disabled |

See `variables.tf` for the full list.

The API pod runs the async report exporter, which needs `s3:PutObject`. Without
`report_export_bucket` the API service account inherits the scanner IRSA role,
which has no `s3:` actions — so S3 export (if enabled by hand) would fail
`AccessDenied`. Setting `report_export_bucket` provisions a separate, minimal
role scoped to only that bucket and binds it to the `-api` service account.

## Outputs

| Output | Purpose |
|--------|---------|
| `ui_url` / `api_endpoint` | Where to reach the UI and API |
| `how_to_reach_it` | Quickstart text (ingress URL or port-forward commands) |
| `db_endpoint` | Control-plane Postgres endpoint |
| `scanner_role_arn` | IRSA role bound to the scanner service account |
| `backup_bucket_name` | S3 bucket for the packaged Postgres backups |
| `connect_role_arn` | Read-only role the scanner assumes (when enabled) |
| `scanner_assume_connect_policy_arn` | Policy letting the scanner assume read-only connect roles cross-account (empty when `connect_role_arns = []`) |
| `report_export_role_arn` | API IRSA role for S3 report export (when `report_export_bucket` is set) |

## Composition notes

- The Helm values are layered (low → high precedence): baseline wiring → image
  tag → ingress → your `extra_helm_values`. Anything not covered here is set
  directly through `extra_helm_values` or by editing your own values file.
- The baseline module owns RDS, IRSA, and S3. Its standalone empty-secret
  option remains available, but this root disables it and consumes only
  pre-populated operator-managed runtime/auth secrets.
- Two Helm releases have separate ownership: `${name}-secret-sync` owns the
  ExternalSecrets and participates in coordinated rotation; `${name}` owns the
  migration hook and workloads. Release-instance labels keep their teardown
  scopes disjoint. Do not remove the sync release while workloads are active.

## Destroy and recovery safety

The production default `db_deletion_protection=true` intentionally blocks
`terraform destroy`. Before an approved decommission, take and verify a backup,
set deletion protection false, and choose a unique
`db_final_snapshot_identifier` that is not already present from an earlier
destroy/recreate cycle. Terraform then removes both Helm releases in dependency
order; do not manually uninstall only one of them while workloads are active.
