# platform-eks — one-apply agent-bom control plane on EKS

A single `terraform apply` stands up the full self-hosted agent-bom platform on
AWS EKS. It ties together the pieces that previously had to be wired by hand:

```
terraform apply
   │
   ├─ (optional) minimal EKS cluster + VPC      terraform-aws-modules/{vpc,eks}
   ├─ baseline                                  ../aws/baseline  (RDS · IRSA · S3 · Secrets)
   ├─ control plane (API + UI)                  helm_release of ../../helm/agent-bom
   └─ (optional) read-only connect role         ../connect-aws   (keyless scanner trust)
```

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

## Two cluster modes

| Mode | `create_cluster` | You provide | Module provisions |
|------|------------------|-------------|-------------------|
| Provision | `true` | region | VPC + EKS + node group + everything below |
| Reference | `false` | `cluster_name`, `vpc_id`, `private_subnet_ids` | baseline + Helm + (optional) connect role |

## Prerequisites

- Terraform >= 1.5, AWS CLI on `PATH`, `kubectl`.
- AWS credentials with permission to create the resources in scope.
- For ingress: an ingress controller (e.g. nginx) and, for TLS, cert-manager
  already installed on the cluster. Set `domain` + `ingress_annotations`.
- For `externalSecrets` (enabled by the baseline wiring): the External Secrets
  Operator with a `ClusterSecretStore` named `aws-secrets-manager`. Without it,
  populate the `*-control-plane-db` / `*-control-plane-auth` secrets yourself
  and set `extra_helm_values` to disable External Secrets.

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
| `domain` | `""` | Public hostname for the UI/API ingress; empty = no ingress, use port-forward |
| `image_tag` | `""` | Override the API/UI image tag (empty = chart default) |
| `extra_helm_values` | `""` | Raw YAML merged last into the Helm release |
| `create_aws_connect_role` | `false` | Mint the read-only role the scanner assumes |
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
| `report_export_role_arn` | API IRSA role for S3 report export (when `report_export_bucket` is set) |

## Composition notes

- The Helm values are layered (low → high precedence): baseline wiring → image
  tag → ingress → your `extra_helm_values`. Anything not covered here is set
  directly through `extra_helm_values` or by editing your own values file.
- The baseline module owns RDS, IRSA, S3, and the Secrets Manager containers;
  this root module only wires their outputs into the chart. To change baseline
  behavior, pass through the relevant variable or extend the `module.baseline`
  block.
