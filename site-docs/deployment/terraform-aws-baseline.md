# Terraform AWS Baseline

> **You do not need to read this unless** your platform team owns the
> AWS pieces around `agent-bom` (RDS, IRSA, S3 backup bucket, Secrets
> Manager) directly through Terraform instead of through the reference
> installer. For the paved AWS rollout use
> [Your Own AWS / EKS](own-infra-eks.md).

Use this page when the question is not "how do I deploy the chart?" but
"who owns the AWS pieces around the chart, and how do I destroy them cleanly?"

`agent-bom` now has a supported Terraform path for the AWS baseline that sits
around the Helm chart:

- Postgres / RDS
- IRSA roles for scanner and backup jobs
- S3 backup bucket
- Secrets Manager containers and references used by ExternalSecrets

The module lives at:

- [`deploy/terraform/aws/baseline`](https://github.com/msaad00/agent-bom/tree/main/deploy/terraform/aws/baseline)

## Ownership split

Keep the ownership boundary explicit:

| Terraform owns | Helm owns |
|---|---|
| RDS subnet group, security group, Postgres instance | API, UI, scanner, gateway, backup CronJob, runtime monitor |
| S3 backup bucket | Ingress, HPA, PDB, NetworkPolicy |
| IAM roles and policies for IRSA | ServiceAccount objects and their annotations |
| Secrets Manager secret containers and generated secret references | ExternalSecret objects that mirror those secrets into Kubernetes |

That split matters because it gives operators a clean destroy story instead of
leaving RDS, S3, and IAM resources behind after `helm uninstall`.

## Minimal usage

```hcl
module "agent_bom_baseline" {
  source = "./deploy/terraform/aws/baseline"

  name                      = "agent-bom-prod"
  namespace                 = "agent-bom"
  release_name              = "agent-bom"
  cluster_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
  cluster_oidc_issuer_url   = "https://oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
  vpc_id                    = "vpc-0123456789abcdef0"
  private_subnet_ids        = ["subnet-aaa", "subnet-bbb", "subnet-ccc"]

  db_allowed_security_group_ids = ["sg-eks-nodes"]
  auth_secret_name              = "agent-bom/control-plane-auth"
}
```

The module outputs:

- `scanner_role_arn`
- `backup_role_arn`
- `backup_bucket_name`
- `db_endpoint`
- `db_secret_arn`
- `db_secret_name`
- `db_url_secret_name`
- `auth_secret_name`
- `helm_values_hint`

`helm_values_hint` is a copy/paste bridge into the packaged chart values so the
module and the chart stay aligned instead of relying on tribal glue.

## Install flow

1. Apply the AWS baseline module.
2. Create or configure your `ClusterSecretStore` for AWS Secrets Manager.
3. Populate the chart-facing DB URL secret with `AGENT_BOM_POSTGRES_URL`.
4. Copy the `helm_values_hint` output into your values file or map it into your
   Helm pipeline.
5. Install the chart:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

## Destroy flow

Use the packaged teardown helper for the supported reverse path:

```bash
export AWS_REGION="<your-aws-region>"
agent-bom teardown \
  --cluster-name agent-bom-prod \
  --region "$AWS_REGION" \
  --namespace agent-bom \
  --release agent-bom \
  --yes
```

The helper does the same two-phase decommission in the correct order:

1. uninstall the Helm release
2. run Helm pre/post-delete cleanup hooks for generated target secrets, CronJobs, Jobs, and PVCs
3. wait for in-cluster workloads to disappear
4. destroy the product-owned Terraform baseline

If you want to inspect the plan first:

```bash
export AWS_REGION="<your-aws-region>"
agent-bom teardown \
  --cluster-name agent-bom-prod \
  --region "$AWS_REGION" \
  --namespace agent-bom \
  --release agent-bom \
  --dry-run
```

For teams working directly from a checked-out repo, the equivalent wrapper is:

```bash
export AWS_REGION="<your-aws-region>"
scripts/deploy/teardown-eks-reference.sh --cluster-name agent-bom-prod --region "$AWS_REGION" --dry-run
```

That ordering avoids:

- backup jobs still writing to S3 while the bucket is being removed
- live pods holding IRSA assumptions while IAM roles are deleted
- live API pods trying to reconnect to an RDS instance Terraform is tearing down

The teardown helper intentionally does **not** delete platform-owned shared infrastructure such as:

- the EKS cluster itself
- VPC and subnet topology
- ingress controllers, DNS, or cert-manager
- shared ExternalSecrets or OTLP controllers

## What this does not do

This module is intentionally narrow. It does not attempt to own:

- the EKS cluster itself
- ALB controller installation
- cert-manager installation
- ExternalSecrets controller installation
- Route53 / DNS records

Those remain cluster-platform responsibilities. The goal here is to make the
`agent-bom` baseline repeatable and destroyable, not to replace an entire AWS
platform module stack.
