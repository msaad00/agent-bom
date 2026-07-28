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

`helm_values_hint` is workload-only wiring for four already-created Kubernetes
Secrets. It does not sync secret values or make the infrastructure-only module
a one-step installer.

## Install flow

1. Apply the AWS baseline module.
2. Create or configure your `ClusterSecretStore` for AWS Secrets Manager.
3. Populate and verify separate chart-facing app, maintenance,
   migration/admin, and auth Kubernetes Secrets in an operator-controlled sync
   stage. Never use the RDS master login in the app or maintenance Secret.
4. Save `terraform output -raw helm_values_hint` as
   `baseline-workload-values.yaml`.
5. Install the chart:

```bash
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml \
  -f baseline-workload-values.yaml
```

## Destroy flow

For the composed EKS platform, use the owning Terraform root. First verify a
backup, stop dependent workloads through the same state, set deletion
protection false only with approval, and choose a new final snapshot identifier:

```bash
cd deploy/terraform/platform-eks
terraform plan -destroy
terraform destroy
```

Terraform removes resources in reverse dependency order:

1. workload Helm release
2. secret-sync Helm release and generated target Secrets
3. product-owned RDS, backup, and IAM resources
4. an optional module-created EKS/VPC

That ordering avoids:

- backup jobs still writing to S3 while the bucket is being removed
- live pods holding IRSA assumptions while IAM roles are deleted
- live API pods trying to reconnect to an RDS instance Terraform is tearing down

In referenced-cluster mode, Terraform intentionally does **not** delete
platform-owned shared infrastructure such as:

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
