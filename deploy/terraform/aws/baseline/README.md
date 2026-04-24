# agent-bom AWS baseline module

This module provisions the AWS resources Helm does not own cleanly:

- PostgreSQL / RDS for the control plane
- IRSA roles for the scanner and backup job
- S3 backup bucket
- Secrets Manager containers/outputs for ExternalSecrets wiring

It does **not** create Kubernetes objects. Terraform owns the AWS baseline;
Helm owns the `agent-bom` workloads inside the cluster.

## What Terraform owns

- RDS subnet group, security group, and Postgres instance
- S3 backup bucket and bucket policy surface for the packaged backup job
- IAM roles and policies for scanner + backup IRSA
- Secrets Manager secret containers / generated secret references

## What Helm still owns

- Deployments, CronJobs, Services, Ingress, HPAs, PDBs
- ExternalSecret objects that mirror AWS secrets into Kubernetes
- runtime service accounts and pod annotations

## Usage

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
  db_url_secret_name            = "agent-bom/control-plane-db"
  auth_secret_name              = "agent-bom/control-plane-auth"

  tags = {
    Environment = "prod"
    Owner       = "security-platform"
  }
}
```

Then wire the output into Helm:

```bash
terraform output -raw helm_values_hint
helm upgrade --install agent-bom deploy/helm/agent-bom \
  --namespace agent-bom --create-namespace \
  -f deploy/helm/agent-bom/examples/eks-production-values.yaml
```

## State Security

Terraform/OpenTofu state can contain generated credentials, resource ARNs, and
customer infrastructure identifiers. For production, keep state in a
customer-managed encrypted backend such as S3 with SSE-KMS, bucket versioning,
least-privilege IAM, and state locking. Local state under
`~/.agent-bom/eks-reference` is intended only for pilots and should live on
encrypted disk with operator-only permissions.

Populate the chart-facing database URL secret after the first apply:

```bash
aws secretsmanager put-secret-value \
  --secret-id agent-bom/control-plane-db \
  --secret-string '{"AGENT_BOM_POSTGRES_URL":"postgresql://agent_bom:REPLACE_ME@REPLACE_ME_RDS_ENDPOINT:5432/agent_bom"}'
```

## Destroy / decommission

Use a two-step teardown so Terraform does not fight live pods:

1. Disable backup jobs and remove the Helm release:
   `helm uninstall agent-bom -n agent-bom`
2. Confirm no pods or ExternalSecrets still reference the IRSA roles or DB.
3. Run:
   `terraform destroy`

If you want `terraform destroy` to remove the backup bucket contents too, set:

```hcl
backup_bucket_force_destroy = true
```

Keep it `false` for production unless you intentionally want teardown to remove
all retained backups.
