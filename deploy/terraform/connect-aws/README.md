# connect-aws

Mints the **read-only** grant agent-bom's AWS connector needs — the exact role
documented in [`docs/CLOUD_CONNECT.md`](../../../docs/CLOUD_CONNECT.md) §3 — so a
customer runs `terraform apply` instead of hand-running `aws iam …` commands.

This is the **only** per-cloud difference in the connect flow: an IAM principal
with the AWS-managed **`SecurityAudit`** (+ optional **`ViewOnlyAccess`**) policy
attached. No create/update/delete permission is granted anywhere — the connector
calls only `List*`/`Describe*`/`Get*` and `sts:GetCallerIdentity`.

## What it creates

- An IAM **role** (default, recommended) or **user** named `agent-bom-readonly`.
- The AWS-managed **`SecurityAudit`** policy attached (always), and
  **`ViewOnlyAccess`** attached when `attach_view_only_access = true` (default).
- A trust policy (role mode) accepting either static cross-account principals or
  keyless OIDC web-identity federation, with optional `ExternalId`.

No access keys are created by this module. In role mode the principal is keyless
(assume-role / OIDC). In user mode, mint keys out-of-band and pass them as env —
they are never written into Terraform state by this module.

## Usage

### BYOC / hosted SaaS (cross-account role — keyless)

```hcl
module "agent_bom_connect" {
  source = "github.com/<org>/agent-bom//deploy/terraform/connect-aws"

  # The agent-bom scanner account/role that will assume this read-only role.
  trusted_principal_arns = ["arn:aws:iam::123456789012:role/agent-bom-scanner"]
  external_id            = "your-tenant-external-id" # optional, recommended
}
```

### Keyless CI (OIDC, e.g. GitHub Actions)

```hcl
module "agent_bom_connect" {
  source = "github.com/<org>/agent-bom//deploy/terraform/connect-aws"

  trusted_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/token.actions.githubusercontent.com"
  trusted_oidc_subjects     = ["repo:my-org/my-repo:ref:refs/heads/main"]
  trusted_oidc_audience     = "sts.amazonaws.com"
}
```

## After apply

```bash
export AGENT_BOM_AWS_INVENTORY=1          # opt-in, default-off
export AWS_PROFILE=abom-readonly          # a profile that assumes the role ARN below
agent-bom agents --preset enterprise --aws
```

`terraform output role_arn` gives the ARN to hand to the agent-bom connector /
hosted scanner. With the flag unset, agent-bom does zero AWS network I/O.

## Inputs (key)

| Variable | Default | Purpose |
|----------|---------|---------|
| `principal_type` | `role` | `role` (assumable, keyless) or `user`. |
| `trusted_principal_arns` | `[]` | Cross-account ARNs allowed to assume the role. |
| `trusted_oidc_provider_arn` | `""` | IAM OIDC provider ARN for keyless federation. |
| `external_id` | `""` | `sts:ExternalId` guard against the confused-deputy problem. |
| `attach_view_only_access` | `true` | Also attach AWS-managed `ViewOnlyAccess`. |

## Outputs

`role_arn`, `role_name`, `user_arn`, `user_name`, `attached_managed_policy_arns`,
`external_id`.
