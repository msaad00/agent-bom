# connect-aws

Mints the **read-only** grant agent-bom's AWS connector needs — the exact role
documented in [`docs/CLOUD_CONNECT.md`](../../../docs/CLOUD_CONNECT.md) §3 — so a
customer runs `terraform apply` instead of hand-running `aws iam …` commands.

This is the **only** per-cloud difference in the connect flow: an IAM principal
with the AWS-managed **`SecurityAudit`** (+ optional **`ViewOnlyAccess`**) policy
attached. No create/update/delete permission is granted anywhere — the connector
calls only `List*`/`Describe*`/`Get*` and `sts:GetCallerIdentity`.

## What it creates

- An IAM **role** (default, recommended) or **user** with a **unique,
  non-guessable name** (`abom-readonly-<random hex>` by default).
- The AWS-managed **`SecurityAudit`** policy attached (always), and
  **`ViewOnlyAccess`** attached when `attach_view_only_access = true` (default).
- A trust policy (role mode) accepting either static cross-account principals or
  keyless OIDC web-identity federation, with an **always-enforced `ExternalId`**
  (auto-generated high-entropy by default).

No access keys are created by this module. In role mode the principal is keyless
(assume-role / OIDC). In user mode, mint keys out-of-band and pass them as env —
they are never written into Terraform state by this module.

## Secure by default

- **Mandatory ExternalId (confused-deputy defense).** The `sts:ExternalId`
  trust condition is **always** applied on cross-account assume-role — it can
  never be silently omitted. Leave `external_id` empty and the module generates
  a 32-char high-entropy value; read it with
  `terraform output -raw external_id` and configure the scanner with it. Set
  `external_id` to pin a known value (BYO-ID).
- **Unique, unpredictable name (anti-squatting).** The role/user name defaults
  to `abom-readonly-<random hex>` so it is not a predictable, squattable, or
  targetable principal. Override with `name = "..."` only when a stable, known
  name is required by an external system.

> **Threat note.** A *fixed, guessable* External ID (or one set to an empty,
> never-applied condition) leaves the role open to the **confused-deputy**
> problem — a third party that knows your role ARN could trick the scanner's
> account into assuming it on their behalf. A *predictable* principal name is
> easier to **squat or target**. The defaults above close both: the ExternalId
> is high-entropy and always enforced, and the name is randomized.

## Usage

### BYOC / hosted SaaS (cross-account role — keyless)

```hcl
module "agent_bom_connect" {
  source = "github.com/<org>/agent-bom//deploy/terraform/connect-aws"

  # The agent-bom scanner account/role that will assume this read-only role.
  trusted_principal_arns = ["arn:aws:iam::123456789012:role/agent-bom-scanner"]
  # external_id omitted → a high-entropy value is generated and ALWAYS enforced.
  # Read it after apply: terraform output -raw external_id
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
| `name` | `""` | Fixed name override. Empty → auto-generated unique name. |
| `name_prefix` | `abom-readonly` | Prefix for the auto-generated unique name. |
| `trusted_principal_arns` | `[]` | Cross-account ARNs allowed to assume the role. |
| `trusted_oidc_provider_arn` | `""` | IAM OIDC provider ARN for keyless federation. |
| `external_id` | `""` | BYO `sts:ExternalId`. Empty → high-entropy value auto-generated and always enforced. |
| `attach_view_only_access` | `true` | Also attach AWS-managed `ViewOnlyAccess`. |

## Outputs

`role_arn`, `role_name`, `user_arn`, `user_name`, `attached_managed_policy_arns`,
`external_id` (**sensitive** — `terraform output -raw external_id`).
