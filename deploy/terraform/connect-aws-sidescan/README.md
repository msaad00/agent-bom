# connect-aws-sidescan

Mints the **separately-scoped snapshot role** the agentless **EBS disk
side-scan** (CWPP) needs. This is **distinct from `connect-aws`** and exists
because the side-scan is the **one deliberate, opt-in, non-read-only**
capability in agent-bom.

| | `connect-aws` | `connect-aws-sidescan` (this module) |
|---|---|---|
| Grant | AWS-managed `SecurityAudit` (+ `ViewOnlyAccess`) | a tiny **inline** snapshot-lifecycle policy |
| Mutations | **none** — `List*`/`Describe*`/`Get*` only | snapshot + temp-volume create/attach/detach/delete |
| Scope of writes | n/a | conditioned on the **`agent-bom-sidescan` tag** |
| When used | every cloud scan (default-off env flag) | **only** when `AGENT_BOM_SIDESCAN=1` |

Keep the read-only connect role for everything else. Apply **this** module only
if you want agentless deep disk inspection (SBOM + CVEs + secret locations
pulled directly off an EBS snapshot, without an in-guest agent).

## The trust model (why a deliberate non-read-only role is safe here)

The side-scan never copies block data out of your account. The flow is:

1. **Snapshot** the target EBS volume (`ec2:CreateSnapshot`), tagged
   `agent-bom-sidescan`.
2. **Create a temp volume** from that snapshot and **attach it to an in-account
   collector** EC2 instance, mounted **read-only**.
3. **Parse** the mounted filesystem on the collector → package SBOM, matched
   CVEs, and secret **type/location** (values are redacted; file contents are
   never read out).
4. **Cleanup** — unmount, detach + delete the temp volume, delete the snapshot.
   The scanner does this in a `try/finally` and best-effort sweeps orphaned
   `agent-bom-sidescan`-tagged snapshots on the next run.

**Only metadata leaves the boundary** (an SBOM + CVE list + secret
locations) — never disk images, never block data, never secret values.

## What this module grants (and what it deliberately does not)

The inline policy is the **minimum** the lifecycle above requires:

- **Read (account-wide, unavoidable):** `ec2:DescribeVolumes`,
  `DescribeSnapshots`, `DescribeInstances`, `DescribeTags`,
  `DescribeAvailabilityZones`. EC2 `Describe*` cannot be resource-scoped; these
  are reads, no mutation.
- **Create (tag-gated):** `ec2:CreateSnapshot`, `ec2:CreateVolume`, and
  `ec2:CreateTags` — but **only** when the request carries the
  `agent-bom-sidescan` tag (`aws:RequestTag`). The role **cannot create an
  untagged (unsweepable) resource**.
- **Mutate / delete (tag-gated):** `ec2:DeleteSnapshot`, `ec2:DeleteVolume`,
  `ec2:AttachVolume`, `ec2:DetachVolume` — **only** on resources already tagged
  `agent-bom-sidescan` (`aws:ResourceTag`). The role **cannot delete or detach a
  pre-existing customer snapshot/volume**.

It does **not** grant `SecurityAudit`, `ViewOnlyAccess`, any S3/data read, any
instance start/stop, or any permission outside this lifecycle.

> **Why tag-conditions matter.** Without `aws:ResourceTag`/`aws:RequestTag`
> conditions, a `DeleteSnapshot`/`DeleteVolume` grant would let the role destroy
> *any* snapshot or volume in the account. Scoping every mutation to the
> `agent-bom-sidescan` tag means the blast radius of the role is exactly — and
> only — the ephemeral resources the side-scan itself creates.

## Secure by default

- **Mandatory ExternalId (confused-deputy defense)** — always applied on
  cross-account assume-role; auto-generated 32-char high-entropy value when you
  don't pin one. Read it with `terraform output -raw external_id`.
- **Unique, unpredictable role name (anti-squatting)** — defaults to
  `abom-sidescan-<random hex>`. Override `name` only when a stable name is
  required.
- **No access keys** — role mode only; the in-account collector (instance role
  / IRSA) or your scanner assumes it. Keyless.

## Usage

### In-account collector (recommended)

```hcl
module "agent_bom_sidescan" {
  source = "github.com/<org>/agent-bom//deploy/terraform/connect-aws-sidescan"

  # The collector instance's role assumes this snapshot role.
  trusted_principal_arns  = ["arn:aws:iam::123456789012:role/agent-bom-collector"]
  collector_instance_arns = ["arn:aws:ec2:us-east-1:123456789012:instance/i-0collector"]
  # external_id omitted → high-entropy value generated and ALWAYS enforced.
}
```

### Keyless collector pod (EKS / IRSA)

```hcl
module "agent_bom_sidescan" {
  source = "github.com/<org>/agent-bom//deploy/terraform/connect-aws-sidescan"

  trusted_oidc_provider_arn = "arn:aws:iam::123456789012:oidc-provider/oidc.eks.us-east-1.amazonaws.com/id/EXAMPLE"
  trusted_oidc_subjects     = ["system:serviceaccount:agent-bom:collector"]
}
```

## After apply

```bash
export AGENT_BOM_SIDESCAN=1               # opt-in, default-OFF — required to enable the side-scan
# Run the side-scan from the in-account collector, which assumes role_arn below
# using external_id, against a target instance or volume.
```

With `AGENT_BOM_SIDESCAN` unset, the side-scan does nothing and no snapshot is
ever created — the capability is fully inert until you opt in.

`terraform output role_arn` gives the ARN to hand to the collector;
`terraform output sidescan_tag` shows the tag the role is bounded to.

## Inputs (key)

| Variable | Default | Purpose |
|----------|---------|---------|
| `name` | `""` | Fixed role-name override. Empty → auto-generated unique name. |
| `name_prefix` | `abom-sidescan` | Prefix for the auto-generated unique name. |
| `trusted_principal_arns` | `[]` | Principals (collector role / scanner) allowed to assume the role. |
| `trusted_oidc_provider_arn` | `""` | IAM OIDC provider ARN for keyless federation. |
| `collector_instance_arns` | `[]` | Restrict attach/detach to these collector instances (empty = any in account/region). |
| `external_id` | `""` | BYO `sts:ExternalId`. Empty → high-entropy value auto-generated and always enforced. |
| `sidescan_tag_key` / `sidescan_tag_value` | `agent-bom-sidescan` / `true` | The tag every mutation is conditioned on. |

## Outputs

`role_arn`, `role_name`, `external_id` (**sensitive** —
`terraform output -raw external_id`), `sidescan_tag`.
