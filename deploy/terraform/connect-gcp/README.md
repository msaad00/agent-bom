# connect-gcp

Mints the **read-only** grant agent-bom's GCP connector needs, following the
same one-model connect pattern as
[`docs/CLOUD_CONNECT.md`](../../../docs/CLOUD_CONNECT.md), so a customer runs
`terraform apply` instead of hand-running `gcloud iam` commands.

This is the **only** per-cloud difference in the connect flow: a service account
with project IAM bindings **`roles/viewer`** + **`roles/iam.securityReviewer`** —
both read-only predefined roles. No write permission is granted. The connector
calls only `list`/`get` APIs.

## What it creates

- A read-only **service account** with a **unique, non-guessable account_id**
  (`abom-readonly-<random hex>@<project>.iam…` by default).
- Project IAM bindings: **`roles/viewer`** (inventory) and
  **`roles/iam.securityReviewer`** (read-only IAM policy access for CIEM/posture).
- **Optionally** (variable-gated) a **Workload Identity Federation** pool +
  OIDC provider, and an impersonation binding, so an external identity can
  assume the SA **keylessly** — no SA key is ever created.

**Keyless by design.** This module creates **no** service-account key (many orgs
disable SA keys org-wide). Prefer Workload Identity Federation or SA
impersonation. If you must use a key, mint it out-of-band; it is never written
into this module's state.

## Secure by default

- **Unique, unpredictable SA name (anti-squatting).** `service_account_id`
  defaults to `abom-readonly-<random hex>`, so the SA is not a predictable,
  squattable, or targetable identity. Override `service_account_id = "..."`
  only when a stable, known account_id is required.
- **No wide-open federation (fail-safe).** When
  `enable_workload_identity_federation = true`, the plan **fails** unless you
  supply a scoped `wif_attribute_condition`, at least one
  `wif_allowed_audiences`, a `wif_issuer_uri`, and a `wif_principal_set`. An
  empty `attribute_condition` previously allowed **any** token from the issuer
  to impersonate the read-only SA; that is now rejected before apply.

> **Threat note.** A WIF provider with no attribute condition trusts *every*
> token the issuer mints — any repo, any workflow, any tenant on that IdP could
> impersonate the read-only SA (**wide-open federation**). Pinning the
> condition, audience, and principalSet narrows the trust to one specific
> external workload. A *predictable* SA name is also easier to **squat or
> target**, which the randomized default closes.

## Usage

### Keyless (Workload Identity Federation)

```hcl
module "agent_bom_connect" {
  source     = "github.com/<org>/agent-bom//deploy/terraform/connect-gcp"
  project_id = "my-project"

  enable_workload_identity_federation = true
  wif_issuer_uri          = "https://token.actions.githubusercontent.com"
  wif_attribute_condition = "assertion.repository == 'my-org/my-repo'"  # required, scoped
  wif_allowed_audiences   = ["https://github.com/my-org"]               # required, pinned
  wif_attribute_mapping = {
    "google.subject"       = "assertion.sub"
    "attribute.repository" = "assertion.repository"
  }
  wif_principal_set = "principalSet://iam.googleapis.com/projects/123456789/locations/global/workloadIdentityPools/agent-bom-pool/attribute.repository/my-org/my-repo"
}
```

### Roles only (impersonate the SA with your own identity)

```hcl
module "agent_bom_connect" {
  source     = "github.com/<org>/agent-bom//deploy/terraform/connect-gcp"
  project_id = "my-project"
}
```

## After apply

```bash
export AGENT_BOM_GCP_INVENTORY=1          # opt-in, default-off
# Authenticate keylessly via WIF / SA impersonation using the SA email below,
# or `gcloud auth application-default login`.
agent-bom agents --preset enterprise --gcp
```

`terraform output service_account_email` gives the SA to impersonate, and
`terraform output workload_identity_provider_name` gives the provider for the
external credential config. With the flag unset, agent-bom does zero GCP
network I/O.

## Inputs (key)

| Variable | Default | Purpose |
|----------|---------|---------|
| `project_id` | — | Project to scope the grant to. |
| `service_account_id` | `""` | Fixed account_id override. Empty → auto-generated unique account_id. |
| `service_account_id_prefix` | `abom-readonly` | Prefix for the auto-generated unique account_id. |
| `enable_workload_identity_federation` | `false` | Create a keyless WIF pool/provider. |
| `wif_issuer_uri` | `""` | OIDC issuer of the external IdP. **Required when WIF is on.** |
| `wif_attribute_condition` | `""` | Scoped CEL condition. **Required when WIF is on** (empty is rejected). |
| `wif_allowed_audiences` | `[]` | Pinned audiences. **Required (≥1) when WIF is on.** |
| `wif_principal_set` | `""` | `principalSet://` member allowed to impersonate the SA. **Required when WIF is on.** |

## Outputs

`service_account_email`, `service_account_name`, `granted_roles`,
`workload_identity_pool_name`, `workload_identity_provider_name`.
