# connect-gcp

Mints the **read-only** grant agent-bom's GCP connector needs, following the
same one-model connect pattern as
[`docs/CLOUD_CONNECT.md`](../../../docs/CLOUD_CONNECT.md), so a customer runs
`terraform apply` instead of hand-running `gcloud iam` commands.

This is the **only** per-cloud difference in the connect flow: a service account
bound to **`roles/viewer`**, **`roles/iam.securityReviewer`**,
**`roles/cloudasset.viewer`**, and **`roles/serviceusage.serviceUsageConsumer`** —
all read-only predefined roles. No write permission is granted. The connector calls only
`list`/`get` APIs. The roles bind at the **project** by default, or **org-wide /
folder-wide** (`iam_binding_scope`) for fleet/mass onboarding — see
[Fleet onboarding](#fleet-onboarding-orgfolder-scope) below.

Project scope covers local project evidence. Complete inherited allow/deny and
organization PAB evidence requires the organization/folder scope that owns it;
the connector reports inaccessible parent sources as incomplete.

## What it creates

- A read-only **service account** with a **unique, non-guessable account_id**
  (`abom-readonly-<random hex>@<project>.iam…` by default).
- IAM bindings for **`roles/viewer`** (inventory),
  **`roles/iam.securityReviewer`** (read-only IAM policy access),
  **`roles/cloudasset.viewer`** (resource-local IAM policies), and
  **`roles/serviceusage.serviceUsageConsumer`** (authorized Cloud Asset API use),
  at the **project** (default), **organization**, or **folder** scope
  (`iam_binding_scope`).
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

### Fleet onboarding (org/folder scope)

For a fleet scan, bind the same read-only role set once at the **organization**
(or **folder**) instead of per project — the GCP analogue of the AWS
Organizations StackSet and the Azure management-group scope. A single apply then
covers every project the `AGENT_BOM_GCP_ALL_PROJECTS` fan-out reaches. The SA
still lives in `project_id`; only the grant scope changes. Still strictly
read-only.

```hcl
module "agent_bom_connect" {
  source     = "github.com/<org>/agent-bom//deploy/terraform/connect-gcp"
  project_id = "sa-host-project" # where the SA is created

  iam_binding_scope = "organization"
  organization_id   = "123456789012" # numeric org ID, no "organizations/" prefix
}
```

Use `iam_binding_scope = "folder"` with `folder_id = "folders/123456789012"` for
a narrower, folder-wide grant. Org/folder-level bindings need
`roles/resourcemanager.organizationAdmin` (or folder admin) on whoever runs the
apply — grant scope is set by the org, not by agent-bom. See
[`docs/CLOUD_CONNECT.md`](../../../docs/CLOUD_CONNECT.md) §5 for the fan-out env.

## After apply

```bash
export AGENT_BOM_GCP_INVENTORY=1          # opt-in, default-off
export AGENT_BOM_GCP_ALL_PROJECTS=1       # fan out across org/folders/projects
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
| `project_id` | — | Project that hosts the service account (and the grant scope when `iam_binding_scope = "project"`). |
| `iam_binding_scope` | `project` | Where to bind the read-only roles: `project`, `organization`, or `folder`. Org/folder is the fleet/mass-onboarding path. |
| `organization_id` | `""` | Numeric org ID. **Required when `iam_binding_scope = "organization"`** (empty is rejected). |
| `folder_id` | `""` | Folder ID (`folders/…` or numeric). **Required when `iam_binding_scope = "folder"`** (empty is rejected). |
| `service_account_id` | `""` | Fixed account_id override. Empty → auto-generated unique account_id. |
| `service_account_id_prefix` | `abom-readonly` | Prefix for the auto-generated unique account_id. |
| `enable_workload_identity_federation` | `false` | Create a keyless WIF pool/provider. |
| `wif_issuer_uri` | `""` | OIDC issuer of the external IdP. **Required when WIF is on.** |
| `wif_attribute_condition` | `""` | Scoped CEL condition. **Required when WIF is on** (empty is rejected). |
| `wif_allowed_audiences` | `[]` | Pinned audiences. **Required (≥1) when WIF is on.** |
| `wif_principal_set` | `""` | `principalSet://` member allowed to impersonate the SA. **Required when WIF is on.** |
| `assign_artifact_registry_reader` | `false` | **Opt-in** data-plane read: `roles/artifactregistry.reader` for GAR image pull (SBOM/CVE extraction). Off by default so image-content read is opt-in, matching the AWS S3/deep-scan pattern. |

## Known coverage limitations

- **Org-level CIS checks need org/folder scope.** At the default **project**
  scope, CIS benchmarks that assert org-wide posture (e.g. org-policy and
  folder-level controls) read as silently-empty. Set
  `iam_binding_scope = "organization"` (or `"folder"`) so the same read-only
  roles bind org/folder-wide and those checks evaluate.

## Outputs

`service_account_email`, `service_account_name`, `granted_roles`,
`iam_binding_scope`, `workload_identity_pool_name`,
`workload_identity_provider_name`.
