# Connect a cloud to agent-bom — Terraform modules

Productized customer onboarding: one `terraform apply` mints exactly the
**read-only, least-privilege** grant agent-bom's connector needs, replacing
hand-run `gcloud` / `aws` / `az` / `snowsql` setup scripts.

Read [`docs/CLOUD_CONNECT.md`](../../docs/CLOUD_CONNECT.md) for the full story of
why every step is read-only, least-privilege, and zero-trust by design. These
modules are the Terraform expression of the **Grant** step in that doc.

## One model, not four

> **The only per-cloud difference is the grant primitive.** Everything else —
> enablement (`AGENT_BOM_<PROVIDER>_INVENTORY=1`), authentication with the
> cloud's own identity, discovery, normalization, the unified graph, and the
> `--fail-on-severity` gate — is identical across clouds.

Each module below creates **exactly** the read-only role/SA/grant the connector
uses, and nothing more. No write permission is granted anywhere. No secret
(key/password) is written into the `.tf` or into Terraform state by these
modules — keys and public-key material are variables or outputs only.

| Module | Grant primitive (the per-cloud difference) | Enable flag |
|--------|--------------------------------------------|-------------|
| [`connect-aws`](./connect-aws/) | IAM role/user + AWS-managed `SecurityAudit` (+ `ViewOnlyAccess`); cross-account or OIDC trust | `AGENT_BOM_AWS_INVENTORY=1` |
| [`connect-azure`](./connect-azure/) | Built-in `Reader` (+ `Security Reader`) RBAC assignment at a subscription / management group | `AGENT_BOM_AZURE_INVENTORY=1` |
| [`connect-gcp`](./connect-gcp/) | Service account + `roles/viewer` & `roles/iam.securityReviewer` at a project / organization / folder; optional keyless Workload Identity Federation | `AGENT_BOM_GCP_INVENTORY=1` |
| [`connect-snowflake`](./connect-snowflake/) | `ABOM_READONLY` role + `IMPORTED PRIVILEGES`/`MONITOR USAGE`/warehouse `USAGE` grants + key-pair user | `SNOWFLAKE_*` (see module README) |

## Keyless-first

Every module defaults to the keyless path where the cloud supports it:

- **AWS** — assumable role via cross-account trust or OIDC web identity (no keys).
- **Azure** — RBAC on an existing service principal (certificate) or managed identity.
- **GCP** — optional Workload Identity Federation, since many orgs disable SA keys.
- **Snowflake** — key-pair (RSA JWT) only; password auth is unsupported by design.

## Using a module

Each module is standalone (`main.tf`, `variables.tf`, `outputs.tf`,
`versions.tf`, `README.md`). From a module directory:

```bash
terraform init
terraform plan   # review the exact read-only grant
terraform apply
```

Then export the per-provider enable flag and point agent-bom at the cloud. See
each module's `README.md` for the precise inputs, outputs, and post-apply env.

## Notes

- Provider versions are pinned in each module's `versions.tf`.
- These modules create grants only; they do not deploy or run agent-bom itself.
  For running the scanner, see `deploy/docker-compose*.yml` and `deploy/helm/`.
