# Azure Managed Disk side-scan role

This optional module assigns a dedicated custom role for the Azure snapshot →
temporary managed disk → collector attach/detach → cleanup lifecycle. It is
separate from the read-only `connect-azure` role and is inert unless the
operator explicitly runs with `AGENT_BOM_SIDESCAN=1`.

The adapter receives already-authenticated Azure SDK clients. It applies
deterministic execution ownership tags and bounds every long-running-operation
poll. The caller-supplied mount controller mounts the attached temporary disk
read-only on an in-subscription collector. Only SBOM/CVE and redacted
type/location evidence is persisted; no disk image or block bytes leave the
customer subscription.

```hcl
module "azure_sidescan" {
  source       = "github.com/<org>/agent-bom//deploy/terraform/connect-azure-sidescan"
  scope        = "/subscriptions/<subscription>/resourceGroups/<workload-and-collector-rg>"
  principal_id = "<collector-workload-identity-object-id>"
}
```

Azure custom roles cannot condition `write`/`delete` permissions on arbitrary
resource tags. Keep `scope` narrow; the adapter independently refuses cleanup
unless all v1 ownership tags match the persisted tenant/account execution.

No live cloud mutation was run for this fixture-tested module. A successful
`terraform plan` and disposable-resource smoke with customer credentials are
still required before claiming a live Azure integration proof.
