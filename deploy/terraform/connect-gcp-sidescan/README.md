# GCP Persistent Disk side-scan role

This optional module binds a project custom role for the GCP snapshot →
temporary Persistent Disk → collector attach/detach → cleanup lifecycle. It is
separate from the read-only `connect-gcp` identity and is inert unless the
operator explicitly runs with `AGENT_BOM_SIDESCAN=1`.

The adapter receives already-authenticated Compute Engine SDK clients. It uses
deterministic execution labels, bounded operation polling, and a read-only disk
attachment to an in-project collector. The caller-supplied mount controller
also mounts the filesystem read-only. Persisted output is package/CVE and
redacted type/location metadata; no disk image or block bytes leave the project.

```hcl
module "gcp_sidescan" {
  source     = "github.com/<org>/agent-bom//deploy/terraform/connect-gcp-sidescan"
  project_id = "my-project"
  member     = "serviceAccount:agent-bom-collector@my-project.iam.gserviceaccount.com"
}
```

Keep the role in the target project and use a dedicated collector identity. GCP
Compute IAM does not provide a portable label condition for every lifecycle
permission, so the adapter also requires the persisted v1 ownership labels
before it reuses or sweeps a resource.

No live cloud mutation was run for this fixture-tested module. A successful
`terraform plan` and disposable-resource smoke with customer credentials are
still required before claiming a live GCP integration proof.
