# Terraform Azure ingestion

`agent-bom` includes an Azure ingestion baseline at:

- `deploy/terraform/azure/ingestion`

The module wires GitHub Actions to Azure through OIDC and prepares a secure path
for pushing Azure scan evidence into the control-plane API.

## What it creates

- Microsoft Entra application and service principal for GitHub Actions
- GitHub federated identity credential scoped to one repo/ref or environment
- least-privilege Azure scanner role definition
- scanner role assignment at the configured subscription or narrower scope
- optional Key Vault for the control-plane API URL and API key

The Azure tenant and subscription must already exist. Create those through the
customer's Azure account and billing process, then run Terraform inside that
tenant/subscription.

## First run

```bash
cd deploy/terraform/azure/ingestion
terraform init
terraform apply \
  -var tenant_id="$AZURE_TENANT_ID" \
  -var subscription_id="$AZURE_SUBSCRIPTION_ID" \
  -var github_owner="msaad00" \
  -var github_repo="agent-bom"
```

After apply, set the GitHub repository variables from:

```bash
terraform output github_variables_hint
```

Then store ingestion config either in GitHub directly:

```text
vars.AGENT_BOM_API_URL
secrets.AGENT_BOM_API_KEY
```

or in the module-created Key Vault:

```bash
az keyvault secret set --vault-name "$(terraform output -raw key_vault_name)" \
  --name agent-bom-api-url \
  --value "https://agent-bom.example.com"

az keyvault secret set --vault-name "$(terraform output -raw key_vault_name)" \
  --name agent-bom-api-key \
  --value "<tenant-scoped analyst API key>"
```

## Ingestion workflow

`.github/workflows/azure-ingestion.yml` runs with:

- `permissions.id-token: write`
- GitHub OIDC login to Azure
- `agent-bom scan --azure --azure-subscription ...`
- push to `/v1/results/push`

The workflow can also sync fleet inventory to `/v1/fleet/sync` when manually
triggered with `push_fleet=true`. That path requires a key with fleet write
permission; the default scan-result push path needs analyst-level write access.
