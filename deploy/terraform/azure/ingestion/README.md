# Azure ingestion baseline

Terraform baseline for running `agent-bom` Azure discovery from GitHub Actions
without stored Azure credentials.

This module assumes the Azure tenant and subscription already exist. It creates:

- a Microsoft Entra application and service principal for GitHub Actions
- a federated identity credential for the selected GitHub repo/ref or environment
- a least-privilege Azure role definition for agent-bom Azure discovery
- a role assignment for the GitHub service principal
- an optional Key Vault for the agent-bom API URL and API key used by ingestion

It does not create an Azure tenant or subscription. Those are account and billing
operations and should be created through the customer's normal Azure enrollment
process before this module runs.

## Usage

```hcl
module "agent_bom_azure_ingestion" {
  source = "./deploy/terraform/azure/ingestion"

  tenant_id       = "00000000-0000-0000-0000-000000000000"
  subscription_id = "11111111-1111-1111-1111-111111111111"
  github_owner    = "msaad00"
  github_repo     = "agent-bom"
  github_ref      = "refs/heads/main"

  tags = {
    owner       = "platform-security"
    environment = "prod"
  }
}
```

Run from an operator shell that is already logged into Azure with permissions to
create Entra applications, role definitions, role assignments, and the optional
Key Vault:

```bash
az login --tenant "$AZURE_TENANT_ID"
az account set --subscription "$AZURE_SUBSCRIPTION_ID"
terraform init
terraform apply
```

## GitHub repository variables

Set these GitHub repository variables from `terraform output github_variables_hint`:

```text
AGENT_BOM_AZURE_CLIENT_ID
AGENT_BOM_AZURE_TENANT_ID
AGENT_BOM_AZURE_SUBSCRIPTION_ID
AGENT_BOM_AZURE_KEY_VAULT_NAME
```

The workflow at `.github/workflows/azure-ingestion.yml` uses GitHub OIDC to log
in to Azure, runs:

```bash
agent-bom scan --azure --azure-subscription "$AZURE_SUBSCRIPTION_ID" \
  --push-url "$AGENT_BOM_API_URL/v1/results/push" \
  --push-api-key "$AGENT_BOM_API_KEY"
```

and optionally pushes fleet inventory to `/v1/fleet/sync`.

## API ingestion configuration

Preferred: store ingestion config in the module-created Key Vault, outside
Terraform state:

```bash
az keyvault secret set \
  --vault-name "$(terraform output -raw key_vault_name)" \
  --name agent-bom-api-url \
  --value "https://agent-bom.example.com"

az keyvault secret set \
  --vault-name "$(terraform output -raw key_vault_name)" \
  --name agent-bom-api-key \
  --value "<tenant-scoped analyst API key>"
```

Alternative: set GitHub `vars.AGENT_BOM_API_URL` and
`secrets.AGENT_BOM_API_KEY` directly.

Use an analyst API key for `/v1/results/push`. If the workflow input
`push_fleet` is enabled, the key must also have permission for
`/v1/fleet/sync`.

## Subject scoping

By default the federated credential trusts:

```text
repo:<github_owner>/<github_repo>:ref:<github_ref>
```

For GitHub environment protection, set `github_environment`; the subject becomes:

```text
repo:<github_owner>/<github_repo>:environment:<github_environment>
```

Use `federated_subject_override` only for non-standard subject contracts.

## Notes

- GitHub Actions needs `permissions: id-token: write` to mint the OIDC token.
- GitHub-hosted runners need Key Vault public network access. For self-hosted
  private runners, set `key_vault_public_network_access_enabled = false` and
  provide private network access.
- The Azure scanner uses SDK `DefaultAzureCredential`; the workflow performs
  `az login --service-principal --federated-token ...` so the SDK can use the
  Azure CLI credential without a client secret.
