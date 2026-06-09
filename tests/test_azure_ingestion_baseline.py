from __future__ import annotations

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
MODULE = ROOT / "deploy" / "terraform" / "azure" / "ingestion"
WORKFLOW = ROOT / ".github" / "workflows" / "azure-ingestion.yml"


def test_azure_ingestion_terraform_module_exists() -> None:
    assert (MODULE / "versions.tf").exists()
    assert (MODULE / "main.tf").exists()
    assert (MODULE / "variables.tf").exists()
    assert (MODULE / "outputs.tf").exists()
    assert (MODULE / "README.md").exists()


def test_azure_ingestion_module_wires_github_oidc_without_client_secret() -> None:
    main_tf = (MODULE / "main.tf").read_text(encoding="utf-8")
    versions_tf = (MODULE / "versions.tf").read_text(encoding="utf-8")
    variables_tf = (MODULE / "variables.tf").read_text(encoding="utf-8")

    assert 'source  = "hashicorp/azurerm"' in versions_tf
    assert 'source  = "hashicorp/azuread"' in versions_tf
    assert "azuread_application_federated_identity_credential" in main_tf
    assert 'issuer         = "https://token.actions.githubusercontent.com"' in main_tf
    assert 'audiences      = ["api://AzureADTokenExchange"]' in main_tf
    assert "repo:${var.github_owner}/${var.github_repo}:ref:${var.github_ref}" in main_tf
    assert "repo:${var.github_owner}/${var.github_repo}:environment:${var.github_environment}" in main_tf
    assert "client_secret" not in main_tf
    assert "client_secret" not in variables_tf


def test_azure_ingestion_module_assigns_scanner_and_key_vault_access() -> None:
    main_tf = (MODULE / "main.tf").read_text(encoding="utf-8")
    outputs_tf = (MODULE / "outputs.tf").read_text(encoding="utf-8")

    for permission in [
        "Microsoft.App/containerApps/read",
        "Microsoft.CognitiveServices/accounts/deployments/read",
        "Microsoft.MachineLearningServices/workspaces/onlineEndpoints/read",
        "Microsoft.Authorization/roleAssignments/read",
        "Microsoft.Web/sites/read",
    ]:
        assert permission in main_tf

    assert 'azurerm_role_assignment" "scanner"' in main_tf
    assert "Key Vault Secrets User" in main_tf
    assert "rbac_authorization_enabled    = true" in main_tf
    assert "purge_protection_enabled      = true" in main_tf
    assert "github_variables_hint" in outputs_tf
    assert "AGENT_BOM_AZURE_CLIENT_ID" in outputs_tf


def test_azure_ingestion_workflow_uses_oidc_and_pushes_to_api() -> None:
    workflow = yaml.safe_load(WORKFLOW.read_text(encoding="utf-8"))
    job = workflow["jobs"]["ingest"]
    text = WORKFLOW.read_text(encoding="utf-8")

    assert workflow["permissions"]["id-token"] == "write"
    assert job["timeout-minutes"] == 45
    assert "az login" in text
    assert "--federated-token" in text
    assert "client-secret" not in text
    assert "AGENT_BOM_AZURE_CLIENT_ID" in text
    assert "AGENT_BOM_AZURE_TENANT_ID" in text
    assert "AGENT_BOM_AZURE_SUBSCRIPTION_ID" in text
    assert "agent-bom-api-url" in text
    assert "agent-bom-api-key" in text
    assert "--extra azure" in text
    assert "/v1/results/push" in text
    assert "/v1/fleet/sync" in text


def test_azure_ingestion_docs_do_not_claim_subscription_creation() -> None:
    readme = (MODULE / "README.md").read_text(encoding="utf-8")
    site_doc = (ROOT / "site-docs" / "deployment" / "terraform-azure-ingestion.md").read_text(encoding="utf-8")
    provision_readme = (ROOT / "scripts" / "provision" / "README.md").read_text(encoding="utf-8")

    assert "It does not create an Azure tenant or subscription" in readme
    assert "The Azure tenant and subscription must already exist" in site_doc
    assert "terraform output github_variables_hint" in readme
    assert "terraform output github_variables_hint" in site_doc
    assert "deploy/terraform/azure/ingestion" in provision_readme
    assert ".github/workflows/azure-ingestion.yml" in provision_readme
