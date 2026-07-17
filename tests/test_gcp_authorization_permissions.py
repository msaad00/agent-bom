from __future__ import annotations

from pathlib import Path

import yaml

from agent_bom.cloud.gcp_inventory import _GCP_IAM_PERMISSIONS

ROOT = Path(__file__).resolve().parents[1]
PROJECT_REQUIRED = {
    "cloudasset.assets.listIamPolicy",
    "iam.denypolicies.list",
    "iam.policybindings.list",
    "iam.roles.get",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "serviceusage.services.use",
}
ORGANIZATION_REQUIRED = {
    "iam.principalaccessboundarypolicies.list",
    "resourcemanager.folders.get",
    "resourcemanager.folders.getIamPolicy",
    "resourcemanager.organizations.getIamPolicy",
}
REQUIRED = PROJECT_REQUIRED | ORGANIZATION_REQUIRED


def test_gcp_identity_envelope_declares_authorization_reads() -> None:
    assert REQUIRED <= set(_GCP_IAM_PERMISSIONS)


def test_gcp_custom_roles_separate_project_and_organization_reads() -> None:
    project = yaml.safe_load((ROOT / "scripts" / "provision" / "gcp_readonly_role.yaml").read_text())
    organization = yaml.safe_load((ROOT / "scripts" / "provision" / "gcp_organization_iam_evidence_role.yaml").read_text())

    assert PROJECT_REQUIRED <= set(project["includedPermissions"])
    assert ORGANIZATION_REQUIRED.isdisjoint(project["includedPermissions"])
    assert ORGANIZATION_REQUIRED <= set(organization["includedPermissions"])


def test_connect_gcp_grants_cloud_asset_read_roles() -> None:
    terraform = (ROOT / "deploy" / "terraform" / "connect-gcp" / "main.tf").read_text()
    assert '"roles/cloudasset.viewer"' in terraform
    assert '"roles/serviceusage.serviceUsageConsumer"' in terraform
