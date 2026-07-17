from __future__ import annotations

from pathlib import Path

import yaml

from agent_bom.cloud.gcp_inventory import _GCP_IAM_PERMISSIONS

ROOT = Path(__file__).resolve().parents[1]
REQUIRED = {
    "cloudasset.assets.listIamPolicy",
    "iam.denypolicies.list",
    "iam.policybindings.list",
    "iam.principalaccessboundarypolicies.list",
    "iam.roles.get",
    "resourcemanager.folders.get",
    "resourcemanager.folders.getIamPolicy",
    "resourcemanager.organizations.getIamPolicy",
    "resourcemanager.projects.get",
    "resourcemanager.projects.getIamPolicy",
    "serviceusage.services.use",
}


def test_gcp_identity_envelope_declares_authorization_reads() -> None:
    assert REQUIRED <= set(_GCP_IAM_PERMISSIONS)


def test_gcp_custom_role_declares_authorization_reads() -> None:
    manifest = yaml.safe_load((ROOT / "scripts" / "provision" / "gcp_readonly_role.yaml").read_text())
    assert REQUIRED <= set(manifest["includedPermissions"])


def test_connect_gcp_grants_cloud_asset_read_roles() -> None:
    terraform = (ROOT / "deploy" / "terraform" / "connect-gcp" / "main.tf").read_text()
    assert '"roles/cloudasset.viewer"' in terraform
    assert '"roles/serviceusage.serviceUsageConsumer"' in terraform
