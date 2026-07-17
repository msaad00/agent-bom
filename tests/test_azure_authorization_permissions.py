from __future__ import annotations

import json
from pathlib import Path

from agent_bom.cloud.azure_inventory import _AZURE_IDENTITY_PERMISSIONS

ROOT = Path(__file__).resolve().parents[1]
DENY_READ = "Microsoft.Authorization/denyAssignments/read"
ROLE_ASSIGNMENT_READ = "Microsoft.Authorization/roleAssignments/read"
ROLE_DEFINITION_READ = "Microsoft.Authorization/roleDefinitions/read"


def test_identity_discovery_envelope_declares_every_authorization_read() -> None:
    assert {DENY_READ, ROLE_ASSIGNMENT_READ, ROLE_DEFINITION_READ} <= set(_AZURE_IDENTITY_PERMISSIONS)


def test_azure_readonly_manifest_declares_every_authorization_read() -> None:
    manifest = json.loads((ROOT / "scripts" / "provision" / "azure_readonly_role.json").read_text())

    assert {DENY_READ, ROLE_ASSIGNMENT_READ, ROLE_DEFINITION_READ} <= set(manifest["Actions"])
    assert manifest["NotActions"] == []
    assert manifest["DataActions"] == []
    assert manifest["NotDataActions"] == []


def test_azure_ingestion_custom_role_declares_deny_read() -> None:
    terraform = (ROOT / "deploy" / "terraform" / "azure" / "ingestion" / "main.tf").read_text()

    assert f'"{DENY_READ}"' in terraform
