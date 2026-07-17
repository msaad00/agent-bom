"""Least-privilege guards for Azure/GCP side-scan mutation roles."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_azure_sidescan_role_is_custom_and_lifecycle_scoped() -> None:
    main = (ROOT / "deploy" / "terraform" / "connect-azure-sidescan" / "main.tf").read_text()

    for action in (
        "Microsoft.Compute/snapshots/read",
        "Microsoft.Compute/snapshots/write",
        "Microsoft.Compute/snapshots/delete",
        "Microsoft.Compute/disks/read",
        "Microsoft.Compute/disks/write",
        "Microsoft.Compute/disks/delete",
        "Microsoft.Compute/virtualMachines/read",
        "Microsoft.Compute/virtualMachines/write",
    ):
        assert action in main
    assert 'role_definition_name = "Owner"' not in main
    assert 'role_definition_name = "Contributor"' not in main
    assert "Microsoft.Storage/storageAccounts/blobServices/containers/blobs/read" not in main


def test_gcp_sidescan_role_has_no_data_plane_or_project_wide_admin() -> None:
    main = (ROOT / "deploy" / "terraform" / "connect-gcp-sidescan" / "main.tf").read_text()

    for permission in (
        "compute.snapshots.create",
        "compute.snapshots.delete",
        "compute.disks.create",
        "compute.disks.delete",
        "compute.instances.attachDisk",
        "compute.instances.detachDisk",
    ):
        assert permission in main
    assert "roles/owner" not in main
    assert "roles/editor" not in main
    assert "storage.objects.get" not in main
    assert "compute.instances.setMetadata" not in main


def test_cross_cloud_sidescan_docs_keep_mutations_opt_in_and_smokes_fixture_scoped() -> None:
    for provider in ("azure", "gcp"):
        readme = (ROOT / "deploy" / "terraform" / f"connect-{provider}-sidescan" / "README.md").read_text()
        assert "AGENT_BOM_SIDESCAN=1" in readme
        assert "No live cloud mutation was run" in readme
        assert "block bytes" in readme
