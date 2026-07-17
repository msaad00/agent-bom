"""Keep public side-scan claims aligned with shipped provider executors."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cloud_connect_scopes_azure_and_gcp_execution_claims() -> None:
    cloud_connect = (ROOT / "docs" / "CLOUD_CONNECT.md").read_text()

    assert "concrete Azure Managed Disk and GCP Persistent Disk adapters" in cloud_connect
    assert "no live credentialed" in cloud_connect
    assert "execution is wired for connection/scheduler integrations" not in cloud_connect


def test_architecture_labels_cross_cloud_surface_as_injected_sdk_only() -> None:
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text()

    assert "injected-SDK Azure Managed Disk and GCP Persistent Disk lifecycle adapters" in architecture
