"""Keep public side-scan claims aligned with shipped provider executors."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cloud_connect_does_not_claim_azure_or_gcp_execution() -> None:
    cloud_connect = (ROOT / "docs" / "CLOUD_CONNECT.md").read_text()

    assert "does not ship Azure or GCP lifecycle executors" in cloud_connect
    assert "execution is wired for connection/scheduler integrations" not in cloud_connect


def test_architecture_labels_cross_cloud_surface_as_contract_only() -> None:
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text()

    assert "Azure/GCP target discovery and lifecycle contract only" in architecture
