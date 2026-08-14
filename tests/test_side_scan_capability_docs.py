"""Keep public side-scan claims aligned with shipped provider executors."""

from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_cloud_connect_scopes_azure_and_gcp_execution_claims() -> None:
    raw = (ROOT / "docs" / "CLOUD_CONNECT.md").read_text()
    cloud_connect = " ".join(raw.split())  # collapse wrapping whitespace

    assert "concrete Azure Managed Disk and GCP Persistent Disk adapters" in cloud_connect
    # Azure/GCP now ship a CLI executor, but no live-cloud smoke is claimed.
    assert "no credentialed live smoke is claimed yet" in cloud_connect
    assert "credentialed_smoke=false" in cloud_connect
    # The old contract_only refusal claim must be gone.
    assert "executor: contract_only" not in cloud_connect
    assert "refuses execution (exit 2)" not in cloud_connect
    assert "execution is wired for connection/scheduler integrations" not in cloud_connect
    assert "POST /v1/cloud/runtime-evidence/ingest" in cloud_connect
    assert "a dedicated ingest REST endpoint" not in cloud_connect


def test_architecture_labels_cross_cloud_surface_as_injected_sdk_only() -> None:
    architecture = (ROOT / "docs" / "ARCHITECTURE.md").read_text()

    assert "injected-SDK Azure Managed Disk and GCP Persistent Disk lifecycle adapters" in architecture


def test_side_scan_capability_docs_mention_shipped_cli_executor() -> None:
    cloud_connect = (ROOT / "docs" / "CLOUD_CONNECT.md").read_text()
    cli_map = (ROOT / "docs" / "CLI_MAP.md").read_text()
    assert "side-scan-capabilities" in cloud_connect or "side-scan-capabilities" in cli_map
    # The docs must describe the shipped Azure/GCP executor, not a refusal.
    assert "side-scan --provider azure|gcp" in cloud_connect
    assert "refuses" not in cli_map.lower()
