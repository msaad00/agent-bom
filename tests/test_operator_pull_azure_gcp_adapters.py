from __future__ import annotations

import importlib.util
import json
from pathlib import Path

from agent_bom.inventory import load_inventory
from agent_bom.models import Agent, AgentType, MCPServer, Package, TransportType

ROOT = Path(__file__).resolve().parents[1]
AZURE_ADAPTER_PATH = ROOT / "examples" / "operator_pull" / "azure_inventory_adapter.py"
GCP_ADAPTER_PATH = ROOT / "examples" / "operator_pull" / "gcp_inventory_adapter.py"
WRITER_PATH = ROOT / "examples" / "operator_pull" / "inventory_writer.py"


def _load_module(path: Path, name: str):
    spec = importlib.util.spec_from_file_location(name, path)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_azure_operator_pull_adapter_cli_writes_sanitized_inventory(monkeypatch, tmp_path: Path) -> None:
    adapter = _load_module(AZURE_ADAPTER_PATH, "azure_inventory_adapter")
    agent = Agent(
        name="azure-ai-endpoint",
        agent_type=AgentType.CUSTOM,
        config_path="/subscriptions/sub-123/resourceGroups/rg/providers/Microsoft.MachineLearningServices/workspaces/ws",
        source="azure",
        metadata={
            "cloud_origin": {
                "provider": "azure",
                "service": "machine-learning",
                "resource_type": "endpoint",
                "resource_id": (
                    "/subscriptions/sub-123/resourceGroups/rg/providers/"
                    "Microsoft.MachineLearningServices/workspaces/ws/onlineEndpoints/endpoint-1"
                ),
                "scope": {"subscription_id": "sub-123", "api_token": "should-not-survive"},
            }
        },
        mcp_servers=[
            MCPServer(
                name="azure-openai",
                command="npx",
                args=["-y", "server", "--api-key", "raw-token"],
                env={"AZURE_OPENAI_API_KEY": "raw-token"},
                transport=TransportType.STDIO,
                packages=[
                    Package(
                        name="@azure/openai",
                        version="1.0.0",
                        ecosystem="npm",
                        purl="pkg:npm/%40azure/openai@1.0.0",
                    )
                ],
            )
        ],
    )
    monkeypatch.setattr(adapter, "discover", lambda **_kwargs: ([agent], ["warning has token=secret"]))
    output_path = tmp_path / "azure-inventory.json"

    assert (
        adapter.main(
            [
                "--subscription-id",
                "sub-123",
                "--resource-group",
                "rg",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    loaded = load_inventory(str(output_path))
    serialized = json.dumps(loaded)
    assert loaded["source"] == "azure-operator-pull"
    assert loaded["discovery_provenance"]["source_type"] == "operator_pushed_inventory"
    assert loaded["discovery_provenance"]["observed_via"] == ["operator_pushed_inventory", "azure_sdk"]
    assert loaded["agents"][0]["metadata"]["cloud_origin"]["resource_id"].startswith("/subscriptions/sub-123/")
    assert loaded["agents"][0]["discovery_provenance"]["resource_id"].startswith("/subscriptions/sub-123/")
    assert loaded["agents"][0]["metadata"]["cloud_origin"]["scope"]["api_token"] == "***REDACTED***"
    assert loaded["agents"][0]["metadata"]["permissions_used"]
    assert loaded["agents"][0]["mcp_servers"][0]["env"]["AZURE_OPENAI_API_KEY"] == "***REDACTED***"
    assert "raw-token" not in serialized
    assert "should-not-survive" not in serialized


def test_gcp_operator_pull_adapter_cli_marks_skill_invoked_inventory(monkeypatch, tmp_path: Path) -> None:
    adapter = _load_module(GCP_ADAPTER_PATH, "gcp_inventory_adapter")
    agent = Agent(
        name="vertex-endpoint",
        agent_type=AgentType.CUSTOM,
        config_path="projects/demo/locations/us-central1/endpoints/endpoint-1",
        source="gcp",
        metadata={
            "cloud_origin": {
                "provider": "gcp",
                "service": "vertex-ai",
                "resource_type": "endpoint",
                "resource_id": "endpoint-1",
                "location": "us-central1",
            },
            "service_account_token": "hidden-token",
        },
        mcp_servers=[],
    )
    monkeypatch.setattr(adapter, "discover", lambda **_kwargs: ([agent], []))
    output_path = tmp_path / "gcp-inventory.json"

    assert (
        adapter.main(
            [
                "--project",
                "demo",
                "--region",
                "us-central1",
                "--source",
                "gcp-skill-invoked",
                "--discovery-method",
                "skill_invoked_pull",
                "--output",
                str(output_path),
            ]
        )
        == 0
    )

    loaded = load_inventory(str(output_path))
    serialized = json.dumps(loaded)
    assert loaded["source"] == "gcp-skill-invoked"
    assert loaded["discovery_provenance"]["source_type"] == "skill_invoked_pull"
    assert loaded["discovery_provenance"]["observed_via"] == ["skill_invoked_pull", "gcp_sdk"]
    assert loaded["agents"][0]["discovery_provenance"]["provider"] == "gcp"
    assert loaded["agents"][0]["metadata"]["permissions_used"]
    assert "hidden-token" not in serialized


def test_operator_pull_inventory_writer_keeps_container_purl_schema_valid() -> None:
    writer = _load_module(WRITER_PATH, "inventory_writer")
    package = Package(
        name="gcr.io/demo/model-api",
        version="2026-04",
        ecosystem="container-image",
        purl="pkg:docker/gcr.io/demo/model-api@2026-04",
    )

    payload = writer._package_to_inventory(package)

    assert payload == {
        "name": "gcr.io/demo/model-api",
        "version": "2026-04",
        "purl": "pkg:docker/gcr.io/demo/model-api@2026-04",
    }


def test_provider_permissions_used_reads_azure_and_gcp_contracts() -> None:
    writer = _load_module(WRITER_PATH, "inventory_writer")

    azure_permissions = writer.provider_permissions_used("azure")
    gcp_permissions = writer.provider_permissions_used("gcp")

    assert azure_permissions
    assert gcp_permissions
    assert all(":" in permission or "." in permission for permission in azure_permissions + gcp_permissions)
