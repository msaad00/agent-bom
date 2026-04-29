"""Discovery provider contract API coverage."""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV, ExtensionCapabilities


@pytest.fixture(autouse=True)
def reset_provider_registry(monkeypatch: pytest.MonkeyPatch) -> Iterator[None]:
    import agent_bom.cloud as cloud_registry

    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    cloud_registry._reset_provider_registry_for_tests()
    yield
    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    cloud_registry._reset_provider_registry_for_tests()
    cloud_registry.list_registered_providers()


def test_provider_contracts_describe_builtin_boundaries_without_loading_sdks() -> None:
    from agent_bom.cloud import provider_contracts

    payload = provider_contracts()
    providers = {provider["name"]: provider for provider in payload["providers"]}

    assert payload["contract_version"] == "1"
    assert payload["entrypoints_enabled"] is False
    assert payload["provider_count"] >= 12
    assert "aws" in providers
    assert providers["aws"]["module"] == "agent_bom.cloud.aws"
    assert providers["aws"]["capabilities"]["scan_modes"] == ["direct_cloud_pull"]
    assert providers["aws"]["capabilities"]["required_scopes"] == ["aws:read"]
    assert "sts:GetCallerIdentity" in providers["aws"]["capabilities"]["permissions_used"]
    assert "bedrock:ListAgents" in providers["aws"]["capabilities"]["permissions_used"]
    assert providers["aws"]["capabilities"]["network_destinations"] == ["aws"]
    assert providers["aws"]["capabilities"]["writes"] is False
    assert providers["aws"]["trust_contract"]["read_only"] is True
    assert providers["aws"]["trust_contract"]["redaction_status"] == "central_sanitizer_applied"
    assert providers["ollama"]["capabilities"]["scan_modes"] == ["runtime_probe"]
    assert providers["ollama"]["capabilities"]["network_access"] is False


def test_provider_contracts_preserve_scope_zero_plugin_modes() -> None:
    import agent_bom.cloud as cloud_registry
    from agent_bom.cloud.base import CloudProviderRegistration

    cloud_registry.register_provider(
        CloudProviderRegistration(
            name="customer-cmdb",
            module="customer.plugins.cmdb",
            capabilities=ExtensionCapabilities(
                scan_modes=("operator_pushed_inventory", "skill_invoked_pull"),
                required_scopes=("cmdb.inventory.read",),
                permissions_used=("cmdb.assets.read",),
                outbound_destinations=(),
                data_boundary="agentless_read_only",
                network_access=False,
                guarantees=("read_only", "schema_validated"),
            ),
            source="entry_point",
        )
    )

    providers = {provider["name"]: provider for provider in cloud_registry.provider_contracts()["providers"]}

    assert providers["customer-cmdb"]["capabilities"]["scan_modes"] == ["operator_pushed_inventory", "skill_invoked_pull"]
    assert providers["customer-cmdb"]["capabilities"]["permissions_used"] == ["cmdb.assets.read"]
    assert providers["customer-cmdb"]["trust_contract"]["supports_scope_zero"] is True
    assert providers["customer-cmdb"]["trust_contract"]["data_residency"] == "operator_environment"


def test_discovery_provider_contract_api_response_is_operator_readable() -> None:
    client = TestClient(app)

    response = client.get("/v1/discovery/providers")

    assert response.status_code == 200
    payload = response.json()
    assert payload["entrypoints_enabled"] is False
    assert payload["warnings"] == []
    aws = next(provider for provider in payload["providers"] if provider["name"] == "aws")
    assert aws["capabilities"]["data_boundary"] == "agentless_read_only"
    assert aws["trust_contract"]["scope_control"] == "operator_supplied_scopes"
    assert "aws:read" in aws["capabilities"]["required_scopes"]
    assert all(":" in permission for permission in aws["capabilities"]["permissions_used"])
