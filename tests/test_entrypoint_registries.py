"""Tests for provider, connector, and parser entry-point registries."""

from __future__ import annotations

import sys
import types
from collections.abc import Callable
from typing import Any

import pytest

from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV, ExtensionCapabilities


class FakeEntryPoint:
    def __init__(self, name: str, loader: Callable[[], Any]) -> None:
        self.name = name
        self._loader = loader

    def load(self) -> Any:
        return self._loader()


class FakeEntryPoints(list):
    def select(self, *, group: str) -> list[FakeEntryPoint]:
        return [entry_point for entry_point in self if getattr(entry_point, "group", group) == group]


def _patch_entry_points(monkeypatch, entries_by_group: dict[str, list[FakeEntryPoint]]) -> None:
    entries = FakeEntryPoints()
    for group, group_entries in entries_by_group.items():
        for entry_point in group_entries:
            entry_point.group = group
            entries.append(entry_point)

    monkeypatch.setattr("agent_bom.extensions.metadata.entry_points", lambda: entries)


def _reset_registries() -> None:
    import agent_bom.cloud as cloud_registry
    import agent_bom.connectors as connector_registry
    import agent_bom.parsers as parser_registry

    cloud_registry._reset_provider_registry_for_tests()
    connector_registry._reset_connector_registry_for_tests()
    parser_registry._reset_inventory_parser_registry_for_tests()


def _load_builtin_registries() -> None:
    import agent_bom.cloud as cloud_registry
    import agent_bom.connectors as connector_registry
    import agent_bom.parsers as parser_registry

    cloud_registry.list_registered_providers()
    connector_registry.list_registered_connectors()
    parser_registry.list_registered_inventory_parsers()


@pytest.fixture(autouse=True)
def reset_registry_state(monkeypatch):
    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    _reset_registries()
    yield
    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    _reset_registries()
    _load_builtin_registries()


def test_built_in_registries_are_available_by_default(monkeypatch):
    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    _reset_registries()

    import agent_bom.cloud as cloud_registry
    import agent_bom.connectors as connector_registry
    import agent_bom.parsers as parser_registry

    providers = {registration.name: registration for registration in cloud_registry.list_registered_providers()}
    connectors = {registration.name: registration for registration in connector_registry.list_registered_connectors()}
    parsers = {registration.name: registration for registration in parser_registry.list_registered_inventory_parsers()}

    assert providers["aws"].module == "agent_bom.cloud.aws"
    assert providers["ollama"].capabilities.writes is False
    assert cloud_registry._PROVIDERS["gcp"] == "agent_bom.cloud.gcp"

    assert connector_registry.list_connectors() == ["jira", "servicenow", "slack"]
    assert connectors["slack"].capabilities.data_boundary == "agentless_read_only"

    assert {"npm", "pip", "go", "maven", "ruby", "swift"} <= set(parsers)
    assert parsers["npm"].parse_attr == "parse_npm_packages"
    assert parsers["npm"].capabilities.network_access is False


def test_opt_in_fake_cloud_provider_entry_point_loads_and_sanitizes(monkeypatch):
    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "true")
    _reset_registries()

    import agent_bom.cloud as cloud_registry
    from agent_bom.cloud.base import CloudProviderRegistration

    module_name = "agent_bom.tests.fake_entrypoint_cloud"
    fake_module = types.ModuleType(module_name)
    fake_module.discover = lambda **_: (
        [],
        ["failed https://user:tok123@example.com/api?key=secret from /Users/alice/.config/provider.json"],
    )
    monkeypatch.setitem(sys.modules, module_name, fake_module)

    registration = CloudProviderRegistration(
        name="acme",
        module=module_name,
        capabilities=ExtensionCapabilities(
            scan_modes=("inventory",),
            required_scopes=("acme.inventory.read",),
            outbound_destinations=("api.acme.example",),
            data_boundary="agentless_read_only",
            network_access=True,
        ),
        source="entry_point",
    )
    _patch_entry_points(
        monkeypatch,
        {"agent_bom.cloud_providers": [FakeEntryPoint("acme", lambda: lambda: registration)]},
    )

    providers = {entry.name: entry for entry in cloud_registry.list_registered_providers()}
    assert providers["acme"].source == "entry_point"
    assert cloud_registry._PROVIDERS["acme"] == module_name

    agents, warnings = cloud_registry.discover_from_provider("acme")
    assert agents == []
    warning = " ".join(warnings)
    assert "tok123" not in warning
    assert "key=secret" not in warning
    assert "/Users/alice" not in warning


def test_entry_point_failures_are_sanitized_and_do_not_hide_builtins(monkeypatch):
    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "1")
    _reset_registries()

    import agent_bom.cloud as cloud_registry

    def fail_load() -> Any:
        raise RuntimeError("boom https://user:tok123@example.com/api?key=secret from /Users/alice/.config/plugin.json")

    _patch_entry_points(
        monkeypatch,
        {"agent_bom.cloud_providers": [FakeEntryPoint("bad-provider", fail_load)]},
    )

    providers = {entry.name for entry in cloud_registry.list_registered_providers()}
    warnings = " ".join(cloud_registry.provider_registry_warnings())

    assert "aws" in providers
    assert "ollama" in providers
    assert "bad-provider" in warnings
    assert "tok123" not in warnings
    assert "key=secret" not in warnings
    assert "/Users/alice" not in warnings


def test_fake_connector_and_parser_entry_points_load_when_enabled(monkeypatch):
    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "yes")
    _reset_registries()

    import agent_bom.connectors as connector_registry
    import agent_bom.parsers as parser_registry
    from agent_bom.connectors.base import ConnectorRegistration
    from agent_bom.parsers.base import InventoryParserRegistration

    connector_registration = ConnectorRegistration(
        name="pagerduty",
        module="agent_bom.tests.fake_pagerduty_connector",
        capabilities=ExtensionCapabilities(
            required_scopes=("pagerduty.read",),
            outbound_destinations=("api.pagerduty.com",),
            network_access=True,
        ),
        source="entry_point",
    )
    parser_registration = InventoryParserRegistration(
        name="custom-lock",
        module="agent_bom.tests.fake_lock_parser",
        capabilities=ExtensionCapabilities(
            required_scopes=("local_project_read",),
            outbound_destinations=(),
            data_boundary="local_manifest_read_only",
            network_access=False,
        ),
        parse_attr="parse_custom_lock",
        manifest_names=("custom.lock",),
        source="entry_point",
    )
    _patch_entry_points(
        monkeypatch,
        {
            "agent_bom.connectors": [FakeEntryPoint("pagerduty", lambda: lambda: connector_registration)],
            "agent_bom.inventory_parsers": [FakeEntryPoint("custom-lock", lambda: lambda: parser_registration)],
        },
    )

    connectors = {entry.name: entry for entry in connector_registry.list_registered_connectors()}
    parsers = {entry.name: entry for entry in parser_registry.list_registered_inventory_parsers()}

    assert connectors["pagerduty"].source == "entry_point"
    assert "jira" in connectors
    assert parsers["custom-lock"].manifest_names == ("custom.lock",)
    assert "pip" in parsers


def test_custom_connector_scan_saves_reusable_tenant_graph(tmp_path, monkeypatch):
    """Exercise registry -> scan report -> durable graph, without a provider account."""
    from agent_bom.api import pipeline
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.cloud.normalization import build_cloud_origin
    from agent_bom.connectors.base import ConnectorRegistration
    from agent_bom.models import Agent, AgentType, MCPServer, Package

    monkeypatch.setenv(ENTRYPOINTS_ENABLED_ENV, "true")
    monkeypatch.setenv("AGENT_BOM_GRAPH_STORE_BACKED_BUILD", "false")
    module_name = "agent_bom.tests.customer_inventory_connector"
    source = types.ModuleType(module_name)
    calls = []
    origin = build_cloud_origin(
        provider="customer",
        service="inventory",
        resource_type="agent",
        resource_id="inventory-agent-42",
        resource_name="review-agent",
        account_id="sandbox-account",
    )

    def discover(**kwargs):
        calls.append(kwargs)
        return [
            Agent(
                name="review-agent",
                agent_type=AgentType.CUSTOM,
                config_path="inventory:agent-42",
                source="customer-inventory",
                metadata={"cloud_origin": origin},
                mcp_servers=[MCPServer(name="review-tools", packages=[Package(name="sample-lib", version="1.0", ecosystem="pypi")])],
            )
        ], []

    source.discover = discover
    monkeypatch.setitem(sys.modules, module_name, source)
    registration = ConnectorRegistration(
        name="customer-inventory",
        module=module_name,
        source="entry_point",
        capabilities=ExtensionCapabilities(writes=False, network_access=False, data_boundary="agentless_read_only"),
    )
    _patch_entry_points(monkeypatch, {"agent_bom.connectors": [FakeEntryPoint("customer-inventory", lambda: lambda: registration)]})
    monkeypatch.setattr("agent_bom.discovery.discover_all", lambda *args, **kwargs: [])
    monkeypatch.setattr("agent_bom.scanners.scan_agents_sync", lambda agents, **kwargs: [])
    monkeypatch.setattr(pipeline, "_sync_scan_agents_to_fleet", lambda *args, **kwargs: None)
    path = tmp_path / "customer-evidence.db"
    store = SQLiteGraphStore(path)
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: store)
    job = ScanJob(
        job_id="custom-source-scan",
        tenant_id="customer-a",
        created_at="2026-09-23T00:00:00Z",
        request=ScanRequest(connectors=["customer-inventory"], enrich=False, offline=True),
    )
    pipeline._run_scan_sync(job)
    assert job.status == JobStatus.DONE
    assert calls == [{}]  # Destination credentials are not forwarded to discovery.
    assert job.result["graph_persistence"]["status"] == "persisted"
    reopened = SQLiteGraphStore(path)
    graph = reopened.load_graph(tenant_id="customer-a", scan_id=job.job_id)
    assert graph.nodes and graph.edges
    resource_id = "cloud_resource:customer:inventory:agent:inventory-agent-42"
    assert graph.nodes[resource_id].attributes["cloud_origin"] == origin
    assert graph.has_edge(resource_id, "agent:review-agent")
    assert not reopened.load_graph(tenant_id="customer-b", scan_id=job.job_id).nodes
    before = (set(graph.nodes), {(e.source, e.target, e.relationship) for e in graph.edges})
    # Re-saving the same report must replace the snapshot without duplicating edges.
    pipeline._persist_graph_snapshot(job, job.result)
    replay = SQLiteGraphStore(path).load_graph(tenant_id="customer-a", scan_id=job.job_id)
    assert (set(replay.nodes), {(e.source, e.target, e.relationship) for e in replay.edges}) == before
    assert len(replay.edges) == len(graph.edges)
