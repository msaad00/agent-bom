"""Plugin registry status CLI/API contract tests."""

from __future__ import annotations

import json
from typing import Any

from click.testing import CliRunner
from starlette.testclient import TestClient

from agent_bom.api.server import app
from agent_bom.cli import main
from agent_bom.extensions import ENTRYPOINTS_ENABLED_ENV
from agent_bom.plugin_entrypoints import plugin_registry_status


class FakeEntryPoint:
    def __init__(self, name: str, value: str, group: str, distribution: str = "acme-plugin") -> None:
        self.name = name
        self.value = value
        self.group = group
        self.dist = type("FakeDist", (), {"metadata": {"Name": distribution}})()


class FakeEntryPoints(list[FakeEntryPoint]):
    def select(self, *, group: str) -> list[FakeEntryPoint]:
        return [entry_point for entry_point in self if entry_point.group == group]


def _patch_entry_points(monkeypatch, entries: list[FakeEntryPoint]) -> None:
    monkeypatch.setattr("agent_bom.extensions.metadata.entry_points", lambda: FakeEntryPoints(entries))


def test_plugin_registry_status_is_metadata_only_and_counts_builtins(monkeypatch):
    monkeypatch.delenv(ENTRYPOINTS_ENABLED_ENV, raising=False)
    _patch_entry_points(
        monkeypatch,
        [
            FakeEntryPoint(
                "acme-tools",
                "acme_agent_bom.tools:register",
                "agent_bom.mcp_tools",
            )
        ],
    )

    status = plugin_registry_status()

    assert status["schema_version"] == "agent-bom.plugin_registry_status.v1"
    assert status["entrypoints_enabled"] is False
    assert status["metadata_only"] is True
    assert status["totals"]["groups"] == 6
    assert status["totals"]["builtin_registrations"] >= 38
    assert status["totals"]["declared_entrypoints"] == 1
    mcp_group = next(group for group in status["groups"] if group["group"] == "agent_bom.mcp_tools")
    assert mcp_group["declared_entrypoints"] == [
        {
            "name": "acme-tools",
            "value": "acme_agent_bom.tools:register",
            "distribution": "acme-plugin",
        }
    ]


def test_plugins_status_cli_emits_json(monkeypatch):
    _patch_entry_points(
        monkeypatch,
        [FakeEntryPoint("briefs", "acme.intel:source", "agent_bom.advisory_sources")],
    )

    result = CliRunner().invoke(main, ["plugins", "status", "--format", "json"])

    assert result.exit_code == 0
    payload: dict[str, Any] = json.loads(result.output)
    assert payload["schema_version"] == "agent-bom.plugin_registry_status.v1"
    assert payload["totals"]["declared_entrypoints"] == 1


def test_plugin_status_api_returns_registry_metadata(monkeypatch):
    _patch_entry_points(monkeypatch, [FakeEntryPoint("otlp", "acme.runtime:emit", "agent_bom.runtime_emitters")])

    response = TestClient(app, raise_server_exceptions=False).get("/v1/plugins/status")

    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == "agent-bom.plugin_registry_status.v1"
    assert payload["metadata_only"] is True
    assert payload["totals"]["declared_entrypoints"] == 1
