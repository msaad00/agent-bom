"""Tests for local fleet sync discovery push (#3471)."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.fleet.sync_client import build_fleet_sync_payload, run_fleet_sync


def test_build_fleet_sync_payload_includes_trust_score() -> None:
    agent = MagicMock()
    agent.name = "cursor"
    agent.agent_type.value = "cursor"
    agent.canonical_id = "cursor:local"
    agent.mcp_servers = []
    payload = build_fleet_sync_payload([agent], source_id="device-a")
    assert payload["source_id"] == "device-a"
    assert len(payload["agents"]) == 1
    assert payload["agents"][0]["name"] == "cursor"
    assert "trust_score" in payload["agents"][0]
    assert payload["agents"][0]["mcp_servers"] == []


def test_run_fleet_sync_discovers_and_pushes(monkeypatch: pytest.MonkeyPatch) -> None:
    agent = MagicMock()
    agent.name = "cursor"
    agent.agent_type.value = "cursor"
    agent.canonical_id = "cursor:local"
    agent.mcp_servers = []

    monkeypatch.setenv("AGENT_BOM_PUSH_URL", "https://control-plane.example/v1/fleet/sync")
    api_response = {"synced": 1, "new": 1, "updated": 0, "source_id": "device-a"}
    with patch("agent_bom.discovery.discover_all", return_value=[agent]) as discover:
        with patch("agent_bom.fleet.sync_client.push_json", return_value=api_response) as push:
            result = run_fleet_sync(source_id="device-a")

    discover.assert_called_once_with(project_dir=None)
    push.assert_called_once()
    assert push.call_args.args[0] == "https://control-plane.example/v1/fleet/sync"
    assert result["discovered"] == 1
    assert result["synced"] == 1


def test_run_fleet_sync_requires_push_url(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("AGENT_BOM_PUSH_URL", raising=False)
    with pytest.raises(ValueError, match="AGENT_BOM_PUSH_URL"):
        run_fleet_sync()
