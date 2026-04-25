from __future__ import annotations

import json
from datetime import datetime, timezone

from click.testing import CliRunner

from agent_bom.cli.claw import fleet_group
from agent_bom.fleet.k8s_reconcile import extract_k8s_inventory_observations, reconcile_k8s_inventory


def _obs(**overrides):
    value = {
        "tenant_id": "tenant-a",
        "cluster": "prod",
        "namespace": "agents",
        "workload": "agent-runner",
        "agent_name": "claude-code",
        "server_name": "filesystem",
        "surface": "mcp-server",
        "image": "ghcr.io/acme/agent-runner:v1",
        "observed_at": "2026-04-25T10:00:00Z",
        "discovery_sources": ["k8s", "config"],
    }
    value.update(overrides)
    return value


def test_reconcile_tracks_added_changed_missing_and_stale():
    previous = [
        _obs(image="ghcr.io/acme/agent-runner:v1"),
        _obs(workload="old-runner", observed_at="2026-04-24T00:00:00Z"),
    ]
    current = [
        _obs(image="ghcr.io/acme/agent-runner:v2"),
        _obs(workload="new-runner"),
    ]

    result = reconcile_k8s_inventory(
        previous,
        current,
        generated_at=datetime(2026, 4, 25, 12, 0, tzinfo=timezone.utc),
        stale_after_seconds=60 * 60,
    )

    assert result["kind"] == "k8s_inventory_reconciliation"
    assert result["summary"] == {
        "previous": 2,
        "current": 2,
        "added": 1,
        "changed": 1,
        "unchanged": 0,
        "missing": 0,
        "stale": 1,
    }
    statuses = {record["identity"]["workload"]: record["status"] for record in result["records"]}
    assert statuses["agent-runner"] == "changed"
    assert statuses["new-runner"] == "added"
    assert statuses["old-runner"] == "stale"


def test_standard_inventory_json_normalizes_to_k8s_observations():
    payload = {
        "tenant_id": "tenant-a",
        "agents": [
            {
                "name": "cursor",
                "metadata": {"cluster": "prod", "namespace": "ai"},
                "mcp_servers": [
                    {
                        "name": "github",
                        "surface": "mcp-server",
                        "metadata": {"workload": "cursor-runner", "image": "agent:v1"},
                        "discovery_sources": ["k8s"],
                    }
                ],
            }
        ],
    }

    observations = extract_k8s_inventory_observations(payload)

    assert len(observations) == 1
    assert observations[0].tenant_id == "tenant-a"
    assert observations[0].cluster == "prod"
    assert observations[0].namespace == "ai"
    assert observations[0].workload == "cursor-runner"
    assert observations[0].agent_name == "cursor"
    assert observations[0].server_name == "github"


def test_fleet_reconcile_k8s_cli_outputs_json(tmp_path):
    previous = tmp_path / "previous.json"
    current = tmp_path / "current.json"
    previous.write_text(json.dumps({"k8s_inventory_observations": [_obs()]}), encoding="utf-8")
    current.write_text(json.dumps({"k8s_inventory_observations": [_obs(workload="agent-runner-2")]}), encoding="utf-8")

    result = CliRunner().invoke(
        fleet_group,
        [
            "reconcile-k8s",
            "--previous",
            str(previous),
            "--current",
            str(current),
            "--json",
        ],
    )

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["summary"]["added"] == 1
    assert payload["summary"]["stale"] == 1
