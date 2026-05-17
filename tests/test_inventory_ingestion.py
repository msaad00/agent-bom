"""Inventory schema dispatch and streaming ingestion regressions."""

from __future__ import annotations

import json

import pytest

from agent_bom.inventory import load_inventory


def _agent(name: str = "agent-a") -> dict[str, object]:
    return {"name": name, "agent_type": "custom", "mcp_servers": []}


def test_json_inventory_schema_version_v1_dispatch(tmp_path):
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(
        json.dumps({"schema_version": "1", "source": "operator", "agents": [_agent()]}),
        encoding="utf-8",
    )

    loaded = load_inventory(str(inventory_path))

    assert loaded["schema_version"] == "1"
    assert loaded["source"] == "operator"
    assert loaded["agents"][0]["name"] == "agent-a"


def test_json_inventory_unknown_schema_version_rejected(tmp_path):
    inventory_path = tmp_path / "inventory.json"
    inventory_path.write_text(json.dumps({"schema_version": "2", "agents": [_agent()]}), encoding="utf-8")

    with pytest.raises(ValueError, match="Unsupported inventory schema_version '2'"):
        load_inventory(str(inventory_path))


def test_ndjson_inventory_validates_agent_chunks(tmp_path):
    inventory_path = tmp_path / "inventory.ndjson"
    inventory_path.write_text(
        "\n".join(
            [
                json.dumps({"schema_version": "1", "source": "fleet-push"}),
                json.dumps(_agent("agent-a")),
                json.dumps(_agent("agent-b")),
            ]
        ),
        encoding="utf-8",
    )

    loaded = load_inventory(str(inventory_path))

    assert loaded["schema_version"] == "1"
    assert loaded["source"] == "fleet-push"
    assert [agent["name"] for agent in loaded["agents"]] == ["agent-a", "agent-b"]


def test_ndjson_inventory_handles_large_chunked_path(tmp_path):
    inventory_path = tmp_path / "large-inventory.ndjson"
    records = [json.dumps({"schema_version": "1", "source": "fleet-push"})]
    records.extend(json.dumps(_agent(f"agent-{idx:04d}")) for idx in range(1000))
    inventory_path.write_text("\n".join(records), encoding="utf-8")

    loaded = load_inventory(str(inventory_path))

    assert loaded["schema_version"] == "1"
    assert loaded["source"] == "fleet-push"
    assert len(loaded["agents"]) == 1000
    assert loaded["agents"][999]["name"] == "agent-0999"


def test_ndjson_inventory_rejects_bad_chunk_with_line_context(tmp_path):
    inventory_path = tmp_path / "inventory.ndjson"
    inventory_path.write_text(
        "\n".join(
            [
                json.dumps({"schema_version": "1"}),
                json.dumps({"agent_type": "custom", "mcp_servers": []}),
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="line 2|Inventory schema validation failed"):
        load_inventory(str(inventory_path))


def test_ndjson_inventory_rejects_mixed_schema_versions(tmp_path):
    inventory_path = tmp_path / "inventory.ndjson"
    inventory_path.write_text(
        "\n".join(
            [
                json.dumps({"schema_version": "1", "source": "fleet-push"}),
                json.dumps({"schema_version": "2", "agents": [_agent("agent-a")]}),
            ]
        ),
        encoding="utf-8",
    )

    with pytest.raises(ValueError, match="Unsupported inventory schema_version '2'"):
        load_inventory(str(inventory_path))
