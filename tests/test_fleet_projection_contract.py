"""The fleet producer emits observation aliases without inventing evidence."""

import json
from pathlib import Path

import jsonschema

from agent_bom.api.fleet_store import FleetAgent


def test_fleet_projection_matches_contract_and_roundtrips():
    agent = FleetAgent(
        agent_id="agent",
        name="engineering",
        agent_type="custom",
        created_at="2026-10-01T00:00:00Z",
        last_discovery="2026-10-01T01:00:00Z",
        last_scan="2026-10-02T01:00:00Z",
    )
    payload = agent.model_dump(mode="json")
    schema = json.loads((Path(__file__).resolve().parents[1] / "contracts/v1/fleet-snapshot.schema.json").read_text())
    jsonschema.validate(payload, schema)
    assert payload["agent_name"] == "engineering"
    assert payload["last_seen"] == "2026-10-02T01:00:00Z"
    assert FleetAgent.model_validate_json(agent.model_dump_json()).model_dump() == agent.model_dump()


def test_fleet_observation_unknown_and_alias_cannot_override_identity():
    agent = FleetAgent.model_validate(
        {"agent_id": "agent", "name": "canonical", "agent_type": "custom", "agent_name": "forged", "last_seen": "2099-01-01T00:00:00Z"}
    )
    payload = agent.model_dump(mode="json")
    assert payload["agent_name"] == "canonical"
    assert payload["last_seen"] is None
