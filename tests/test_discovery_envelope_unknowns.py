"""Missing collection metadata must not become a safety or freshness claim."""

from __future__ import annotations

import pytest

from agent_bom.discovery_envelope import DiscoveryEnvelope
from agent_bom.models import Agent, AgentType


@pytest.mark.parametrize("value", [None, "", "future_mode", 7, {}, []])
def test_unrecognized_scan_mode_remains_unknown(value: object) -> None:
    envelope = DiscoveryEnvelope.from_dict({"scan_mode": value})
    assert envelope.to_dict()["scan_mode"] == "unknown"


@pytest.mark.parametrize("value", [None, "", "future_redaction", 7, {}, []])
def test_unrecognized_redaction_remains_unknown(value: object) -> None:
    envelope = DiscoveryEnvelope.from_dict({"redaction_status": value})
    assert envelope.to_dict()["redaction_status"] == "unknown"


@pytest.mark.parametrize("payload", [{}, {"captured_at": None}, {"captured_at": ""}, {"captured_at": 123}])
def test_decoding_does_not_invent_a_capture_timestamp(payload: dict[str, object]) -> None:
    envelope = DiscoveryEnvelope.from_dict(payload)
    assert envelope.captured_at == ""
    assert DiscoveryEnvelope.from_dict(envelope.to_dict()).captured_at == ""


def test_unknown_envelope_survives_agent_json_transport() -> None:
    from agent_bom.api.routes.discovery import _serialize_agent

    envelope = DiscoveryEnvelope.from_dict({})
    agent = Agent(name="imported", agent_type=AgentType.CUSTOM, config_path="", discovery_envelope=envelope.to_dict())
    assert _serialize_agent(agent)["discovery_envelope"] == {
        "envelope_version": 1,
        "scan_mode": "unknown",
        "discovery_scope": [],
        "permissions_used": [],
        "redaction_status": "unknown",
        "captured_at": "",
    }


def test_recorded_capture_timestamp_is_preserved_exactly() -> None:
    timestamp = "2026-09-01T09:30:00-04:00"
    assert DiscoveryEnvelope.from_dict({"captured_at": timestamp}).captured_at == timestamp
