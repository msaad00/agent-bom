"""Runtime → graph incident feedback (the feedback direction of the moat).

Covers the full loop: a runtime incident is emitted to a durable JSONL sink,
loaded back, and projected into the next scan's unified graph as an
``observed_*`` agent-node attribute plus an observed-reach edge tagged
``source="runtime-feedback"``. Also pins the default-off no-op posture and the
fail-safe handling of absent/malformed data.
"""

from __future__ import annotations

import asyncio
import json

from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.graph.types import RelationshipType
from agent_bom.runtime.incident_feedback import (
    ENV_FEEDBACK_PATH,
    IncidentKind,
    RuntimeIncidentRecord,
    RuntimeIncidentSink,
    load_incident_records,
    resolve_sink_path,
)
from agent_bom.runtime.protection import ProtectionEngine

_TS = "2026-06-24T00:00:00+00:00"


def _record(**overrides: object) -> RuntimeIncidentRecord:
    base: dict[str, object] = {
        "agent_id": "billing-agent",
        "kind": IncidentKind.REACHED_CREDENTIAL.value,
        "observed_at": _TS,
        "severity": "high",
        "observed_tool_labels": ["read_secret"],
    }
    base.update(overrides)
    return RuntimeIncidentRecord(**base)  # type: ignore[arg-type]


# ── sink / loader roundtrip ──────────────────────────────────────────────────


def test_emit_then_load_roundtrip(tmp_path):
    path = tmp_path / "feedback.jsonl"
    sink = RuntimeIncidentSink(path)
    assert sink.enabled is True

    assert sink.emit(_record()) is True
    assert sink.emit(_record(kind=IncidentKind.LATERAL_MOVEMENT.value, observed_tool_labels=["transfer_funds"])) is True

    records = load_incident_records(path)
    assert len(records) == 2
    kinds = {r.kind for r in records}
    assert kinds == {IncidentKind.REACHED_CREDENTIAL.value, IncidentKind.LATERAL_MOVEMENT.value}
    assert records[0].agent_id == "billing-agent"
    assert records[0].observed_at == _TS


def test_record_is_deterministic_with_injected_timestamp(tmp_path):
    sink = RuntimeIncidentSink(tmp_path / "f.jsonl")
    sink.emit(_record(observed_at="FIXED-CLOCK"))
    [loaded] = load_incident_records(tmp_path / "f.jsonl")
    assert loaded.observed_at == "FIXED-CLOCK"


# ── default-off posture ──────────────────────────────────────────────────────


def test_sink_default_off_is_noop():
    sink = RuntimeIncidentSink(None)
    assert sink.enabled is False
    assert sink.path is None
    assert sink.emit(_record()) is False


def test_resolve_sink_path_env_and_blank(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_FEEDBACK_PATH, raising=False)
    assert resolve_sink_path(None) is None
    assert resolve_sink_path("") is None
    assert resolve_sink_path("   ") is None

    monkeypatch.setenv(ENV_FEEDBACK_PATH, str(tmp_path / "env.jsonl"))
    resolved = resolve_sink_path(None)
    assert resolved is not None and resolved.name == "env.jsonl"
    # explicit arg beats env
    assert resolve_sink_path(str(tmp_path / "explicit.jsonl")).name == "explicit.jsonl"


def test_protection_engine_default_off(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_FEEDBACK_PATH, raising=False)
    engine = ProtectionEngine(shield=True)
    assert engine._feedback_sink.enabled is False

    async def run() -> None:
        # A credential-bearing response would normally emit feedback; with the
        # sink off it must be a silent no-op (no file, no crash).
        await engine.process_tool_response("read_file", "AKIAIOSFODNN7EXAMPLE secret", agent_id="billing-agent")

    asyncio.run(run())
    assert list(tmp_path.glob("*.jsonl")) == []


# ── absent / malformed data is fail-safe ─────────────────────────────────────


def test_load_missing_and_blank(tmp_path):
    assert load_incident_records(None) == []
    assert load_incident_records(tmp_path / "does-not-exist.jsonl") == []
    empty = tmp_path / "empty.jsonl"
    empty.write_text("\n\n  \n")
    assert load_incident_records(empty) == []


def test_load_skips_malformed_lines(tmp_path):
    path = tmp_path / "mixed.jsonl"
    good = RuntimeIncidentRecord(agent_id="a", kind=IncidentKind.KILL_SWITCH.value, observed_at=_TS)
    path.write_text(
        "\n".join(
            [
                "not json at all",
                json.dumps({"schema_version": "wrong.version", "agent_id": "x", "kind": "kill_switch"}),
                json.dumps({"schema_version": good.to_dict()["schema_version"], "agent_id": "", "kind": "kill_switch"}),
                json.dumps({"schema_version": good.to_dict()["schema_version"], "agent_id": "a", "kind": "bogus_kind"}),
                json.dumps(good.to_dict()),
            ]
        )
    )
    records = load_incident_records(path)
    assert len(records) == 1
    assert records[0].agent_id == "a"
    assert records[0].kind == IncidentKind.KILL_SWITCH.value


def test_from_dict_rejects_non_mapping():
    assert RuntimeIncidentRecord.from_dict([]) is None  # type: ignore[arg-type]


# ── graph projection (the core feedback assertion) ───────────────────────────


def _report_with_agent(name: str = "billing-agent") -> dict:
    return {
        "scan_id": "feedback-scan",
        "agents": [{"name": name, "type": "custom", "status": "configured", "mcp_servers": []}],
    }


def test_inline_records_mark_agent_and_edge(tmp_path):
    report = _report_with_agent()
    report["runtime_incident_feedback"] = [
        _record().to_dict(),
        _record(kind=IncidentKind.LATERAL_MOVEMENT.value, observed_tool_labels=["transfer_funds"]).to_dict(),
    ]
    graph = build_unified_graph_from_report(report)

    agent_node = graph.get_node("agent:billing-agent")
    assert agent_node is not None
    assert agent_node.attributes.get("observed_reached_credential") is True
    assert agent_node.attributes.get("observed_lateral_movement") is True
    feedback = agent_node.attributes.get("runtime_feedback")
    assert isinstance(feedback, dict)
    assert feedback["source"] == "runtime-feedback"
    assert set(feedback["incident_kinds"]) == {"reached_credential", "lateral_movement"}

    feedback_edges = [e for e in graph.edges if e.evidence.get("source") == "runtime-feedback"]
    assert feedback_edges, "expected runtime-feedback edges"
    rels = {e.relationship for e in feedback_edges}
    assert RelationshipType.USED_CREDENTIAL in rels  # reached_credential
    assert RelationshipType.ACCESSED in rels  # lateral_movement
    # Synthetic observed-tool node created for label-only reach.
    assert graph.get_node("tool:observed:read_secret") is not None


def test_records_loaded_from_path(tmp_path):
    sink = RuntimeIncidentSink(tmp_path / "fb.jsonl")
    sink.emit(_record(kind=IncidentKind.KILL_SWITCH.value, severity="critical", observed_tool_labels=["delete_db"]))

    report = _report_with_agent()
    report["runtime_incident_feedback_path"] = str(tmp_path / "fb.jsonl")
    graph = build_unified_graph_from_report(report)

    agent_node = graph.get_node("agent:billing-agent")
    assert agent_node is not None
    assert agent_node.attributes.get("observed_kill_switch") is True


def test_no_feedback_data_is_byte_identical(tmp_path):
    """Absent feedback ⇒ no observed_* attributes, no runtime-feedback edges."""
    report = _report_with_agent()
    graph = build_unified_graph_from_report(report)
    agent_node = graph.get_node("agent:billing-agent")
    assert agent_node is not None
    assert "observed_reached_credential" not in agent_node.attributes
    assert "runtime_feedback" not in agent_node.attributes
    assert [e for e in graph.edges if e.evidence.get("source") == "runtime-feedback"] == []


def test_observed_node_id_edge_when_node_present(tmp_path):
    """A record naming an existing graph node id draws the edge to it directly."""
    report = _report_with_agent()
    # The agent's own provider node exists this scan; point the observed reach at it.
    report["runtime_incident_feedback"] = [
        _record(
            kind=IncidentKind.LATERAL_MOVEMENT.value,
            observed_tool_labels=[],
            observed_node_ids=["provider:local"],
        ).to_dict()
    ]
    graph = build_unified_graph_from_report(report)
    edges = [e for e in graph.edges if e.evidence.get("source") == "runtime-feedback" and e.target == "provider:local"]
    assert edges, "expected an observed-reach edge to the existing provider node"


def test_dangling_node_id_is_skipped(tmp_path):
    """A record naming a node id absent this scan does not create a dangling edge."""
    report = _report_with_agent()
    report["runtime_incident_feedback"] = [
        _record(
            kind=IncidentKind.LATERAL_MOVEMENT.value,
            observed_tool_labels=[],
            observed_node_ids=["credential:nonexistent"],
        ).to_dict()
    ]
    graph = build_unified_graph_from_report(report)
    # Agent still marked, but no edge to the missing node.
    agent_node = graph.get_node("agent:billing-agent")
    assert agent_node is not None and agent_node.attributes.get("observed_lateral_movement") is True
    assert [e for e in graph.edges if e.target == "credential:nonexistent"] == []


# ── ProtectionEngine emission wiring ─────────────────────────────────────────


def test_engine_emits_credential_reach(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_FEEDBACK_PATH, raising=False)
    path = tmp_path / "engine.jsonl"
    engine = ProtectionEngine(shield=True, feedback_sink=RuntimeIncidentSink(path))
    # Deterministic clock for the emitted record.
    monkeypatch.setattr(engine, "_feedback_timestamp", lambda: "FIXED")

    async def run() -> None:
        await engine.process_tool_response("read_file", "AKIAIOSFODNN7EXAMPLE", agent_id="billing-agent")

    asyncio.run(run())
    records = load_incident_records(path)
    cred = [r for r in records if r.kind == IncidentKind.REACHED_CREDENTIAL.value]
    assert cred, "expected a reached_credential feedback record"
    assert cred[0].agent_id == "billing-agent"
    assert cred[0].observed_at == "FIXED"


def test_engine_emits_kill_switch(tmp_path, monkeypatch):
    monkeypatch.delenv(ENV_FEEDBACK_PATH, raising=False)
    path = tmp_path / "ks.jsonl"
    engine = ProtectionEngine(shield=True, feedback_sink=RuntimeIncidentSink(path))
    engine.start()
    # Force the kill-switch active so the next call is blocked + fed back.
    engine._blocked = True

    async def run() -> None:
        await engine.process_tool_call("delete_database", {}, agent_id="rogue-agent")

    asyncio.run(run())
    records = load_incident_records(path)
    ks = [r for r in records if r.kind == IncidentKind.KILL_SWITCH.value]
    assert ks and ks[0].agent_id == "rogue-agent"
