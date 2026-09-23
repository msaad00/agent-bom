"""Tests for runtime evidence joins and compliance tag flattening."""

from __future__ import annotations

import pytest

from agent_bom.finding_runtime_evidence import (
    RUNTIME_STATE_BLOCKED,
    RUNTIME_STATE_OBSERVED,
    RUNTIME_STATE_STATIC,
    RuntimeEvidenceIndex,
    attach_runtime_evidence_to_finding,
    compliance_tags_from_finding_row,
)
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.evidence_overlay import apply_runtime_evidence_overlay
from agent_bom.graph.node import UnifiedNode
from agent_bom.graph.types import EntityType


def test_compliance_tags_from_finding_row_flattens_framework_fields() -> None:
    tags = compliance_tags_from_finding_row(
        {
            "owasp_tags": ["LLM05"],
            "compliance_tags": {"nist_csf": ["ID.RA-01"]},
        }
    )
    assert "owasp_llm:LLM05" in tags
    assert "nist_csf:ID.RA-01" in tags


def test_attach_runtime_evidence_blocked_wins_over_observed() -> None:
    row = {
        "affected_agents": ["dev-agent"],
        "exposed_tools": ["run_shell"],
    }
    index = RuntimeEvidenceIndex(
        blocked=[
            {
                "state": RUNTIME_STATE_BLOCKED,
                "agent": "dev-agent",
                "tool": "run_shell",
                "timestamp": "2026-07-06T00:00:00Z",
                "reason_code": "policy",
                "source": "proxy_alert",
            }
        ],
        observed=[
            {
                "state": RUNTIME_STATE_OBSERVED,
                "agent": "dev-agent",
                "tool": "run_shell",
                "timestamp": "2026-07-06T00:00:00Z",
                "reason_code": "allowed",
                "source": "proxy_alert",
            }
        ],
    )
    attach_runtime_evidence_to_finding(row, index)
    assert row["runtime_evidence"]["state"] == RUNTIME_STATE_BLOCKED
    assert row["runtime_evidence"]["blocked_count"] == 1


def test_attach_runtime_evidence_defaults_static_without_matches() -> None:
    row = {"affected_agents": ["other-agent"], "exposed_tools": ["read_file"]}
    attach_runtime_evidence_to_finding(row, RuntimeEvidenceIndex())
    assert row["runtime_evidence"]["state"] == RUNTIME_STATE_STATIC


def test_runtime_evidence_overlay_tags_feedback_nodes() -> None:
    graph = UnifiedGraph()
    graph.add_node(
        UnifiedNode(
            id="agent:demo",
            entity_type=EntityType.AGENT,
            label="demo",
            attributes={"observed_reached_credential": True},
            data_sources=["runtime-feedback"],
        )
    )
    apply_runtime_evidence_overlay(graph)
    assert graph.nodes["agent:demo"].attributes["evidence_tier"] == "runtime_observed"


@pytest.mark.parametrize(
    ("agents", "tools", "event_agent", "event_tool"),
    [
        (["agent-a"], ["read_file"], "agent-b", "read_file"),
        (["agent-a"], ["read_file"], "", "read_file"),
        ([], ["read_file"], "agent-b", "read_file"),
        (["agent-a"], ["read_file"], "agent-a", ""),
        (["agent-a"], [], "agent-a", "unrelated_tool"),
        (["Agent-A"], ["read_file"], "agent-a", "read_file"),
        (["agent-a"], ["Read_File"], "agent-a", "read_file"),
    ],
)
def test_runtime_activity_requires_exact_agent_and_tool_binding(agents, tools, event_agent, event_tool):
    row = {"affected_agents": agents, "exposed_tools": tools}
    event = {"state": RUNTIME_STATE_OBSERVED, "agent": event_agent, "tool": event_tool}
    attach_runtime_evidence_to_finding(row, RuntimeEvidenceIndex(observed=[event]))
    assert row["runtime_evidence"] == {"state": RUNTIME_STATE_STATIC, "blocked_count": 0, "observed_count": 0, "events": []}


def test_runtime_activity_shared_tool_does_not_cross_agent_scope():
    event = {"state": RUNTIME_STATE_OBSERVED, "agent": "agent-a", "tool": "read_file"}
    index = RuntimeEvidenceIndex(observed=[event])
    for agent, expected in [("agent-a", 1), ("agent-b", 0)]:
        row = {"affected_agents": [agent], "exposed_tools": ["read_file"]}
        attach_runtime_evidence_to_finding(row, index)
        assert row["runtime_evidence"]["observed_count"] == expected
