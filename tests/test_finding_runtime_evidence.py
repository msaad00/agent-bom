"""Tests for runtime evidence joins and compliance tag flattening."""

from __future__ import annotations

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
