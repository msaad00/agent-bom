"""Tests for trace explorer correlation (#3608)."""

from __future__ import annotations

from agent_bom.api.trace_explorer import build_trace_explorer_payload, correlate_findings


def test_correlate_findings_matches_agent_and_tool() -> None:
    findings = [
        {
            "id": "CVE-2024-1:pkg",
            "vulnerability_id": "CVE-2024-1",
            "affected_agents": ["dev-agent"],
            "exposed_tools": ["run_shell"],
            "framework_tags": ["owasp_llm:LLM05"],
            "runtime_evidence": {"state": "blocked"},
        }
    ]
    matched = correlate_findings(agent="dev-agent", tool="run_shell", findings=findings)
    assert matched[0]["vulnerability_id"] == "CVE-2024-1"
    assert "owasp_llm:LLM05" in matched[0]["framework_tags"]


def test_build_trace_explorer_payload_groups_blocked_span_with_findings() -> None:
    payload = build_trace_explorer_payload(
        tenant_id="tenant-a",
        feed_events=[
            {
                "ts": "2026-07-06T12:00:00Z",
                "agent": "dev-agent",
                "action_type": "tool_call_blocked",
                "target": "run_shell",
                "detail": "policy",
                "shadow": False,
                "source": "proxy",
            }
        ],
        findings=[
            {
                "vulnerability_id": "CVE-2024-9",
                "affected_agents": ["dev-agent"],
                "exposed_tools": ["run_shell"],
                "framework_tags": ["nist_csf:ID.RA-01"],
            }
        ],
        sessions=[],
        observations=[],
        limit=10,
    )
    assert payload["blocked_count"] == 1
    session = payload["sessions"][0]
    span = session["spans"][0]
    assert span["verdict"] == "blocked"
    assert span["linked_findings"][0]["vulnerability_id"] == "CVE-2024-9"
    assert "nist_csf:ID.RA-01" in span["compliance_controls"]
