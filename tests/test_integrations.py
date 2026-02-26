"""Tests for enterprise integrations (Jira, Slack, Vanta, Drata)."""

from agent_bom.integrations.jira import _SEVERITY_PRIORITY
from agent_bom.integrations.slack import _build_slack_blocks, build_summary_message

# ─── Jira ─────────────────────────────────────────────────────────────────────


def test_severity_priority_mapping():
    assert _SEVERITY_PRIORITY["critical"] == "Highest"
    assert _SEVERITY_PRIORITY["high"] == "High"
    assert _SEVERITY_PRIORITY["medium"] == "Medium"
    assert _SEVERITY_PRIORITY["low"] == "Low"


def test_severity_priority_covers_all():
    for sev in ("critical", "high", "medium", "low", "none"):
        assert sev in _SEVERITY_PRIORITY


# ─── Slack ────────────────────────────────────────────────────────────────────


def _make_finding(**overrides):
    base = {
        "vulnerability_id": "CVE-2024-1234",
        "severity": "high",
        "package": "express@4.17.1",
        "risk_score": 7.5,
        "affected_agents": ["Claude Desktop"],
        "affected_servers": ["github-mcp"],
        "exposed_credentials": ["GITHUB_TOKEN"],
        "fixed_version": "4.18.0",
        "owasp_tags": ["LLM05"],
        "owasp_mcp_tags": ["MCP04"],
        "atlas_tags": [],
        "nist_ai_rmf_tags": [],
    }
    base.update(overrides)
    return base


def test_slack_blocks_header():
    finding = _make_finding()
    blocks = _build_slack_blocks(finding)
    assert blocks[0]["type"] == "header"
    assert "agent-bom" in blocks[0]["text"]["text"]


def test_slack_blocks_fields():
    finding = _make_finding()
    blocks = _build_slack_blocks(finding)
    section = blocks[1]
    assert section["type"] == "section"
    fields = section["fields"]
    texts = [f["text"] for f in fields]
    assert any("CVE-2024-1234" in t for t in texts)
    assert any("express@4.17.1" in t for t in texts)


def test_slack_blocks_fix_version():
    finding = _make_finding(fixed_version="4.18.0")
    blocks = _build_slack_blocks(finding)
    fix_blocks = [b for b in blocks if "Fix" in str(b)]
    assert len(fix_blocks) >= 1


def test_slack_blocks_no_fix():
    finding = _make_finding(fixed_version=None)
    blocks = _build_slack_blocks(finding)
    fix_blocks = [b for b in blocks if "Fix:" in str(b)]
    assert len(fix_blocks) == 0


def test_slack_blocks_compliance_tags():
    finding = _make_finding(owasp_tags=["LLM05"], owasp_mcp_tags=["MCP04"])
    blocks = _build_slack_blocks(finding)
    context_blocks = [b for b in blocks if b.get("type") == "context"]
    assert len(context_blocks) >= 1
    assert "LLM05" in str(context_blocks)
    assert "MCP04" in str(context_blocks)


def test_slack_blocks_no_creds():
    finding = _make_finding(
        affected_agents=[], affected_servers=[], exposed_credentials=[],
    )
    blocks = _build_slack_blocks(finding)
    # Should still have header + fields but no context with agents/creds
    assert len(blocks) >= 2


def test_slack_summary_message():
    findings = [
        _make_finding(severity="critical", risk_score=9.5),
        _make_finding(severity="high", risk_score=7.5),
        _make_finding(severity="medium", risk_score=4.0),
    ]
    msg = build_summary_message(findings)
    assert "blocks" in msg
    assert any("Scan Summary" in str(b) for b in msg["blocks"])


def test_slack_summary_top_risks():
    findings = [
        _make_finding(vulnerability_id="CVE-1", risk_score=9.5, package="pkg-a"),
        _make_finding(vulnerability_id="CVE-2", risk_score=3.0, package="pkg-b"),
        _make_finding(vulnerability_id="CVE-3", risk_score=7.0, package="pkg-c"),
        _make_finding(vulnerability_id="CVE-4", risk_score=1.0, package="pkg-d"),
    ]
    msg = build_summary_message(findings)
    # Top 3 should include CVE-1, CVE-3, CVE-2 (sorted by risk)
    blocks_text = str(msg["blocks"])
    assert "pkg-a" in blocks_text  # highest risk
    assert "pkg-c" in blocks_text  # second highest


def test_slack_summary_empty():
    msg = build_summary_message([])
    assert "blocks" in msg
    assert len(msg["blocks"]) >= 1
