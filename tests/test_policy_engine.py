"""Tests for the policy-as-code engine (agent_bom.policy)."""

from __future__ import annotations

import json
from unittest.mock import MagicMock

import pytest

from agent_bom.policy import (
    _rule_matches,
    _validate_policy,
    evaluate_policy,
    load_policy,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _make_severity(value: str):
    """Create a mock Severity enum member."""
    sev = MagicMock()
    sev.value = value
    return sev


def _make_blast_radius(
    vuln_id: str = "CVE-2024-0001",
    severity: str = "critical",
    is_kev: bool = False,
    pkg_name: str = "example-pkg",
    pkg_version: str = "1.0.0",
    ecosystem: str = "pypi",
    is_malicious: bool = False,
    ai_risk_context: str | None = None,
    exposed_credentials: list | None = None,
    affected_agents: list | None = None,
    affected_servers: list | None = None,
    exposed_tools: list | None = None,
    owasp_tags: list | None = None,
    owasp_mcp_tags: list | None = None,
):
    """Build a MagicMock that quacks like a BlastRadius dataclass."""
    br = MagicMock()

    # Vulnerability
    br.vulnerability.id = vuln_id
    br.vulnerability.severity = _make_severity(severity)
    br.vulnerability.is_kev = is_kev

    # Package
    br.package.name = pkg_name
    br.package.version = pkg_version
    br.package.ecosystem = ecosystem
    br.package.is_malicious = is_malicious

    # Blast-radius attributes
    br.ai_risk_context = ai_risk_context
    br.exposed_credentials = exposed_credentials or []
    br.affected_agents = affected_agents or []
    br.affected_servers = affected_servers or []
    br.exposed_tools = exposed_tools or []
    br.owasp_tags = owasp_tags or []
    br.owasp_mcp_tags = owasp_mcp_tags or []

    return br


def _minimal_policy(**overrides) -> dict:
    """Return a minimal valid policy dict, applying any overrides."""
    policy = {
        "version": "1",
        "name": "test-policy",
        "rules": [
            {"id": "r1", "description": "test rule", "action": "fail"},
        ],
    }
    policy.update(overrides)
    return policy


# ---------------------------------------------------------------------------
# load_policy
# ---------------------------------------------------------------------------


def test_load_policy_json(tmp_path):
    """Valid JSON policy loads and validates successfully."""
    policy_data = _minimal_policy()
    path = tmp_path / "policy.json"
    path.write_text(json.dumps(policy_data))

    result = load_policy(str(path))

    assert result["name"] == "test-policy"
    assert len(result["rules"]) == 1
    assert result["rules"][0]["id"] == "r1"


def test_load_policy_file_not_found():
    """Loading a nonexistent file raises FileNotFoundError."""
    with pytest.raises(FileNotFoundError, match="Policy file not found"):
        load_policy("/no/such/path/policy.json")


def test_load_policy_invalid_json(tmp_path):
    """Malformed JSON raises ValueError."""
    path = tmp_path / "bad.json"
    path.write_text("{not valid json!!!")

    with pytest.raises(ValueError, match="Invalid JSON"):
        load_policy(str(path))


# ---------------------------------------------------------------------------
# _validate_policy
# ---------------------------------------------------------------------------


def test_validate_policy_missing_rules():
    """Policy without a 'rules' key raises ValueError."""
    with pytest.raises(ValueError, match="must have a 'rules' array"):
        _validate_policy({"name": "no-rules"})


def test_validate_policy_rules_not_list():
    """Policy where 'rules' is not a list raises ValueError."""
    with pytest.raises(ValueError, match="'rules' must be an array"):
        _validate_policy({"rules": "not-a-list"})


def test_validate_policy_missing_rule_id():
    """A rule without 'id' raises ValueError."""
    with pytest.raises(ValueError, match="missing 'id'"):
        _validate_policy({"rules": [{"action": "fail"}]})


def test_validate_policy_invalid_action():
    """Action that is neither 'fail' nor 'warn' raises ValueError."""
    with pytest.raises(ValueError, match="action must be 'fail' or 'warn'"):
        _validate_policy({"rules": [{"id": "bad", "action": "ignore"}]})


# ---------------------------------------------------------------------------
# _rule_matches
# ---------------------------------------------------------------------------


def test_rule_matches_severity_gte():
    """severity_gte: matches when severity >= threshold, rejects when below."""
    br_critical = _make_blast_radius(severity="critical")
    br_low = _make_blast_radius(severity="low")

    rule_high = {"id": "sev", "severity_gte": "HIGH", "action": "fail"}

    # CRITICAL (4) >= HIGH (3) -> match
    assert _rule_matches(rule_high, br_critical) is True
    # LOW (1) < HIGH (3) -> no match
    assert _rule_matches(rule_high, br_low) is False


def test_rule_matches_is_kev():
    """is_kev: matches when vulnerability is in CISA KEV catalog."""
    br_kev = _make_blast_radius(is_kev=True)
    br_no_kev = _make_blast_radius(is_kev=False)

    rule = {"id": "kev", "is_kev": True, "action": "fail"}

    assert _rule_matches(rule, br_kev) is True
    assert _rule_matches(rule, br_no_kev) is False


def test_rule_matches_has_credentials():
    """has_credentials: matches when exposed_credentials is truthy."""
    br_creds = _make_blast_radius(exposed_credentials=["API_KEY", "DB_TOKEN"])
    br_no_creds = _make_blast_radius(exposed_credentials=[])

    rule = {"id": "creds", "has_credentials": True, "action": "fail"}

    assert _rule_matches(rule, br_creds) is True
    assert _rule_matches(rule, br_no_creds) is False


def test_rule_matches_ecosystem_filter():
    """ecosystem: matches when package ecosystem equals the rule value."""
    br_pypi = _make_blast_radius(ecosystem="pypi")
    br_npm = _make_blast_radius(ecosystem="npm")

    rule = {"id": "eco", "ecosystem": "pypi", "action": "fail"}

    assert _rule_matches(rule, br_pypi) is True
    assert _rule_matches(rule, br_npm) is False


def test_rule_matches_and_logic():
    """Multiple conditions must ALL be true (AND logic)."""
    # This BR satisfies severity_gte=HIGH and is_kev, but NOT has_credentials
    br = _make_blast_radius(
        severity="critical",
        is_kev=True,
        exposed_credentials=[],
    )

    rule = {
        "id": "combo",
        "severity_gte": "HIGH",
        "is_kev": True,
        "has_credentials": True,
        "action": "fail",
    }

    # All three conditions must hold; has_credentials fails -> no match
    assert _rule_matches(rule, br) is False

    # Now give it credentials -> all three conditions pass
    br.exposed_credentials = ["SECRET_KEY"]
    assert _rule_matches(rule, br) is True


def test_rule_matches_min_tools():
    """min_tools: matches when exposed_tools count >= threshold."""
    tools_3 = [MagicMock() for _ in range(3)]
    tools_6 = [MagicMock() for _ in range(6)]

    br_few = _make_blast_radius(exposed_tools=tools_3)
    br_many = _make_blast_radius(exposed_tools=tools_6)

    rule = {"id": "tools", "min_tools": 5, "action": "warn"}

    assert _rule_matches(rule, br_few) is False
    assert _rule_matches(rule, br_many) is True


# ---------------------------------------------------------------------------
# evaluate_policy
# ---------------------------------------------------------------------------


def test_evaluate_policy_failures():
    """Rules that match with action='fail' produce failures and passed=False."""
    policy = {
        "name": "strict-policy",
        "rules": [
            {"id": "no-critical", "severity_gte": "CRITICAL", "action": "fail"},
            {"id": "no-kev", "is_kev": True, "action": "fail"},
        ],
    }

    # Agent mock (needs .name for the violation output)
    agent = MagicMock()
    agent.name = "cursor"

    br = _make_blast_radius(
        vuln_id="CVE-2024-9999",
        severity="critical",
        is_kev=True,
        affected_agents=[agent],
    )

    result = evaluate_policy(policy, [br])

    assert result["policy_name"] == "strict-policy"
    assert result["passed"] is False
    # Both rules match the same finding -> 2 violations, both failures
    assert len(result["failures"]) == 2
    assert len(result["warnings"]) == 0
    # Verify violation contents
    rule_ids = {v["rule_id"] for v in result["violations"]}
    assert rule_ids == {"no-critical", "no-kev"}
    assert result["violations"][0]["vulnerability_id"] == "CVE-2024-9999"


def test_evaluate_policy_warnings_and_passed():
    """Warn-only violations still let the policy pass; mixed results are correct."""
    policy = {
        "name": "mixed-policy",
        "rules": [
            {"id": "warn-medium", "severity_gte": "MEDIUM", "action": "warn"},
            {"id": "fail-critical", "severity_gte": "CRITICAL", "action": "fail"},
        ],
    }

    agent = MagicMock()
    agent.name = "claude-desktop"

    # A HIGH severity finding: matches warn-medium (HIGH >= MEDIUM) but NOT
    # fail-critical (HIGH < CRITICAL)
    br = _make_blast_radius(
        vuln_id="CVE-2024-5555",
        severity="high",
        affected_agents=[agent],
    )

    result = evaluate_policy(policy, [br])

    assert result["policy_name"] == "mixed-policy"
    assert result["passed"] is True
    assert len(result["warnings"]) == 1
    assert len(result["failures"]) == 0
    assert result["warnings"][0]["rule_id"] == "warn-medium"
    assert result["warnings"][0]["severity"] == "high"
    assert result["warnings"][0]["package"] == "example-pkg@1.0.0"
