"""Tests for the policy-as-code engine (agent_bom.policy)."""

from __future__ import annotations

import io
import json
from unittest.mock import MagicMock

import pytest
from rich.console import Console

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


def test_load_policy_invalid_yaml(tmp_path):
    """Malformed YAML raises ValueError instead of leaking a parser exception."""
    pytest.importorskip("yaml")
    path = tmp_path / "bad.yaml"
    path.write_text("rules:\n  - id: [unterminated\n")

    with pytest.raises(ValueError, match="Invalid YAML"):
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
    """Action that is not a recognised value raises ValueError."""
    with pytest.raises(ValueError, match="action must be"):
        _validate_policy({"rules": [{"id": "bad", "action": "ignore"}]})


def test_validate_policy_field_type_int():
    """min_agents must be an integer."""
    with pytest.raises(ValueError, match="must be an integer"):
        _validate_policy({"rules": [{"id": "r1", "action": "fail", "min_agents": "two"}]})


def test_validate_policy_field_type_float():
    """max_epss_score must be a number."""
    with pytest.raises(ValueError, match="must be a number"):
        _validate_policy({"rules": [{"id": "r1", "action": "fail", "max_epss_score": "high"}]})


def test_validate_policy_field_type_str():
    """ecosystem must be a string."""
    with pytest.raises(ValueError, match="must be a string"):
        _validate_policy({"rules": [{"id": "r1", "action": "fail", "ecosystem": 123}]})


def test_validate_policy_field_type_bool():
    """is_kev must be a boolean."""
    with pytest.raises(ValueError, match="must be a boolean"):
        _validate_policy({"rules": [{"id": "r1", "action": "fail", "is_kev": "yes"}]})


def test_validate_policy_invalid_severity_gte():
    """severity_gte with invalid severity value raises ValueError."""
    with pytest.raises(ValueError, match="is not valid"):
        _validate_policy({"rules": [{"id": "r1", "action": "fail", "severity_gte": "MEGA"}]})


def test_validate_policy_invalid_registry_risk():
    """registry_risk_gte with invalid risk level raises ValueError."""
    with pytest.raises(ValueError, match="is not valid"):
        _validate_policy({"rules": [{"id": "r1", "action": "fail", "registry_risk_gte": "extreme"}]})


def test_validate_policy_valid_fields_pass():
    """Valid declarative fields pass validation."""
    _validate_policy(
        {
            "rules": [
                {
                    "id": "r1",
                    "action": "fail",
                    "severity_gte": "HIGH",
                    "min_agents": 2,
                    "max_epss_score": 0.7,
                    "ecosystem": "pypi",
                    "is_kev": True,
                }
            ]
        }
    )


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


def test_severity_order_includes_unknown():
    """UNKNOWN must be in SEVERITY_ORDER and sort below NONE (per FIRST CVSS spec)."""
    from agent_bom.policy import SEVERITY_ORDER

    assert "UNKNOWN" in SEVERITY_ORDER, "UNKNOWN missing from SEVERITY_ORDER"
    assert SEVERITY_ORDER["UNKNOWN"] < SEVERITY_ORDER["NONE"]
    assert SEVERITY_ORDER["NONE"] < SEVERITY_ORDER["LOW"]


def test_rule_matches_severity_gte_unknown():
    """UNKNOWN severity (-1) should NOT match severity_gte: LOW (1)."""
    br_unknown = _make_blast_radius(severity="unknown")
    rule_low = {"id": "sev", "severity_gte": "LOW", "action": "fail"}
    assert _rule_matches(rule_low, br_unknown) is False


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


def test_policy_fail_action_sets_scan_exit_code(tmp_path):
    """A matching action=fail policy must make the scan gate fail."""
    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cli.agents._post import compute_exit_code, run_integrations

    policy = tmp_path / "policy.json"
    policy.write_text(
        json.dumps({"rules": [{"id": "fail-high", "severity_gte": "HIGH", "action": "fail"}]}),
        encoding="utf-8",
    )
    br = _make_blast_radius(severity="high")
    ctx = ScanContext(
        con=Console(file=io.StringIO(), force_terminal=False),
        blast_radii=[br],
        report=None,
    )

    run_integrations(
        ctx,
        quiet=True,
        jira_url=None,
        jira_user=None,
        jira_token=None,
        jira_project=None,
        slack_webhook=None,
        jira_discover=False,
        servicenow_flag=False,
        servicenow_instance=None,
        servicenow_user=None,
        servicenow_password=None,
        slack_discover=False,
        slack_bot_token=None,
        vanta_token=None,
        drata_token=None,
        siem_type=None,
        siem_url=None,
        siem_token=None,
        siem_index=None,
        siem_format="json",
        clickhouse_url=None,
        policy=str(policy),
    )

    assert ctx.policy_passed is False
    assert (
        compute_exit_code(
            ctx,
            fail_on_severity=None,
            warn_on_severity=None,
            fail_on_kev=False,
            fail_if_ai_risk=False,
            push_url=None,
            push_api_key=None,
            quiet=True,
        )
        == 1
    )


# ---------------------------------------------------------------------------
# Expression engine (v0.58.0+)
# ---------------------------------------------------------------------------


class TestExpressionTokenizer:
    def test_tokenize_simple(self):
        from agent_bom.policy import _tokenize

        tokens = _tokenize("epss_score > 0.7")
        assert len(tokens) == 3
        assert tokens[0] == ("IDENT", "epss_score")
        assert tokens[1] == ("CMP", ">")
        assert tokens[2] == ("NUMBER", "0.7")

    def test_tokenize_boolean_ops(self):
        from agent_bom.policy import _tokenize

        tokens = _tokenize("is_kev and severity >= HIGH")
        assert tokens[0] == ("IDENT", "is_kev")
        assert tokens[1] == ("BOOL_OP", "and")
        assert tokens[2] == ("IDENT", "severity")
        assert tokens[3] == ("CMP", ">=")
        assert tokens[4] == ("IDENT", "HIGH")

    def test_tokenize_parens(self):
        from agent_bom.policy import _tokenize

        tokens = _tokenize("(a or b) and c")
        types = [t[0] for t in tokens]
        assert "PAREN" in types

    def test_tokenize_string_literal(self):
        from agent_bom.policy import _tokenize

        tokens = _tokenize('ecosystem == "pypi"')
        assert tokens[2] == ("STRING", "pypi")

    def test_tokenize_invalid_raises(self):
        from agent_bom.policy import _tokenize

        with pytest.raises(ValueError, match="Invalid token"):
            _tokenize("epss_score @@ 0.7")


class TestExpressionEvaluator:
    def test_simple_comparison(self):
        from agent_bom.policy import evaluate_expression

        br = _make_blast_radius(severity="critical")
        br.vulnerability.epss_score = 0.85
        br.vulnerability.cvss_score = 9.5
        br.package.scorecard_score = None
        br.risk_score = 8.0
        assert evaluate_expression("epss_score > 0.7", br) is True
        assert evaluate_expression("epss_score < 0.5", br) is False

    def test_severity_comparison(self):
        from agent_bom.policy import evaluate_expression

        br = _make_blast_radius(severity="high")
        br.vulnerability.epss_score = 0.5
        br.vulnerability.cvss_score = 7.0
        br.package.scorecard_score = None
        br.risk_score = 5.0
        # HIGH (3) >= MEDIUM (2) = True
        assert evaluate_expression("severity >= MEDIUM", br) is True
        # HIGH (3) >= CRITICAL (4) = False
        assert evaluate_expression("severity >= CRITICAL", br) is False

    def test_boolean_and(self):
        from agent_bom.policy import evaluate_expression

        br = _make_blast_radius(severity="critical", is_kev=True)
        br.vulnerability.epss_score = 0.9
        br.vulnerability.cvss_score = 9.0
        br.package.scorecard_score = None
        br.risk_score = 9.0
        assert evaluate_expression("is_kev and severity >= HIGH", br) is True

    def test_boolean_or(self):
        from agent_bom.policy import evaluate_expression

        br = _make_blast_radius(severity="low", is_kev=True)
        br.vulnerability.epss_score = 0.1
        br.vulnerability.cvss_score = 2.0
        br.package.scorecard_score = None
        br.risk_score = 2.0
        assert evaluate_expression("is_kev or severity >= HIGH", br) is True

    def test_not_operator(self):
        from agent_bom.policy import evaluate_expression

        br = _make_blast_radius(severity="low", is_kev=False)
        br.vulnerability.epss_score = 0.1
        br.vulnerability.cvss_score = 2.0
        br.package.scorecard_score = None
        br.risk_score = 2.0
        assert evaluate_expression("not is_kev", br) is True

    def test_parentheses(self):
        from agent_bom.policy import evaluate_expression

        br = _make_blast_radius(
            severity="high",
            is_kev=False,
            ai_risk_context="AI framework",
        )
        br.vulnerability.epss_score = 0.5
        br.vulnerability.cvss_score = 7.0
        br.package.scorecard_score = 2.0
        br.risk_score = 7.0
        # ai_risk AND (is_kev OR scorecard_score < 3.0)
        assert evaluate_expression("ai_risk and (is_kev or scorecard_score < 3.0)", br) is True

    def test_agent_count(self):
        from agent_bom.policy import evaluate_expression

        agents = [MagicMock(), MagicMock(), MagicMock()]
        br = _make_blast_radius(severity="high", affected_agents=agents)
        br.vulnerability.epss_score = 0.5
        br.vulnerability.cvss_score = 7.0
        br.package.scorecard_score = None
        br.risk_score = 7.0
        assert evaluate_expression("agent_count >= 3", br) is True
        assert evaluate_expression("agent_count >= 5", br) is False

    def test_has_credentials(self):
        from agent_bom.policy import evaluate_expression

        br = _make_blast_radius(exposed_credentials=["AWS_SECRET_KEY"])
        br.vulnerability.epss_score = 0.5
        br.vulnerability.cvss_score = 5.0
        br.package.scorecard_score = None
        br.risk_score = 5.0
        assert evaluate_expression("has_credentials", br) is True
        assert evaluate_expression("credential_count > 0", br) is True

    def test_unknown_field_raises(self):
        from agent_bom.policy import evaluate_expression

        br = _make_blast_radius()
        br.vulnerability.epss_score = 0.5
        # Unknown field in expression = rule doesn't match (fail-safe)
        # evaluate_expression raises ValueError, but _rule_matches catches it
        with pytest.raises(ValueError, match="Unknown field"):
            evaluate_expression("nonexistent_field > 0", br)

    def test_empty_expression(self):
        from agent_bom.policy import evaluate_expression

        br = _make_blast_radius()
        assert evaluate_expression("", br) is False


class TestExpressionInRuleMatches:
    def test_condition_field_in_rule(self):
        rule = {"id": "test", "condition": "is_kev", "action": "fail"}
        br = _make_blast_radius(is_kev=True)
        br.vulnerability.epss_score = 0.5
        br.vulnerability.cvss_score = 5.0
        br.package.scorecard_score = None
        br.risk_score = 5.0
        assert _rule_matches(rule, br) is True

    def test_condition_and_declarative_both_must_match(self):
        rule = {
            "id": "test",
            "condition": "epss_score > 0.5",
            "severity_gte": "HIGH",
            "action": "fail",
        }
        br = _make_blast_radius(severity="high")
        br.vulnerability.epss_score = 0.8
        br.vulnerability.cvss_score = 7.0
        br.package.scorecard_score = None
        br.risk_score = 7.0
        # Both match
        assert _rule_matches(rule, br) is True

        # Expression matches, declarative doesn't
        br2 = _make_blast_radius(severity="low")
        br2.vulnerability.epss_score = 0.8
        br2.vulnerability.cvss_score = 3.0
        br2.package.scorecard_score = None
        br2.risk_score = 3.0
        assert _rule_matches(rule, br2) is False

    def test_invalid_expression_fails_safe(self):
        rule = {"id": "test", "condition": "@@invalid@@", "action": "fail"}
        br = _make_blast_radius()
        # Invalid expression = doesn't match (fail-safe, not fail-open)
        assert _rule_matches(rule, br) is False
