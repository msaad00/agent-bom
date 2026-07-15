"""Tests for the observe->enforce block-rule proposal bridge."""

from __future__ import annotations

from agent_bom.api.policy_store import PolicyMode
from agent_bom.observe_enforce import propose_block_rules
from agent_bom.runtime_correlation import CorrelatedFinding, CorrelationReport


def _finding(tool: str, vuln: str, count: int = 3, risk: float = 8.0) -> CorrelatedFinding:
    return CorrelatedFinding(
        vulnerability_id=vuln,
        severity="high",
        cvss_score=8.1,
        epss_score=0.4,
        is_kev=False,
        package_name="pkg",
        package_version="1.0.0",
        tool_name=tool,
        server_name="srv",
        call_count=count,
        last_called="2026-07-14T00:00:00+00:00",
        first_called="2026-07-13T00:00:00+00:00",
        was_blocked=False,
        risk_amplifier=1.5,
        original_risk_score=risk,
        correlated_risk_score=risk,
    )


def _report(findings: list[CorrelatedFinding]) -> CorrelationReport:
    return CorrelationReport(
        total_tool_calls=sum(f.call_count for f in findings),
        unique_tools_called=len(findings),
        vulnerable_tools_called=len(findings),
        correlated_findings=findings,
        uncalled_vulnerable_tools=[],
    )


def test_proposes_block_rule_for_confirmed_vulnerable_and_called_tool() -> None:
    report = _report([_finding("read_file", "CVE-2025-1")])
    result = propose_block_rules(report)

    assert len(result.proposals) == 1
    prop = result.proposals[0]
    assert prop.tool_name == "read_file"
    assert prop.rule.action == "block"
    assert prop.rule.block_tools == ["read_file"]
    assert "CVE-2025-1" in prop.vulnerability_ids


def test_default_is_propose_not_enforce() -> None:
    report = _report([_finding("read_file", "CVE-2025-1")])
    result = propose_block_rules(report)

    # Default must NOT enforce: policy is audit-mode (advisory / warn only).
    assert result.enforced is False
    assert result.mode == "audit"
    assert result.policy.mode == PolicyMode.AUDIT
    assert result.to_dict()["enforced"] is False


def test_enforce_requires_explicit_opt_in() -> None:
    report = _report([_finding("read_file", "CVE-2025-1")])
    result = propose_block_rules(report, enforce=True)

    assert result.enforced is True
    assert result.mode == "enforce"
    assert result.policy.mode == PolicyMode.ENFORCE


def test_audit_mode_policy_does_not_block_at_gateway() -> None:
    # Security invariant: a proposed (audit) policy is downgraded to warn by the
    # gateway, so nothing is silently blocked without the enforce opt-in.
    from agent_bom.gateway import evaluate_gateway_policies

    report = _report([_finding("read_file", "CVE-2025-1")])
    proposed = propose_block_rules(report)  # audit
    allowed, _reason, _pid = evaluate_gateway_policies([proposed.policy], "read_file", {})
    assert allowed is True  # audit proposal never blocks

    enforced = propose_block_rules(report, enforce=True)
    blocked, _r, _p = evaluate_gateway_policies([enforced.policy], "read_file", {})
    assert blocked is False  # enforce policy actually blocks the call


def test_uncalled_vulnerable_tools_get_no_proposal() -> None:
    # A finding with zero calls is theoretical only — no block proposal.
    report = _report([_finding("idle_tool", "CVE-2025-9", count=0)])
    result = propose_block_rules(report)
    assert result.proposals == []
    assert result.policy.rules == []


def test_duplicate_tool_deduped_into_one_rule() -> None:
    report = _report(
        [
            _finding("read_file", "CVE-2025-1", risk=9.0),
            _finding("read_file", "CVE-2025-2", risk=5.0),
        ]
    )
    result = propose_block_rules(report)
    assert len(result.proposals) == 1
    prop = result.proposals[0]
    # Both CVEs are cited in the single rule's rationale.
    assert "CVE-2025-1" in prop.vulnerability_ids
    assert "CVE-2025-2" in prop.vulnerability_ids


def test_empty_correlation_yields_no_proposals() -> None:
    result = propose_block_rules(_report([]))
    assert result.proposals == []
    assert result.to_dict()["proposal_count"] == 0


def test_to_dict_is_serializable_and_complete() -> None:
    report = _report([_finding("read_file", "CVE-2025-1")])
    payload = propose_block_rules(report).to_dict()
    assert payload["mode"] == "audit"
    assert payload["proposal_count"] == 1
    assert payload["proposals"][0]["tool_name"] == "read_file"
    assert payload["policy"]["mode"] == "audit"
    # round-trips through JSON without error
    import json

    json.loads(json.dumps(payload))
