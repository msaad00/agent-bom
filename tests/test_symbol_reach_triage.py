"""Tests for symbol-reach triage adjustments."""

from __future__ import annotations

from agent_bom.effective_reach import ReachScore
from agent_bom.exploitability import fused_triage_priority
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.reachability_cve import FUNCTION_REACHABLE, UNREACHABLE
from agent_bom.symbol_reach_triage import adjust_effective_reach_breakdown, apply_composite_delta
from agent_bom.vex import VexStatus, generate_vex


def test_apply_composite_delta_function_reachable_boosts() -> None:
    assert apply_composite_delta(40.0, FUNCTION_REACHABLE) == 55.0


def test_apply_composite_delta_unreachable_penalizes() -> None:
    assert apply_composite_delta(40.0, UNREACHABLE) == 10.0


def test_reach_score_includes_symbol_reachability() -> None:
    base = ReachScore(cvss=6.5, epss=0.02, is_kev=False, tool_capability=0.1, cred_visibility=0.1, agent_breadth=1)
    boosted = ReachScore(
        cvss=6.5,
        epss=0.02,
        is_kev=False,
        tool_capability=0.1,
        cred_visibility=0.1,
        agent_breadth=1,
        symbol_reachability=FUNCTION_REACHABLE,
    )
    assert boosted.composite > base.composite


def test_adjust_effective_reach_breakdown_updates_band() -> None:
    breakdown = {"composite": 35.0, "band": "amber", "cvss": 6.5}
    adjusted = adjust_effective_reach_breakdown(breakdown, UNREACHABLE)
    assert adjusted["composite"] == 5.0
    assert adjusted["band"] == "green"
    assert adjusted["symbol_reach_adjustment"] == -30.0


def test_fused_triage_priority_symbol_unreachable_penalizes() -> None:
    base = fused_triage_priority(severity="high", reachable=True)
    penalized = fused_triage_priority(severity="high", reachable=True, symbol_reachability=UNREACHABLE)
    assert penalized["score"] < base["score"]
    assert "symbol_unreachable" in penalized["reasons"]


def test_generate_vex_auto_triage_unreachable_is_not_affected() -> None:
    vuln = Vulnerability(id="CVE-2099-1", summary="x", severity=Severity.HIGH)
    pkg = Package(name="leftpad", version="1.0.0", ecosystem="npm")
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
        symbol_reachability=UNREACHABLE,
    )
    report = AIBOMReport(agents=[], blast_radii=[br])
    doc = generate_vex(report, auto_triage=True)
    assert len(doc.statements) == 1
    assert doc.statements[0].status == VexStatus.NOT_AFFECTED
    assert "symbol-reach" in (doc.statements[0].action_statement or "").lower()
