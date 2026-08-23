"""One reachability verdict drives labels, ranking, paths, and correlations."""

from __future__ import annotations

from agent_bom.models import BlastRadius, MCPTool, Package, Severity, Vulnerability


def _blast(*, severity: Severity, graph: bool | None = None, symbol: str | None = None) -> BlastRadius:
    return BlastRadius(
        vulnerability=Vulnerability(
            id="CVE-2026-9001",
            summary="unrated actively exploited advisory",
            severity=severity,
            is_kev=True,
            epss_score=0.95,
        ),
        package=Package(name="edge-case", version="1.0.0", ecosystem="pypi", is_direct=True),
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=["PROD_TOKEN"],
        exposed_tools=[MCPTool(name="run_shell", description="execute a shell command")],
        graph_reachable=graph,
        symbol_reachability=symbol,
    )


def test_proven_unreachable_overrides_exposure_heuristics_everywhere() -> None:
    blast = _blast(severity=Severity.HIGH, graph=False, symbol="unreachable")

    assert blast.reachability == "unlikely"
    blast.calculate_risk_score()
    assert blast.risk_score < _blast(severity=Severity.HIGH, graph=True, symbol="function_reachable").calculate_risk_score()


def test_confirmed_path_and_symbol_evidence_produce_confirmed_label() -> None:
    assert _blast(severity=Severity.HIGH, graph=True).reachability == "confirmed"
    assert _blast(severity=Severity.HIGH, symbol="function_reachable").reachability == "confirmed"


def test_unrated_active_exploitation_never_ranks_below_equivalent_low() -> None:
    unknown = _blast(severity=Severity.UNKNOWN)
    none = _blast(severity=Severity.NONE)
    low = _blast(severity=Severity.LOW)

    assert unknown.calculate_risk_score() >= low.calculate_risk_score()
    assert none.calculate_risk_score() >= low.calculate_risk_score()
