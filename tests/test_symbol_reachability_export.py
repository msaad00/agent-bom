"""Export contract for function-level symbol reachability on findings.

Pins that ``symbol_reachability`` and ``reachable_affected_symbols`` stamped
on ``BlastRadius`` rows flow through canonical outputs (unified Finding
evidence, JSON blast_radius, SARIF properties) and that the API pipeline
helper mirrors the CLI ``--project`` AST join when a Python project path is
available.
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.api.pipeline import _ast_result_for_symbol_reach, _project_paths_for_symbol_reach
from agent_bom.ast_models import ASTAnalysisResult, DependencySymbolReach
from agent_bom.finding import blast_radius_to_finding
from agent_bom.graph.blast_reach import apply_symbol_reachability_to_blast_radii
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output import to_json
from agent_bom.output.sarif import to_sarif
from agent_bom.reachability_cve import FUNCTION_REACHABLE


def _reach(package: str, module: str, symbol: str) -> DependencySymbolReach:
    return DependencySymbolReach(
        entrypoint="tool_entry",
        package=package,
        module=module,
        symbol=symbol,
        file_path="agent.py",
        line_number=5,
        call_path=["tool_entry", f"{module}.{symbol}"],
    )


def _python_br(symbols: list[str], *, pkg_name: str = "requests") -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2099-7",
        summary="x",
        severity=Severity.HIGH,
        affected_symbols=symbols,
    )
    pkg = Package(name=pkg_name, version="2.0.0", ecosystem="pypi")
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
    )


def _stamp_python_br() -> BlastRadius:
    br = _python_br(["get"])
    apply_symbol_reachability_to_blast_radii(
        [br],
        ASTAnalysisResult(dependency_symbol_reach=[_reach("requests", "requests", "get")]),
    )
    return br


def test_finding_evidence_exports_symbol_reachability_fields() -> None:
    br = _stamp_python_br()
    finding = blast_radius_to_finding(br)

    assert finding.evidence["symbol_reachability"] == FUNCTION_REACHABLE
    assert finding.evidence["reachable_affected_symbols"] == ["get"]


def test_to_json_blast_radius_exports_symbol_reachability_fields() -> None:
    br = _stamp_python_br()
    payload = to_json(AIBOMReport(agents=[], blast_radii=[br]))

    row = payload["blast_radius"][0]
    assert row["symbol_reachability"] == FUNCTION_REACHABLE
    assert row["reachable_affected_symbols"] == ["get"]

    unified = payload["findings"][0]
    assert unified["evidence"]["symbol_reachability"] == FUNCTION_REACHABLE
    assert unified["evidence"]["reachable_affected_symbols"] == ["get"]


def test_sarif_exports_symbol_reachability_fields() -> None:
    br = _stamp_python_br()
    doc = to_sarif(AIBOMReport(agents=[], blast_radii=[br]))

    props = doc["runs"][0]["results"][0]["properties"]
    assert props["symbol_reachability"] == FUNCTION_REACHABLE
    assert props["reachable_affected_symbols"] == ["get"]


def test_project_paths_for_symbol_reach_dedupes_scan_targets() -> None:
    class _Req:
        agent_projects = ["/tmp/agent-a", "/tmp/agent-b"]
        filesystem_paths = ["/tmp/agent-a"]
        jupyter_dirs = ["/tmp/notebooks"]
        gha_path = "/tmp/repo"

    assert _project_paths_for_symbol_reach(_Req()) == [
        "/tmp/agent-a",
        "/tmp/agent-b",
        "/tmp/notebooks",
        "/tmp/repo",
    ]


def test_ast_result_for_symbol_reach_reads_python_project(tmp_path: Path) -> None:
    project = tmp_path / "proj"
    project.mkdir()
    (project / "agent.py").write_text(
        "import requests\n\n@tool\ndef fetch(url):\n    return requests.get(url)\n",
        encoding="utf-8",
    )

    result = _ast_result_for_symbol_reach([str(project)])

    assert result is not None
    assert result.dependency_symbol_reach


def test_ast_result_for_symbol_reach_skips_non_python_paths(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _ast_result_for_symbol_reach([str(empty)]) is None
