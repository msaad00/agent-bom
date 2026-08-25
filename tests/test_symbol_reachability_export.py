"""Export contract for function-level symbol reachability on findings.

Pins that ``symbol_reachability`` and ``reachable_affected_symbols`` stamped
on ``BlastRadius`` rows flow through canonical outputs (unified Finding
evidence, JSON blast_radius, SARIF properties) and that the API pipeline
helper mirrors the CLI ``--project`` AST join when a Python project path is
available.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.api.pipeline import _ast_result_for_symbol_reach, _project_paths_for_symbol_reach
from agent_bom.ast_models import ASTAnalysisResult, DependencySymbolReach
from agent_bom.finding import blast_radius_to_finding
from agent_bom.graph.blast_reach import apply_symbol_reachability_to_blast_radii, resync_cve_findings_from_blast_radii
from agent_bom.graph.builder import build_unified_graph_from_report
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output import to_json
from agent_bom.output.sarif import to_sarif
from agent_bom.parsers.python_parsers import parse_uv_lock
from agent_bom.reachability_cve import FUNCTION_REACHABLE, PACKAGE_REACHABLE, UNREACHABLE


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
    br.vulnerability.cwe_ids = ["CWE-502"]
    finding = blast_radius_to_finding(br)

    assert finding.evidence["symbol_reachability"] == FUNCTION_REACHABLE
    assert finding.evidence["reachable_affected_symbols"] == ["get"]
    assert finding.evidence["reachability_advisory_cwe_ids"] == ["CWE-502"]


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


def test_dual_write_findings_resync_carries_reachability_into_json() -> None:
    """Regression: the CLI materializes `report.findings` *before* the blast_radii
    are stamped, so the JSON `findings[]` projection carried null reachability
    while `blast_radius[]`/CSV/Parquet/SARIF carried the verdict. The resync must
    reconcile them."""
    from agent_bom.graph.blast_reach import resync_cve_findings_from_blast_radii

    br = _python_br(["get"])
    # Dual-write: findings built from the row before stamping (the CLI ordering).
    findings = [blast_radius_to_finding(br)]
    apply_symbol_reachability_to_blast_radii(
        [br],
        ASTAnalysisResult(dependency_symbol_reach=[_reach("requests", "requests", "get")]),
    )
    assert findings[0].evidence["symbol_reachability"] is None  # stale before resync

    replaced = resync_cve_findings_from_blast_radii(findings, [br])
    assert replaced == 1

    payload = to_json(AIBOMReport(agents=[], blast_radii=[br], findings=findings))
    assert payload["blast_radius"][0]["symbol_reachability"] == FUNCTION_REACHABLE
    assert payload["findings"][0]["evidence"]["symbol_reachability"] == FUNCTION_REACHABLE
    # The two views must agree, not merely both be truthy.
    assert payload["findings"][0]["evidence"]["symbol_reachability"] == payload["blast_radius"][0]["symbol_reachability"]


def test_all_machine_views_agree_on_reachability_verdict() -> None:
    """json findings[], blast_radius[], CSV, SARIF (and Parquet when pyarrow is
    present) must surface the same symbol_reachability verdict for a finding."""
    import csv as _csv
    import io

    from agent_bom.output.csv_fmt import to_csv

    br = _stamp_python_br()
    report = AIBOMReport(agents=[], blast_radii=[br], findings=[blast_radius_to_finding(br)])

    payload = to_json(report)
    assert payload["findings"][0]["evidence"]["symbol_reachability"] == FUNCTION_REACHABLE
    assert payload["blast_radius"][0]["symbol_reachability"] == FUNCTION_REACHABLE

    sarif = to_sarif(report)
    assert sarif["runs"][0]["results"][0]["properties"]["symbol_reachability"] == FUNCTION_REACHABLE

    rows = list(_csv.DictReader(io.StringIO(to_csv(report))))
    assert rows[0]["symbol_reachability"] == FUNCTION_REACHABLE

    try:
        import pyarrow.parquet as pq  # noqa: F401

        from agent_bom.output.parquet_fmt import to_arrow_table

        table = to_arrow_table(report)
        assert table.column("symbol_reachability").to_pylist()[0] == FUNCTION_REACHABLE
    except ImportError:
        pass


def test_transitive_runtime_reach_provenance_is_preserved_across_machine_views() -> None:
    import csv
    import io

    from agent_bom.output.csv_fmt import to_csv

    br = _python_br([], pkg_name="urllib3")
    br.package.is_direct = False
    br.package.parent_package = "requests"
    br.package.dependency_depth = 1
    br.package.reachability_evidence = "lockfile"
    packages = [Package(name="requests", version="2.19.1", ecosystem="pypi"), br.package]

    apply_symbol_reachability_to_blast_radii(
        [br],
        ASTAnalysisResult(dependency_symbol_reach=[_reach("requests", "requests", "get")]),
        packages=packages,
    )
    finding = blast_radius_to_finding(br)
    report = AIBOMReport(agents=[], blast_radii=[br], findings=[finding])
    payload = to_json(report)
    sarif_props = to_sarif(report)["runs"][0]["results"][0]["properties"]
    graph_attrs = build_unified_graph_from_report(payload).get_node(f"vuln:{br.vulnerability.id}").attributes
    csv_row = next(csv.DictReader(io.StringIO(to_csv(report))))

    assert payload["findings"][0]["evidence"]["runtime_dependency_chain"] == ["requests", "urllib3"]
    assert payload["blast_radius"][0]["runtime_dependency_chain"] == ["requests", "urllib3"]
    assert sarif_props["runtime_dependency_chain"] == ["requests", "urllib3"]
    assert graph_attrs["runtime_dependency_chain"] == ["requests", "urllib3"]
    assert csv_row["runtime_dependency_chain"] == "requests;urllib3"


def test_api_finding_projection_preserves_transitive_runtime_reach_provenance() -> None:
    from agent_bom.api.models import ScanJob, ScanRequest
    from agent_bom.api.routes.scan import _finding_from_blast_radius

    row = _finding_from_blast_radius(
        {
            "vulnerability_id": "CVE-2099-7",
            "package": "urllib3@1.23",
            "symbol_reachability": PACKAGE_REACHABLE,
            "symbol_reachability_reason": "runtime dependency reached from an entrypoint",
            "runtime_dependency_chain": ["requests", "urllib3"],
        },
        ScanJob(job_id="scan-1", created_at="2026-08-25T00:00:00Z", request=ScanRequest()),
    )

    assert row["symbol_reachability"] == PACKAGE_REACHABLE
    assert row["symbol_reachability_reason"] == "runtime dependency reached from an entrypoint"
    assert row["runtime_dependency_chain"] == ["requests", "urllib3"]


@pytest.mark.parametrize(
    ("graph_reachable", "dependency_reachable", "expected"),
    [
        (True, False, PACKAGE_REACHABLE),
        (False, True, UNREACHABLE),
        (None, True, UNREACHABLE),
    ],
)
def test_graph_path_truth_drives_symbol_fallback_across_projections(
    graph_reachable: bool | None,
    dependency_reachable: bool,
    expected: str,
) -> None:
    """Graph-path truth, not manifest closure, drives the package fallback."""
    br = _python_br(["danger"], pkg_name="leftpad")
    br.graph_reachable = graph_reachable
    br.dependency_reachable = dependency_reachable
    findings = [blast_radius_to_finding(br)]

    stamped = apply_symbol_reachability_to_blast_radii(
        [br],
        ASTAnalysisResult(dependency_symbol_reach=[_reach("requests", "requests", "get")]),
    )
    assert stamped == 1
    assert br.symbol_reachability == expected

    assert resync_cve_findings_from_blast_radii(findings, [br]) == 1
    report = AIBOMReport(agents=[], blast_radii=[br], findings=findings)
    payload = to_json(report)

    finding_verdict = payload["findings"][0]["evidence"]["symbol_reachability"]
    blast_verdict = payload["blast_radius"][0]["symbol_reachability"]
    sarif_verdict = to_sarif(report)["runs"][0]["results"][0]["properties"]["symbol_reachability"]
    graph = build_unified_graph_from_report(payload)
    graph_verdict = graph.get_node(f"vuln:{br.vulnerability.id}").attributes["symbol_reachability"]

    assert finding_verdict == blast_verdict == sarif_verdict == graph_verdict == expected


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


def test_ast_result_for_symbol_reach_reads_ordinary_application_project() -> None:
    fixture = Path(__file__).parent / "fixtures" / "ordinary-python-app"

    result = _ast_result_for_symbol_reach([str(fixture)])

    assert result is not None
    assert result.tools == []
    assert result.application_entrypoints
    assert {reach.package for reach in result.dependency_symbol_reach} == {"requests"}
    assert all(reach.entrypoint_provenance for reach in result.dependency_symbol_reach)


def test_ordinary_application_reaches_runtime_child_but_not_unused_manifest_dependency() -> None:
    fixture = Path(__file__).parent / "fixtures" / "ordinary-python-app"
    ast_result = _ast_result_for_symbol_reach([str(fixture)])
    assert ast_result is not None
    packages = parse_uv_lock(fixture)
    by_name = {package.name: package for package in packages}
    runtime_child = _python_br([], pkg_name="urllib3")
    runtime_child.package = by_name["urllib3"]
    unused = _python_br([], pkg_name="attrs")
    unused.package = by_name["attrs"]

    apply_symbol_reachability_to_blast_radii(
        [runtime_child, unused],
        ast_result,
        packages=packages,
    )

    assert runtime_child.symbol_reachability == PACKAGE_REACHABLE
    assert runtime_child.runtime_dependency_chain == ["requests", "urllib3"]
    assert unused.symbol_reachability == UNREACHABLE
    assert unused.runtime_dependency_chain == []


def test_ast_result_for_symbol_reach_reads_php_only_project(tmp_path: Path) -> None:
    project = tmp_path / "php-mcp"
    project.mkdir()
    (project / "composer.json").write_text(
        '{"require": {"guzzlehttp/guzzle": "^7.0"}}',
        encoding="utf-8",
    )
    (project / "composer.lock").write_text(
        '{"packages": [{"name": "guzzlehttp/guzzle", "version": "7.8.1"}]}',
        encoding="utf-8",
    )
    (project / "Server.php").write_text(
        "<?php\n"
        "use GuzzleHttp\\Client;\n\n"
        "class Server {\n"
        "    public function register($server) {\n"
        '        $server->tool("fetch_url", [$this, "fetchUrl"]);\n'
        "    }\n\n"
        "    public function fetchUrl($url) {\n"
        "        $client = new Client();\n"
        "        return $client->get($url);\n"
        "    }\n"
        "}\n",
        encoding="utf-8",
    )

    result = _ast_result_for_symbol_reach([str(project)])

    assert result is not None
    assert any(reach.ecosystem == "composer" for reach in result.dependency_symbol_reach)


def test_ast_result_for_symbol_reach_skips_empty_paths(tmp_path: Path) -> None:
    empty = tmp_path / "empty"
    empty.mkdir()
    assert _ast_result_for_symbol_reach([str(empty)]) is None
