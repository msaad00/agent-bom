"""Parquet export contract for data-lake interop (#3499)."""

from __future__ import annotations

import pytest

from agent_bom.ast_models import ASTAnalysisResult, DependencySymbolReach
from agent_bom.graph.blast_reach import apply_symbol_reachability_to_blast_radii
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output.parquet_fmt import export_parquet, to_parquet_bytes
from agent_bom.reachability_cve import FUNCTION_REACHABLE


pyarrow = pytest.importorskip("pyarrow")


def _stamped_br() -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2099-8",
        summary="x",
        severity=Severity.HIGH,
        affected_symbols=["get"],
    )
    pkg = Package(name="requests", version="2.0.0", ecosystem="pypi")
    br = BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=["agent-a"],
        exposed_credentials=[],
        exposed_tools=[],
        graph_reachable=True,
        graph_min_hop_distance=1,
    )
    apply_symbol_reachability_to_blast_radii(
        [br],
        ASTAnalysisResult(
            dependency_symbol_reach=[
                DependencySymbolReach(
                    entrypoint="tool_entry",
                    package="requests",
                    module="requests",
                    symbol="get",
                    file_path="agent.py",
                    line_number=5,
                    call_path=["tool_entry", "requests.get"],
                )
            ]
        ),
    )
    return br


def test_parquet_export_includes_reachability_columns(tmp_path) -> None:
    br = _stamped_br()
    report = AIBOMReport(agents=[], blast_radii=[br], scan_id="parquet-test")
    out_path = tmp_path / "findings.parquet"

    export_parquet(report, str(out_path), [br])

    table = pyarrow.parquet.read_table(out_path)
    assert table.num_rows == 1
    row = table.to_pylist()[0]
    assert row["cve_id"] == "CVE-2099-8"
    assert row["symbol_reachability"] == FUNCTION_REACHABLE
    assert row["reachable_affected_symbols"] == "get"
    assert row["graph_reachable"] is True
    assert row["graph_min_hop_distance"] == 1


def test_parquet_bytes_round_trip() -> None:
    br = _stamped_br()
    report = AIBOMReport(agents=[], blast_radii=[br], scan_id="parquet-test")
    payload = to_parquet_bytes(report, [br])
    table = pyarrow.parquet.read_table(pyarrow.BufferReader(payload))
    assert table.num_rows == 1


def test_parquet_requires_pyarrow(monkeypatch) -> None:
    import agent_bom.output.parquet_fmt as parquet_fmt

    def _boom():
        raise RuntimeError("Parquet export requires pyarrow. Install with: pip install 'agent-bom[lake]'")

    monkeypatch.setattr(parquet_fmt, "_require_pyarrow", _boom)
    with pytest.raises(RuntimeError, match="agent-bom\\[lake\\]"):
        to_parquet_bytes(AIBOMReport(agents=[], scan_id="x"))
