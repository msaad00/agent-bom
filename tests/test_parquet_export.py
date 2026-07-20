"""Parquet export contract for data-lake interop (#3499)."""

from __future__ import annotations

import pytest

from agent_bom.ast_models import ASTAnalysisResult, DependencySymbolReach
from agent_bom.finding import Asset, Finding, FindingSource, FindingType
from agent_bom.graph.blast_reach import apply_symbol_reachability_to_blast_radii
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output.parquet_fmt import (
    PARQUET_SCHEMA_VERSION,
    export_parquet,
    to_arrow_table,
    to_parquet_bytes,
)
from agent_bom.reachability_cve import FUNCTION_REACHABLE

pyarrow = pytest.importorskip("pyarrow")

# The original CVE+malicious lake schema (v1). New unified columns are appended
# AFTER these so existing Iceberg/lake consumers keep reading the same shape.
_V1_COLUMNS = (
    "cve_id",
    "package",
    "version",
    "ecosystem",
    "severity",
    "cvss_score",
    "epss_score",
    "is_kev",
    "is_malicious",
    "malicious_reason",
    "published_at",
    "modified_at",
    "fixed_version",
    "cwe_ids",
    "affected_agents",
    "affected_servers",
    "exposed_credentials",
    "summary",
    "severity_source",
    "epss_percentile",
    "kev_date_added",
    "kev_due_date",
    "compliance_tags",
    "reachability",
    "symbol_reachability",
    "reachable_affected_symbols",
    "graph_reachable",
    "graph_min_hop_distance",
)


def _stamped_br() -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2099-8",
        summary="x",
        severity=Severity.HIGH,
        affected_symbols=["get"],
        compliance_tags={"OWASP": ["LLM01"]},
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
    assert row["compliance_tags"] == "OWASP:LLM01"


def test_parquet_bytes_round_trip() -> None:
    br = _stamped_br()
    report = AIBOMReport(agents=[], blast_radii=[br], scan_id="parquet-test")
    payload = to_parquet_bytes(report, [br])
    table = pyarrow.parquet.read_table(pyarrow.BufferReader(payload))
    assert table.num_rows == 1


def _mixed_report() -> AIBOMReport:
    """Report carrying a CVE finding plus non-CVE unified types (#4280)."""
    report = AIBOMReport(agents=[], scan_id="parquet-unified")
    report.findings = [
        Finding(
            finding_type=FindingType.CVE,
            source=FindingSource.SBOM,
            asset=Asset(name="web-lib", asset_type="package", identifier="pkg:npm/web-lib@1.0.0"),
            severity="high",
            title="CVE-2026-4242: web-lib@1.0.0",
            description="Unified vulnerability",
            cve_id="CVE-2026-4242",
            cwe_ids=["CWE-79"],
            cvss_score=8.8,
            epss_score=0.812345,
            fixed_version="2.0.0",
            is_kev=True,
            evidence={
                "package_name": "web-lib",
                "package_version": "1.0.0",
                "ecosystem": "npm",
                "published_at": "2026-01-01T00:00:00Z",
                "severity_source": "nvd:cvss_v3",
                "epss_percentile": 99.1234,
            },
            affected_agents=["prod-agent"],
        ),
        Finding(
            finding_type=FindingType.COMBINATION,
            source=FindingSource.GRAPH_ANALYSIS,
            asset=Asset(name="prod-agent", asset_type="agent", identifier="agent:prod-agent"),
            severity="critical",
            title="Toxic combination: KEV CVE + exposed credential",
            description="KEV-listed CVE chained with an exposed credential on one path",
        ),
        Finding(
            finding_type=FindingType.PROMPT_SECURITY,
            source=FindingSource.PROMPT_SCAN,
            asset=Asset(name="system-prompt", asset_type="prompt", identifier="prompt:system-prompt"),
            severity="high",
            title="Prompt injection sink in template",
            description="Untrusted input interpolated into system prompt",
        ),
    ]
    return report


def test_parquet_exports_all_unified_finding_types(tmp_path) -> None:
    """Parquet must carry COMBINATION / PROMPT_SECURITY, not just CVE+malicious (#4280)."""
    report = _mixed_report()
    out_path = tmp_path / "unified.parquet"

    export_parquet(report, str(out_path))

    table = pyarrow.parquet.read_table(out_path)
    # Row count reconciles to the full unified stream, not just CVE+malicious.
    assert table.num_rows == len(report.to_findings()) == 3
    rows = table.to_pylist()
    by_type = {row["finding_type"]: row for row in rows}
    assert {"CVE", "COMBINATION", "PROMPT_SECURITY"} <= set(by_type)

    combo = by_type["COMBINATION"]
    assert combo["severity"] == "critical"
    assert combo["title"] == "Toxic combination: KEV CVE + exposed credential"
    assert combo["summary"]
    assert combo["finding_id"]
    prompt = by_type["PROMPT_SECURITY"]
    assert prompt["severity"] == "high"
    assert prompt["finding_type"] == "PROMPT_SECURITY"


def test_parquet_cve_columns_byte_identical_to_cve_only_export(tmp_path) -> None:
    """Widening must not perturb any existing CVE column value/dtype (#4280).

    A CVE row exported from the mixed estate must be byte-identical (across the
    v1 columns) to the same CVE exported alone — existing Iceberg consumers of
    those columns cannot break.
    """
    mixed = _mixed_report()
    cve_only = AIBOMReport(agents=[], scan_id="cve-only")
    cve_only.findings = [mixed.findings[0]]

    mixed_table = to_arrow_table(mixed)
    cve_only_table = to_arrow_table(cve_only)

    # Every original column keeps its exact type in the widened schema.
    for name in _V1_COLUMNS:
        assert mixed_table.schema.field(name).type == cve_only_table.schema.field(name).type

    mixed_cve = next(r for r in mixed_table.to_pylist() if r["finding_type"] == "CVE")
    cve_row = cve_only_table.to_pylist()[0]
    for name in _V1_COLUMNS:
        assert mixed_cve[name] == cve_row[name], name


def test_parquet_schema_is_additive_and_versioned() -> None:
    """New columns are appended after the v1 block; schema carries a version bump."""
    table = to_arrow_table(_mixed_report())
    # v1 columns preserved, in order, at the front.
    assert tuple(table.schema.names[: len(_V1_COLUMNS)]) == _V1_COLUMNS
    # New nullable columns appended at the end.
    assert table.schema.names[len(_V1_COLUMNS) :] == ["finding_type", "finding_id", "title"]
    for name in ("finding_type", "finding_id", "title"):
        assert table.schema.field(name).nullable
    # A CVE-only consumer view still resolves every original column.
    for name in _V1_COLUMNS:
        assert name in table.schema.names
    # Additive change is signalled via a schema-version bump in file metadata.
    assert PARQUET_SCHEMA_VERSION == "2"
    meta = table.schema.metadata or {}
    assert meta.get(b"agent_bom.parquet_schema_version") == b"2"


def test_parquet_requires_pyarrow(monkeypatch) -> None:
    import agent_bom.output.parquet_fmt as parquet_fmt

    def _boom():
        raise RuntimeError("Parquet export requires pyarrow. Install with: pip install 'agent-bom[lake]'")

    monkeypatch.setattr(parquet_fmt, "_require_pyarrow", _boom)
    with pytest.raises(RuntimeError, match="agent-bom\\[lake\\]"):
        to_parquet_bytes(AIBOMReport(agents=[], scan_id="x"))
