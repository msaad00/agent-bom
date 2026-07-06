"""Compliance tag export parity across lake, API, and finding stream surfaces."""

from __future__ import annotations

import csv
import io

import pytest

import pyarrow.parquet as pq
from agent_bom.compliance_utils import (
    COMPLIANCE_TAGS_EXPORT_SEPARATOR,
    compliance_tags_export_cell,
    framework_qualified_finding_tags,
    framework_qualified_tags_from_row,
)
from agent_bom.finding import blast_radius_to_finding
from agent_bom.finding_runtime_evidence import compliance_tags_from_finding_row
from agent_bom.models import AIBOMReport, BlastRadius, Package, Severity, Vulnerability
from agent_bom.output.csv_fmt import to_csv
from agent_bom.output.parquet_fmt import to_parquet_bytes

pyarrow = pytest.importorskip("pyarrow")


def _tagged_br() -> BlastRadius:
    vuln = Vulnerability(
        id="CVE-2099-42",
        summary="prompt injection path",
        severity=Severity.HIGH,
        compliance_tags={"OWASP": ["LLM01"]},
    )
    pkg = Package(name="langchain", version="0.2.0", ecosystem="pypi")
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=["cursor"],
        exposed_credentials=[],
        exposed_tools=[],
        owasp_tags=["LLM01:2025"],
        atlas_tags=["AML.T0051"],
    )


def _api_row_from_br(br: BlastRadius) -> dict:
    return {
        "compliance_tags": br.vulnerability.compliance_tags,
        "owasp_tags": list(br.owasp_tags),
        "atlas_tags": list(br.atlas_tags),
    }


def test_compliance_tags_export_parity_across_surfaces() -> None:
    br = _tagged_br()
    finding = blast_radius_to_finding(br)
    qualified = framework_qualified_finding_tags(finding)
    export_cell = compliance_tags_export_cell(finding)

    assert export_cell == COMPLIANCE_TAGS_EXPORT_SEPARATOR.join(qualified)
    assert framework_qualified_tags_from_row(_api_row_from_br(br)) == qualified
    assert compliance_tags_from_finding_row(_api_row_from_br(br)) == qualified

    report = AIBOMReport(agents=[], blast_radii=[br], scan_id="parity-test")
    csv_text = to_csv(report, [br])
    csv_row = next(csv.DictReader(io.StringIO(csv_text.lstrip("\ufeff"))))
    assert csv_row["compliance_tags"] == export_cell

    parquet_row = pq.read_table(pyarrow.BufferReader(to_parquet_bytes(report, [br]))).to_pylist()[0]
    assert parquet_row["compliance_tags"] == export_cell

    payload = finding.to_dict()
    assert payload["framework_tags"] == qualified
