"""Output-fidelity regression tests (0.94.3).

Covers four export fixes:
  5. Malicious (MAL-) packages are flagged in every SBOM (CycloneDX / SPDX 3.0 /
     SPDX 2.x), not emitted as ordinary components.
  6. The SPDX 3.0 emitter uses SPDX 3.0 vocabulary (not SPDX-2.x tokens) — the
     declared version and the emitted vocabulary agree.
  7. The base ``reachability`` verdict rides on CSV and Parquet exports, matching
     SARIF.
  8. The Prometheus exporter caps per-finding series so a large report can't
     explode scrape cardinality.
"""

from __future__ import annotations

import csv
import io
import logging

import pytest

from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    Severity,
    Vulnerability,
)


def _mal_report() -> AIBOMReport:
    mal_pkg = Package(
        name="evil-lib",
        version="1.0.0",
        ecosystem="pypi",
        is_malicious=True,
        malicious_reason="MAL-2024-0001",
    )
    vuln = Vulnerability(
        id="CVE-2026-9",
        summary="rce",
        severity=Severity.HIGH,
        cvss_score=7.5,
        fixed_version="2.0.0",
    )
    vpkg = Package(name="requests", version="1.0.0", ecosystem="pypi", vulnerabilities=[vuln])
    server = MCPServer(name="srv", command="python", args=["-m", "srv"], packages=[mal_pkg, vpkg])
    agent = Agent(name="agent", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/c.json", mcp_servers=[server])
    return AIBOMReport(agents=[agent], blast_radii=[])


# ─── Fix #5: malicious flag surfaced in every SBOM ───────────────────────────


def test_cyclonedx_flags_malicious_package():
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx

    cdx = to_cyclonedx(_mal_report())
    evil = next(c for c in cdx["components"] if c.get("name") == "evil-lib")
    props = {p["name"]: p["value"] for p in evil.get("properties", [])}
    assert props.get("agent-bom:is-malicious") == "true"
    assert props.get("agent-bom:malicious-reason") == "MAL-2024-0001"

    # A benign package is NOT flagged.
    benign = next(c for c in cdx["components"] if c.get("name") == "requests")
    benign_props = {p["name"]: p["value"] for p in benign.get("properties", [])}
    assert "agent-bom:is-malicious" not in benign_props


def test_spdx3_flags_malicious_package():
    from agent_bom.output.spdx_fmt import to_spdx

    doc = to_spdx(_mal_report())
    evil = next(e for e in doc["@graph"] if e.get("name") == "evil-lib")
    statements = {a["statement"] for a in evil.get("annotation", [])}
    assert any(s.startswith("agent-bom:malicious=true") for s in statements)

    benign = next(e for e in doc["@graph"] if e.get("name") == "requests")
    benign_statements = {a["statement"] for a in benign.get("annotation", [])}
    assert not any(s.startswith("agent-bom:malicious=true") for s in benign_statements)


def test_spdx2_flags_malicious_package():
    from agent_bom.output.spdx2_fmt import to_spdx2

    doc = to_spdx2(_mal_report())
    evil = next(p for p in doc["packages"] if p.get("name") == "evil-lib")
    comments = {a["comment"] for a in evil.get("annotations", [])}
    assert any(c.startswith("agent-bom:malicious=true") for c in comments)


# ─── Fix #6: SPDX 3.0 declared version matches emitted vocabulary ─────────────

_SPDX2_TOKENS = ("SOFTWARE_PACKAGE", "security/Vulnerability", "security/VulnAssessmentRelationship")
_SPDX2_REL_TYPES = ("CONTAINS", "DEPENDS_ON", "AFFECTS")


def test_spdx3_uses_spdx3_vocabulary():
    from agent_bom.output.spdx_fmt import to_spdx

    doc = to_spdx(_mal_report())
    graph = doc["@graph"]
    creation_info = next(n for n in graph if n["type"] == "CreationInfo")
    assert creation_info["specVersion"] == "3.0.1"

    element_types = {e.get("type") for e in graph}
    assert "software_Package" in element_types
    assert "security_Vulnerability" in element_types
    # No SPDX-2.x element vocabulary leaked into a 3.0 document.
    assert not set(_SPDX2_TOKENS) & element_types

    for elem in graph:
        # 2.x used "primaryPurpose"; 3.0 namespaces it as "software_primaryPurpose".
        assert "primaryPurpose" not in elem
        # No ad-hoc CVSS score object on the vulnerability element.
        assert "score" not in elem

    relationships = [r for r in graph if str(r.get("type") or "").endswith("Relationship")]
    rel_types = {r.get("relationshipType") for r in relationships}
    assert {"contains", "dependsOn", "affects"} <= rel_types
    assert not set(_SPDX2_REL_TYPES) & rel_types

    # CVSS is expressed as a security-profile assessment relationship.
    cvss_rels = [r for r in relationships if r.get("type") == "security_CvssV3VulnAssessmentRelationship"]
    assert cvss_rels
    assert cvss_rels[0]["security_score"] == 7.5
    assert cvss_rels[0]["relationshipType"] == "hasAssessmentFor"


def test_spdx3_round_trips_through_parser():
    """The corrected 3.0 vocabulary is still ingestible by the SBOM parser."""
    from agent_bom.output.spdx_fmt import to_spdx
    from agent_bom.sbom import parse_spdx

    doc = to_spdx(_mal_report())
    packages = parse_spdx(doc)
    names = {p.name for p in packages}
    assert {"evil-lib", "requests"} <= names
    requests_pkg = next(p for p in packages if p.name == "requests")
    assert any(v.id == "CVE-2026-9" and v.cvss_score == 7.5 for v in requests_pkg.vulnerabilities)


# ─── Fix #7: base reachability rides on CSV + Parquet ────────────────────────


def _reachability_br() -> BlastRadius:
    vuln = Vulnerability(id="CVE-2026-77", summary="x", severity=Severity.HIGH)
    pkg = Package(name="requests", version="2.0.0", ecosystem="pypi")
    return BlastRadius(
        vulnerability=vuln,
        package=pkg,
        affected_servers=[],
        affected_agents=["agent-a"],
        exposed_credentials=[],
        exposed_tools=[],
    )


def test_csv_export_includes_base_reachability():
    from agent_bom.output.csv_fmt import to_csv
    from agent_bom.output.finding_views import machine_export_findings

    br = _reachability_br()
    report = AIBOMReport(agents=[], blast_radii=[br], scan_id="csv-test")

    rows = list(csv.DictReader(io.StringIO(to_csv(report, [br]).lstrip("﻿"))))
    assert "reachability" in rows[0]
    expected = machine_export_findings(report, [br])[0].reachability
    assert rows[0]["reachability"] == expected
    assert expected  # non-empty verdict


def test_parquet_export_includes_base_reachability():
    pytest.importorskip("pyarrow")
    import pyarrow as pa
    import pyarrow.parquet as pq

    from agent_bom.output.finding_views import machine_export_findings
    from agent_bom.output.parquet_fmt import to_parquet_bytes

    br = _reachability_br()
    report = AIBOMReport(agents=[], blast_radii=[br], scan_id="pq-test")
    table = pq.read_table(pa.BufferReader(to_parquet_bytes(report, [br])))
    assert "reachability" in table.column_names
    row = table.to_pylist()[0]
    assert row["reachability"] == machine_export_findings(report, [br])[0].reachability


# ─── Fix #8: Prometheus per-finding cardinality cap ──────────────────────────


def _many_findings_report(n: int) -> tuple[AIBOMReport, list[BlastRadius]]:
    brs: list[BlastRadius] = []
    for i in range(n):
        vuln = Vulnerability(
            id=f"CVE-2026-{i:04d}",
            summary="x",
            severity=Severity.HIGH,
            cvss_score=5.0 + (i % 5),
            epss_score=0.1,
        )
        pkg = Package(name=f"pkg-{i}", version="1.0.0", ecosystem="pypi")
        brs.append(
            BlastRadius(
                vulnerability=vuln,
                package=pkg,
                affected_servers=[],
                affected_agents=["agent-a"],
                exposed_credentials=[],
                exposed_tools=[],
            )
        )
    report = AIBOMReport(agents=[], blast_radii=brs, scan_id="prom-test")
    return report, brs


def test_prometheus_caps_per_finding_series(caplog):
    from agent_bom.output.prometheus import to_prometheus

    report, brs = _many_findings_report(5)
    with caplog.at_level(logging.WARNING, logger="agent_bom.output.prometheus"):
        text = to_prometheus(report, brs, max_per_finding_series=2)

    # Only the capped number of per-finding blast-radius series are emitted.
    assert text.count("agent_bom_blast_radius_score{") == 2
    assert text.count("agent_bom_vulnerability_cvss_score{") == 2
    # The truncation is surfaced as its own metric and logged.
    assert "agent_bom_per_finding_series_truncated 3" in text
    assert any("truncated per-finding series" in r.message for r in caplog.records)


def test_prometheus_no_truncation_under_cap():
    from agent_bom.output.prometheus import to_prometheus

    report, brs = _many_findings_report(3)
    text = to_prometheus(report, brs, max_per_finding_series=500)
    assert text.count("agent_bom_blast_radius_score{") == 3
    assert "per_finding_series_truncated" not in text


if __name__ == "__main__":  # pragma: no cover
    raise SystemExit(pytest.main([__file__, "-q"]))
