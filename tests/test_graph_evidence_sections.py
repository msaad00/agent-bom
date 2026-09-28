"""The scan graph input is projected from the in-memory report, not ``to_json``.

``graph_evidence_sections`` must hand the graph builder exactly the evidence
the full serialized report would, so skipping the interim ``to_json`` can never
change the graph, its attack paths, or anything stamped from them.
"""

from __future__ import annotations

from dataclasses import asdict

import pytest

from agent_bom.graph.build_input import GraphBuildInput, GraphEvidenceSections
from agent_bom.graph.builder import build_unified_graph, build_unified_graph_from_report
from agent_bom.models import (
    Agent,
    AgentType,
    AIBOMReport,
    BlastRadius,
    MCPServer,
    MCPTool,
    Package,
    Severity,
    Vulnerability,
)
from agent_bom.output.graph_evidence import graph_evidence_sections
from agent_bom.output.json_fmt import to_json

_CIS = {"checks": [{"check_id": "1.1", "title": "Root MFA", "status": "fail", "severity": "high"}]}

# Every report attribute feeding an optional graph section, populated.
_SECTION_ATTRS: dict[str, object] = {
    "model_provenance": [{"model_id": "org/model", "source": "huggingface"}],
    "dataset_cards": {"datasets": [{"name": "ds"}]},
    "serving_configs": [{"name": "svc", "framework": "vllm"}],
    "cloud_inventory_data": {"provider": "aws", "resources": [{"id": "arn:aws:s3:::b", "type": "s3_bucket"}]},
    "cis_benchmark_data": _CIS,
    "snowflake_cis_benchmark_data": _CIS,
    "azure_cis_benchmark_data": _CIS,
    "gcp_cis_benchmark_data": _CIS,
    "databricks_security_data": {"checks": []},
    "sast_data": {"findings": [{"rule_id": "r1", "file": "a.py", "line": 3, "severity": "high"}]},
    "iac_findings_data": {"findings": [{"rule_id": "i1", "file": "main.tf", "severity": "medium"}]},
    "skill_audit_data": {"findings": [{"title": "risky skill", "severity": "high"}]},
    "ai_inventory_data": {"framework_agents": [{"name": "fw-agent"}]},
    "runtime_session_graph": {"nodes": [], "edges": []},
    "toxic_combinations": [{"id": "tc-1", "title": "combo"}],
    "aws_organization_data": {"accounts": [{"id": "123456789012"}]},
    "cloud_audit_trail_data": {"provider": "aws", "events": []},
    "snowflake_object_graph_data": {"objects": []},
    "snowflake_exfil_graph_data": {"paths": []},
    "snowflake_login_anomalies_data": {"anomalies": []},
    "snowflake_auth_posture_data": {"users": []},
    "snowflake_services_data": {"services": []},
    "snowflake_pipeline_data": {"pipes": []},
    "snowflake_integrations_data": {"integrations": []},
    "snowflake_external_data_data": {"stages": []},
    "snowflake_governance_data": {"policies": []},
    "snowflake_activity_data": {"queries": []},
    "identity_discovery_data": {"identities": [{"id": "user:alice"}]},
    "project_inventory_data": {"root": ".", "folders": []},
    "repo_trust_data": {"signals": [{"name": "branch_protection", "status": "missing"}]},
    "endpoint_inventory_data": {"host": "wks-1"},
    "prompt_scan_data": {"findings": [{"title": "prompt injection", "severity": "high", "file": "p.txt"}]},
    "browser_extensions": {"extensions": [{"id": "ext1", "name": "Ext", "risk_level": "high", "risk_reasons": ["broad host access"]}]},
    "codeowners": {"services": "@team"},
}


def _report(*, populated: bool) -> AIBOMReport:
    vuln = Vulnerability(id="CVE-2024-0001", summary="rce", severity=Severity.CRITICAL, fixed_version="2.0.0", aliases=["GHSA-aaaa"])
    pkg = Package(name="left-pad", version="1.0.0", ecosystem="npm", vulnerabilities=[vuln])
    tool = MCPTool(name="read_file", description="read")
    server = MCPServer(name="files", command="npx", args=["files-mcp"], packages=[pkg], tools=[tool])
    agent = Agent(name="desktop", agent_type=AgentType.CLAUDE_DESKTOP, config_path="/tmp/config.json", mcp_servers=[server])
    br = BlastRadius(
        vulnerability=vuln, package=pkg, affected_servers=[server], affected_agents=[agent], exposed_credentials=[], exposed_tools=[]
    )
    br.calculate_risk_score()
    report = AIBOMReport(agents=[agent], blast_radii=[br], scan_id="scan-graph-input", scan_sources=["agent_discovery"])
    if populated:
        for attr, value in _SECTION_ATTRS.items():
            assert hasattr(report, attr), attr
            setattr(report, attr, value)
    return report


@pytest.mark.parametrize("populated", [False, True])
def test_graph_evidence_sections_match_serialized_report(populated: bool) -> None:
    report = _report(populated=populated)
    expected = GraphBuildInput.from_report(to_json(report))
    actual = GraphBuildInput.from_report(graph_evidence_sections(report))

    assert asdict(actual) == asdict(expected)
    assert set(actual.evidence) == set(expected.evidence)
    if populated:
        # The fixture must exercise every section the serialized report can carry.
        emitted = set(expected.evidence)
        assert {"findings", "project_inventory", "repo_trust", "cis_benchmark", "databricks_cis_benchmark"} <= emitted


def test_graph_evidence_sections_emit_only_graph_keys() -> None:
    sections = graph_evidence_sections(_report(populated=True))
    assert set(sections) <= set(GraphEvidenceSections.__annotations__)


def test_graph_built_from_sections_matches_serialized_build() -> None:
    report = _report(populated=True)
    serialized = build_unified_graph_from_report(to_json(report), scan_id="s", tenant_id="t")
    direct = build_unified_graph(GraphBuildInput.from_report(graph_evidence_sections(report)), scan_id="s", tenant_id="t")

    assert sorted(direct.nodes) == sorted(serialized.nodes)
    assert sorted((e.source, e.target, str(e.relationship)) for e in direct.edges) == sorted(
        (e.source, e.target, str(e.relationship)) for e in serialized.edges
    )
    assert [p.to_dict() if hasattr(p, "to_dict") else p for p in direct.attack_paths] == [
        p.to_dict() if hasattr(p, "to_dict") else p for p in serialized.attack_paths
    ]


def test_surface_graph_derived_findings_skips_full_serialization(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.output as output_pkg
    import agent_bom.output.json_fmt as json_fmt
    from agent_bom.graph.scan_findings import surface_graph_derived_findings

    def _forbidden(_report: AIBOMReport) -> dict:
        raise AssertionError("graph surfacing must not serialize the full report")

    monkeypatch.setattr(output_pkg, "to_json", _forbidden)
    monkeypatch.setattr(json_fmt, "to_json", _forbidden)

    surface = surface_graph_derived_findings(_report(populated=True), scan_id="s", tenant_id="t", include_dependency_reachability=True)

    assert surface is not None
    assert surface.dependency_reachability is not None
    assert "vuln:CVE-2024-0001" in surface.dependency_reachability.vulnerabilities
