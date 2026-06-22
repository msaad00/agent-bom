"""Surfacing tests for unified-Finding fields across JSON / SARIF / OCSF (#2918, PR-2).

PR-1 (#2960) made suppression state, AI-native context, and the structured reach
lists first-class on :class:`~agent_bom.finding.Finding`. This stage surfaces them
in the three Finding-native formatters. These tests assert each format now carries
the new fields AND that a plain (non-suppressed, no-AI) finding's output is otherwise
unchanged — the additive fields are the *only* delta.
"""

from __future__ import annotations

import json

from agent_bom.finding import blast_radius_to_finding
from agent_bom.models import (
    AIBOMReport,
    BlastRadius,
    MCPServer,
    Package,
    TransportType,
    Vulnerability,
)
from agent_bom.output.json_fmt import to_json
from agent_bom.output.ocsf import finding_to_ocsf, findings_to_ocsf
from agent_bom.output.sarif import to_sarif

# The fields PR-2 adds to each format. Stripping these from a plain finding's
# serialization must reproduce the pre-PR-2 output exactly (snapshot guard).
_NEW_JSON_FINDING_KEYS = {
    "suppressed",
    "suppression_id",
    "suppression_state",
    "suppression_reason",
    "unsuppressed_risk_score",
    "ai_risk_context",
    "ai_summary",
    "attack_vector_summary",
    "affected_servers",
    "affected_agents",
    "exposed_credentials",
    "exposed_tools",
    "reachability",
    "is_actionable",
    "impact_category",
}
_NEW_SARIF_RESULT_PROPERTY_KEYS = {
    "affected_servers",
    "affected_agents",
    "exposed_tools",
    "ai_risk_context",
    "ai_summary",
    "suppressed",
}


# ---------------------------------------------------------------------------
# Fixtures
# ---------------------------------------------------------------------------


def _vuln(vuln_id: str = "CVE-2024-0001", severity=None) -> Vulnerability:
    from agent_bom.models import Severity

    return Vulnerability(
        id=vuln_id,
        summary="Test vulnerability",
        severity=severity or Severity.HIGH,
        cvss_score=7.5,
        fixed_version="2.0.0",
    )


def _pkg(name: str = "requests", version: str = "1.0.0") -> Package:
    return Package(name=name, version=version, ecosystem="pypi")


def _server(name: str) -> MCPServer:
    return MCPServer(name=name, command="npx srv", transport=TransportType.STDIO)


def _plain_br() -> BlastRadius:
    """An ordinary, non-suppressed, no-AI-context blast radius."""
    return BlastRadius(
        vulnerability=_vuln("CVE-2024-PLAIN"),
        package=_pkg("plainpkg"),
        affected_servers=[_server("plain-server")],
        affected_agents=[],
        exposed_credentials=[],
        exposed_tools=[],
        risk_score=5.0,
    )


def _suppressed_br() -> BlastRadius:
    br = BlastRadius(
        vulnerability=_vuln("CVE-2024-SUPPRESSED"),
        package=_pkg("suppressedpkg"),
        affected_servers=[_server("supp-server")],
        affected_agents=[],
        exposed_credentials=["OPENAI_API_KEY"],
        exposed_tools=[],
        risk_score=0.0,
    )
    br.suppressed = True
    br.suppression_id = "550e8400-e29b-41d4-a716-446655440000"  # valid GUID
    br.suppression_state = "acknowledged"
    br.suppression_reason = "Risk accepted by platform owner"
    br.unsuppressed_risk_score = 9.2
    return br


def _ai_context_br() -> BlastRadius:
    br = BlastRadius(
        vulnerability=_vuln("CVE-2024-AICTX"),
        package=_pkg("aipkg"),
        affected_servers=[_server("srv-a"), _server("srv-b"), _server("srv-c")],
        affected_agents=[],
        exposed_credentials=["AWS_SECRET_ACCESS_KEY", "STRIPE_KEY"],
        exposed_tools=[],
        risk_score=8.5,
    )
    br.ai_risk_context = "Reachable from an internet-exposed agent"
    br.ai_summary = "LLM-generated risk narrative"
    br.attack_vector_summary = "agent -> srv-a -> vulnerable aipkg"
    return br


def _report() -> AIBOMReport:
    return AIBOMReport(
        agents=[],
        blast_radii=[_plain_br(), _suppressed_br(), _ai_context_br()],
    )


# ---------------------------------------------------------------------------
# JSON surfacing
# ---------------------------------------------------------------------------


def _json_finding(data: dict, cve_id: str) -> dict:
    for finding in data["findings"]:
        if finding.get("cve_id") == cve_id:
            return finding
    raise AssertionError(f"no JSON finding for {cve_id}")


def test_json_findings_surface_suppression():
    data = to_json(_report())
    supp = _json_finding(data, "CVE-2024-SUPPRESSED")
    assert supp["suppressed"] is True
    assert supp["suppression_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert supp["suppression_state"] == "acknowledged"
    assert supp["suppression_reason"] == "Risk accepted by platform owner"
    assert supp["unsuppressed_risk_score"] == 9.2


def test_json_findings_surface_ai_context_and_reach():
    data = to_json(_report())
    ai = _json_finding(data, "CVE-2024-AICTX")
    assert ai["ai_risk_context"] == "Reachable from an internet-exposed agent"
    assert ai["ai_summary"] == "LLM-generated risk narrative"
    assert ai["attack_vector_summary"] == "agent -> srv-a -> vulnerable aipkg"
    assert ai["affected_servers"] == ["srv-a", "srv-b", "srv-c"]
    assert ai["exposed_credentials"] == ["AWS_SECRET_ACCESS_KEY", "STRIPE_KEY"]


def test_json_plain_finding_unchanged_except_additive_fields():
    """Snapshot guard: stripping the new keys reproduces the pre-PR-2 payload."""
    data = to_json(_report())
    plain = _json_finding(data, "CVE-2024-PLAIN")

    # Every new key is present (additive contract).
    assert _NEW_JSON_FINDING_KEYS.issubset(plain.keys())

    # A plain finding has benign defaults — nothing alarming surfaced.
    assert plain["suppressed"] is False
    assert plain["suppression_id"] is None
    assert plain["ai_risk_context"] is None

    # Rebuild the legacy payload by removing only the additive keys and confirm
    # it equals what Finding.to_dict produced before this PR (recomputed from a
    # finding whose new fields are all defaults => identical to legacy output).
    legacy = {k: v for k, v in plain.items() if k not in _NEW_JSON_FINDING_KEYS}
    expected = blast_radius_to_finding(_plain_br()).to_dict()
    expected_legacy = {k: v for k, v in expected.items() if k not in _NEW_JSON_FINDING_KEYS}
    assert legacy == expected_legacy
    # And the doc round-trips as JSON.
    json.dumps(data)


# ---------------------------------------------------------------------------
# SARIF surfacing
# ---------------------------------------------------------------------------


def _sarif_result(doc: dict, rule_id: str) -> dict:
    for result in doc["runs"][0]["results"]:
        if result.get("ruleId") == rule_id:
            return result
    raise AssertionError(f"no SARIF result for {rule_id}")


def test_sarif_suppressed_finding_emits_suppressions_array():
    doc = to_sarif(_report())
    result = _sarif_result(doc, "CVE-2024-SUPPRESSED")
    suppressions = result["suppressions"]
    assert len(suppressions) == 1
    entry = suppressions[0]
    assert entry["kind"] == "external"
    assert entry["guid"] == "550e8400-e29b-41d4-a716-446655440000"
    assert entry["status"] == "accepted"  # "acknowledged" maps to SARIF "accepted"
    assert entry["justification"] == "Risk accepted by platform owner"
    assert entry["properties"]["suppression_state"] == "acknowledged"
    assert entry["properties"]["unsuppressed_risk_score"] == 9.2


def test_sarif_plain_finding_has_no_suppressions():
    doc = to_sarif(_report())
    result = _sarif_result(doc, "CVE-2024-PLAIN")
    assert "suppressions" not in result
    assert result["properties"]["suppressed"] is False


def test_sarif_surfaces_ai_context_and_reach():
    doc = to_sarif(_report())
    props = _sarif_result(doc, "CVE-2024-AICTX")["properties"]
    assert props["ai_risk_context"] == "Reachable from an internet-exposed agent"
    assert props["ai_summary"] == "LLM-generated risk narrative"
    assert props["affected_servers"] == ["srv-a", "srv-b", "srv-c"]
    assert props["exposed_tools"] == []


def test_sarif_plain_result_properties_superset_only():
    """The plain result must carry the additive property keys and nothing alarming."""
    doc = to_sarif(_report())
    props = _sarif_result(doc, "CVE-2024-PLAIN")["properties"]
    assert _NEW_SARIF_RESULT_PROPERTY_KEYS.issubset(props.keys())
    assert props["affected_servers"] == ["plain-server"]
    assert props["ai_risk_context"] is None


# ---------------------------------------------------------------------------
# OCSF surfacing
# ---------------------------------------------------------------------------


def test_ocsf_suppressed_finding_status_suppressed():
    finding = blast_radius_to_finding(_suppressed_br())
    event = finding_to_ocsf(finding, product_version="9.9.9")
    assert event["class_uid"] == 2001
    assert event["status_id"] == 4  # Suppressed
    assert event["status"] == "Suppressed"
    supp = event["unmapped"]["suppression"]
    assert supp["suppressed"] is True
    assert supp["suppression_id"] == "550e8400-e29b-41d4-a716-446655440000"
    assert supp["suppression_state"] == "acknowledged"
    assert supp["unsuppressed_risk_score"] == 9.2


def test_ocsf_ai_context_and_reach_surface():
    finding = blast_radius_to_finding(_ai_context_br())
    event = finding_to_ocsf(finding)
    ai = event["unmapped"]["ai_context"]
    assert ai["ai_risk_context"] == "Reachable from an internet-exposed agent"
    assert ai["ai_summary"] == "LLM-generated risk narrative"
    assert ai["attack_vector_summary"] == "agent -> srv-a -> vulnerable aipkg"
    assert event["unmapped"]["affected_servers"] == ["srv-a", "srv-b", "srv-c"]
    assert event["unmapped"]["exposed_credentials"] == ["AWS_SECRET_ACCESS_KEY", "STRIPE_KEY"]


def test_ocsf_plain_finding_status_new_and_no_suppression():
    finding = blast_radius_to_finding(_plain_br())
    event = finding_to_ocsf(finding)
    assert event["status_id"] == 1  # New
    assert event["status"] == "New"
    assert "suppression" not in event["unmapped"]
    assert "ai_context" not in event["unmapped"]
    assert event["unmapped"]["affected_servers"] == ["plain-server"]
    # JSON-serializable.
    json.dumps(event)


def test_findings_to_ocsf_batch():
    findings = [blast_radius_to_finding(br) for br in (_plain_br(), _suppressed_br())]
    events = findings_to_ocsf(findings)
    assert [e["status_id"] for e in events] == [1, 4]
