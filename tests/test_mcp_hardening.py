from __future__ import annotations

from agent_bom.mcp_hardening import build_mcp_hardening_catalog


def test_mcp_hardening_catalog_maps_nsa_security_themes() -> None:
    catalog = build_mcp_hardening_catalog()

    assert catalog["schema_version"] == "mcp.hardening.v1"
    assert "NSA CSI" in catalog["source"]["name"]
    assert catalog["control_count"] == len(catalog["controls"])

    control_ids = {control["id"] for control in catalog["controls"]}
    assert {
        "supported_project_inventory",
        "explicit_trust_boundaries",
        "strict_parameter_validation",
        "sandbox_tool_execution",
        "message_integrity_and_replay",
        "output_pipeline_filtering",
        "audit_logging_and_detection",
        "vulnerability_tracking",
        "network_discovery",
    }.issubset(control_ids)

    validation = next(control for control in catalog["controls"] if control["id"] == "strict_parameter_validation")
    assert "55 strict-args MCP tools" in validation["agent_bom_surfaces"]
    assert "additionalProperties=false" in " ".join(validation["agent_bom_surfaces"])

    audit = next(control for control in catalog["controls"] if control["id"] == "audit_logging_and_detection")
    assert {"runtime_production_index", "audit_query", "audit_integrity", "proxy_alerts"}.issubset(set(audit["agent_bom_surfaces"]))

    assert "not a certification" in catalog["claim_boundary"]
