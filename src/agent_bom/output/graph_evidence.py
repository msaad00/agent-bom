"""Project only the report sections the unified graph builder consumes.

Scan surfaces build the graph mid-pipeline, before later stages mutate the
report, so they cannot reuse the final serialized report. Serializing the whole
report just to hand the builder a handful of sections spends most of that work
on output the graph never reads (entity snapshots, posture, remediation and
framework rollups). This projection shares the row serializers with
:func:`agent_bom.output.json_fmt.to_json`, so every section it emits is exactly
what the full report would carry under the same key.
"""

from __future__ import annotations

from typing import Any

from agent_bom.cloud.cis_remediation import fail_closed_cis_bundle
from agent_bom.models import AIBOMReport
from agent_bom.output.json_fmt import (
    _append_side_findings,
    _blast_radius_rows,
    _cve_pairs_and_exposure_paths,
    _export_findings_json,
)
from agent_bom.output.json_sections import agents_json

# (report key, AIBOMReport attribute) for sections copied through when present.
_PASSTHROUGH_SECTIONS: tuple[tuple[str, str], ...] = (
    ("skill_audit", "skill_audit_data"),
    ("model_provenance", "model_provenance"),
    ("toxic_combinations", "toxic_combinations"),
    ("sast", "sast_data"),
    ("iac_findings", "iac_findings_data"),
    ("cloud_inventory", "cloud_inventory_data"),
    ("aws_organization", "aws_organization_data"),
    ("identity_discovery", "identity_discovery_data"),
    ("cloud_audit_trail", "cloud_audit_trail_data"),
    ("snowflake_object_graph", "snowflake_object_graph_data"),
    ("snowflake_login_anomalies", "snowflake_login_anomalies_data"),
    ("snowflake_exfil_graph", "snowflake_exfil_graph_data"),
    ("snowflake_auth_posture", "snowflake_auth_posture_data"),
    ("snowflake_services", "snowflake_services_data"),
    ("snowflake_pipeline", "snowflake_pipeline_data"),
    ("snowflake_integrations", "snowflake_integrations_data"),
    ("snowflake_external_data", "snowflake_external_data_data"),
    ("snowflake_governance", "snowflake_governance_data"),
    ("snowflake_activity", "snowflake_activity_data"),
    ("databricks_security", "databricks_security_data"),
    ("databricks_cis_benchmark", "databricks_security_data"),
    ("runtime_session_graph", "runtime_session_graph"),
    ("dataset_cards", "dataset_cards"),
    ("serving_configs", "serving_configs"),
    ("endpoint_inventory", "endpoint_inventory_data"),
    ("ai_inventory", "ai_inventory_data"),
    ("project_inventory", "project_inventory_data"),
    ("repo_trust", "repo_trust_data"),
)

# (report key, AIBOMReport attribute, cloud) for fail-closed CIS bundles.
_CIS_SECTIONS: tuple[tuple[str, str, str], ...] = (
    ("cis_benchmark", "cis_benchmark_data", "aws"),
    ("snowflake_cis_benchmark", "snowflake_cis_benchmark_data", "snowflake"),
    ("azure_cis_benchmark", "azure_cis_benchmark_data", "azure"),
    ("gcp_cis_benchmark", "gcp_cis_benchmark_data", "gcp"),
)


def graph_evidence_sections(report: AIBOMReport) -> dict[str, Any]:
    """Return the graph-consumed subset of ``to_json(report)``, key for key."""
    cve_pairs, exposure_paths = _cve_pairs_and_exposure_paths(report)
    findings = _export_findings_json(report)
    _append_side_findings(findings, report)
    sections: dict[str, Any] = {
        "scan_id": report.scan_id,
        "scan_sources": report.scan_sources,
        "codeowners": dict(report.codeowners) if isinstance(report.codeowners, dict) else list(report.codeowners),
        "agents": agents_json(report),
        "blast_radius": _blast_radius_rows(cve_pairs, exposure_paths),
        "findings": findings,
    }
    for key, attr in _PASSTHROUGH_SECTIONS:
        value = getattr(report, attr)
        if value:
            sections[key] = value
    for key, attr, cloud in _CIS_SECTIONS:
        value = getattr(report, attr)
        if value:
            sections[key] = fail_closed_cis_bundle(value, cloud=cloud)
    inventory = sections.get("project_inventory")
    if report.repo_trust_data and isinstance(inventory, dict) and "repo_trust" not in inventory:
        sections["project_inventory"] = {**inventory, "repo_trust": report.repo_trust_data}
    return sections


__all__ = ["graph_evidence_sections"]
