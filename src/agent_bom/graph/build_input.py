"""Narrow graph input contract adapted once from the public serialized report."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from typing import Any, TypedDict, cast

from agent_bom.graph.projection_support import _is_repository_inventory, _is_sbom_import

Record = dict[str, Any]


class GraphEvidenceSections(TypedDict, total=False):
    scan_id: str
    agents: list[Record]
    blast_radius: list[Record]
    blast_radii: list[Record]
    scan_sources: list[str]
    model_provenance: list[Record]
    dataset_cards: Record
    serving_configs: list[Record]
    cloud_inventory: Record | list[Record]
    cis_benchmark: Record
    cis_benchmark_data: Record
    snowflake_cis_benchmark: Record
    snowflake_cis_benchmark_data: Record
    azure_cis_benchmark: Record
    azure_cis_benchmark_data: Record
    gcp_cis_benchmark: Record
    gcp_cis_benchmark_data: Record
    databricks_security: Record
    databricks_cis_benchmark: Record
    sast: Record
    sast_data: Record
    iac_findings: Record
    iac_findings_data: Record
    skill_audit: Record
    ai_inventory: Record
    runtime_session_graph: Record
    agentic_identity_graph: Record | list[Record]
    agentic_identity_graphs: Record | list[Record]
    audit_events: list[Record]
    runtime_incident_feedback: list[Record]
    runtime_incident_feedback_path: str
    toxic_combinations: Record | list[Record]
    aws_organization: Record
    cloud_audit_trail: Record | list[Record]
    snowflake_object_graph: Record
    snowflake_exfil_graph: Record
    snowflake_login_anomalies: Record
    snowflake_auth_posture: Record
    snowflake_services: Record
    snowflake_pipeline: Record
    snowflake_integrations: Record
    snowflake_external_data: Record
    snowflake_governance: Record
    snowflake_activity: Record
    identity_discovery: Record
    findings: list[Record]
    runtime_enforcement_events: list[Record]
    project_inventory: Record
    repo_trust: Record
    endpoint_inventory: Record
    source_id: str
    observed_at: str
    scan_timestamp: str
    codeowners: Record | list[Record]
    llm_cost_records: list[Record]


@dataclass(frozen=True)
class GraphBuildInput:
    """Only evidence consumed by graph stages; unrelated report output stays outside."""

    scan_id: str
    agents: list[Record]
    blast_radius: list[Record]
    data_source: str
    evidence: GraphEvidenceSections

    @classmethod
    def from_report(cls, report: Mapping[str, Any]) -> GraphBuildInput:
        evidence = cast(GraphEvidenceSections, {key: report[key] for key in GraphEvidenceSections.__annotations__ if key in report})
        agents = evidence.get("agents", [])
        blast = evidence.get("blast_radius", evidence.get("blast_radii", []))
        sources = evidence.get("scan_sources", [])
        inferred = "sbom" if agents and all(_is_sbom_import(agent) for agent in agents) else "mcp-scan"
        if agents and all(_is_repository_inventory(agent) for agent in agents):
            inferred = str(agents[0]["source"])
        return cls(evidence.get("scan_id", ""), agents, blast, sources[0] if sources else inferred, evidence)

    def report_sections(self) -> dict[str, Any]:
        """Compatibility view for overlays as they adopt section-specific inputs."""
        return dict(self.evidence)
