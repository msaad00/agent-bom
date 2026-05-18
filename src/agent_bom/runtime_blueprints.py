"""Canonical runtime role/profile blueprints for agent and MCP governance."""

from __future__ import annotations

from dataclasses import asdict, dataclass


@dataclass(frozen=True)
class RuntimeRoleBlueprint:
    blueprint_id: str
    label: str
    description: str
    intended_users: tuple[str, ...]
    allowed_tool_categories: tuple[str, ...]
    restricted_tool_categories: tuple[str, ...]
    approval_required_for: tuple[str, ...]
    default_decision: str
    retention_mode: str
    evidence_required: tuple[str, ...]

    def to_dict(self) -> dict[str, object]:
        return asdict(self)


_BLUEPRINTS: tuple[RuntimeRoleBlueprint, ...] = (
    RuntimeRoleBlueprint(
        blueprint_id="developer",
        label="Developer",
        description="Build and debug code with bounded repository, package, and local development access.",
        intended_users=("software_engineer", "platform_engineer"),
        allowed_tool_categories=("repo_read", "repo_write", "package_scan", "local_runtime", "mcp_discovery"),
        restricted_tool_categories=("production_write", "payment_data", "privileged_identity"),
        approval_required_for=("production_deploy", "credential_export", "database_write"),
        default_decision="warn",
        retention_mode="metadata_only",
        evidence_required=("tool_name", "workspace", "package_or_resource", "decision", "trace_id"),
    ),
    RuntimeRoleBlueprint(
        blueprint_id="security_analyst",
        label="Security Analyst",
        description="Investigate findings, ExposurePaths, threat intel, and runtime evidence without direct production mutation.",
        intended_users=("appsec", "soc_analyst", "incident_responder"),
        allowed_tool_categories=("finding_read", "graph_query", "threat_intel", "audit_read", "evidence_export"),
        restricted_tool_categories=("production_write", "credential_export", "customer_data_write"),
        approval_required_for=("remediation_action", "evidence_pack_export", "tenant_scope_change"),
        default_decision="allow",
        retention_mode="redacted",
        evidence_required=("finding_id", "exposure_path_id", "source_id", "decision", "audit_chain_ref"),
    ),
    RuntimeRoleBlueprint(
        blueprint_id="mlops",
        label="MLOps",
        description="Operate model, dataset, feature, and agent-runtime surfaces with explicit provenance boundaries.",
        intended_users=("ml_engineer", "data_platform_engineer"),
        allowed_tool_categories=("model_registry_read", "dataset_read", "runtime_trace", "experiment_read", "mcp_discovery"),
        restricted_tool_categories=("training_data_export", "model_delete", "privileged_identity"),
        approval_required_for=("model_publish", "dataset_export", "production_endpoint_write"),
        default_decision="warn",
        retention_mode="metadata_only",
        evidence_required=("model_ref", "dataset_ref", "tool_name", "decision", "trace_id"),
    ),
    RuntimeRoleBlueprint(
        blueprint_id="finance",
        label="Finance",
        description="Use approved business-system tools with strict data filtering and write approvals.",
        intended_users=("finance_operator", "business_analyst"),
        allowed_tool_categories=("business_app_read", "report_generate", "ticket_create"),
        restricted_tool_categories=("payment_write", "payroll_export", "customer_pii_export", "privileged_identity"),
        approval_required_for=("payment_write", "invoice_update", "bank_data_export"),
        default_decision="block",
        retention_mode="redacted",
        evidence_required=("business_system", "record_type", "data_filter", "decision", "approver_ref"),
    ),
    RuntimeRoleBlueprint(
        blueprint_id="admin",
        label="Admin",
        description="Manage runtime policies, credentials, integrations, and tenant controls with full audit evidence.",
        intended_users=("security_admin", "platform_admin"),
        allowed_tool_categories=("policy_write", "integration_manage", "credential_reference_manage", "tenant_admin"),
        restricted_tool_categories=("raw_secret_read", "unredacted_prompt_export"),
        approval_required_for=("policy_disable", "tenant_delete", "audit_retention_change"),
        default_decision="warn",
        retention_mode="redacted",
        evidence_required=("actor", "resource", "policy_id", "decision", "audit_chain_ref"),
    ),
)


def runtime_role_blueprints() -> list[dict[str, object]]:
    return [blueprint.to_dict() for blueprint in _BLUEPRINTS]


def runtime_role_blueprint(blueprint_id: str) -> dict[str, object] | None:
    normalized = blueprint_id.strip().lower().replace("-", "_")
    for blueprint in _BLUEPRINTS:
        if blueprint.blueprint_id == normalized:
            return blueprint.to_dict()
    return None


__all__ = ["RuntimeRoleBlueprint", "runtime_role_blueprint", "runtime_role_blueprints"]
