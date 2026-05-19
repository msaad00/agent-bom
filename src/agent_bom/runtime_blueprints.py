"""Canonical runtime role/profile blueprints for agent and MCP governance."""

from __future__ import annotations

from collections import Counter
from dataclasses import asdict, dataclass
from datetime import datetime, timezone
from typing import Any


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


_CATEGORY_KEYWORDS: tuple[tuple[str, tuple[str, ...]], ...] = (
    ("payment_write", ("payment", "payroll", "bank", "invoice_update")),
    ("production_write", ("deploy", "rollback", "production", "prod_write")),
    ("database_write", ("insert", "update", "delete", "query_write", "write_query")),
    ("repo_write", ("write", "edit", "commit", "push", "merge", "create_file", "apply_patch")),
    ("credential_export", ("credential", "secret", "token", "env", "key", "vault")),
    ("policy_write", ("policy", "firewall", "shield", "admin")),
    ("tenant_admin", ("tenant", "scim", "saml", "oidc", "entitlement")),
    ("threat_intel", ("intel", "advisory", "cve", "ghsa", "osv", "kev", "epss")),
    ("finding_read", ("finding", "sarif", "vulnerability", "vuln")),
    ("graph_query", ("graph", "exposure", "path", "blast", "lineage")),
    ("audit_read", ("audit", "trace", "integrity", "evidence")),
    ("evidence_export", ("export", "report", "evidence", "bundle")),
    ("package_scan", ("package", "sbom", "dependency", "scan", "image")),
    ("model_registry_read", ("model", "huggingface", "ollama", "mlflow")),
    ("dataset_read", ("dataset", "experiment", "feature")),
    ("runtime_trace", ("runtime", "proxy", "gateway", "session", "span")),
    ("mcp_discovery", ("mcp", "tool", "server", "inventory", "manifest")),
    ("business_app_read", ("salesforce", "snowflake", "jira", "servicenow", "slack")),
    ("report_generate", ("summary", "brief", "report", "dashboard")),
    ("ticket_create", ("ticket", "issue", "case")),
    ("local_runtime", ("shell", "terminal", "docker", "process", "exec")),
    ("repo_read", ("read", "list", "search", "grep", "git", "repo", "file")),
)


def classify_runtime_tool(tool_name: str) -> str:
    """Map a runtime tool name to a blueprint category.

    Runtime events often carry only a tool name, not a formal capability map.
    This conservative classifier keeps drift checks deterministic and
    explainable until deployments attach richer tool metadata.
    """
    normalized = tool_name.strip().lower().replace("-", "_").replace("/", "_").replace(".", "_")
    if not normalized:
        return "unknown"
    for category, keywords in _CATEGORY_KEYWORDS:
        if any(keyword in normalized for keyword in keywords):
            return category
    return "unknown"


def _iter_runtime_tools(production_index: dict[str, Any]) -> Counter[str]:
    traffic = production_index.get("traffic")
    if not isinstance(traffic, dict):
        return Counter()
    calls_by_tool = traffic.get("calls_by_tool")
    if isinstance(calls_by_tool, dict):
        return Counter({str(tool): int(count) for tool, count in calls_by_tool.items() if str(tool).strip()})
    top_tools = traffic.get("top_tools")
    counts: Counter[str] = Counter()
    if isinstance(top_tools, list):
        for item in top_tools:
            if isinstance(item, dict):
                name = str(item.get("name") or "").strip()
                if name:
                    counts[name] += int(item.get("count") or 0)
    return counts


def _as_str_set(value: object) -> set[str]:
    if not isinstance(value, list | tuple | set):
        return set()
    return {str(item) for item in value}


def _as_int(value: object, default: int = 0) -> int:
    try:
        return int(value)  # type: ignore[call-overload]
    except (TypeError, ValueError):
        return default


def evaluate_runtime_blueprint_drift(
    blueprint_id: str,
    production_index: dict[str, Any],
    *,
    tenant_id: str = "default",
) -> dict[str, object]:
    """Compare live runtime posture with an approved role/profile blueprint."""
    blueprint = runtime_role_blueprint(blueprint_id)
    if blueprint is None:
        raise KeyError(blueprint_id)

    allowed = _as_str_set(blueprint.get("allowed_tool_categories"))
    restricted = _as_str_set(blueprint.get("restricted_tool_categories"))
    approval_required = _as_str_set(blueprint.get("approval_required_for"))
    tool_counts = _iter_runtime_tools(production_index)
    category_counts: Counter[str] = Counter()
    violations: list[dict[str, object]] = []
    warnings: list[dict[str, object]] = []

    for tool_name, count in sorted(tool_counts.items()):
        category = classify_runtime_tool(tool_name)
        category_counts[category] += count
        if category in restricted:
            violations.append(
                {
                    "type": "restricted_tool_category",
                    "severity": "high",
                    "tool_name": tool_name,
                    "category": category,
                    "observed_count": count,
                    "recommendation": "Block this tool for the selected blueprint or move the agent to a higher-privilege blueprint.",
                }
            )
        elif category in approval_required:
            warnings.append(
                {
                    "type": "approval_required_tool_category",
                    "severity": "medium",
                    "tool_name": tool_name,
                    "category": category,
                    "observed_count": count,
                    "recommendation": "Require an approval trace before allowing this action for the selected blueprint.",
                }
            )
        elif category not in allowed and category != "unknown":
            warnings.append(
                {
                    "type": "outside_allowed_tool_category",
                    "severity": "medium",
                    "tool_name": tool_name,
                    "category": category,
                    "observed_count": count,
                    "recommendation": "Review whether this category belongs in the blueprint or should be blocked.",
                }
            )
        elif category == "unknown":
            warnings.append(
                {
                    "type": "unclassified_tool",
                    "severity": "low",
                    "tool_name": tool_name,
                    "category": category,
                    "observed_count": count,
                    "recommendation": "Attach a tool category annotation so drift evaluation can make a stronger decision.",
                }
            )

    authorization = production_index.get("authorization_trace")
    approval_count = 0
    data_filter_count = 0
    if isinstance(authorization, dict):
        approval_count = _as_int(authorization.get("approval_required"))
        data_filter_count = _as_int(authorization.get("data_filter_applied"))
    if approval_count:
        warnings.append(
            {
                "type": "runtime_approval_required",
                "severity": "medium",
                "observed_count": approval_count,
                "recommendation": "Preserve approval evidence and confirm the selected blueprint allows this workflow.",
            }
        )
    if data_filter_count:
        warnings.append(
            {
                "type": "runtime_data_filter_applied",
                "severity": "low",
                "observed_count": data_filter_count,
                "recommendation": "Retain redaction evidence for audit and verify filters match the blueprint.",
            }
        )

    raw_traffic = production_index.get("traffic")
    traffic = raw_traffic if isinstance(raw_traffic, dict) else {}
    total_tool_calls = _as_int(traffic.get("total_tool_calls"), sum(tool_counts.values()))
    high_weight = sum(_as_int(item.get("observed_count"), 1) for item in violations if item.get("severity") == "high")
    medium_weight = sum(_as_int(item.get("observed_count"), 1) for item in warnings if item.get("severity") == "medium")
    drift_score = 0.0 if not total_tool_calls else min(1.0, (high_weight + medium_weight * 0.5) / max(total_tool_calls, 1))
    status = "no_runtime_activity" if total_tool_calls == 0 else ("drift_detected" if violations else "review" if warnings else "aligned")

    return {
        "schema_version": "runtime.blueprint_drift.v1",
        "tenant_id": tenant_id or "default",
        "blueprint_id": blueprint["blueprint_id"],
        "evaluated_at": datetime.now(timezone.utc).isoformat(),
        "status": status,
        "drift_score": round(drift_score, 4),
        "runtime_status": production_index.get("status", "unknown"),
        "observed": {
            "total_tool_calls": total_tool_calls,
            "categories": dict(sorted(category_counts.items())),
            "tools": [
                {"name": name, "category": classify_runtime_tool(name), "count": count} for name, count in sorted(tool_counts.items())
            ],
        },
        "blueprint": blueprint,
        "violations": violations,
        "warnings": warnings,
        "retention": "metadata_only",
    }


__all__ = [
    "RuntimeRoleBlueprint",
    "classify_runtime_tool",
    "evaluate_runtime_blueprint_drift",
    "runtime_role_blueprint",
    "runtime_role_blueprints",
]
