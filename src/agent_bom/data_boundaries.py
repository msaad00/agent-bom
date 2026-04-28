"""Machine-readable data access boundary contract."""

from __future__ import annotations


def describe_data_access_boundaries() -> dict[str, object]:
    """Return operator-facing data access and control boundaries."""
    return {
        "default_posture": {
            "self_hosted_first": True,
            "mandatory_hosted_control_plane": False,
            "hidden_telemetry": False,
            "credential_values_stored": False,
            "credential_values_transmitted": False,
            "credential_values_validated_by_default": False,
            "support_access_default": "customer_selected",
        },
        "modes": [
            {
                "mode": "local_discovery",
                "reads": ["known_agent_mcp_config_paths", "server_name", "command", "args", "urls", "env_var_names"],
                "does_not_read": ["env_var_values", "arbitrary_personal_files"],
                "operator_controls": ["--dry-run", "--inventory", "--project", "--config-dir", "--no-scan", "--offline"],
            },
            {
                "mode": "project_scan",
                "reads": ["operator_selected_project_scope"],
                "evidence": ["relative_path", "line_number_when_needed", "finding_type", "severity", "redacted_label"],
                "does_not_store": ["matched_secret_value", "matched_secret_prefix"],
                "operator_controls": ["--project", "--no-skill", "--skill-only", "--offline"],
            },
            {
                "mode": "cloud_inventory",
                "reads": ["metadata_available_to_operator_provided_identity"],
                "required_identity": "read_only",
                "does_not_do": ["mutate_cloud_resources", "broaden_iam_permissions", "use_discovered_credentials"],
                "operator_controls": ["provider_flags", "scoped_provider_credentials", "--dry-run"],
            },
            {
                "mode": "endpoint_fleet",
                "reads": ["generated_inventory", "operator_selected_scan_summary"],
                "does_not_read": ["browser_history", "unrelated_user_documents", "arbitrary_home_directory_content"],
                "operator_controls": ["mdm_command_scope", "--dry-run", "--no-scan", "--offline"],
            },
            {
                "mode": "api_ui_control_plane",
                "reads": ["tenant_scoped_jobs", "findings", "fleet", "graph", "policy", "audit", "auth_state"],
                "controls": ["api_key_scope", "rbac_role", "tenant_scope", "audit_log", "retention_policy"],
                "does_not_do": ["cross_tenant_access", "silent_vendor_backhaul"],
            },
            {
                "mode": "proxy_gateway",
                "reads": ["explicitly_proxied_mcp_requests", "explicitly_proxied_mcp_responses"],
                "controls": ["policy_mode", "redaction", "audit_sink", "rate_limit", "sandbox"],
                "does_not_read": ["unrelated_application_traffic"],
            },
        ],
        "operator_controls": {
            "scope_preview": "agent-bom agents --dry-run",
            "inventory_only": "--inventory <file>",
            "project_scope": "--project <dir>",
            "config_scope": "--config-dir <dir>",
            "disable_vulnerability_network": "--offline",
            "disable_scan_network_and_vuln_lookup": "--no-scan",
            "disable_skill_scan": "--no-skill",
            "isolate_skill_scan": "--skill-only",
            "api_access_control": ["api_keys", "rbac_roles", "tenant_scope", "trusted_proxy_attestation"],
            "optional_exports": ["siem", "otel", "slack", "jira", "vanta", "drata", "customer_archive"],
        },
        "credential_evidence": {
            "config_env_vars": "names_only",
            "project_secret_scan": "redacted_labels_only",
            "stores_matched_value": False,
            "stores_matched_prefix": False,
            "validates_live_secret": False,
        },
    }
