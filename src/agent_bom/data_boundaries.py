"""Machine-readable data access boundary contract."""

from __future__ import annotations


def describe_data_access_boundaries() -> dict[str, object]:
    """Return operator-facing data access and control boundaries."""
    return {
        "default_posture": {
            "self_hosted_first": True,
            "mandatory_hosted_control_plane": False,
            "hidden_telemetry": False,
            "default_network_mode": "operator_controlled",
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
        "network_boundaries": {
            "telemetry": "none",
            "vulnerability_enrichment": "operator_controlled",
            "cloud_provider_api_calls": "operator_credentials_only",
            "outbound_exports": "opt_in_only",
            "proxy_gateway_egress": "policy_controlled",
            "disable_controls": ["--offline", "--no-scan", "--sandbox-egress deny"],
        },
        "storage_boundaries": {
            "local_default": "local_files_and_stdout_only",
            "control_plane_default": "tenant_scoped_database_records",
            "secret_values": "never_stored",
            "secret_previews": "never_stored",
            "raw_artifact_exports": "operator_opt_in",
            "support_bundle_default": "customer_selected_redacted_evidence",
        },
        "auth_boundaries": {
            "api": ["api_key", "oidc_bearer", "saml_session_key", "trusted_reverse_proxy"],
            "authorization": ["rbac_role", "tenant_scope", "admin_required_for_key_lifecycle"],
            "scim": {
                "provisioning_authority": "scim_lifecycle_store",
                "runtime_auth_overlay": "enabled_when_configured",
                "tenant_source": "AGENT_BOM_SCIM_TENANT_ID",
                "payload_tenant_attributes_ignored": True,
            },
            "does_not_do": ["accept_untrusted_payload_tenant", "cross_tenant_lookup_without_auth_context"],
        },
        "deployment_boundaries": {
            "local": ["explicit_project_or_config_scope", "offline_mode_available", "inventory_only_mode_available"],
            "endpoint": ["mdm_command_scope", "fleet_summary_sync", "no_arbitrary_home_directory_scan"],
            "eks": ["network_policy", "read_only_cloud_identity", "tenant_scoped_control_plane"],
            "gateway": ["explicit_mcp_proxy_path", "policy_reload", "sandbox_and_rate_limit_controls"],
        },
        "extension_boundaries": {
            "connectors": {
                "default_posture": "agentless_read_only",
                "credential_scope": "operator_provided_connector_identity",
                "does_not_do": ["write_remote_systems", "escalate_permissions", "reuse_discovered_credentials"],
                "stronger_actions_require": ["explicit_connector_config", "rbac_permission", "audit_event"],
            },
            "plugins_and_skills": {
                "default_posture": "disabled_until_scoped_by_operator",
                "execution_boundary": "selected_path_or_registry_entry",
                "does_not_do": ["silent_install", "unscoped_filesystem_read", "unapproved_network_export"],
                "controls": ["--no-skill", "--skill-only", "signed_skill_verification"],
            },
            "roles": {
                "viewer": ["read_allowed_tenant_evidence"],
                "analyst": ["run_scans", "review_findings", "operate_non_admin_workflows"],
                "admin": ["manage_keys", "manage_policy", "manage_tenant_settings"],
                "principle": "least_privilege_by_default",
            },
        },
        "posture_vocabulary": {
            "capability_flags": ["rotation_tracking_supported"],
            "enforcement_flags": ["runtime_auth_enforced", "mtls_enforced"],
            "intentional_boundary_flags": ["payload_tenant_attributes_ignored"],
        },
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
        "redacted_evidence_context": {
            "allowed_context": [
                "tenant_id",
                "subject_id",
                "device_id",
                "agent_id",
                "server_name",
                "resource_id",
                "attack_path",
                "finding_type",
                "severity",
                "relative_path",
                "line_number",
            ],
            "never_show": [
                "matched_secret_value",
                "matched_secret_prefix",
                "env_var_value",
                "personal_file_contents",
                "full_prompt_payload",
                "raw_request_body",
                "raw_response_body",
            ],
            "display_model": "show_actor_asset_finding_and_attack_path_with_redacted_sensitive_value",
        },
    }
