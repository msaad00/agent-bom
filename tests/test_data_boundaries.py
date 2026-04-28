from __future__ import annotations

from agent_bom.data_boundaries import describe_data_access_boundaries


def test_data_access_boundary_contract_pins_operator_controls() -> None:
    contract = describe_data_access_boundaries()

    assert contract["default_posture"]["self_hosted_first"] is True
    assert contract["default_posture"]["mandatory_hosted_control_plane"] is False
    assert contract["default_posture"]["hidden_telemetry"] is False
    assert contract["default_posture"]["default_network_mode"] == "operator_controlled"
    assert contract["credential_evidence"] == {
        "config_env_vars": "names_only",
        "project_secret_scan": "redacted_labels_only",
        "stores_matched_value": False,
        "stores_matched_prefix": False,
        "validates_live_secret": False,
    }
    assert "device_id" in contract["redacted_evidence_context"]["allowed_context"]
    assert "attack_path" in contract["redacted_evidence_context"]["allowed_context"]
    assert "matched_secret_value" in contract["redacted_evidence_context"]["never_show"]
    assert "raw_request_body" in contract["redacted_evidence_context"]["never_show"]
    assert (
        contract["redacted_evidence_context"]["display_model"] == "show_actor_asset_finding_and_attack_path_with_redacted_sensitive_value"
    )
    assert contract["network_boundaries"]["telemetry"] == "none"
    assert contract["network_boundaries"]["outbound_exports"] == "opt_in_only"
    assert "--offline" in contract["network_boundaries"]["disable_controls"]
    assert contract["storage_boundaries"]["secret_values"] == "never_stored"
    assert contract["storage_boundaries"]["raw_artifact_exports"] == "operator_opt_in"
    assert contract["auth_boundaries"]["scim"]["payload_tenant_attributes_ignored"] is True
    assert contract["extension_boundaries"]["connectors"]["default_posture"] == "agentless_read_only"
    assert "reuse_discovered_credentials" in contract["extension_boundaries"]["connectors"]["does_not_do"]
    assert contract["extension_boundaries"]["plugins_and_skills"]["default_posture"] == "disabled_until_scoped_by_operator"
    assert "--no-skill" in contract["extension_boundaries"]["plugins_and_skills"]["controls"]
    assert contract["extension_boundaries"]["roles"]["principle"] == "least_privilege_by_default"
    assert "payload_tenant_attributes_ignored" in contract["posture_vocabulary"]["intentional_boundary_flags"]

    controls = contract["operator_controls"]
    assert controls["scope_preview"] == "agent-bom agents --dry-run"
    assert controls["disable_vulnerability_network"] == "--offline"
    assert controls["disable_scan_network_and_vuln_lookup"] == "--no-scan"

    modes = {mode["mode"]: mode for mode in contract["modes"]}
    assert modes["local_discovery"]["does_not_read"] == ["env_var_values", "arbitrary_personal_files"]
    assert "matched_secret_prefix" in modes["project_scan"]["does_not_store"]
    assert modes["cloud_inventory"]["required_identity"] == "read_only"
    assert "cross_tenant_access" in modes["api_ui_control_plane"]["does_not_do"]
    assert modes["proxy_gateway"]["does_not_read"] == ["unrelated_application_traffic"]
