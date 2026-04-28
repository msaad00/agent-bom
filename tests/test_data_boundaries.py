from __future__ import annotations

from agent_bom.data_boundaries import describe_data_access_boundaries


def test_data_access_boundary_contract_pins_operator_controls() -> None:
    contract = describe_data_access_boundaries()

    assert contract["default_posture"]["self_hosted_first"] is True
    assert contract["default_posture"]["mandatory_hosted_control_plane"] is False
    assert contract["default_posture"]["hidden_telemetry"] is False
    assert contract["credential_evidence"] == {
        "config_env_vars": "names_only",
        "project_secret_scan": "redacted_labels_only",
        "stores_matched_value": False,
        "stores_matched_prefix": False,
        "validates_live_secret": False,
    }

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
