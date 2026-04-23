from __future__ import annotations

import json
from pathlib import Path

from agent_bom.endpoint_onboarding import build_proxy_configure_command, write_endpoint_onboarding_bundle


def test_build_proxy_configure_command_includes_control_plane_flags():
    cmd = build_proxy_configure_command(
        log_dir="~/.agent-bom/logs",
        control_plane_url="https://agent-bom.internal.example.com",
        control_plane_token="token-123",
        policy_refresh_seconds=45,
        audit_push_interval=15,
        policy_path="/tmp/policy.json",
        secure_defaults=True,
        detect_credentials=False,
        block_undeclared=False,
        apply=True,
    )
    assert cmd[:4] == ["agent-bom", "proxy-configure", "--log-dir", "~/.agent-bom/logs"]
    assert "--control-plane-url" in cmd
    assert "--control-plane-token" in cmd
    assert "--policy" in cmd
    assert "--apply" in cmd


def test_write_endpoint_onboarding_bundle_writes_artifacts(tmp_path):
    artifacts = write_endpoint_onboarding_bundle(
        tmp_path,
        control_plane_url="https://agent-bom.internal.example.com",
        control_plane_token="token-123",
        policy_refresh_seconds=30,
        audit_push_interval=10,
        policy_path=None,
        log_dir="~/.agent-bom/logs",
        secure_defaults=True,
        detect_credentials=False,
        block_undeclared=False,
        push_url="https://agent-bom.internal.example.com/v1/fleet/sync",
        push_api_key="fleet-key",
        source_id="device-acme-001",
        enrollment_name="corp-laptop-rollout",
        owner="platform-security",
        environment="production",
        tags=["mdm", "developer-endpoint"],
        mdm_provider="jamf",
    )
    assert set(artifacts) >= {
        "shell_bootstrap",
        "powershell_bootstrap",
        "jamf_install",
        "kandji_install",
        "intune_install",
        "intune_detect",
        "fleet_sync_env",
        "launch_agent_plist",
        "enrollment_manifest",
        "summary",
    }
    shell_script = Path(artifacts["shell_bootstrap"]).read_text()
    assert "proxy-configure" in shell_script
    assert "--control-plane-url" in shell_script
    env_file = Path(artifacts["fleet_sync_env"]).read_text()
    assert "AGENT_BOM_PUSH_URL" in env_file
    assert "AGENT_BOM_PUSH_API_KEY" in env_file
    assert 'AGENT_BOM_PUSH_SOURCE_ID="device-acme-001"' in env_file
    assert 'AGENT_BOM_PUSH_ENROLLMENT_NAME="corp-laptop-rollout"' in env_file
    assert 'AGENT_BOM_PUSH_OWNER="platform-security"' in env_file
    assert 'AGENT_BOM_PUSH_ENVIRONMENT="production"' in env_file
    assert 'AGENT_BOM_PUSH_TAGS="developer-endpoint,mdm"' in env_file
    assert 'AGENT_BOM_PUSH_MDM_PROVIDER="jamf"' in env_file
    jamf_script = Path(artifacts["jamf_install"]).read_text()
    assert "install-agent-bom-endpoint.sh" in jamf_script
    intune_script = Path(artifacts["intune_install"]).read_text()
    assert "install-agent-bom-endpoint.ps1" in intune_script
    plist = Path(artifacts["launch_agent_plist"]).read_text()
    assert "AGENT_BOM_PUSH_ENROLLMENT_NAME" in plist
    assert "AGENT_BOM_PUSH_MDM_PROVIDER" in plist
    enrollment = json.loads(Path(artifacts["enrollment_manifest"]).read_text())
    assert enrollment["enrollment_name"] == "corp-laptop-rollout"
    assert enrollment["owner"] == "platform-security"
    assert enrollment["environment"] == "production"
    assert enrollment["mdm_provider"] == "jamf"
    assert enrollment["device_identity"]["source_id"] == "device-acme-001"
    assert enrollment["device_identity"]["source_id_strategy"] == "configured"
    summary = json.loads(Path(artifacts["summary"]).read_text())
    assert summary["control_plane_url"] == "https://agent-bom.internal.example.com"
    assert summary["source_id"] == "device-acme-001"
    assert summary["mdm_provider"] == "jamf"
    assert summary["artifacts"]["shell_bootstrap"] == artifacts["shell_bootstrap"]
