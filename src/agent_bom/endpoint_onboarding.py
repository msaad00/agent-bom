"""Managed endpoint onboarding helpers for proxy + fleet rollout."""

from __future__ import annotations

import json
import os
import stat
from pathlib import Path


def _write_text(path: Path, body: str, mode: int) -> Path:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(body, encoding="utf-8")
    os.chmod(path, mode)
    return path


def build_proxy_configure_command(
    *,
    log_dir: str,
    control_plane_url: str,
    control_plane_token: str | None,
    policy_refresh_seconds: int,
    audit_push_interval: int,
    policy_path: str | None,
    secure_defaults: bool,
    detect_credentials: bool,
    block_undeclared: bool,
    apply: bool,
) -> list[str]:
    """Build the canonical endpoint proxy bootstrap command."""
    cmd = [
        "agent-bom",
        "proxy-configure",
        "--log-dir",
        log_dir,
        "--control-plane-url",
        control_plane_url,
        "--policy-refresh-seconds",
        str(policy_refresh_seconds),
        "--audit-push-interval",
        str(audit_push_interval),
    ]
    if control_plane_token:
        cmd.extend(["--control-plane-token", control_plane_token])
    if policy_path:
        cmd.extend(["--policy", policy_path])
    if not secure_defaults:
        cmd.append("--no-secure-defaults")
    if detect_credentials:
        cmd.append("--detect-credentials")
    if block_undeclared:
        cmd.append("--block-undeclared")
    if apply:
        cmd.append("--apply")
    return cmd


def render_shell_bootstrap_script(proxy_configure_command: list[str], *, install_dir: str = "$HOME/.local/bin") -> str:
    """Render the managed shell bootstrap script."""
    command = " ".join(f'"{part}"' if " " in part else part for part in proxy_configure_command)
    return f"""#!/usr/bin/env sh
set -eu

if command -v uv >/dev/null 2>&1; then
  uv tool install --python 3.13 agent-bom >/dev/null 2>&1 || uv tool upgrade agent-bom
elif command -v pipx >/dev/null 2>&1; then
  pipx install agent-bom >/dev/null 2>&1 || pipx upgrade agent-bom
else
  python3 -m pip install --user pipx
  python3 -m pipx ensurepath
  PATH="{install_dir}:$PATH"
  python3 -m pipx install agent-bom >/dev/null 2>&1 || python3 -m pipx upgrade agent-bom
fi

mkdir -p "$HOME/.agent-bom/logs"
{command}
"""


def render_powershell_bootstrap_script(proxy_configure_command: list[str]) -> str:
    """Render the managed PowerShell bootstrap script."""
    quoted = " ".join(f'"{part}"' for part in proxy_configure_command)
    return f"""$ErrorActionPreference = "Stop"

try {{
    uv tool install --python 3.13 agent-bom | Out-Null
}} catch {{
    py -m pip install --user pipx | Out-Null
    py -m pipx ensurepath | Out-Null
    py -m pipx install agent-bom | Out-Null
}}

$logDir = Join-Path $HOME ".agent-bom\\logs"
New-Item -ItemType Directory -Force -Path $logDir | Out-Null
& {quoted}
"""


def render_fleet_sync_env(push_url: str, push_api_key: str | None) -> str:
    """Render a fleet-sync env file for the shipped timer/service assets."""
    lines = [f'AGENT_BOM_PUSH_URL="{push_url}"']
    if push_api_key:
        lines.append(f'AGENT_BOM_PUSH_API_KEY="{push_api_key}"')
    return "\n".join(lines) + "\n"


def render_jamf_install_script(*, bundle_subdir: str = "agent-bom-endpoint") -> str:
    """Render a Jamf-friendly shell installer wrapper."""
    return f"""#!/bin/sh
set -eu

BUNDLE_ROOT="/Library/Application Support/{bundle_subdir}"
mkdir -p "$BUNDLE_ROOT"
cp "$(dirname "$0")/../install-agent-bom-endpoint.sh" "$BUNDLE_ROOT/install-agent-bom-endpoint.sh"
chmod 755 "$BUNDLE_ROOT/install-agent-bom-endpoint.sh"
"$BUNDLE_ROOT/install-agent-bom-endpoint.sh"
"""


def render_kandji_install_script(*, bundle_subdir: str = "agent-bom-endpoint") -> str:
    """Render a Kandji custom-script wrapper."""
    return f"""#!/bin/sh
set -eu

BUNDLE_ROOT="/Library/Application Support/{bundle_subdir}"
mkdir -p "$BUNDLE_ROOT"
cp "$(dirname "$0")/../install-agent-bom-endpoint.sh" "$BUNDLE_ROOT/install-agent-bom-endpoint.sh"
chmod 755 "$BUNDLE_ROOT/install-agent-bom-endpoint.sh"
su "${{CURRENT_USER:-$(stat -f %Su /dev/console)}}" -c "$BUNDLE_ROOT/install-agent-bom-endpoint.sh"
"""


def render_intune_install_script(*, bundle_subdir: str = "agent-bom-endpoint") -> str:
    """Render an Intune remediation/install wrapper."""
    return f"""$ErrorActionPreference = "Stop"

$bundleRoot = Join-Path $env:ProgramData "{bundle_subdir}"
New-Item -ItemType Directory -Force -Path $bundleRoot | Out-Null
Copy-Item (Join-Path $PSScriptRoot "..\\install-agent-bom-endpoint.ps1") (Join-Path $bundleRoot "install-agent-bom-endpoint.ps1") -Force
& (Join-Path $bundleRoot "install-agent-bom-endpoint.ps1")
"""


def render_intune_detect_script() -> str:
    """Render a simple Intune detection script."""
    return """$ErrorActionPreference = "Stop"

if (Get-Command agent-bom -ErrorAction SilentlyContinue) {
    exit 0
}
exit 1
"""


def render_launch_agent_plist(push_url: str, push_api_key: str | None) -> str:
    """Render a launchd plist with concrete fleet-sync values."""
    token_xml = (
        f"""    <key>AGENT_BOM_PUSH_API_KEY</key>
    <string>{push_api_key}</string>
"""
        if push_api_key
        else ""
    )
    return f"""<?xml version="1.0" encoding="UTF-8"?>
<!DOCTYPE plist PUBLIC "-//Apple//DTD PLIST 1.0//EN" "http://www.apple.com/DTDs/PropertyList-1.0.dtd">
<plist version="1.0">
<dict>
  <key>Label</key>
  <string>com.agentbom.fleet-sync</string>
  <key>ProgramArguments</key>
  <array>
    <string>/bin/sh</string>
    <string>-lc</string>
    <string>$HOME/.local/share/agent-bom/agent-bom-fleet-sync.sh</string>
  </array>
  <key>EnvironmentVariables</key>
  <dict>
    <key>AGENT_BOM_PUSH_URL</key>
    <string>{push_url}</string>
{token_xml}  </dict>
  <key>RunAtLoad</key>
  <true/>
  <key>StartInterval</key>
  <integer>1800</integer>
  <key>StandardOutPath</key>
  <string>/tmp/agent-bom-fleet-sync.log</string>
  <key>StandardErrorPath</key>
  <string>/tmp/agent-bom-fleet-sync.log</string>
</dict>
</plist>
"""


def write_endpoint_onboarding_bundle(
    bundle_dir: Path,
    *,
    control_plane_url: str,
    control_plane_token: str | None,
    policy_refresh_seconds: int,
    audit_push_interval: int,
    policy_path: str | None,
    log_dir: str,
    secure_defaults: bool,
    detect_credentials: bool,
    block_undeclared: bool,
    push_url: str | None,
    push_api_key: str | None,
) -> dict[str, str]:
    """Write packaged endpoint onboarding artifacts to *bundle_dir*."""
    command = build_proxy_configure_command(
        log_dir=log_dir,
        control_plane_url=control_plane_url,
        control_plane_token=control_plane_token,
        policy_refresh_seconds=policy_refresh_seconds,
        audit_push_interval=audit_push_interval,
        policy_path=policy_path,
        secure_defaults=secure_defaults,
        detect_credentials=detect_credentials,
        block_undeclared=block_undeclared,
        apply=True,
    )
    artifacts: dict[str, str] = {}
    shell_path = _write_text(
        bundle_dir / "install-agent-bom-endpoint.sh",
        render_shell_bootstrap_script(command),
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR,
    )
    artifacts["shell_bootstrap"] = str(shell_path)
    powershell_path = _write_text(
        bundle_dir / "install-agent-bom-endpoint.ps1",
        render_powershell_bootstrap_script(command),
        stat.S_IRUSR | stat.S_IWUSR,
    )
    artifacts["powershell_bootstrap"] = str(powershell_path)

    jamf_path = _write_text(
        bundle_dir / "jamf" / "install-agent-bom-endpoint.sh",
        render_jamf_install_script(),
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR,
    )
    artifacts["jamf_install"] = str(jamf_path)

    kandji_path = _write_text(
        bundle_dir / "kandji" / "install-agent-bom-endpoint.sh",
        render_kandji_install_script(),
        stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR,
    )
    artifacts["kandji_install"] = str(kandji_path)

    intune_install_path = _write_text(
        bundle_dir / "intune" / "install-agent-bom-endpoint.ps1",
        render_intune_install_script(),
        stat.S_IRUSR | stat.S_IWUSR,
    )
    artifacts["intune_install"] = str(intune_install_path)

    intune_detect_path = _write_text(
        bundle_dir / "intune" / "detect-agent-bom-endpoint.ps1",
        render_intune_detect_script(),
        stat.S_IRUSR | stat.S_IWUSR,
    )
    artifacts["intune_detect"] = str(intune_detect_path)

    if push_url:
        env_path = _write_text(
            bundle_dir / "fleet-sync.env",
            render_fleet_sync_env(push_url, push_api_key),
            stat.S_IRUSR | stat.S_IWUSR,
        )
        artifacts["fleet_sync_env"] = str(env_path)
        plist_path = _write_text(
            bundle_dir / "com.agentbom.fleet-sync.plist",
            render_launch_agent_plist(push_url, push_api_key),
            stat.S_IRUSR | stat.S_IWUSR,
        )
        artifacts["launch_agent_plist"] = str(plist_path)

    summary = {
        "control_plane_url": control_plane_url,
        "log_dir": log_dir,
        "policy_path": policy_path,
        "policy_refresh_seconds": policy_refresh_seconds,
        "audit_push_interval": audit_push_interval,
        "secure_defaults": secure_defaults,
        "detect_credentials": detect_credentials,
        "block_undeclared": block_undeclared,
        "artifacts": artifacts,
    }
    summary_path = _write_text(
        bundle_dir / "endpoint-onboarding-summary.json",
        json.dumps(summary, indent=2),
        stat.S_IRUSR | stat.S_IWUSR,
    )
    artifacts["summary"] = str(summary_path)
    return artifacts
