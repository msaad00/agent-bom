from __future__ import annotations

import importlib.util
from pathlib import Path

from agent_bom.endpoint_onboarding import (
    render_intune_detect_script,
    render_intune_install_script,
    render_jamf_install_script,
    render_kandji_install_script,
)


def _load_render_formula():
    script_path = Path(__file__).parent.parent / "scripts" / "render_homebrew_formula.py"
    spec = importlib.util.spec_from_file_location("render_homebrew_formula", script_path)
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module.render_formula


def test_render_jamf_install_script_reuses_bundle_bootstrap():
    body = render_jamf_install_script()
    assert "/Library/Application Support/agent-bom-endpoint" in body
    assert "install-agent-bom-endpoint.sh" in body


def test_render_kandji_install_script_runs_as_console_user():
    body = render_kandji_install_script()
    assert "CURRENT_USER" in body
    assert "install-agent-bom-endpoint.sh" in body


def test_render_intune_scripts_are_operator_ready():
    install_body = render_intune_install_script()
    detect_body = render_intune_detect_script()
    assert "ProgramData" in install_body
    assert "Get-Command agent-bom" in detect_body


def test_render_homebrew_formula_embeds_release_metadata():
    render_formula = _load_render_formula()
    body = render_formula(
        version="0.81.0",
        url="https://example.invalid/agent-bom-0.81.0.tar.gz",
        sha256="a" * 64,
    )
    assert 'url "https://example.invalid/agent-bom-0.81.0.tar.gz"' in body
    assert 'sha256 "' + ("a" * 64) + '"' in body
    assert 'assert_match "0.81.0"' in body


def test_packaged_endpoint_rollout_assets_exist():
    root = Path(__file__).parent.parent / "deploy" / "endpoints"
    assert (root / "jamf" / "install-agent-bom-endpoint.sh").exists()
    assert (root / "intune" / "install-agent-bom-endpoint.ps1").exists()
    assert (root / "intune" / "detect-agent-bom-endpoint.ps1").exists()
    assert (root / "kandji" / "install-agent-bom-endpoint.sh").exists()
