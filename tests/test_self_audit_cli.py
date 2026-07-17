from __future__ import annotations

import json

from click.testing import CliRunner

from agent_bom.cli import main


def test_self_audit_renders_honest_human_report(monkeypatch):
    for key in ("AGENT_BOM_DEPLOYMENT_ENV", "AGENT_BOM_ENV", "ENVIRONMENT"):
        monkeypatch.delenv(key, raising=False)
    result = CliRunner().invoke(main, ["self-audit"])

    assert result.exit_code == 0
    assert "agent-bom self-audit" in result.output
    assert "API authentication enforced" in result.output
    assert "Tenant isolation enforced by the database" in result.output
    assert "Self-posture:" in result.output


def test_self_audit_flags_misconfigured_production(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DEPLOYMENT_ENV", "production")
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    result = CliRunner().invoke(main, ["self-audit"])

    assert result.exit_code == 0
    assert "at risk" in result.output
    assert "✗" in result.output


def test_self_audit_agent_mode_emits_valid_envelope_without_secret(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_DEPLOYMENT_ENV", "dev")
    monkeypatch.setenv("AGENT_BOM_AUDIT_HMAC_KEY", "top-secret-literal")
    result = CliRunner().invoke(main, ["--agent-mode", "self-audit"])

    assert result.exit_code == 0
    payload = json.loads(result.output)
    assert payload["command"] == "self-audit"
    assert payload["data"]["overall_status"] in {"hardened", "action_advised", "needs_review", "at_risk"}
    # The literal secret value must never appear in the machine-readable output.
    assert "top-secret-literal" not in result.output
