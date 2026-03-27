"""Tests for post-scan integration delivery reporting."""

from __future__ import annotations

from rich.console import Console

from agent_bom.cli.agents._context import ScanContext
from agent_bom.cli.agents._post import run_integrations


def _ctx() -> ScanContext:
    return ScanContext(con=Console(record=True, force_terminal=False), blast_radii=[object()])


def _kwargs(**overrides):
    base = {
        "quiet": False,
        "jira_url": None,
        "jira_user": None,
        "jira_token": None,
        "jira_project": None,
        "slack_webhook": "https://hooks.slack.com/services/test",
        "jira_discover": False,
        "servicenow_flag": False,
        "servicenow_instance": None,
        "servicenow_user": None,
        "servicenow_password": None,
        "slack_discover": False,
        "slack_bot_token": None,
        "vanta_token": None,
        "drata_token": None,
        "siem_type": None,
        "siem_url": None,
        "siem_token": None,
        "siem_index": None,
        "siem_format": "json",
        "clickhouse_url": None,
        "policy": None,
    }
    base.update(overrides)
    return base


def _blast(vuln_id: str, severity: str = "high", version: str = "1.0.0"):
    severity_obj = type("_Severity", (), {"value": severity})()
    vuln_obj = type("_Vuln", (), {"id": vuln_id, "severity": severity_obj, "fixed_version": None})()
    pkg_obj = type("_Pkg", (), {"name": "pkg", "version": version})()
    return type(
        "_Blast",
        (),
        {
            "vulnerability": vuln_obj,
            "package": pkg_obj,
            "risk_score": 8.0,
            "affected_agents": [],
            "affected_servers": [],
            "exposed_credentials": [],
            "owasp_tags": [],
            "owasp_mcp_tags": [],
            "atlas_tags": [],
            "nist_ai_rmf_tags": [],
        },
    )()


def test_run_integrations_reports_partial_slack_delivery(monkeypatch):
    ctx = _ctx()
    ctx.blast_radii = [_blast("CVE-1"), _blast("CVE-2", severity="medium", version="1.0.1")]

    async def _send_alert(url, finding):
        return finding["vulnerability_id"] == "CVE-1"

    async def _send_payload(url, payload):
        return False

    monkeypatch.setattr("agent_bom.integrations.slack.send_slack_alert", _send_alert)
    monkeypatch.setattr("agent_bom.integrations.slack.send_slack_payload", _send_payload)

    run_integrations(ctx, **_kwargs())
    out = ctx.con.export_text()
    assert "Slack: delivered 1/3 message(s); 2 failed" in out


def test_run_integrations_reports_zero_slack_delivery(monkeypatch):
    ctx = _ctx()
    ctx.blast_radii = [_blast("CVE-1")]

    async def _send_alert(url, finding):
        return False

    monkeypatch.setattr("agent_bom.integrations.slack.send_slack_alert", _send_alert)

    run_integrations(ctx, **_kwargs())
    out = ctx.con.export_text()
    assert "Slack: delivered 0/1 message(s)" in out
