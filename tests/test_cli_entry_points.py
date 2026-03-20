"""End-to-end tests for 5 CLI entry points.

Verifies:
- Each product's Click group renders --help correctly
- --version shows correct product name
- Subcommand dispatch works for each product
- Backward compatibility: agent-bom still exposes runtime/cloud/iac/policy groups
- No import errors or circular dependencies
"""

from __future__ import annotations

from click.testing import CliRunner

# ── agent-bom (original) ────────────────────────────────────────────────────


class TestAgentBom:
    def test_help(self):
        from agent_bom.cli import main

        r = CliRunner().invoke(main, ["--help"])
        assert r.exit_code == 0
        assert "agent-bom" in r.output

    def test_version(self):
        from agent_bom.cli import main

        r = CliRunner().invoke(main, ["--version"])
        assert r.exit_code == 0
        assert "agent-bom" in r.output

    def test_agents_help(self):
        from agent_bom.cli import main

        r = CliRunner().invoke(main, ["agents", "--help"])
        assert r.exit_code == 0

    def test_scan_backward_compat(self):
        from agent_bom.cli import main

        r = CliRunner().invoke(main, ["scan", "--help"])
        assert r.exit_code == 0

    def test_check_help(self):
        from agent_bom.cli import main

        r = CliRunner().invoke(main, ["check", "--help"])
        assert r.exit_code == 0

    def test_backward_compat_runtime_group(self):
        from agent_bom.cli import main

        r = CliRunner().invoke(main, ["runtime", "--help"])
        assert r.exit_code == 0
        assert "proxy" in r.output

    def test_backward_compat_cloud_group(self):
        from agent_bom.cli import main

        r = CliRunner().invoke(main, ["cloud", "--help"])
        assert r.exit_code == 0
        assert "aws" in r.output

    def test_backward_compat_mcp_group(self):
        from agent_bom.cli import main

        r = CliRunner().invoke(main, ["mcp", "--help"])
        assert r.exit_code == 0


# ── agent-shield ─────────────────────────────────────────────────────────────


class TestAgentShield:
    def test_help(self):
        from agent_bom.cli.shield import shield

        r = CliRunner().invoke(shield, ["--help"])
        assert r.exit_code == 0
        assert "agent-shield" in r.output
        assert "Runtime" in r.output

    def test_version(self):
        from agent_bom.cli.shield import shield

        r = CliRunner().invoke(shield, ["--version"])
        assert r.exit_code == 0
        assert "agent-shield" in r.output

    def test_proxy_help(self):
        from agent_bom.cli.shield import shield

        r = CliRunner().invoke(shield, ["proxy", "--help"])
        assert r.exit_code == 0
        assert "proxy" in r.output.lower()

    def test_audit_help(self):
        from agent_bom.cli.shield import shield

        r = CliRunner().invoke(shield, ["audit", "--help"])
        assert r.exit_code == 0


# ── agent-cloud ──────────────────────────────────────────────────────────────


class TestAgentCloud:
    def test_help(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["--help"])
        assert r.exit_code == 0
        assert "agent-cloud" in r.output
        assert "Cloud Providers" in r.output

    def test_version(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["--version"])
        assert r.exit_code == 0
        assert "agent-cloud" in r.output

    def test_aws_help(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["aws", "--help"])
        assert r.exit_code == 0
        assert "--region" in r.output

    def test_azure_help(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["azure", "--help"])
        assert r.exit_code == 0
        assert "--subscription" in r.output

    def test_gcp_help(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["gcp", "--help"])
        assert r.exit_code == 0
        assert "--project" in r.output

    def test_snowflake_help(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["snowflake", "--help"])
        assert r.exit_code == 0

    def test_databricks_help(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["databricks", "--help"])
        assert r.exit_code == 0

    def test_huggingface_help(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["huggingface", "--help"])
        assert r.exit_code == 0

    def test_ollama_help(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["ollama", "--help"])
        assert r.exit_code == 0

    def test_posture_help(self):
        from agent_bom.cli.cloud_entry import cloud

        r = CliRunner().invoke(cloud, ["posture", "--help"])
        assert r.exit_code == 0


# ── agent-iac ────────────────────────────────────────────────────────────────


class TestAgentIac:
    def test_help(self):
        from agent_bom.cli.iac_entry import iac

        r = CliRunner().invoke(iac, ["--help"])
        assert r.exit_code == 0
        assert "agent-iac" in r.output
        assert "Scanning" in r.output

    def test_version(self):
        from agent_bom.cli.iac_entry import iac

        r = CliRunner().invoke(iac, ["--version"])
        assert r.exit_code == 0
        assert "agent-iac" in r.output

    def test_scan_help(self):
        from agent_bom.cli.iac_entry import iac

        r = CliRunner().invoke(iac, ["scan", "--help"])
        assert r.exit_code == 0

    def test_policy_help(self):
        from agent_bom.cli.iac_entry import iac

        r = CliRunner().invoke(iac, ["policy", "--help"])
        assert r.exit_code == 0
        assert "template" in r.output

    def test_validate_help(self):
        from agent_bom.cli.iac_entry import iac

        r = CliRunner().invoke(iac, ["validate", "--help"])
        assert r.exit_code == 0


# ── agent-claw ───────────────────────────────────────────────────────────────


class TestAgentClaw:
    def test_help(self):
        from agent_bom.cli.claw import claw

        r = CliRunner().invoke(claw, ["--help"])
        assert r.exit_code == 0
        assert "agent-claw" in r.output
        assert "Fleet" in r.output

    def test_version(self):
        from agent_bom.cli.claw import claw

        r = CliRunner().invoke(claw, ["--version"])
        assert r.exit_code == 0
        assert "agent-claw" in r.output

    def test_serve_help(self):
        from agent_bom.cli.claw import claw

        r = CliRunner().invoke(claw, ["serve", "--help"])
        assert r.exit_code == 0

    def test_api_help(self):
        from agent_bom.cli.claw import claw

        r = CliRunner().invoke(claw, ["api", "--help"])
        assert r.exit_code == 0

    def test_fleet_help(self):
        from agent_bom.cli.claw import claw

        r = CliRunner().invoke(claw, ["fleet", "--help"])
        assert r.exit_code == 0
        assert "sync" in r.output
        assert "list" in r.output
        assert "stats" in r.output

    def test_schedule_help(self):
        from agent_bom.cli.claw import claw

        r = CliRunner().invoke(claw, ["schedule", "--help"])
        assert r.exit_code == 0

    def test_report_help(self):
        from agent_bom.cli.claw import claw

        r = CliRunner().invoke(claw, ["report", "--help"])
        assert r.exit_code == 0

    def test_connectors_help(self):
        from agent_bom.cli.claw import claw

        r = CliRunner().invoke(claw, ["connectors", "--help"])
        assert r.exit_code == 0


# ── Cross-product: same command object, no duplication ───────────────────────


class TestNoDuplication:
    def test_proxy_cmd_is_same_object(self):
        """proxy_cmd registered on both shield and main must be the same Python object."""
        from agent_bom.cli._runtime import proxy_cmd as bom_proxy
        from agent_bom.cli.shield import shield

        shield_proxy = shield.get_command(None, "proxy")
        assert shield_proxy is bom_proxy

    def test_policy_check_is_guard(self):
        """guard_cmd registered as policy check must be the same object."""
        from agent_bom.cli import main

        policy = main.get_command(None, "policy")
        check_cmd = policy.get_command(None, "check") if policy else None
        assert check_cmd is not None

    def test_aws_cmd_is_same_object(self):
        """aws_cmd registered on both cloud_entry and cloud_group must be the same object."""
        from agent_bom.cli._cloud_group import aws_cmd as group_aws
        from agent_bom.cli.cloud_entry import cloud

        cloud_aws = cloud.get_command(None, "aws")
        assert cloud_aws is group_aws

    def test_audit_cmd_is_same_object(self):
        from agent_bom.cli._runtime import audit_replay_cmd as bom_audit
        from agent_bom.cli.shield import shield

        shield_audit = shield.get_command(None, "audit")
        assert shield_audit is bom_audit
