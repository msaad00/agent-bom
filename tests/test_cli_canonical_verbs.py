"""Tests for the 5 canonical front-door verbs.

The CLI exposes a narrow human front door — connect → scan → graph → report,
plus `up` to run the platform locally — layered additively on top of the full
command catalog. These tests verify:

* All 5 verbs exist and delegate to the right implementation.
* `--help` leads with the front door ("Get started").
* Nothing was removed: existing commands/aliases still resolve and work.
"""

from __future__ import annotations

import click
from click.testing import CliRunner


def _runner() -> CliRunner:
    return CliRunner()


# ── The 5 verbs exist + are the front door ───────────────────────────────────


class TestFrontDoorExists:
    def test_top_level_help_leads_with_get_started(self):
        from agent_bom.cli import main

        r = _runner().invoke(main, ["--help"])
        assert r.exit_code == 0
        assert "Get started" in r.output
        # The Get started section precedes the Scanning section.
        assert r.output.index("Get started") < r.output.index("Scanning")
        assert "connect → scan → graph → report" in r.output

    def test_five_verbs_resolve(self):
        from agent_bom.cli import main

        for verb in ("connect", "scan", "graph", "report", "up"):
            cmd = main.get_command(None, verb)
            assert cmd is not None, f"missing front-door verb: {verb}"

    def test_visible_verbs_appear_in_help(self):
        from agent_bom.cli import main

        r = _runner().invoke(main, ["--help"])
        for verb in ("connect", "graph", "report", "up"):
            assert verb in r.output, f"{verb} not shown in --help"


# ── connect ──────────────────────────────────────────────────────────────────


class TestConnect:
    def test_connect_lists_sources(self):
        from agent_bom.cli import main

        r = _runner().invoke(main, ["connect"])
        assert r.exit_code == 0
        for source in ("aws", "azure", "gcp", "snowflake"):
            assert source in r.output

    def test_connect_help_states_read_only_and_needs(self):
        from agent_bom.cli import main

        r = _runner().invoke(main, ["connect", "--help"])
        assert r.exit_code == 0
        assert "read-only" in r.output.lower()
        # Each subcommand listed in help.
        for source in ("aws", "azure", "gcp", "snowflake"):
            assert source in r.output

    def test_connect_aws_prints_terraform_module_and_env(self):
        from agent_bom.cli import main

        r = _runner().invoke(main, ["connect", "aws"])
        assert r.exit_code == 0
        assert "deploy/terraform/connect-aws" in r.output
        assert "AGENT_BOM_AWS_INVENTORY" in r.output
        assert "agent-bom scan --aws" in r.output

    def test_connect_snowflake_prints_module(self):
        from agent_bom.cli import main

        r = _runner().invoke(main, ["connect", "snowflake"])
        assert r.exit_code == 0
        assert "deploy/terraform/connect-snowflake" in r.output

    def test_connect_reports_no_credentials_when_unset(self, monkeypatch):
        from agent_bom.cli import main

        for var in ("AWS_PROFILE", "AWS_ACCESS_KEY_ID", "AWS_ROLE_ARN", "AWS_WEB_IDENTITY_TOKEN_FILE"):
            monkeypatch.delenv(var, raising=False)
        r = _runner().invoke(main, ["connect", "aws"])
        assert r.exit_code == 0
        assert "No credentials detected" in r.output

    def test_connect_detects_present_credentials(self, monkeypatch):
        from agent_bom.cli import main

        monkeypatch.setenv("AWS_PROFILE", "abom-readonly")
        r = _runner().invoke(main, ["connect", "aws"])
        assert r.exit_code == 0
        assert "Credentials detected" in r.output
        assert "AWS_PROFILE" in r.output


# ── up (alias of serve) ──────────────────────────────────────────────────────


class TestUp:
    def test_up_help_points_at_serve_and_fullstack_compose(self):
        from agent_bom.cli import main

        r = _runner().invoke(main, ["up", "--help"])
        assert r.exit_code == 0
        assert "serve" in r.output
        assert "deploy/docker-compose.fullstack.yml" in r.output

    def test_up_inherits_serve_flags(self):
        from agent_bom.cli import main
        from agent_bom.cli._server import serve_cmd

        up_cmd = main.get_command(None, "up")
        serve_params = {p.name for p in serve_cmd.params}
        up_params = {p.name for p in up_cmd.params}
        assert serve_params <= up_params, "up dropped serve flags"

    def test_up_delegates_to_serve(self, monkeypatch):
        from agent_bom.cli._entry_points import make_up_command
        from agent_bom.cli._server import serve_cmd

        seen: dict[str, object] = {}

        def fake_serve(**kwargs: object) -> None:
            seen.update(kwargs)

        monkeypatch.setattr(serve_cmd, "callback", fake_serve)
        up_cmd = make_up_command(serve_cmd)
        r = _runner().invoke(up_cmd, ["--port", "9911"])
        assert r.exit_code == 0, r.output
        assert seen.get("port") == 9911


# ── Nothing removed: existing commands/aliases still work ─────────────────────


class TestNothingRemoved:
    def test_scan_alias_still_works(self):
        from agent_bom.cli import main

        r = _runner().invoke(main, ["scan", "--help"])
        assert r.exit_code == 0

    def test_agents_primary_command_still_works(self):
        from agent_bom.cli import main

        r = _runner().invoke(main, ["agents", "--help"])
        assert r.exit_code == 0

    def test_graph_command_unchanged(self):
        from agent_bom.cli import main
        from agent_bom.cli._analysis import graph_cmd

        assert main.get_command(None, "graph") is graph_cmd

    def test_report_group_unchanged(self):
        from agent_bom.cli import main
        from agent_bom.cli._report_group import report_group

        assert main.get_command(None, "report") is report_group

    def test_serve_command_still_registered(self):
        from agent_bom.cli import main
        from agent_bom.cli._server import serve_cmd

        assert main.get_command(None, "serve") is serve_cmd

    def test_existing_groups_intact(self):
        from agent_bom.cli import main

        for group in ("cloud", "mcp", "policy", "runtime", "identity", "cost", "report"):
            assert main.get_command(None, group) is not None, f"{group} removed"

    def test_up_is_distinct_object_from_serve(self):
        """`up` wraps serve but is its own command (so hiding/renaming serve is unaffected)."""
        from agent_bom.cli import main
        from agent_bom.cli._server import serve_cmd

        up_cmd = main.get_command(None, "up")
        assert isinstance(up_cmd, click.Command)
        assert up_cmd is not serve_cmd
