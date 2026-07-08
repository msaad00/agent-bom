"""CLI clarity cleanup: canonical scan verb, tiered flags, format dedup.

Covers the back-compat guarantees and the new help tiering introduced by the
"CLI front door" cleanup:

* ``scan`` is the visible canonical verb; ``agents`` stays as a hidden alias.
* ``scan --help`` shows Core options only (~25–40 flags); advanced More and
  vendor-token flags only show under ``scan --help-all`` (with their env var).
* ``-f text`` remains accepted as a deprecated alias of ``plain``.
* ``--inventory-only`` remains accepted as a hidden alias of ``--no-discover``.
* ``api`` is hidden but reachable; ``serve --no-ui`` provides REST-only mode.
"""

from __future__ import annotations

from click.testing import CliRunner


def _run(args):
    from agent_bom.cli import main

    return CliRunner().invoke(main, args)


# ── FIX 1: canonical scan verb, agents hidden alias ──────────────────────────


class TestScanVerbUnified:
    def test_scan_is_visible_in_top_level_help(self):
        result = _run(["--help"])
        assert result.exit_code == 0
        assert "\n  scan " in result.output

    def test_agents_hidden_from_top_level_help(self):
        result = _run(["--help"])
        assert "\n  agents " not in result.output

    def test_agents_alias_still_runs(self):
        assert _run(["agents", "--help"]).exit_code == 0

    def test_scan_and_agents_are_same_underlying_command(self):
        from agent_bom.cli import main

        scan_cmd = main.get_command(None, "scan")
        agents_cmd = main.get_command(None, "agents")
        assert scan_cmd is not None and agents_cmd is not None
        assert agents_cmd.hidden is True
        assert scan_cmd.hidden is False


# ── FIX 2: tiered flags behind --help-all ────────────────────────────────────


class TestFlagTiering:
    def test_default_help_hides_vendor_tokens(self):
        out = _run(["scan", "--help"]).output
        for flag in ("--jira-url", "--siem-token", "--vanta-token", "--drata-token", "--wandb-api-key"):
            assert flag not in out, f"{flag} should be hidden in default help"

    def test_default_help_shows_core_only(self):
        out = _run(["scan", "--help"]).output
        assert "Core options:" in out
        assert "--fail-on-severity" in out
        assert "additional scan flags" in out
        assert not any(line.strip().startswith("--sbom") for line in out.splitlines())
        assert "scan --help-all" in out

    def test_default_help_core_option_count_bounded(self):
        out = _run(["scan", "--help"]).output
        option_lines = [line for line in out.splitlines() if line.strip().startswith("--")]
        assert 20 <= len(option_lines) <= 40, f"expected 20–40 core flags, got {len(option_lines)}"

    def test_help_all_shows_advanced_more_flags(self):
        out = _run(["scan", "--help-all"]).output
        assert "--sbom" in out

    def test_help_all_reveals_vendor_tokens_with_env(self):
        result = _run(["scan", "--help-all"])
        assert result.exit_code == 0
        out = result.output
        assert "--jira-url" in out
        assert "--siem-token" in out
        # Env var surfaced for vendor-token flags.
        assert "VANTA_API_TOKEN" in out
        assert "DRATA_API_TOKEN" in out


# ── FIX 3: format dedup (text → plain; graph-html retained) ──────────────────


class TestFormatDedup:
    def test_text_dropped_from_advertised_choices(self):
        out = _run(["scan", "--help"]).output
        # The choice metavar lists plain but not the deprecated text alias.
        assert "plain" in out
        assert "|text|" not in out and "|text]" not in out

    def test_graph_html_retained(self):
        out = _run(["scan", "--help"]).output
        assert "graph-html" in out

    def test_text_alias_still_accepted(self, tmp_path):
        out = tmp_path / "report.txt"
        result = _run(
            [
                "scan",
                "--demo",
                "--no-scan",
                "--offline",
                "--no-auto-update-db",
                "-f",
                "text",
                "-o",
                str(out),
            ]
        )
        assert result.exit_code == 0, result.output
        assert out.exists()


# ── FIX 4: server triplet — api hidden, serve --no-ui ────────────────────────


class TestServerSurface:
    def test_api_hidden_but_reachable(self):
        from agent_bom.cli import main

        assert "\n  api " not in _run(["--help"]).output
        assert main.get_command(None, "api") is not None
        assert _run(["api", "--help"]).exit_code == 0

    def test_serve_has_no_ui_flag(self):
        assert "--no-ui" in _run(["serve", "--help"]).output

    def test_up_inherits_no_ui(self):
        assert "--no-ui" in _run(["up", "--help"]).output


# ── FIX 5: inventory-flag dedup ──────────────────────────────────────────────


class TestInventoryFlagAlias:
    def test_inventory_only_hidden_from_help(self):
        assert "--inventory-only" not in _run(["scan", "--help"]).output
        assert "--inventory-only" not in _run(["scan", "--help-all"]).output

    def test_no_discover_visible(self):
        assert "--no-discover" in _run(["scan", "--help"]).output

    def test_inventory_only_alias_still_accepted(self):
        result = _run(["scan", "--inventory-only", "--demo", "--no-scan", "--offline", "--no-auto-update-db"])
        assert result.exit_code == 0, result.output

    def test_no_scan_still_distinct(self):
        assert "--no-scan" in _run(["scan", "--help"]).output
