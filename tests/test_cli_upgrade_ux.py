"""Tests for the consolidated CLI upgrade/update/DB-freshness UX.

Covers three surfaces:
  1. Install-method-aware upgrade guidance (``_detect_install_method``).
  2. The hidden ``update`` disambiguation command (message + exit 2).
  3. The day-based vuln-DB staleness warning + opt-in ``--require-fresh-db`` gate.
"""

from __future__ import annotations

import os
import sys

import pytest
from click.testing import CliRunner

from agent_bom.cli import main
from agent_bom.cli._common import _detect_install_method
from agent_bom.vuln_freshness import (
    VulnDataFreshness,
    db_stale_days_threshold,
    db_staleness,
    require_fresh_db_env,
)

# ---------------------------------------------------------------------------
# 1. Install-method detection
# ---------------------------------------------------------------------------


def _no_dockerenv(monkeypatch):
    """Force ``/.dockerenv`` to look absent so path-based methods are reachable."""
    real_exists = os.path.exists
    monkeypatch.setattr(
        os.path,
        "exists",
        lambda p: False if p == "/.dockerenv" else real_exists(p),
    )
    monkeypatch.delenv("AGENT_BOM_IN_CONTAINER", raising=False)


def test_detect_frozen_binary(monkeypatch):
    monkeypatch.setattr(sys, "frozen", True, raising=False)
    method, command = _detect_install_method()
    assert method == "frozen"
    assert "release binary" in command
    assert "github.com" in command


def test_detect_docker_via_env(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setenv("AGENT_BOM_IN_CONTAINER", "1")
    monkeypatch.delenv("AGENT_BOM_DOCKER_IMAGE", raising=False)
    method, command = _detect_install_method()
    assert method == "docker"
    assert command == "docker pull agentbom/agent-bom:latest"


def test_detect_docker_image_override(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    monkeypatch.setenv("AGENT_BOM_IN_CONTAINER", "yes")
    monkeypatch.setenv("AGENT_BOM_DOCKER_IMAGE", "myreg/agent-bom")
    method, command = _detect_install_method()
    assert method == "docker"
    assert command == "docker pull myreg/agent-bom:latest"


def test_detect_pipx(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    _no_dockerenv(monkeypatch)
    monkeypatch.setattr(sys, "prefix", "/home/u/.local/pipx/venvs/agent-bom")
    method, command = _detect_install_method()
    assert method == "pipx"
    assert command == "pipx upgrade agent-bom"


def test_detect_uv_tool(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    _no_dockerenv(monkeypatch)
    monkeypatch.setattr(sys, "prefix", "/home/u/.local/share/uv/tools/agent-bom")
    method, command = _detect_install_method()
    assert method == "uv"
    assert command == "uv tool upgrade agent-bom"


def test_detect_brew(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    _no_dockerenv(monkeypatch)
    monkeypatch.setattr(sys, "prefix", "/opt/homebrew/Cellar/agent-bom/1.0.0/libexec")
    method, command = _detect_install_method()
    assert method == "brew"
    assert command == "brew upgrade agent-bom"


def test_detect_pip_default(monkeypatch):
    monkeypatch.setattr(sys, "frozen", False, raising=False)
    _no_dockerenv(monkeypatch)
    monkeypatch.setattr(sys, "prefix", "/usr/local/venvs/proj")
    monkeypatch.setattr(sys, "argv", ["agent-bom"])
    method, command = _detect_install_method()
    assert method == "pip"
    assert command == "pip install --upgrade agent-bom"


def test_upgrade_notice_uses_detected_command(monkeypatch, tmp_path):
    """The background update notice reflects the detected install method."""
    import threading

    import agent_bom.cli._common as mod

    monkeypatch.setattr(sys, "frozen", False, raising=False)
    _no_dockerenv(monkeypatch)
    monkeypatch.setattr(sys, "prefix", "/home/u/.local/pipx/venvs/agent-bom")
    monkeypatch.delenv("AGENT_BOM_OFFLINE", raising=False)
    monkeypatch.delenv("AGENT_BOM_SKIP_UPDATE_CHECK", raising=False)
    monkeypatch.setattr(sys, "argv", ["agent-bom", "scan"])

    # Force a "newer version available" and a cache miss.
    monkeypatch.setattr("agent_bom.http_client.fetch_json", lambda *a, **k: {"info": {"version": "999.0.0"}})
    monkeypatch.setattr(mod, "_update_check_cache_file", lambda: tmp_path / "update-check.txt")

    old_result, old_done = mod._update_check_result, mod._update_check_done
    mod._update_check_done = threading.Event()
    try:
        mod._check_for_update_bg()
        assert mod._update_check_result is not None
        assert "pipx upgrade agent-bom" in mod._update_check_result
    finally:
        mod._update_check_result, mod._update_check_done = old_result, old_done


# ---------------------------------------------------------------------------
# 2. `update` disambiguation
# ---------------------------------------------------------------------------


def test_update_command_disambiguates_and_exits_2():
    result = CliRunner().invoke(main, ["update"], catch_exceptions=False)
    assert result.exit_code == 2
    assert "`update` is not a command" in result.output
    assert "agent-bom upgrade" in result.output
    assert "agent-bom db update" in result.output


def test_update_command_hidden_from_help():
    result = CliRunner().invoke(main, ["--help"])
    assert result.exit_code == 0
    # Hidden: not listed as a top-level command in help output.
    assert "\n  update " not in result.output


def test_update_command_with_extra_args_still_disambiguates():
    result = CliRunner().invoke(main, ["update", "--force", "now"], catch_exceptions=False)
    assert result.exit_code == 2
    assert "`update` is not a command" in result.output


# ---------------------------------------------------------------------------
# 1b. `upgrade` install action is method-aware
# ---------------------------------------------------------------------------


def _patch_pypi_newer(monkeypatch):
    monkeypatch.setattr("agent_bom.http_client.fetch_json", lambda *a, **k: {"info": {"version": "999.0.0"}})


def test_upgrade_non_pip_prints_command_and_never_runs_pip(monkeypatch):
    """A pipx/uv/brew/frozen/docker install must not be driven with pip."""
    import subprocess

    _patch_pypi_newer(monkeypatch)
    monkeypatch.setattr("agent_bom.cli._common._detect_install_method", lambda: ("pipx", "pipx upgrade agent-bom"))

    def _boom(*a, **k):
        raise AssertionError("pip must never run for a non-pip install method")

    monkeypatch.setattr(subprocess, "run", _boom)
    result = CliRunner().invoke(main, ["upgrade"], catch_exceptions=False)
    assert result.exit_code == 0
    assert "pipx upgrade agent-bom" in result.output
    assert "pipx" in result.output


def test_upgrade_pip_method_runs_pip(monkeypatch):
    import subprocess

    _patch_pypi_newer(monkeypatch)
    monkeypatch.setattr("agent_bom.cli._common._detect_install_method", lambda: ("pip", "pip install --upgrade agent-bom"))
    calls: list[list] = []

    class _Result:
        returncode = 0
        stderr = ""

    def _fake_run(cmd, *a, **k):
        calls.append(cmd)
        return _Result()

    monkeypatch.setattr(subprocess, "run", _fake_run)
    result = CliRunner().invoke(main, ["upgrade"], catch_exceptions=False)
    assert result.exit_code == 0
    assert len(calls) == 1
    assert "pip" in calls[0] and "install" in calls[0] and "--upgrade" in calls[0]


def test_upgrade_pypi_unreachable_still_shows_command(monkeypatch):
    def _fail(*a, **k):
        raise OSError("no network")

    monkeypatch.setattr("agent_bom.http_client.fetch_json", _fail)
    monkeypatch.setattr("agent_bom.cli._common._detect_install_method", lambda: ("uv", "uv tool upgrade agent-bom"))
    result = CliRunner().invoke(main, ["upgrade"], catch_exceptions=False)
    assert result.exit_code == 1
    assert "Could not reach PyPI" in result.output
    assert "uv tool upgrade agent-bom" in result.output


# ---------------------------------------------------------------------------
# 3. DB-freshness helpers
# ---------------------------------------------------------------------------


def test_db_stale_days_threshold_default(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_DB_STALE_DAYS", raising=False)
    assert db_stale_days_threshold() == 14


@pytest.mark.parametrize("raw,expected", [("7", 7), ("30", 30), ("0", 14), ("-3", 14), ("junk", 14)])
def test_db_stale_days_threshold_env(monkeypatch, raw, expected):
    monkeypatch.setenv("AGENT_BOM_DB_STALE_DAYS", raw)
    assert db_stale_days_threshold() == expected


@pytest.mark.parametrize("raw,expected", [("1", True), ("true", True), ("YES", True), ("0", False), ("", False)])
def test_require_fresh_db_env(monkeypatch, raw, expected):
    monkeypatch.setenv("AGENT_BOM_REQUIRE_FRESH_DB", raw)
    assert require_fresh_db_env() is expected


def _freshness(*, mode="local", age_days=None):
    age_hours = None if age_days is None else age_days * 24
    return VulnDataFreshness(mode=mode, age_hours=age_hours)


def test_db_staleness_fresh():
    stale, age = db_staleness(_freshness(age_days=3), threshold_days=14)
    assert stale is False
    assert age == 3


def test_db_staleness_stale():
    stale, age = db_staleness(_freshness(age_days=30), threshold_days=14)
    assert stale is True
    assert age == 30


def test_db_staleness_live_mode_not_stale():
    # No local cache but online (live APIs back the scan) → nothing to be stale.
    stale, age = db_staleness(_freshness(mode="live", age_days=None))
    assert stale is False
    assert age is None


def test_db_staleness_offline_no_cache_is_stale():
    stale, age = db_staleness(_freshness(mode="offline", age_days=None))
    assert stale is True
    assert age is None


# ---------------------------------------------------------------------------
# 3b. DB-freshness gate — CLI exit behavior
# ---------------------------------------------------------------------------


def _patch_stale_scan(monkeypatch, freshness):
    monkeypatch.setattr("agent_bom.vuln_freshness.compute_freshness", lambda **kwargs: freshness)


def test_scan_warns_but_does_not_fail_by_default(monkeypatch, tmp_path):
    stale = VulnDataFreshness(mode="offline", age_hours=30 * 24, last_updated="2026-01-01T00:00:00+00:00", stale=True)
    _patch_stale_scan(monkeypatch, stale)
    monkeypatch.delenv("AGENT_BOM_REQUIRE_FRESH_DB", raising=False)
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--offline", "--no-discover", "--no-auto-update-db"],
        catch_exceptions=False,
    )
    assert result.exit_code != 3  # default: warn only, never a stale-DB gate failure
    assert "Vulnerability DB is stale" in result.output


def test_scan_require_fresh_db_flag_exits_3(monkeypatch, tmp_path):
    stale = VulnDataFreshness(mode="offline", age_hours=30 * 24, last_updated="2026-01-01T00:00:00+00:00", stale=True)
    _patch_stale_scan(monkeypatch, stale)
    monkeypatch.delenv("AGENT_BOM_REQUIRE_FRESH_DB", raising=False)
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--offline", "--no-discover", "--no-auto-update-db", "--require-fresh-db"],
        catch_exceptions=False,
    )
    assert result.exit_code == 3
    assert "Vulnerability DB is stale" in result.output


def test_scan_require_fresh_db_env_exits_3(monkeypatch, tmp_path):
    stale = VulnDataFreshness(mode="offline", age_hours=30 * 24, last_updated="2026-01-01T00:00:00+00:00", stale=True)
    _patch_stale_scan(monkeypatch, stale)
    monkeypatch.setenv("AGENT_BOM_REQUIRE_FRESH_DB", "1")
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--offline", "--no-discover", "--no-auto-update-db"],
        catch_exceptions=False,
    )
    assert result.exit_code == 3


def test_scan_fresh_db_does_not_trigger_gate(monkeypatch, tmp_path):
    fresh = VulnDataFreshness(mode="local", age_hours=2 * 24, last_updated="2026-07-09T00:00:00+00:00", stale=False)
    _patch_stale_scan(monkeypatch, fresh)
    result = CliRunner().invoke(
        main,
        ["scan", str(tmp_path), "--offline", "--no-discover", "--no-auto-update-db", "--require-fresh-db"],
        catch_exceptions=False,
    )
    assert result.exit_code != 3
    assert "Vulnerability DB is stale" not in result.output


# ---------------------------------------------------------------------------
# 3c. agent-mode surfaces db + version metadata
# ---------------------------------------------------------------------------


def test_agent_mode_summary_includes_db_and_version():
    from agent_bom import __version__
    from agent_bom.cli._agent_mode import _summary

    report = {
        "summary": {"total_vulnerabilities": 0},
        "vuln_data_freshness": {"last_updated": "2026-07-01T00:00:00+00:00", "age_days": 9},
    }
    summary = _summary(report)
    assert summary["tool_version"] == __version__
    assert summary["db_last_updated"] == "2026-07-01T00:00:00+00:00"
    assert summary["db_age_days"] == 9
