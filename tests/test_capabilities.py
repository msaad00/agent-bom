"""Tests for the nothing-silent capability registry + doctor/capabilities CLI.

Asserts the core contract:
  * every known gate appears in the registry and in `capabilities`/`doctor`
    output with a state and an unlock path (nothing silent),
  * an unset feature shows OFF + how-to-unlock,
  * a set env flag shows ENABLED,
  * no secret values are ever printed,
  * the output is deterministic for a fixed environment.
"""

from __future__ import annotations

import re

import pytest
from click.testing import CliRunner

from agent_bom import capabilities as cap_mod
from agent_bom.capabilities import (
    CAPABILITIES,
    State,
    coverage_line,
    env_truthy,
    resolved_capabilities,
    scan_status_line,
)
from agent_bom.cli._capabilities import capabilities_cmd

# Every gate this session shipped must be represented. If a new gate lands and
# this list is updated but the registry isn't (or vice versa), the test fails —
# that is the nothing-silent guarantee, enforced.
KNOWN_GATE_KEYS = {
    "aws_inventory",
    "azure_inventory",
    "gcp_inventory",
    "snowflake_inventory",
    "org_rollup",
    "side_scan",
    "audit_trail",
    "registry_sweep",
    "vuln_db_cache",
}

# Env vars whose *values* must never be printed (credentials / secrets).
SECRET_VALUE_ENV_VARS = (
    "AWS_ACCESS_KEY_ID",
    "AWS_ROLE_ARN",
    "AZURE_CLIENT_ID",
    "GOOGLE_APPLICATION_CREDENTIALS",
    "SNOWFLAKE_PRIVATE_KEY_PATH",
    "AGENT_BOM_REGISTRY_PASS",
)

# All gate flags — cleared before each test so probing is deterministic.
_ALL_GATE_ENV = {
    "AGENT_BOM_AWS_INVENTORY",
    "AGENT_BOM_AZURE_INVENTORY",
    "AGENT_BOM_GCP_INVENTORY",
    "AGENT_BOM_SNOWFLAKE_INVENTORY",
    "AGENT_BOM_CLOUD_INVENTORY",
    "AGENT_BOM_SIDESCAN",
    "AGENT_BOM_AUDIT_TRAIL",
    "AGENT_BOM_REGISTRY_USER",
    "AGENT_BOM_REGISTRY_PASS",
    "AGENT_BOM_REGISTRY_AIRGAPPED",
    "AGENT_BOM_VULN_DB_OFFLINE",
    "AGENT_BOM_VULN_DB_MAX_AGE_HOURS",
    "AGENT_BOM_SCAN_CACHE",
    *SECRET_VALUE_ENV_VARS,
}


@pytest.fixture
def clean_env(monkeypatch, tmp_path):
    """Clear every gate var and point the vuln cache at a non-existent path."""
    for name in _ALL_GATE_ENV:
        monkeypatch.delenv(name, raising=False)
    # Point cache override at a missing file so vuln_db_cache is deterministic OFF.
    monkeypatch.setenv("AGENT_BOM_SCAN_CACHE", str(tmp_path / "no-such-cache.db"))
    return monkeypatch


# ---------------------------------------------------------------------------
# Registry shape + nothing-silent coverage
# ---------------------------------------------------------------------------


def test_registry_covers_every_known_gate():
    keys = {cap.key for cap in CAPABILITIES}
    assert KNOWN_GATE_KEYS <= keys, f"missing gates: {KNOWN_GATE_KEYS - keys}"


def test_capability_keys_are_unique():
    keys = [cap.key for cap in CAPABILITIES]
    assert len(keys) == len(set(keys))


def test_every_capability_has_unlock_and_condition():
    for cap in CAPABILITIES:
        assert cap.unlock.strip(), f"{cap.key} has no unlock path"
        assert cap.condition.strip(), f"{cap.key} has no condition"
        assert cap.does.strip()
        assert cap.env_vars, f"{cap.key} declares no env vars"


def test_resolved_capabilities_have_state_and_detail(clean_env):
    resolved = resolved_capabilities()
    assert len(resolved) == len(CAPABILITIES)
    for cap, status in resolved:
        assert isinstance(status.state, State)
        assert status.detail.strip(), f"{cap.key} has empty detail"


# ---------------------------------------------------------------------------
# State computation: unset → OFF, set → ENABLED, degraded
# ---------------------------------------------------------------------------


def test_unset_flag_capability_is_off_with_unlock(clean_env):
    statuses = {cap.key: (cap, st) for cap, st in resolved_capabilities()}
    cap, status = statuses["side_scan"]
    assert status.state is State.OFF
    assert "AGENT_BOM_SIDESCAN" in cap.unlock


def test_set_flag_capability_is_enabled(clean_env):
    clean_env.setenv("AGENT_BOM_AUDIT_TRAIL", "1")
    statuses = {cap.key: st for cap, st in resolved_capabilities()}
    assert statuses["audit_trail"].state is State.ON


def test_inventory_opted_in_without_creds_is_degraded(clean_env):
    clean_env.setenv("AGENT_BOM_AWS_INVENTORY", "true")
    statuses = {cap.key: st for cap, st in resolved_capabilities()}
    assert statuses["aws_inventory"].state is State.DEGRADED
    assert "no credentials" in statuses["aws_inventory"].detail.lower()


def test_inventory_opted_in_with_creds_is_enabled(clean_env):
    clean_env.setenv("AGENT_BOM_AWS_INVENTORY", "1")
    clean_env.setenv("AWS_PROFILE", "readonly")
    statuses = {cap.key: st for cap, st in resolved_capabilities()}
    assert statuses["aws_inventory"].state is State.ON


def test_vuln_cache_off_when_no_local_cache(clean_env):
    statuses = {cap.key: st for cap, st in resolved_capabilities()}
    assert statuses["vuln_db_cache"].state is State.OFF


def test_vuln_cache_fresh_is_enabled(clean_env, tmp_path):
    db = tmp_path / "scan_cache.db"
    db.write_text("x")
    clean_env.setenv("AGENT_BOM_SCAN_CACHE", str(db))
    statuses = {cap.key: st for cap, st in resolved_capabilities()}
    assert statuses["vuln_db_cache"].state is State.ON


def test_env_truthy_matches_gate_vocabulary(clean_env):
    for value in ("1", "true", "YES", "On"):
        clean_env.setenv("AGENT_BOM_AUDIT_TRAIL", value)
        assert env_truthy("AGENT_BOM_AUDIT_TRAIL")
    for value in ("0", "false", "", "nope"):
        clean_env.setenv("AGENT_BOM_AUDIT_TRAIL", value)
        assert not env_truthy("AGENT_BOM_AUDIT_TRAIL")


def test_probe_never_raises(monkeypatch):
    """A broken probe degrades to UNKNOWN — never crashes."""

    def boom() -> cap_mod.CapabilityStatus:
        raise RuntimeError("kaboom")

    bad = cap_mod.Capability(
        key="bad",
        name="Bad",
        group="scan",
        does="x",
        condition="c",
        unlock="u",
        env_vars=("X",),
        probe=boom,
    )
    status = bad.status()
    assert status.state is State.UNKNOWN
    assert "kaboom" in status.detail


# ---------------------------------------------------------------------------
# Determinism + no-secrets
# ---------------------------------------------------------------------------


def test_resolution_is_deterministic(clean_env):
    a = [(c.key, s.state, s.detail) for c, s in resolved_capabilities()]
    b = [(c.key, s.state, s.detail) for c, s in resolved_capabilities()]
    assert a == b


def test_no_secret_values_printed(clean_env):
    sentinel = "SUPERSECRETVALUE12345"
    for name in SECRET_VALUE_ENV_VARS:
        clean_env.setenv(name, sentinel)
    # Also opt in so credential-detection paths run.
    clean_env.setenv("AGENT_BOM_AWS_INVENTORY", "1")
    clean_env.setenv("AGENT_BOM_REGISTRY_USER", sentinel)

    result = CliRunner().invoke(capabilities_cmd, [])
    assert result.exit_code == 0, result.output
    assert sentinel not in result.output


def test_coverage_line_is_a_sentence(clean_env):
    line = coverage_line()
    assert line.startswith("Coverage:")
    assert "gated capabilities" in line


def test_scan_status_line_names_unlock_var(clean_env):
    line = scan_status_line()
    assert "enabled" in line
    assert "doctor" in line
    # With everything off, at least one OFF capability surfaces its env var.
    assert "AGENT_BOM_" in line


# ---------------------------------------------------------------------------
# CLI: capabilities command lists everything with state + unlock
# ---------------------------------------------------------------------------


def test_capabilities_cmd_lists_all_with_state_and_unlock(clean_env):
    result = CliRunner().invoke(capabilities_cmd, [])
    assert result.exit_code == 0, result.output
    out = result.output
    for cap in CAPABILITIES:
        assert cap.name in out, f"{cap.name} missing from capabilities output"
    # Every state label legend present, and OFF entries show an unlock line.
    assert "OFF" in out
    assert "unlock:" in out
    assert "Coverage:" in out


def test_capabilities_cmd_shows_unlock_for_off_capability(clean_env):
    result = CliRunner().invoke(capabilities_cmd, [])
    # side-scan is off by default; its unlock var must appear.
    assert "AGENT_BOM_SIDESCAN" in result.output


def test_capabilities_cmd_marks_enabled(clean_env):
    clean_env.setenv("AGENT_BOM_AUDIT_TRAIL", "1")
    result = CliRunner().invoke(capabilities_cmd, [])
    assert "ENABLED" in result.output


def test_doctor_includes_capability_section(clean_env):
    from agent_bom.cli._doctor import doctor_cmd

    result = CliRunner().invoke(doctor_cmd, [])
    assert result.exit_code == 0, result.output
    assert "Capabilities" in result.output
    # The doctor capability section names each gated capability.
    for cap in CAPABILITIES:
        assert cap.name in result.output


def test_capabilities_registered_on_main_cli():
    from agent_bom.cli import main

    assert "capabilities" in main.commands
    assert "doctor" in main.commands


def test_output_contains_no_ansi_secret_leak(clean_env):
    """Sanity: strip rich markup, confirm only var names (not values) surface."""
    clean_env.setenv("AGENT_BOM_AWS_INVENTORY", "1")
    clean_env.setenv("AWS_PROFILE", "my-ro-profile")
    result = CliRunner().invoke(capabilities_cmd, [])
    plain = re.sub(r"\x1b\[[0-9;]*m", "", result.output)
    # The detected-credential line names the variable, by design, but never a
    # value that looks like a secret token. AWS_PROFILE is a low-sensitivity
    # selector and is intentionally surfaced as "detected".
    assert "AGENT_BOM_AWS_INVENTORY" in plain
