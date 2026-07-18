"""Tests for the published gateway fail-open/fail-closed posture matrix.

The matrix in ``agent_bom.runtime.fail_mode`` is the single honest inventory
of what each gateway subsystem does when its own machinery fails. These tests
pin the documented posture to the behavior actually implemented in
``gateway_server.py`` — if enforcement code changes posture, the matrix (and
these tests) must change with it.
"""

from __future__ import annotations

import pytest

from agent_bom.runtime.fail_mode import (
    GATEWAY_FAIL_MODE_MATRIX,
    FailPosture,
    SubsystemFailMode,
    gateway_fail_mode_matrix,
)

_BY_NAME = {entry.subsystem: entry for entry in GATEWAY_FAIL_MODE_MATRIX}


def test_matrix_covers_every_gateway_enforcement_subsystem() -> None:
    assert set(_BY_NAME) == {
        "policy_engine",
        "firewall_policy",
        "control_plane_policy_bundle",
        "policy_plugins",
        "conditional_access",
        "caller_identity",
        "runtime_rate_limit",
        "spend_budgets",
        "cost_anomaly_enforcement",
        "fleet_quarantine_enforcement",
        "drift_enforcement",
        "graph_reachability_enforcement",
        "device_posture_enrichment",
        "audit_export",
    }


def test_every_entry_is_fully_documented() -> None:
    for entry in GATEWAY_FAIL_MODE_MATRIX:
        assert isinstance(entry, SubsystemFailMode)
        assert entry.subsystem
        assert entry.on_failure, f"{entry.subsystem} must describe its failure behavior"
        assert entry.control, f"{entry.subsystem} must name the operator control (or state there is none)"
        assert entry.default_posture in (FailPosture.OPEN, FailPosture.CLOSED)


def test_advisory_enrichment_paths_are_documented_fail_open() -> None:
    for subsystem in (
        "spend_budgets",
        "cost_anomaly_enforcement",
        "fleet_quarantine_enforcement",
        "drift_enforcement",
        "graph_reachability_enforcement",
        "audit_export",
    ):
        assert _BY_NAME[subsystem].default_posture is FailPosture.OPEN, subsystem
        assert not _BY_NAME[subsystem].follows_gateway_fail_mode, subsystem


def test_security_decision_paths_are_documented_fail_closed() -> None:
    for subsystem in (
        "control_plane_policy_bundle",
        "conditional_access",
        "caller_identity",
        "runtime_rate_limit",
        "device_posture_enrichment",
    ):
        assert _BY_NAME[subsystem].default_posture is FailPosture.CLOSED, subsystem
        assert not _BY_NAME[subsystem].follows_gateway_fail_mode, subsystem


def test_fail_mode_governed_subsystems_default_closed() -> None:
    for subsystem in ("policy_engine", "firewall_policy", "policy_plugins"):
        entry = _BY_NAME[subsystem]
        assert entry.follows_gateway_fail_mode, subsystem
        assert entry.default_posture is FailPosture.CLOSED, subsystem
        assert "AGENT_BOM_GATEWAY_FAIL_MODE" in entry.control, subsystem


def test_matrix_summary_resolves_configurable_entries() -> None:
    closed = {row["subsystem"]: row for row in gateway_fail_mode_matrix("closed")}
    opened = {row["subsystem"]: row for row in gateway_fail_mode_matrix("open")}

    assert closed["policy_engine"]["posture"] == "fail_closed"
    assert opened["policy_engine"]["posture"] == "fail_open"
    assert opened["policy_engine"]["follows_gateway_fail_mode"] is True

    # Fixed postures never flip with the gateway fail mode.
    assert closed["caller_identity"]["posture"] == "fail_closed"
    assert opened["caller_identity"]["posture"] == "fail_closed"
    assert closed["drift_enforcement"]["posture"] == "fail_open"
    assert opened["drift_enforcement"]["posture"] == "fail_open"


def test_matrix_summary_rows_are_json_shaped() -> None:
    rows = gateway_fail_mode_matrix("closed")
    assert len(rows) == len(GATEWAY_FAIL_MODE_MATRIX)
    for row in rows:
        assert set(row) == {"subsystem", "posture", "follows_gateway_fail_mode", "control", "on_failure"}
        assert row["posture"] in ("fail_open", "fail_closed")
        assert isinstance(row["follows_gateway_fail_mode"], bool)


def test_matrix_summary_rejects_unresolved_fail_mode() -> None:
    with pytest.raises(ValueError):
        gateway_fail_mode_matrix("maybe")
