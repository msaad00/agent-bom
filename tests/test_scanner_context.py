"""Tests for scanner context-aware dispatch (#2223).

Verifies the two-gate model:
  Gate 1 — Authorization: enabled_scanners allowlist → "disabled" verdict
  Gate 2 — Applicability: files matched during walk → "ran" vs "not-applicable"

Deployment modes (standalone / native-app / github-action / mcp) round-trip
through ScanContext without affecting scanner logic — they are surfaced in
verdicts for the caller to render.
"""

from __future__ import annotations

import pytest

from agent_bom.iac import scan_iac_with_context
from agent_bom.iac.models import ScanContext, ScannerVerdict, ScanResult

# ─── Helpers ─────────────────────────────────────────────────────────────────


def _verdicts_by_id(result: ScanResult) -> dict[str, ScannerVerdict]:
    return {v.scanner_id: v for v in result.verdicts}


# ─── ScanResult shape ─────────────────────────────────────────────────────────


def test_scan_result_always_has_all_scanner_ids(tmp_path):
    """Every known scanner ID must appear in verdicts regardless of files present."""
    result = scan_iac_with_context(tmp_path)
    ids = {v.scanner_id for v in result.verdicts}
    assert {"helm", "dockerfile", "terraform", "dcm", "kubernetes", "cloudformation"} <= ids


def test_empty_directory_all_not_applicable(tmp_path):
    result = scan_iac_with_context(tmp_path)
    for v in result.verdicts:
        assert v.status == "not-applicable", f"{v.scanner_id} expected not-applicable, got {v.status}"
    assert result.findings == []


def test_nonexistent_root_returns_empty():
    result = scan_iac_with_context("/nonexistent/path/xyz")
    assert result.findings == []
    for v in result.verdicts:
        assert v.status in ("not-applicable", "disabled")


# ─── Gate 2: applicability (files matched) ────────────────────────────────────


def test_terraform_file_produces_ran_verdict(tmp_path):
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}', encoding="utf-8")
    result = scan_iac_with_context(tmp_path)
    v = _verdicts_by_id(result)
    assert v["terraform"].status == "ran"
    assert v["terraform"].files_scanned >= 1


def test_dockerfile_produces_ran_verdict(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\n", encoding="utf-8")
    result = scan_iac_with_context(tmp_path)
    v = _verdicts_by_id(result)
    assert v["dockerfile"].status == "ran"
    assert v["dockerfile"].files_scanned == 1



def test_dcm_migration_produces_ran_verdict(tmp_path):
    d = tmp_path / "dcm"
    d.mkdir()
    (d / "V001__init.sql").write_text("CREATE SCHEMA core;", encoding="utf-8")
    result = scan_iac_with_context(tmp_path)
    v = _verdicts_by_id(result)
    assert v["dcm"].status == "ran"
    assert v["dcm"].files_scanned == 1


def test_helm_chart_yaml_produces_ran_verdict(tmp_path):
    (tmp_path / "Chart.yaml").write_text("apiVersion: v2\nname: test\nversion: 0.1.0\n", encoding="utf-8")
    result = scan_iac_with_context(tmp_path)
    v = _verdicts_by_id(result)
    assert v["helm"].status == "ran"


def test_scanners_with_no_targets_are_not_applicable(tmp_path):
    """Only terraform scanner has a target; all others should be not-applicable."""
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" {}', encoding="utf-8")
    result = scan_iac_with_context(tmp_path)
    v = _verdicts_by_id(result)
    assert v["terraform"].status == "ran"
    for sid in ("helm", "dockerfile", "dcm", "kubernetes", "cloudformation"):
        assert v[sid].status == "not-applicable", f"{sid} should be not-applicable"


# ─── Gate 1: authorization (enabled_scanners allowlist) ───────────────────────


def test_disabled_scanner_never_dispatched(tmp_path):
    """Terraform file present but terraform locked out → disabled, zero findings."""
    (tmp_path / "main.tf").write_text('resource "aws_s3_bucket" "b" { acl = "public-read" }', encoding="utf-8")
    ctx = ScanContext(enabled_scanners=frozenset({"dcm", "dockerfile", "helm", "kubernetes", "cloudformation"}))
    result = scan_iac_with_context(tmp_path, ctx)
    v = _verdicts_by_id(result)
    assert v["terraform"].status == "disabled"
    assert v["terraform"].files_scanned == 0
    assert not any(f.category == "terraform" for f in result.findings)


def test_allowlist_single_scanner_others_disabled(tmp_path):
    """Only dcm in allowlist → all other scanners disabled, dcm not-applicable (no files)."""
    ctx = ScanContext(enabled_scanners=frozenset({"dcm"}))
    result = scan_iac_with_context(tmp_path, ctx)
    v = _verdicts_by_id(result)
    assert v["dcm"].status == "not-applicable"
    for sid in ("helm", "dockerfile", "terraform", "kubernetes", "cloudformation"):
        assert v[sid].status == "disabled"


def test_none_enabled_scanners_unlocks_all(tmp_path):
    """enabled_scanners=None (default) means all scanners are unlocked."""
    ctx = ScanContext(enabled_scanners=None)
    result = scan_iac_with_context(tmp_path, ctx)
    for v in result.verdicts:
        assert v.status != "disabled"


# ─── Deployment modes ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("mode", ["standalone", "native-app", "github-action", "mcp"])
def test_deployment_mode_round_trips(tmp_path, mode):
    """deployment_mode is stored in context; scan logic is identical across modes."""
    ctx = ScanContext(deployment_mode=mode)
    result = scan_iac_with_context(tmp_path, ctx)
    # No scanner should be disabled purely because of deployment_mode
    for v in result.verdicts:
        assert v.status in ("ran", "not-applicable")



def test_native_app_with_dcm_only_allowlist(tmp_path):
    """Simulate Snowflake Native App context: only dcm authorised, DCM file present."""
    d = tmp_path / "dcm"
    d.mkdir()
    (d / "V001__init.sql").write_text("GRANT MANAGE GRANTS ON ACCOUNT TO ROLE ops;", encoding="utf-8")
    ctx = ScanContext(
        deployment_mode="native-app",
        enabled_scanners=frozenset({"dcm"}),
    )
    result = scan_iac_with_context(tmp_path, ctx)
    v = _verdicts_by_id(result)
    assert v["dcm"].status == "ran"
    assert any(f.rule_id == "DCM-001" for f in result.findings)
    for sid in ("helm", "dockerfile", "terraform", "kubernetes", "cloudformation"):
        assert v[sid].status == "disabled"


# ─── Backward compat: scan_iac_directory still works ─────────────────────────


def test_scan_iac_directory_still_returns_list(tmp_path):
    """Legacy entry point must keep returning list[IaCFinding], not ScanResult."""
    from agent_bom.iac import scan_iac_directory

    result = scan_iac_directory(tmp_path)
    assert isinstance(result, list)


def test_scan_iac_directory_findings_match_scan_iac_with_context(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM ubuntu:latest\nUSER root\n", encoding="utf-8")
    from agent_bom.iac import scan_iac_directory

    legacy = scan_iac_directory(tmp_path)
    modern = scan_iac_with_context(tmp_path).findings
    assert [f.rule_id for f in legacy] == [f.rule_id for f in modern]
