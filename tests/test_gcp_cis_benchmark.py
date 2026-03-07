"""Tests for gcp_cis_benchmark.py — CIS GCP Foundation Benchmark v3.0."""

from __future__ import annotations

import sys
import types
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.base import CloudDiscoveryError
from agent_bom.cloud.gcp_cis_benchmark import (
    GCPCISReport,
    _check_3_1,
    _check_3_6,
    _check_3_7,
    _check_5_1,
    run_benchmark,
)

# ---------------------------------------------------------------------------
# Helpers — install fake GCP SDK modules into sys.modules so lazy imports work
# ---------------------------------------------------------------------------


def _ensure_google_namespace() -> tuple:
    """Ensure google / google.cloud namespace modules exist in sys.modules."""
    google_mod = sys.modules.get("google") or types.ModuleType("google")
    google_cloud = sys.modules.get("google.cloud") or types.ModuleType("google.cloud")
    google_mod.cloud = google_cloud
    sys.modules.setdefault("google", google_mod)
    sys.modules.setdefault("google.cloud", google_cloud)
    return google_mod, google_cloud


def _install_mock_gcp_compute(networks_list=None, firewalls_list=None):
    """Install a fake google.cloud.compute_v1 returning controlled data."""
    google_mod, google_cloud = _ensure_google_namespace()
    compute_mod = types.ModuleType("google.cloud.compute_v1")

    mock_networks_client = MagicMock()
    mock_networks_client.return_value.list.return_value = networks_list or []
    mock_firewalls_client = MagicMock()
    mock_firewalls_client.return_value.list.return_value = firewalls_list or []

    compute_mod.NetworksClient = mock_networks_client
    compute_mod.FirewallsClient = mock_firewalls_client

    google_cloud.compute_v1 = compute_mod
    sys.modules["google.cloud.compute_v1"] = compute_mod
    return compute_mod


def _install_mock_gcp_storage(buckets=None):
    """Install a fake google.cloud.storage returning controlled buckets."""
    google_mod, google_cloud = _ensure_google_namespace()
    storage_mod = types.ModuleType("google.cloud.storage")

    mock_client = MagicMock()
    mock_client.return_value.list_buckets.return_value = buckets or []
    storage_mod.Client = mock_client

    google_cloud.storage = storage_mod
    sys.modules["google.cloud.storage"] = storage_mod
    return storage_mod


# ---------------------------------------------------------------------------
# GCPCISReport model
# ---------------------------------------------------------------------------


def _make_report(*statuses: CheckStatus) -> GCPCISReport:
    report = GCPCISReport(project_id="my-project")
    for i, status in enumerate(statuses):
        report.checks.append(
            CISCheckResult(
                check_id=str(i + 1),
                title=f"Check {i + 1}",
                status=status,
                severity="medium",
                cis_section="1 - Identity and Access Management",
            )
        )
    return report


def test_report_pass_count():
    r = _make_report(CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.FAIL)
    assert r.passed == 1
    assert r.failed == 2
    assert r.total == 3


def test_report_pass_rate():
    r = _make_report(CheckStatus.PASS, CheckStatus.PASS, CheckStatus.FAIL, CheckStatus.FAIL)
    assert r.pass_rate == pytest.approx(50.0)


def test_report_to_dict_structure():
    r = _make_report(CheckStatus.PASS)
    d = r.to_dict()
    assert d["benchmark"] == "CIS Google Cloud Platform Foundation"
    assert d["benchmark_version"] == "3.0"
    assert "project_id" in d
    assert "checks" in d


def test_report_to_dict_check_has_attack_techniques():
    r = _make_report(CheckStatus.FAIL)
    r.checks[0].cis_section = "2 - Logging"
    d = r.to_dict()
    check = d["checks"][0]
    assert "attack_techniques" in check
    assert isinstance(check["attack_techniques"], list)


def test_report_to_dict_passing_no_attack():
    r = _make_report(CheckStatus.PASS)
    d = r.to_dict()
    assert d["checks"][0]["attack_techniques"] == []


# ---------------------------------------------------------------------------
# _check_3_1 — Default VPC
# ---------------------------------------------------------------------------


def _gcp_firewall_rule(name: str, direction: str = "INGRESS", disabled: bool = False, source_ranges=None, allowed=None):
    rule = MagicMock()
    rule.name = name
    rule.direction = direction
    rule.disabled = disabled
    rule.source_ranges = source_ranges or []
    rule.allowed = allowed or []
    return rule


def test_check_3_1_no_default_network():
    custom_net = MagicMock()
    custom_net.name = "custom-vpc"
    _install_mock_gcp_compute(networks_list=[custom_net])
    result = _check_3_1("my-project")
    assert result.status == CheckStatus.PASS


def test_check_3_1_default_network_exists():
    default_net = MagicMock()
    default_net.name = "default"
    _install_mock_gcp_compute(networks_list=[default_net])
    result = _check_3_1("my-project")
    assert result.status == CheckStatus.FAIL
    assert "default" in result.evidence


def test_check_3_1_exception_returns_error():
    """If the API call raises, the check returns ERROR."""
    compute_mod = _install_mock_gcp_compute()
    # Make the client raise on list()
    compute_mod.NetworksClient.return_value.list.side_effect = Exception("API down")
    result = _check_3_1("my-project")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_3_6 — SSH firewall exposure
# ---------------------------------------------------------------------------


def _make_allowed(proto: str, ports: list[str]):
    allowed = MagicMock()
    allowed.ip_protocol = proto
    allowed.I_p_protocol = proto
    allowed.ports = ports
    return allowed


def test_check_3_6_no_ssh_exposure():
    rule = _gcp_firewall_rule("allow-https", source_ranges=["0.0.0.0/0"], allowed=[_make_allowed("tcp", ["443"])])
    _install_mock_gcp_compute(firewalls_list=[rule])
    result = _check_3_6("my-project")
    assert result.status == CheckStatus.PASS


def test_check_3_6_ssh_exposed():
    rule = _gcp_firewall_rule("allow-ssh", source_ranges=["0.0.0.0/0"], allowed=[_make_allowed("tcp", ["22"])])
    _install_mock_gcp_compute(firewalls_list=[rule])
    result = _check_3_6("my-project")
    assert result.status == CheckStatus.FAIL
    assert "allow-ssh" in result.evidence


def test_check_3_6_disabled_rule_ignored():
    rule = _gcp_firewall_rule("allow-ssh-disabled", disabled=True, source_ranges=["0.0.0.0/0"], allowed=[_make_allowed("tcp", ["22"])])
    _install_mock_gcp_compute(firewalls_list=[rule])
    result = _check_3_6("my-project")
    assert result.status == CheckStatus.PASS


def test_check_3_6_egress_ignored():
    rule = _gcp_firewall_rule("egress-ssh", direction="EGRESS", source_ranges=["0.0.0.0/0"], allowed=[_make_allowed("tcp", ["22"])])
    _install_mock_gcp_compute(firewalls_list=[rule])
    result = _check_3_6("my-project")
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# _check_3_7 — RDP firewall exposure
# ---------------------------------------------------------------------------


def test_check_3_7_rdp_exposed():
    rule = _gcp_firewall_rule("allow-rdp", source_ranges=["0.0.0.0/0"], allowed=[_make_allowed("tcp", ["3389"])])
    _install_mock_gcp_compute(firewalls_list=[rule])
    result = _check_3_7("my-project")
    assert result.status == CheckStatus.FAIL
    assert "allow-rdp" in result.evidence


def test_check_3_7_no_rdp_exposure():
    _install_mock_gcp_compute(firewalls_list=[])
    result = _check_3_7("my-project")
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# _check_5_1 — Public GCS buckets
# ---------------------------------------------------------------------------


def test_check_5_1_no_public_buckets():
    bucket = MagicMock()
    bucket.name = "private-bucket"
    policy = MagicMock()
    policy.bindings = [{"role": "roles/storage.objectViewer", "members": ["user:alice@example.com"]}]
    bucket.get_iam_policy.return_value = policy
    _install_mock_gcp_storage(buckets=[bucket])
    result = _check_5_1("my-project")
    assert result.status == CheckStatus.PASS


def test_check_5_1_public_bucket():
    bucket = MagicMock()
    bucket.name = "public-bucket"
    policy = MagicMock()
    policy.bindings = [{"role": "roles/storage.objectViewer", "members": ["allUsers"]}]
    bucket.get_iam_policy.return_value = policy
    _install_mock_gcp_storage(buckets=[bucket])
    result = _check_5_1("my-project")
    assert result.status == CheckStatus.FAIL
    assert "public-bucket" in result.evidence


# ---------------------------------------------------------------------------
# run_benchmark — no SDK / no project
# ---------------------------------------------------------------------------


def test_run_benchmark_no_project(monkeypatch):
    monkeypatch.delenv("GOOGLE_CLOUD_PROJECT", raising=False)
    with pytest.raises((CloudDiscoveryError, Exception)):
        run_benchmark(project_id=None)


def test_run_benchmark_no_sdk(monkeypatch):
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "my-project")
    sdk_mods = {
        "google.cloud.compute_v1": None,
        "google.cloud.logging_v2": None,
        "google.cloud.storage": None,
        "googleapiclient": None,
    }
    with patch.dict("sys.modules", sdk_mods):
        with pytest.raises((CloudDiscoveryError, Exception)):
            run_benchmark(project_id="my-project")
