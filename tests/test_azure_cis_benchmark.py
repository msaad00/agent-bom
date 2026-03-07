"""Tests for azure_cis_benchmark.py — CIS Azure Security Benchmark v3.0."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.azure_cis_benchmark import (
    AzureCISReport,
    _check_3_1,
    _check_3_7,
    _check_6_1,
    _check_6_2,
    _is_internet_exposed,
    run_benchmark,
)
from agent_bom.cloud.base import CloudDiscoveryError

# ---------------------------------------------------------------------------
# AzureCISReport model
# ---------------------------------------------------------------------------


def _make_report(*statuses: CheckStatus) -> AzureCISReport:
    report = AzureCISReport(subscription_id="sub-123")
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
    r = _make_report(CheckStatus.PASS, CheckStatus.PASS, CheckStatus.FAIL)
    assert r.passed == 2
    assert r.failed == 1
    assert r.total == 3


def test_report_pass_rate():
    r = _make_report(CheckStatus.PASS, CheckStatus.FAIL)
    assert r.pass_rate == pytest.approx(50.0)


def test_report_pass_rate_empty():
    r = AzureCISReport()
    assert r.pass_rate == 0.0


def test_report_to_dict_structure():
    r = _make_report(CheckStatus.PASS)
    d = r.to_dict()
    assert d["benchmark"] == "CIS Microsoft Azure Foundations"
    assert d["benchmark_version"] == "3.0"
    assert "pass_rate" in d
    assert "checks" in d
    assert len(d["checks"]) == 1


def test_report_to_dict_check_has_attack_techniques():
    r = _make_report(CheckStatus.FAIL)
    # Override section so ATT&CK mapping returns something
    r.checks[0].cis_section = "1 - Identity and Access Management"
    d = r.to_dict()
    check = d["checks"][0]
    assert "attack_techniques" in check
    assert isinstance(check["attack_techniques"], list)


def test_report_to_dict_passing_check_no_attack():
    r = _make_report(CheckStatus.PASS)
    d = r.to_dict()
    assert d["checks"][0]["attack_techniques"] == []


# ---------------------------------------------------------------------------
# _is_internet_exposed helper
# ---------------------------------------------------------------------------


def _make_nsg_rule(direction="Inbound", access="Allow", source="*", port="22"):
    rule = MagicMock()
    rule.direction = direction
    rule.access = access
    rule.source_address_prefix = source
    rule.destination_port_range = port
    return rule


def test_is_internet_exposed_ssh():
    rule = _make_nsg_rule(port="22")
    assert _is_internet_exposed(rule, "22") is True


def test_is_internet_exposed_rdp():
    rule = _make_nsg_rule(port="3389")
    assert _is_internet_exposed(rule, "3389") is True


def test_is_internet_exposed_wildcard_port():
    rule = _make_nsg_rule(port="*")
    assert _is_internet_exposed(rule, "22") is True


def test_not_exposed_outbound():
    rule = _make_nsg_rule(direction="Outbound", port="22")
    assert _is_internet_exposed(rule, "22") is False


def test_not_exposed_deny():
    rule = _make_nsg_rule(access="Deny", port="22")
    assert _is_internet_exposed(rule, "22") is False


def test_not_exposed_restricted_source():
    rule = _make_nsg_rule(source="10.0.0.0/8", port="22")
    assert _is_internet_exposed(rule, "22") is False


def test_not_exposed_different_port():
    rule = _make_nsg_rule(port="443")
    assert _is_internet_exposed(rule, "22") is False


@pytest.mark.parametrize("source", ["0.0.0.0/0", "::/0", "Internet", "Any"])
def test_internet_sources_all_flagged(source: str):
    rule = _make_nsg_rule(source=source, port="22")
    assert _is_internet_exposed(rule, "22") is True


# ---------------------------------------------------------------------------
# _check_3_1 — Secure Transfer Required
# ---------------------------------------------------------------------------


def test_check_3_1_all_secure():
    acct = MagicMock()
    acct.enable_https_traffic_only = True
    acct.name = "mystorage"

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_1(storage_client)
    assert result.status == CheckStatus.PASS


def test_check_3_1_insecure_account():
    acct = MagicMock()
    acct.enable_https_traffic_only = False
    acct.name = "insecure-storage"

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_1(storage_client)
    assert result.status == CheckStatus.FAIL
    assert "insecure-storage" in result.evidence


def test_check_3_1_exception():
    storage_client = MagicMock()
    storage_client.storage_accounts.list.side_effect = Exception("API error")

    result = _check_3_1(storage_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_3_7 — Public Blob Access
# ---------------------------------------------------------------------------


def test_check_3_7_all_private():
    acct = MagicMock()
    acct.allow_blob_public_access = False
    acct.name = "private-storage"

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_7(storage_client)
    assert result.status == CheckStatus.PASS


def test_check_3_7_public_account():
    acct = MagicMock()
    acct.allow_blob_public_access = True
    acct.name = "public-storage"

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_7(storage_client)
    assert result.status == CheckStatus.FAIL
    assert "public-storage" in result.evidence


# ---------------------------------------------------------------------------
# _check_6_1 / _check_6_2 — NSG rules
# ---------------------------------------------------------------------------


def test_check_6_1_no_rdp_exposure():
    nsg = MagicMock()
    nsg.name = "my-nsg"
    rule = _make_nsg_rule(port="443")  # HTTPS only, not RDP
    nsg.security_rules = [rule]

    network_client = MagicMock()
    network_client.network_security_groups.list_all.return_value = [nsg]

    result = _check_6_1(network_client)
    assert result.status == CheckStatus.PASS


def test_check_6_1_rdp_exposed():
    nsg = MagicMock()
    nsg.name = "my-nsg"
    rule = _make_nsg_rule(port="3389")
    rule.name = "allow-rdp"
    nsg.security_rules = [rule]

    network_client = MagicMock()
    network_client.network_security_groups.list_all.return_value = [nsg]

    result = _check_6_1(network_client)
    assert result.status == CheckStatus.FAIL
    assert "3389" in result.evidence or "RDP" in result.evidence


def test_check_6_2_ssh_exposed():
    nsg = MagicMock()
    nsg.name = "my-nsg"
    rule = _make_nsg_rule(port="22")
    rule.name = "allow-ssh"
    nsg.security_rules = [rule]

    network_client = MagicMock()
    network_client.network_security_groups.list_all.return_value = [nsg]

    result = _check_6_2(network_client)
    assert result.status == CheckStatus.FAIL
    assert "22" in result.evidence or "SSH" in result.evidence


# ---------------------------------------------------------------------------
# run_benchmark — missing azure-identity
# ---------------------------------------------------------------------------


def test_run_benchmark_no_azure_identity():
    with patch.dict("sys.modules", {"azure.identity": None}):
        with pytest.raises((CloudDiscoveryError, ImportError, Exception)):
            run_benchmark(subscription_id="sub-123")


def test_run_benchmark_no_subscription_id(monkeypatch):
    monkeypatch.delenv("AZURE_SUBSCRIPTION_ID", raising=False)
    try:
        from azure.identity import DefaultAzureCredential  # noqa: F401
    except ImportError:
        pytest.skip("azure-identity not installed")

    with pytest.raises((CloudDiscoveryError, Exception)):
        run_benchmark(subscription_id=None)
