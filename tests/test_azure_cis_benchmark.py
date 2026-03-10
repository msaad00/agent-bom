"""Tests for azure_cis_benchmark.py — CIS Azure Security Benchmark v3.0."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.azure_cis_benchmark import (
    AzureCISReport,
    _check_2_1,
    _check_2_2,
    _check_2_3,
    _check_3_1,
    _check_3_2,
    _check_3_7,
    _check_3_10,
    _check_4_1_1,
    _check_4_2_1,
    _check_6_1,
    _check_6_2,
    _check_6_3,
    _check_6_5,
    _check_7_1,
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
# _check_2_1 — Defender for Servers
# ---------------------------------------------------------------------------


def test_check_2_1_standard_tier():
    security_client = MagicMock()
    pricing = MagicMock()
    pricing.pricing_tier = "Standard"
    security_client.pricings.get.return_value = pricing

    result = _check_2_1(security_client, "sub-123")
    assert result.status == CheckStatus.PASS
    assert "Standard" in result.evidence


def test_check_2_1_free_tier():
    security_client = MagicMock()
    pricing = MagicMock()
    pricing.pricing_tier = "Free"
    security_client.pricings.get.return_value = pricing

    result = _check_2_1(security_client, "sub-123")
    assert result.status == CheckStatus.FAIL
    assert "Free" in result.evidence


def test_check_2_1_exception():
    security_client = MagicMock()
    security_client.pricings.get.side_effect = Exception("API error")

    result = _check_2_1(security_client, "sub-123")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_2_2 — Defender for App Services
# ---------------------------------------------------------------------------


def test_check_2_2_standard_tier():
    security_client = MagicMock()
    pricing = MagicMock()
    pricing.pricing_tier = "Standard"
    security_client.pricings.get.return_value = pricing

    result = _check_2_2(security_client, "sub-123")
    assert result.status == CheckStatus.PASS
    assert "App Services" in result.evidence


def test_check_2_2_free_tier():
    security_client = MagicMock()
    pricing = MagicMock()
    pricing.pricing_tier = "Free"
    security_client.pricings.get.return_value = pricing

    result = _check_2_2(security_client, "sub-123")
    assert result.status == CheckStatus.FAIL
    assert "Free" in result.evidence


def test_check_2_2_exception():
    security_client = MagicMock()
    security_client.pricings.get.side_effect = Exception("API error")

    result = _check_2_2(security_client, "sub-123")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_2_3 — Defender for SQL Servers
# ---------------------------------------------------------------------------


def test_check_2_3_standard_tier():
    security_client = MagicMock()
    pricing = MagicMock()
    pricing.pricing_tier = "Standard"
    security_client.pricings.get.return_value = pricing

    result = _check_2_3(security_client, "sub-123")
    assert result.status == CheckStatus.PASS
    assert "SQL Servers" in result.evidence


def test_check_2_3_free_tier():
    security_client = MagicMock()
    pricing = MagicMock()
    pricing.pricing_tier = "Free"
    security_client.pricings.get.return_value = pricing

    result = _check_2_3(security_client, "sub-123")
    assert result.status == CheckStatus.FAIL
    assert "Free" in result.evidence


def test_check_2_3_exception():
    security_client = MagicMock()
    security_client.pricings.get.side_effect = Exception("API error")

    result = _check_2_3(security_client, "sub-123")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_3_2 — Default network access rule = Deny
# ---------------------------------------------------------------------------


def test_check_3_2_all_deny():
    acct = MagicMock()
    acct.name = "secure-storage"
    network_rule_set = MagicMock()
    network_rule_set.default_action = "Deny"
    acct.network_rule_set = network_rule_set

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_2(storage_client)
    assert result.status == CheckStatus.PASS


def test_check_3_2_allow_default():
    acct = MagicMock()
    acct.name = "open-storage"
    network_rule_set = MagicMock()
    network_rule_set.default_action = "Allow"
    acct.network_rule_set = network_rule_set

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_2(storage_client)
    assert result.status == CheckStatus.FAIL
    assert "open-storage" in result.evidence


def test_check_3_2_exception():
    storage_client = MagicMock()
    storage_client.storage_accounts.list.side_effect = Exception("API error")

    result = _check_3_2(storage_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_3_10 — Soft delete enabled
# ---------------------------------------------------------------------------


def test_check_3_10_soft_delete_enabled():
    acct = MagicMock()
    acct.name = "mystorage"
    acct.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/mystorage"

    blob_props = MagicMock()
    retention = MagicMock()
    retention.enabled = True
    blob_props.delete_retention_policy = retention

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]
    storage_client.blob_services.get_service_properties.return_value = blob_props

    result = _check_3_10(storage_client)
    assert result.status == CheckStatus.PASS


def test_check_3_10_soft_delete_disabled():
    acct = MagicMock()
    acct.name = "nosoftdelete"
    acct.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Storage/storageAccounts/nosoftdelete"

    blob_props = MagicMock()
    retention = MagicMock()
    retention.enabled = False
    blob_props.delete_retention_policy = retention

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]
    storage_client.blob_services.get_service_properties.return_value = blob_props

    result = _check_3_10(storage_client)
    assert result.status == CheckStatus.FAIL
    assert "nosoftdelete" in result.evidence


def test_check_3_10_exception():
    storage_client = MagicMock()
    storage_client.storage_accounts.list.side_effect = Exception("API error")

    result = _check_3_10(storage_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_4_1_1 — SQL server auditing
# ---------------------------------------------------------------------------


def test_check_4_1_1_auditing_enabled():
    server = MagicMock()
    server.name = "sql-prod"
    server.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Sql/servers/sql-prod"

    audit_settings = MagicMock()
    audit_settings.state = "Enabled"

    sql_client = MagicMock()
    sql_client.servers.list.return_value = [server]
    sql_client.server_blob_auditing_policies.get.return_value = audit_settings

    result = _check_4_1_1(sql_client)
    assert result.status == CheckStatus.PASS


def test_check_4_1_1_auditing_disabled():
    server = MagicMock()
    server.name = "sql-dev"
    server.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Sql/servers/sql-dev"

    audit_settings = MagicMock()
    audit_settings.state = "Disabled"

    sql_client = MagicMock()
    sql_client.servers.list.return_value = [server]
    sql_client.server_blob_auditing_policies.get.return_value = audit_settings

    result = _check_4_1_1(sql_client)
    assert result.status == CheckStatus.FAIL
    assert "sql-dev" in result.evidence


def test_check_4_1_1_exception():
    sql_client = MagicMock()
    sql_client.servers.list.side_effect = Exception("API error")

    result = _check_4_1_1(sql_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_4_2_1 — TLS 1.2 enforcement
# ---------------------------------------------------------------------------


def test_check_4_2_1_tls_12():
    server = MagicMock()
    server.name = "sql-prod"
    server.minimal_tls_version = "1.2"

    sql_client = MagicMock()
    sql_client.servers.list.return_value = [server]

    result = _check_4_2_1(sql_client)
    assert result.status == CheckStatus.PASS


def test_check_4_2_1_tls_10():
    server = MagicMock()
    server.name = "sql-legacy"
    server.minimal_tls_version = "1.0"

    sql_client = MagicMock()
    sql_client.servers.list.return_value = [server]

    result = _check_4_2_1(sql_client)
    assert result.status == CheckStatus.FAIL
    assert "sql-legacy" in result.evidence
    assert "1.0" in result.evidence


def test_check_4_2_1_tls_not_set():
    server = MagicMock()
    server.name = "sql-noset"
    server.minimal_tls_version = None

    sql_client = MagicMock()
    sql_client.servers.list.return_value = [server]

    result = _check_4_2_1(sql_client)
    assert result.status == CheckStatus.FAIL
    assert "sql-noset" in result.evidence


def test_check_4_2_1_exception():
    sql_client = MagicMock()
    sql_client.servers.list.side_effect = Exception("API error")

    result = _check_4_2_1(sql_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_6_3 — SQL port 1433 NSG exposure
# ---------------------------------------------------------------------------


def test_check_6_3_no_sql_exposure():
    nsg = MagicMock()
    nsg.name = "my-nsg"
    rule = _make_nsg_rule(port="443")
    nsg.security_rules = [rule]

    network_client = MagicMock()
    network_client.network_security_groups.list_all.return_value = [nsg]

    result = _check_6_3(network_client)
    assert result.status == CheckStatus.PASS


def test_check_6_3_sql_exposed():
    nsg = MagicMock()
    nsg.name = "my-nsg"
    rule = _make_nsg_rule(port="1433")
    rule.name = "allow-sql"
    nsg.security_rules = [rule]

    network_client = MagicMock()
    network_client.network_security_groups.list_all.return_value = [nsg]

    result = _check_6_3(network_client)
    assert result.status == CheckStatus.FAIL
    assert "1433" in result.evidence


def test_check_6_3_exception():
    network_client = MagicMock()
    network_client.network_security_groups.list_all.side_effect = Exception("API error")

    result = _check_6_3(network_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_6_5 — Network Watcher enabled
# ---------------------------------------------------------------------------


def test_check_6_5_watchers_present():
    watcher = MagicMock()
    watcher.location = "eastus"

    network_client = MagicMock()
    network_client.network_watchers.list_all.return_value = [watcher]

    result = _check_6_5(network_client)
    assert result.status == CheckStatus.PASS
    assert "eastus" in result.evidence


def test_check_6_5_no_watchers():
    network_client = MagicMock()
    network_client.network_watchers.list_all.return_value = []

    result = _check_6_5(network_client)
    assert result.status == CheckStatus.FAIL
    assert "No Network Watcher" in result.evidence


def test_check_6_5_exception():
    network_client = MagicMock()
    network_client.network_watchers.list_all.side_effect = Exception("API error")

    result = _check_6_5(network_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_7_1 — VMs use Managed Disks
# ---------------------------------------------------------------------------


def test_check_7_1_all_managed():
    vm = MagicMock()
    vm.name = "vm-prod"
    storage_profile = MagicMock()
    os_disk = MagicMock()
    os_disk.managed_disk = MagicMock()  # non-None means managed
    storage_profile.os_disk = os_disk
    vm.storage_profile = storage_profile

    compute_client = MagicMock()
    compute_client.virtual_machines.list_all.return_value = [vm]

    result = _check_7_1(compute_client)
    assert result.status == CheckStatus.PASS


def test_check_7_1_unmanaged_disk():
    vm = MagicMock()
    vm.name = "vm-legacy"
    storage_profile = MagicMock()
    os_disk = MagicMock()
    os_disk.managed_disk = None  # unmanaged
    storage_profile.os_disk = os_disk
    vm.storage_profile = storage_profile

    compute_client = MagicMock()
    compute_client.virtual_machines.list_all.return_value = [vm]

    result = _check_7_1(compute_client)
    assert result.status == CheckStatus.FAIL
    assert "vm-legacy" in result.evidence


def test_check_7_1_exception():
    compute_client = MagicMock()
    compute_client.virtual_machines.list_all.side_effect = Exception("API error")

    result = _check_7_1(compute_client)
    assert result.status == CheckStatus.ERROR


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
