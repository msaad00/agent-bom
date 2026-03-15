"""Tests for azure_cis_benchmark.py — CIS Azure Security Benchmark v3.0."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.azure_cis_benchmark import (
    AzureCISReport,
    _check_1_3,
    _check_1_5,
    _check_1_7,
    _check_1_15,
    _check_2_1,
    _check_2_2,
    _check_2_3,
    _check_2_4,
    _check_3_1,
    _check_3_2,
    _check_3_3,
    _check_3_7,
    _check_3_10,
    _check_3_12,
    _check_4_1_1,
    _check_4_1_2,
    _check_4_2_1,
    _check_5_1_3,
    _check_6_1,
    _check_6_2,
    _check_6_3,
    _check_6_4,
    _check_6_5,
    _check_7_1,
    _check_7_2,
    _check_7_3,
    _check_8_3,
    _check_9_1,
    _check_9_2,
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


# ---------------------------------------------------------------------------
# _check_1_3 — Guest users reviewed (NOT_APPLICABLE)
# ---------------------------------------------------------------------------


def test_check_1_3_not_applicable():
    result = _check_1_3()
    assert result.status == CheckStatus.NOT_APPLICABLE
    assert result.check_id == "1.3"
    assert "Graph API" in result.evidence


# ---------------------------------------------------------------------------
# _check_1_5 — No custom subscription Administrator roles
# ---------------------------------------------------------------------------


def _make_custom_role(role_name: str, actions: list[str], assignable_scopes: list[str] | None = None):
    rd = MagicMock()
    rd.role_name = role_name
    rd.name = role_name
    perm = MagicMock()
    perm.actions = actions
    rd.permissions = [perm]
    rd.assignable_scopes = assignable_scopes if assignable_scopes is not None else ["/subscriptions/sub-123"]
    return rd


def test_check_1_5_no_admin_roles():
    auth_client = MagicMock()
    rd = _make_custom_role("custom-reader", ["Microsoft.Storage/*/read"])
    auth_client.role_definitions.list.return_value = [rd]

    result = _check_1_5(auth_client, "sub-123")
    assert result.status == CheckStatus.PASS


def test_check_1_5_admin_role_found():
    auth_client = MagicMock()
    rd = _make_custom_role("SuperAdmin", ["*"])
    auth_client.role_definitions.list.return_value = [rd]

    result = _check_1_5(auth_client, "sub-123")
    assert result.status == CheckStatus.FAIL
    assert "SuperAdmin" in result.evidence


def test_check_1_5_exception():
    auth_client = MagicMock()
    auth_client.role_definitions.list.side_effect = Exception("API error")

    result = _check_1_5(auth_client, "sub-123")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_1_7 — No custom Owner roles at subscription scope
# ---------------------------------------------------------------------------


def test_check_1_7_no_owner_roles():
    auth_client = MagicMock()
    rd = _make_custom_role("custom-reader", ["Microsoft.Storage/*/read"])
    auth_client.role_definitions.list.return_value = [rd]

    result = _check_1_7(auth_client, "sub-123")
    assert result.status == CheckStatus.PASS


def test_check_1_7_owner_role_found():
    auth_client = MagicMock()
    rd = _make_custom_role("SubscriptionOwner", ["*"], ["/subscriptions/sub-123"])
    auth_client.role_definitions.list.return_value = [rd]

    result = _check_1_7(auth_client, "sub-123")
    assert result.status == CheckStatus.FAIL
    assert "SubscriptionOwner" in result.evidence


def test_check_1_7_wildcard_actions_rg_scope_still_flagged():
    # The implementation flags any scope starting with /subscriptions/ as subscription-level
    auth_client = MagicMock()
    rd = _make_custom_role("ResourceGroupAdmin", ["*"], ["/subscriptions/sub-123/resourceGroups/my-rg"])
    auth_client.role_definitions.list.return_value = [rd]

    result = _check_1_7(auth_client, "sub-123")
    assert result.status == CheckStatus.FAIL


def test_check_1_7_wildcard_actions_no_matching_scope():
    auth_client = MagicMock()
    rd = _make_custom_role("NarrowAdmin", ["*"], [])
    auth_client.role_definitions.list.return_value = [rd]

    result = _check_1_7(auth_client, "sub-123")
    assert result.status == CheckStatus.PASS


def test_check_1_7_exception():
    auth_client = MagicMock()
    auth_client.role_definitions.list.side_effect = Exception("API error")

    result = _check_1_7(auth_client, "sub-123")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_1_15 — No custom subscription Administrator roles (variant)
# ---------------------------------------------------------------------------


def test_check_1_15_no_admin_roles():
    auth_client = MagicMock()
    rd = _make_custom_role("custom-reader", ["Microsoft.Compute/*/read"])
    auth_client.role_definitions.list.return_value = [rd]

    result = _check_1_15(auth_client, "sub-123")
    assert result.status == CheckStatus.PASS


def test_check_1_15_admin_role_found():
    auth_client = MagicMock()
    rd = _make_custom_role("FullAdmin", ["*"])
    auth_client.role_definitions.list.return_value = [rd]

    result = _check_1_15(auth_client, "sub-123")
    assert result.status == CheckStatus.FAIL
    assert "FullAdmin" in result.evidence


def test_check_1_15_exception():
    auth_client = MagicMock()
    auth_client.role_definitions.list.side_effect = Exception("API error")

    result = _check_1_15(auth_client, "sub-123")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_2_4 — Defender for Storage
# ---------------------------------------------------------------------------


def test_check_2_4_standard_tier():
    security_client = MagicMock()
    pricing = MagicMock()
    pricing.pricing_tier = "Standard"
    security_client.pricings.get.return_value = pricing

    result = _check_2_4(security_client, "sub-123")
    assert result.status == CheckStatus.PASS
    assert "Storage" in result.evidence


def test_check_2_4_free_tier():
    security_client = MagicMock()
    pricing = MagicMock()
    pricing.pricing_tier = "Free"
    security_client.pricings.get.return_value = pricing

    result = _check_2_4(security_client, "sub-123")
    assert result.status == CheckStatus.FAIL
    assert "Free" in result.evidence


def test_check_2_4_exception():
    security_client = MagicMock()
    security_client.pricings.get.side_effect = Exception("API error")

    result = _check_2_4(security_client, "sub-123")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_3_3 — Storage encrypted with Customer Managed Key
# ---------------------------------------------------------------------------


def test_check_3_3_all_cmk():
    acct = MagicMock()
    acct.name = "secure-storage"
    encryption = MagicMock()
    encryption.key_source = "Microsoft.Keyvault"
    acct.encryption = encryption

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_3(storage_client)
    assert result.status == CheckStatus.PASS


def test_check_3_3_not_cmk():
    acct = MagicMock()
    acct.name = "default-storage"
    encryption = MagicMock()
    encryption.key_source = "Microsoft.Storage"
    acct.encryption = encryption

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_3(storage_client)
    assert result.status == CheckStatus.FAIL
    assert "default-storage" in result.evidence


def test_check_3_3_exception():
    storage_client = MagicMock()
    storage_client.storage_accounts.list.side_effect = Exception("API error")

    result = _check_3_3(storage_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_3_12 — Infrastructure encryption enabled
# ---------------------------------------------------------------------------


def test_check_3_12_infra_encryption_enabled():
    acct = MagicMock()
    acct.name = "secure-storage"
    encryption = MagicMock()
    encryption.require_infrastructure_encryption = True
    acct.encryption = encryption

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_12(storage_client)
    assert result.status == CheckStatus.PASS


def test_check_3_12_infra_encryption_disabled():
    acct = MagicMock()
    acct.name = "weak-storage"
    encryption = MagicMock()
    encryption.require_infrastructure_encryption = False
    acct.encryption = encryption

    storage_client = MagicMock()
    storage_client.storage_accounts.list.return_value = [acct]

    result = _check_3_12(storage_client)
    assert result.status == CheckStatus.FAIL
    assert "weak-storage" in result.evidence


def test_check_3_12_exception():
    storage_client = MagicMock()
    storage_client.storage_accounts.list.side_effect = Exception("API error")

    result = _check_3_12(storage_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_4_1_2 — SQL Server TDE enabled
# ---------------------------------------------------------------------------


def test_check_4_1_2_tde_configured():
    server = MagicMock()
    server.name = "sql-prod"
    server.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Sql/servers/sql-prod"

    enc_protector = MagicMock()
    enc_protector.kind = "azurekeyvault"
    enc_protector.server_key_type = "AzureKeyVault"

    sql_client = MagicMock()
    sql_client.servers.list.return_value = [server]
    sql_client.encryption_protectors.get.return_value = enc_protector

    result = _check_4_1_2(sql_client)
    assert result.status == CheckStatus.PASS


def test_check_4_1_2_tde_not_configured():
    server = MagicMock()
    server.name = "sql-dev"
    server.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Sql/servers/sql-dev"

    enc_protector = MagicMock()
    enc_protector.kind = ""
    enc_protector.server_key_type = ""

    sql_client = MagicMock()
    sql_client.servers.list.return_value = [server]
    sql_client.encryption_protectors.get.return_value = enc_protector

    result = _check_4_1_2(sql_client)
    assert result.status == CheckStatus.FAIL
    assert "sql-dev" in result.evidence


def test_check_4_1_2_exception():
    sql_client = MagicMock()
    sql_client.servers.list.side_effect = Exception("API error")

    result = _check_4_1_2(sql_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_5_1_3 — Activity Log alert for Create/Update Key Vault
# ---------------------------------------------------------------------------


def _make_activity_log_alert(operation_name: str, enabled: bool = True):
    alert = MagicMock()
    alert.enabled = enabled
    cond = MagicMock()
    cond.field = "operationName"
    cond.equals = operation_name
    condition = MagicMock()
    condition.all_of = [cond]
    alert.condition = condition
    return alert


def test_check_5_1_3_alert_exists():
    monitor_client = MagicMock()
    alert = _make_activity_log_alert("Microsoft.KeyVault/vaults/write")
    monitor_client.activity_log_alerts.list_by_subscription_id.return_value = [alert]

    result = _check_5_1_3(monitor_client, "sub-123")
    assert result.status == CheckStatus.PASS
    assert "KeyVault" in result.evidence


def test_check_5_1_3_no_alert():
    monitor_client = MagicMock()
    monitor_client.activity_log_alerts.list_by_subscription_id.return_value = []

    result = _check_5_1_3(monitor_client, "sub-123")
    assert result.status == CheckStatus.FAIL


def test_check_5_1_3_alert_disabled():
    monitor_client = MagicMock()
    alert = _make_activity_log_alert("Microsoft.KeyVault/vaults/write", enabled=False)
    monitor_client.activity_log_alerts.list_by_subscription_id.return_value = [alert]

    result = _check_5_1_3(monitor_client, "sub-123")
    assert result.status == CheckStatus.FAIL


def test_check_5_1_3_exception():
    monitor_client = MagicMock()
    monitor_client.activity_log_alerts.list_by_subscription_id.side_effect = Exception("API error")

    result = _check_5_1_3(monitor_client, "sub-123")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_6_4 — UDP access from internet restricted
# ---------------------------------------------------------------------------


def test_check_6_4_no_udp_exposure():
    nsg = MagicMock()
    nsg.name = "my-nsg"
    rule = _make_nsg_rule(port="443")
    rule.protocol = "Tcp"
    nsg.security_rules = [rule]

    network_client = MagicMock()
    network_client.network_security_groups.list_all.return_value = [nsg]

    result = _check_6_4(network_client)
    assert result.status == CheckStatus.PASS


def test_check_6_4_udp_exposed():
    nsg = MagicMock()
    nsg.name = "my-nsg"
    rule = _make_nsg_rule(port="*")
    rule.protocol = "Udp"
    rule.name = "allow-udp"
    nsg.security_rules = [rule]

    network_client = MagicMock()
    network_client.network_security_groups.list_all.return_value = [nsg]

    result = _check_6_4(network_client)
    assert result.status == CheckStatus.FAIL
    assert "UDP" in result.evidence or "udp" in result.evidence.lower()


def test_check_6_4_exception():
    network_client = MagicMock()
    network_client.network_security_groups.list_all.side_effect = Exception("API error")

    result = _check_6_4(network_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_7_2 — VMs use Managed Disks for OS disks
# ---------------------------------------------------------------------------


def test_check_7_2_all_managed():
    vm = MagicMock()
    vm.name = "vm-prod"
    storage_profile = MagicMock()
    os_disk = MagicMock()
    os_disk.managed_disk = MagicMock()
    storage_profile.os_disk = os_disk
    vm.storage_profile = storage_profile

    compute_client = MagicMock()
    compute_client.virtual_machines.list_all.return_value = [vm]

    result = _check_7_2(compute_client)
    assert result.status == CheckStatus.PASS


def test_check_7_2_unmanaged_disk():
    vm = MagicMock()
    vm.name = "vm-legacy"
    storage_profile = MagicMock()
    os_disk = MagicMock()
    os_disk.managed_disk = None
    storage_profile.os_disk = os_disk
    vm.storage_profile = storage_profile

    compute_client = MagicMock()
    compute_client.virtual_machines.list_all.return_value = [vm]

    result = _check_7_2(compute_client)
    assert result.status == CheckStatus.FAIL
    assert "vm-legacy" in result.evidence


def test_check_7_2_exception():
    compute_client = MagicMock()
    compute_client.virtual_machines.list_all.side_effect = Exception("API error")

    result = _check_7_2(compute_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_7_3 — OS and data disks encrypted with CMK
# ---------------------------------------------------------------------------


def test_check_7_3_all_cmk():
    disk = MagicMock()
    disk.name = "disk-prod"
    encryption = MagicMock()
    encryption.type = "EncryptionAtRestWithCustomerManagedKey"
    disk.encryption = encryption

    compute_client = MagicMock()
    compute_client.disks.list.return_value = [disk]

    result = _check_7_3(compute_client)
    assert result.status == CheckStatus.PASS


def test_check_7_3_platform_managed():
    disk = MagicMock()
    disk.name = "disk-default"
    encryption = MagicMock()
    encryption.type = "EncryptionAtRestWithPlatformKey"
    disk.encryption = encryption

    compute_client = MagicMock()
    compute_client.disks.list.return_value = [disk]

    result = _check_7_3(compute_client)
    assert result.status == CheckStatus.FAIL
    assert "disk-default" in result.evidence


def test_check_7_3_no_encryption():
    disk = MagicMock()
    disk.name = "disk-none"
    disk.encryption = None

    compute_client = MagicMock()
    compute_client.disks.list.return_value = [disk]

    result = _check_7_3(compute_client)
    assert result.status == CheckStatus.FAIL
    assert "disk-none" in result.evidence


def test_check_7_3_exception():
    compute_client = MagicMock()
    compute_client.disks.list.side_effect = Exception("API error")

    result = _check_7_3(compute_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_8_3 — Key Vault recoverable (soft delete + purge protection)
# ---------------------------------------------------------------------------


def test_check_8_3_fully_recoverable():
    vault = MagicMock()
    vault.name = "my-vault"
    vault.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.KeyVault/vaults/my-vault"

    full_vault = MagicMock()
    props = MagicMock()
    props.enable_soft_delete = True
    props.enable_purge_protection = True
    full_vault.properties = props

    kv_client = MagicMock()
    kv_client.vaults.list.return_value = [vault]
    kv_client.vaults.get.return_value = full_vault

    result = _check_8_3(kv_client, "sub-123")
    assert result.status == CheckStatus.PASS


def test_check_8_3_missing_purge_protection():
    vault = MagicMock()
    vault.name = "my-vault"
    vault.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.KeyVault/vaults/my-vault"

    full_vault = MagicMock()
    props = MagicMock()
    props.enable_soft_delete = True
    props.enable_purge_protection = False
    full_vault.properties = props

    kv_client = MagicMock()
    kv_client.vaults.list.return_value = [vault]
    kv_client.vaults.get.return_value = full_vault

    result = _check_8_3(kv_client, "sub-123")
    assert result.status == CheckStatus.FAIL
    assert "my-vault" in result.evidence


def test_check_8_3_missing_soft_delete():
    vault = MagicMock()
    vault.name = "my-vault"
    vault.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.KeyVault/vaults/my-vault"

    full_vault = MagicMock()
    props = MagicMock()
    props.enable_soft_delete = False
    props.enable_purge_protection = True
    full_vault.properties = props

    kv_client = MagicMock()
    kv_client.vaults.list.return_value = [vault]
    kv_client.vaults.get.return_value = full_vault

    result = _check_8_3(kv_client, "sub-123")
    assert result.status == CheckStatus.FAIL
    assert "my-vault" in result.evidence


def test_check_8_3_exception():
    kv_client = MagicMock()
    kv_client.vaults.list.side_effect = Exception("API error")

    result = _check_8_3(kv_client, "sub-123")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_9_1 — App Service Authentication enabled
# ---------------------------------------------------------------------------


def test_check_9_1_auth_enabled():
    app = MagicMock()
    app.name = "my-app"
    app.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Web/sites/my-app"

    auth_settings = MagicMock()
    auth_settings.enabled = True

    webapp_client = MagicMock()
    webapp_client.web_apps.list.return_value = [app]
    webapp_client.web_apps.get_auth_settings.return_value = auth_settings

    result = _check_9_1(webapp_client)
    assert result.status == CheckStatus.PASS


def test_check_9_1_auth_disabled():
    app = MagicMock()
    app.name = "my-app"
    app.id = "/subscriptions/sub-123/resourceGroups/my-rg/providers/Microsoft.Web/sites/my-app"

    auth_settings = MagicMock()
    auth_settings.enabled = False

    webapp_client = MagicMock()
    webapp_client.web_apps.list.return_value = [app]
    webapp_client.web_apps.get_auth_settings.return_value = auth_settings

    result = _check_9_1(webapp_client)
    assert result.status == CheckStatus.FAIL
    assert "my-app" in result.evidence


def test_check_9_1_exception():
    webapp_client = MagicMock()
    webapp_client.web_apps.list.side_effect = Exception("API error")

    result = _check_9_1(webapp_client)
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_9_2 — Web app redirects HTTP to HTTPS
# ---------------------------------------------------------------------------


def test_check_9_2_https_only():
    app = MagicMock()
    app.name = "my-app"
    app.https_only = True

    webapp_client = MagicMock()
    webapp_client.web_apps.list.return_value = [app]

    result = _check_9_2(webapp_client)
    assert result.status == CheckStatus.PASS


def test_check_9_2_no_https():
    app = MagicMock()
    app.name = "insecure-app"
    app.https_only = False

    webapp_client = MagicMock()
    webapp_client.web_apps.list.return_value = [app]

    result = _check_9_2(webapp_client)
    assert result.status == CheckStatus.FAIL
    assert "insecure-app" in result.evidence


def test_check_9_2_exception():
    webapp_client = MagicMock()
    webapp_client.web_apps.list.side_effect = Exception("API error")

    result = _check_9_2(webapp_client)
    assert result.status == CheckStatus.ERROR
