"""Tests for agent_bom.cloud.azure_cis_benchmark to improve coverage."""

from __future__ import annotations

from types import SimpleNamespace
from unittest.mock import MagicMock

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.azure_cis_benchmark import (
    AzureCISReport,
    _check_1_1,
    _check_1_2,
    _check_2_1,
    _check_2_2,
    _check_2_3,
    _check_3_1,
    _check_3_2,
    _check_3_7,
    _check_3_10,
    _check_4_1_1,
    _check_4_2_1,
    _check_5_1_1,
    _check_5_1_2,
    _check_6_1,
    _check_6_2,
    _check_6_3,
    _check_6_5,
    _check_7_1,
    _is_internet_exposed,
)

# ---------------------------------------------------------------------------
# AzureCISReport properties
# ---------------------------------------------------------------------------


def test_report_empty():
    r = AzureCISReport()
    assert r.passed == 0
    assert r.failed == 0
    assert r.total == 0
    assert r.pass_rate == 0.0


def test_report_with_checks():
    r = AzureCISReport(
        checks=[
            CISCheckResult(check_id="1.1", title="t", status=CheckStatus.PASS, severity="high"),
            CISCheckResult(check_id="1.2", title="t", status=CheckStatus.FAIL, severity="medium"),
            CISCheckResult(check_id="1.3", title="t", status=CheckStatus.ERROR, severity="low"),
        ]
    )
    assert r.passed == 1
    assert r.failed == 1
    assert r.total == 3
    assert r.pass_rate == 50.0


def test_report_to_dict():
    r = AzureCISReport(
        subscription_id="sub-123",
        checks=[
            CISCheckResult(check_id="1.1", title="Test", status=CheckStatus.PASS, severity="high"),
        ],
    )
    d = r.to_dict()
    assert d["benchmark"] == "CIS Microsoft Azure Foundations"
    assert d["subscription_id"] == "sub-123"
    assert d["passed"] == 1
    assert len(d["checks"]) == 1
    assert "attack_techniques" in d["checks"][0]


# ---------------------------------------------------------------------------
# _is_internet_exposed
# ---------------------------------------------------------------------------


def test_internet_exposed_rdp():
    rule = SimpleNamespace(
        direction="Inbound",
        access="Allow",
        source_address_prefix="0.0.0.0/0",
        destination_port_range="3389",
    )
    assert _is_internet_exposed(rule, "3389") is True


def test_not_exposed_wrong_direction():
    rule = SimpleNamespace(
        direction="Outbound",
        access="Allow",
        source_address_prefix="0.0.0.0/0",
        destination_port_range="3389",
    )
    assert _is_internet_exposed(rule, "3389") is False


def test_not_exposed_deny():
    rule = SimpleNamespace(
        direction="Inbound",
        access="Deny",
        source_address_prefix="0.0.0.0/0",
        destination_port_range="3389",
    )
    assert _is_internet_exposed(rule, "3389") is False


def test_not_exposed_private_source():
    rule = SimpleNamespace(
        direction="Inbound",
        access="Allow",
        source_address_prefix="10.0.0.0/8",
        destination_port_range="3389",
    )
    assert _is_internet_exposed(rule, "3389") is False


def test_exposed_wildcard_port():
    rule = SimpleNamespace(
        direction="Inbound",
        access="Allow",
        source_address_prefix="*",
        destination_port_range="*",
    )
    assert _is_internet_exposed(rule, "22") is True


def test_not_exposed_wrong_port():
    rule = SimpleNamespace(
        direction="Inbound",
        access="Allow",
        source_address_prefix="0.0.0.0/0",
        destination_port_range="80",
    )
    assert _is_internet_exposed(rule, "3389") is False


def test_exposed_internet_keyword():
    rule = SimpleNamespace(
        direction="Inbound",
        access="Allow",
        source_address_prefix="Internet",
        destination_port_range="22",
    )
    assert _is_internet_exposed(rule, "22") is True


# ---------------------------------------------------------------------------
# Individual check functions
# ---------------------------------------------------------------------------


def test_check_1_1_pass():
    auth = MagicMock()
    auth.role_assignments.list_for_scope.return_value = []
    r = _check_1_1(auth, "sub-123")
    assert r.status == CheckStatus.PASS


def test_check_1_1_error():
    auth = MagicMock()
    auth.role_assignments.list_for_scope.side_effect = Exception("denied")
    r = _check_1_1(auth, "sub-123")
    assert r.status == CheckStatus.ERROR


def test_check_1_1_with_owners():
    auth = MagicMock()
    ra = SimpleNamespace(
        role_definition_id="/providers/Microsoft.Authorization/roleDefinitions/8e3af657-a8ff-443c-a75c-2fe8c4bcb635",
        principal_id="user-1",
    )
    auth.role_assignments.list_for_scope.return_value = [ra]
    r = _check_1_1(auth, "sub-123")
    assert r.status == CheckStatus.PASS  # Can't confirm guest without Graph


def test_check_1_2_pass():
    auth = MagicMock()
    auth.role_assignments.list_for_scope.return_value = []
    r = _check_1_2(auth, "sub-123")
    assert r.status == CheckStatus.PASS


def test_check_1_2_error():
    auth = MagicMock()
    auth.role_assignments.list_for_scope.side_effect = RuntimeError("x")
    r = _check_1_2(auth, "sub-123")
    assert r.status == CheckStatus.ERROR


def test_check_2_1_pass():
    sec = MagicMock()
    sec.pricings.get.return_value = SimpleNamespace(pricing_tier="Standard")
    r = _check_2_1(sec, "sub-123")
    assert r.status == CheckStatus.PASS


def test_check_2_1_fail():
    sec = MagicMock()
    sec.pricings.get.return_value = SimpleNamespace(pricing_tier="Free")
    r = _check_2_1(sec, "sub-123")
    assert r.status == CheckStatus.FAIL


def test_check_2_2_pass():
    sec = MagicMock()
    sec.pricings.get.return_value = SimpleNamespace(pricing_tier="Standard")
    r = _check_2_2(sec, "sub-123")
    assert r.status == CheckStatus.PASS


def test_check_2_2_fail():
    sec = MagicMock()
    sec.pricings.get.return_value = SimpleNamespace(pricing_tier="Free")
    r = _check_2_2(sec, "sub-123")
    assert r.status == CheckStatus.FAIL


def test_check_2_3_pass():
    sec = MagicMock()
    sec.pricings.get.return_value = SimpleNamespace(pricing_tier="Standard")
    r = _check_2_3(sec, "sub-123")
    assert r.status == CheckStatus.PASS


def test_check_3_1_pass():
    st = MagicMock()
    acct = SimpleNamespace(name="acct1", enable_https_traffic_only=True)
    st.storage_accounts.list.return_value = [acct]
    r = _check_3_1(st)
    assert r.status == CheckStatus.PASS


def test_check_3_1_fail():
    st = MagicMock()
    acct = SimpleNamespace(name="acct1", enable_https_traffic_only=False)
    st.storage_accounts.list.return_value = [acct]
    r = _check_3_1(st)
    assert r.status == CheckStatus.FAIL


def test_check_3_7_pass():
    st = MagicMock()
    acct = SimpleNamespace(name="acct1", allow_blob_public_access=False)
    st.storage_accounts.list.return_value = [acct]
    r = _check_3_7(st)
    assert r.status == CheckStatus.PASS


def test_check_3_7_fail():
    st = MagicMock()
    acct = SimpleNamespace(name="acct1", allow_blob_public_access=True)
    st.storage_accounts.list.return_value = [acct]
    r = _check_3_7(st)
    assert r.status == CheckStatus.FAIL


def test_check_3_2_pass():
    st = MagicMock()
    nr = SimpleNamespace(default_action="Deny")
    acct = SimpleNamespace(name="acct1", network_rule_set=nr)
    st.storage_accounts.list.return_value = [acct]
    r = _check_3_2(st)
    assert r.status == CheckStatus.PASS


def test_check_3_2_fail():
    st = MagicMock()
    nr = SimpleNamespace(default_action="Allow")
    acct = SimpleNamespace(name="acct1", network_rule_set=nr)
    st.storage_accounts.list.return_value = [acct]
    r = _check_3_2(st)
    assert r.status == CheckStatus.FAIL


def test_check_3_10_pass():
    st = MagicMock()
    acct = SimpleNamespace(
        name="acct1",
        id="/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/acct1",
    )
    st.storage_accounts.list.return_value = [acct]
    retention = SimpleNamespace(enabled=True)
    blob_props = SimpleNamespace(delete_retention_policy=retention)
    st.blob_services.get_service_properties.return_value = blob_props
    r = _check_3_10(st)
    assert r.status == CheckStatus.PASS


def test_check_3_10_fail():
    st = MagicMock()
    acct = SimpleNamespace(
        name="acct1",
        id="/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Storage/storageAccounts/acct1",
    )
    st.storage_accounts.list.return_value = [acct]
    retention = SimpleNamespace(enabled=False)
    blob_props = SimpleNamespace(delete_retention_policy=retention)
    st.blob_services.get_service_properties.return_value = blob_props
    r = _check_3_10(st)
    assert r.status == CheckStatus.FAIL


def test_check_4_1_1_pass():
    sql = MagicMock()
    server = SimpleNamespace(
        name="srv1",
        id="/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Sql/servers/srv1",
    )
    sql.servers.list.return_value = [server]
    audit = SimpleNamespace(state="Enabled")
    sql.server_blob_auditing_policies.get.return_value = audit
    r = _check_4_1_1(sql)
    assert r.status == CheckStatus.PASS


def test_check_4_1_1_fail():
    sql = MagicMock()
    server = SimpleNamespace(
        name="srv1",
        id="/subscriptions/sub/resourceGroups/rg1/providers/Microsoft.Sql/servers/srv1",
    )
    sql.servers.list.return_value = [server]
    audit = SimpleNamespace(state="Disabled")
    sql.server_blob_auditing_policies.get.return_value = audit
    r = _check_4_1_1(sql)
    assert r.status == CheckStatus.FAIL


def test_check_4_2_1_pass():
    sql = MagicMock()
    server = SimpleNamespace(name="srv1", minimal_tls_version="1.2")
    sql.servers.list.return_value = [server]
    r = _check_4_2_1(sql)
    assert r.status == CheckStatus.PASS


def test_check_4_2_1_fail():
    sql = MagicMock()
    server = SimpleNamespace(name="srv1", minimal_tls_version="1.0")
    sql.servers.list.return_value = [server]
    r = _check_4_2_1(sql)
    assert r.status == CheckStatus.FAIL


def test_check_4_2_1_no_tls():
    sql = MagicMock()
    server = SimpleNamespace(name="srv1", minimal_tls_version=None)
    sql.servers.list.return_value = [server]
    r = _check_4_2_1(sql)
    assert r.status == CheckStatus.FAIL


def test_check_5_1_1_pass():
    mon = MagicMock()
    mon.diagnostic_settings.list.return_value = [SimpleNamespace()]
    r = _check_5_1_1(mon, "sub-123")
    assert r.status == CheckStatus.PASS


def test_check_5_1_1_fail():
    mon = MagicMock()
    mon.diagnostic_settings.list.return_value = []
    r = _check_5_1_1(mon, "sub-123")
    assert r.status == CheckStatus.FAIL


def test_check_5_1_2_pass():
    mon = MagicMock()
    profile = SimpleNamespace(
        name="p1",
        retention_policy=SimpleNamespace(enabled=True, days=365),
    )
    mon.log_profiles.list.return_value = [profile]
    r = _check_5_1_2(mon, "sub-123")
    assert r.status == CheckStatus.PASS


def test_check_5_1_2_fail_short_retention():
    mon = MagicMock()
    profile = SimpleNamespace(
        name="p1",
        retention_policy=SimpleNamespace(enabled=True, days=30),
    )
    mon.log_profiles.list.return_value = [profile]
    r = _check_5_1_2(mon, "sub-123")
    assert r.status == CheckStatus.FAIL


def test_check_5_1_2_fail_no_profiles():
    mon = MagicMock()
    mon.log_profiles.list.return_value = []
    r = _check_5_1_2(mon, "sub-123")
    assert r.status == CheckStatus.FAIL


def test_check_5_1_2_retention_disabled():
    mon = MagicMock()
    profile = SimpleNamespace(
        name="p1",
        retention_policy=SimpleNamespace(enabled=False, days=0),
    )
    mon.log_profiles.list.return_value = [profile]
    r = _check_5_1_2(mon, "sub-123")
    assert r.status == CheckStatus.FAIL
    assert "disabled" in r.evidence.lower()


def test_check_6_1_pass():
    net = MagicMock()
    nsg = SimpleNamespace(name="nsg1", security_rules=[])
    net.network_security_groups.list_all.return_value = [nsg]
    r = _check_6_1(net)
    assert r.status == CheckStatus.PASS


def test_check_6_1_fail():
    net = MagicMock()
    rule = SimpleNamespace(
        name="allow-rdp",
        direction="Inbound",
        access="Allow",
        source_address_prefix="0.0.0.0/0",
        destination_port_range="3389",
    )
    nsg = SimpleNamespace(name="nsg1", security_rules=[rule])
    net.network_security_groups.list_all.return_value = [nsg]
    r = _check_6_1(net)
    assert r.status == CheckStatus.FAIL


def test_check_6_2_pass():
    net = MagicMock()
    net.network_security_groups.list_all.return_value = []
    r = _check_6_2(net)
    assert r.status == CheckStatus.PASS


def test_check_6_3_pass():
    net = MagicMock()
    net.network_security_groups.list_all.return_value = []
    r = _check_6_3(net)
    assert r.status == CheckStatus.PASS


def test_check_6_5_pass():
    net = MagicMock()
    watcher = SimpleNamespace(location="eastus")
    net.network_watchers.list_all.return_value = [watcher]
    r = _check_6_5(net)
    assert r.status == CheckStatus.PASS


def test_check_6_5_fail():
    net = MagicMock()
    net.network_watchers.list_all.return_value = []
    r = _check_6_5(net)
    assert r.status == CheckStatus.FAIL


def test_check_7_1_pass():
    compute = MagicMock()
    vm = SimpleNamespace(
        name="vm1",
        storage_profile=SimpleNamespace(os_disk=SimpleNamespace(managed_disk=SimpleNamespace(id="md1"))),
    )
    compute.virtual_machines.list_all.return_value = [vm]
    r = _check_7_1(compute)
    assert r.status == CheckStatus.PASS


def test_check_7_1_fail():
    compute = MagicMock()
    vm = SimpleNamespace(
        name="vm1",
        storage_profile=SimpleNamespace(os_disk=SimpleNamespace(managed_disk=None)),
    )
    compute.virtual_machines.list_all.return_value = [vm]
    r = _check_7_1(compute)
    assert r.status == CheckStatus.FAIL
