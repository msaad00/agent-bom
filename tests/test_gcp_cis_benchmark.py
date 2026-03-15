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
    _check_1_1,
    _check_1_2,
    _check_1_6,
    _check_1_7,
    _check_2_3,
    _check_3_1,
    _check_3_2,
    _check_3_3,
    _check_3_6,
    _check_3_7,
    _check_3_9,
    _check_4_1,
    _check_4_2,
    _check_4_3,
    _check_5_1,
    _check_5_2,
    _check_6_1,
    _check_6_2,
    _check_7_1,
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
# Helpers — mock CRM (IAM policy) and SQL admin via googleapiclient.discovery
# ---------------------------------------------------------------------------


def _ensure_googleapiclient_namespace():
    """Ensure googleapiclient.discovery namespace modules exist in sys.modules."""
    ga_mod = sys.modules.get("googleapiclient") or types.ModuleType("googleapiclient")
    ga_discovery = sys.modules.get("googleapiclient.discovery") or types.ModuleType("googleapiclient.discovery")
    # Ensure 'build' exists so unittest.mock.patch can find the attribute
    if not hasattr(ga_discovery, "build"):
        ga_discovery.build = None
    ga_mod.discovery = ga_discovery
    sys.modules.setdefault("googleapiclient", ga_mod)
    sys.modules.setdefault("googleapiclient.discovery", ga_discovery)
    return ga_mod, ga_discovery


def _mock_crm_with_policy(bindings):
    """Install fake googleapiclient and return a CRM mock with given IAM bindings."""
    _ensure_googleapiclient_namespace()
    mock_crm = MagicMock()
    mock_crm.projects.return_value.getIamPolicy.return_value.execute.return_value = {
        "bindings": bindings,
    }
    return mock_crm


def _mock_sqladmin_with_instances(instances):
    """Install fake googleapiclient and return a sqladmin mock with given instances."""
    _ensure_googleapiclient_namespace()
    mock_sqladmin = MagicMock()
    mock_sqladmin.instances.return_value.list.return_value.execute.return_value = {
        "items": instances,
    }
    return mock_sqladmin


def _install_mock_gcp_compute_extended(
    networks_list=None,
    firewalls_list=None,
    subnets_aggregated=None,
    instances_aggregated=None,
):
    """Install a fake google.cloud.compute_v1 with SubnetworksClient and InstancesClient."""
    google_mod, google_cloud = _ensure_google_namespace()
    compute_mod = types.ModuleType("google.cloud.compute_v1")

    mock_networks_client = MagicMock()
    mock_networks_client.return_value.list.return_value = networks_list or []
    mock_firewalls_client = MagicMock()
    mock_firewalls_client.return_value.list.return_value = firewalls_list or []

    mock_subnets_client = MagicMock()
    mock_subnets_client.return_value.aggregated_list.return_value = subnets_aggregated or []
    mock_instances_client = MagicMock()
    mock_instances_client.return_value.aggregated_list.return_value = instances_aggregated or []

    compute_mod.NetworksClient = mock_networks_client
    compute_mod.FirewallsClient = mock_firewalls_client
    compute_mod.SubnetworksClient = mock_subnets_client
    compute_mod.InstancesClient = mock_instances_client

    google_cloud.compute_v1 = compute_mod
    sys.modules["google.cloud.compute_v1"] = compute_mod
    return compute_mod


# ---------------------------------------------------------------------------
# _check_1_6 — Service account admin privileges
# ---------------------------------------------------------------------------


def test_check_1_6_pass_no_sa_admin():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/viewer", "members": ["serviceAccount:sa1@proj.iam.gserviceaccount.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_6("my-project")
    assert result.status == CheckStatus.PASS


def test_check_1_6_fail_sa_has_owner():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/owner", "members": ["serviceAccount:admin-sa@proj.iam.gserviceaccount.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_6("my-project")
    assert result.status == CheckStatus.FAIL
    assert "admin-sa@proj" in result.evidence


def test_check_1_6_fail_sa_has_iam_admin():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/iam.admin", "members": ["serviceAccount:iam-sa@proj.iam.gserviceaccount.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_6("my-project")
    assert result.status == CheckStatus.FAIL


def test_check_1_6_ignores_non_sa_members():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/owner", "members": ["user:admin@example.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_6("my-project")
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# _check_1_7 — User-managed service account admin privileges
# ---------------------------------------------------------------------------


def test_check_1_7_pass_no_sa_admin_roles():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/viewer", "members": ["serviceAccount:sa1@proj.iam.gserviceaccount.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_7("my-project")
    assert result.status == CheckStatus.PASS


def test_check_1_7_fail_sa_has_service_account_admin():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/iam.serviceAccountAdmin", "members": ["serviceAccount:dev-sa@proj.iam.gserviceaccount.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_7("my-project")
    assert result.status == CheckStatus.FAIL
    assert "dev-sa@proj" in result.evidence


def test_check_1_7_fail_sa_has_compute_admin():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/compute.admin", "members": ["serviceAccount:compute-sa@proj.iam.gserviceaccount.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_7("my-project")
    assert result.status == CheckStatus.FAIL


def test_check_1_7_ignores_non_sa_members():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/iam.serviceAccountAdmin", "members": ["user:admin@example.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_7("my-project")
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# _check_3_2 — Legacy networks
# ---------------------------------------------------------------------------


def test_check_3_2_pass_no_legacy_networks():
    net = MagicMock()
    net.name = "custom-vpc"
    net.auto_create_subnetworks = True
    _install_mock_gcp_compute(networks_list=[net])
    result = _check_3_2("my-project")
    assert result.status == CheckStatus.PASS


def test_check_3_2_fail_legacy_network_exists():
    legacy_net = MagicMock(spec=[])  # empty spec so getattr returns None
    legacy_net.name = "legacy-net"
    # auto_create_subnetworks is not set (None) — indicating legacy network
    _install_mock_gcp_compute(networks_list=[legacy_net])
    result = _check_3_2("my-project")
    assert result.status == CheckStatus.FAIL
    assert "legacy-net" in result.evidence


def test_check_3_2_pass_auto_create_false():
    """A custom-mode network (auto_create_subnetworks=False) is not legacy."""
    net = MagicMock()
    net.name = "custom-mode"
    net.auto_create_subnetworks = False
    _install_mock_gcp_compute(networks_list=[net])
    result = _check_3_2("my-project")
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# _check_3_9 — VPC Flow Logs
# ---------------------------------------------------------------------------


def _make_subnet(name: str, flow_logs_enabled: bool | None):
    """Create a mock subnet with optional log_config."""
    subnet = MagicMock()
    subnet.name = name
    if flow_logs_enabled is None:
        subnet.log_config = None
    else:
        subnet.log_config = MagicMock()
        subnet.log_config.enable = flow_logs_enabled
    return subnet


def test_check_3_9_pass_all_subnets_have_flow_logs():
    s1 = _make_subnet("subnet-a", True)
    s2 = _make_subnet("subnet-b", True)
    response = MagicMock()
    response.subnetworks = [s1, s2]
    _install_mock_gcp_compute_extended(subnets_aggregated=[("us-central1", response)])
    result = _check_3_9("my-project")
    assert result.status == CheckStatus.PASS
    assert "2 subnet" in result.evidence


def test_check_3_9_fail_subnet_without_flow_logs():
    s1 = _make_subnet("subnet-good", True)
    s2 = _make_subnet("subnet-bad", False)
    response = MagicMock()
    response.subnetworks = [s1, s2]
    _install_mock_gcp_compute_extended(subnets_aggregated=[("us-central1", response)])
    result = _check_3_9("my-project")
    assert result.status == CheckStatus.FAIL
    assert "subnet-bad" in result.evidence


def test_check_3_9_fail_subnet_no_log_config():
    s1 = _make_subnet("subnet-noconfig", None)
    response = MagicMock()
    response.subnetworks = [s1]
    _install_mock_gcp_compute_extended(subnets_aggregated=[("us-east1", response)])
    result = _check_3_9("my-project")
    assert result.status == CheckStatus.FAIL
    assert "subnet-noconfig" in result.evidence


# ---------------------------------------------------------------------------
# _check_4_1 — Default service account on instances
# ---------------------------------------------------------------------------


def _make_instance(name: str, sa_email: str | None = None, metadata_items=None):
    """Create a mock compute instance."""
    instance = MagicMock()
    instance.name = name
    if sa_email:
        sa = MagicMock()
        sa.email = sa_email
        instance.service_accounts = [sa]
    else:
        instance.service_accounts = []
    if metadata_items is not None:
        instance.metadata = MagicMock()
        instance.metadata.items = metadata_items
    else:
        instance.metadata = None
    return instance


def test_check_4_1_pass_custom_service_account():
    inst = _make_instance("vm-1", sa_email="custom-sa@proj.iam.gserviceaccount.com")
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-central1-a", response)])
    result = _check_4_1("my-project")
    assert result.status == CheckStatus.PASS


def test_check_4_1_fail_default_service_account():
    inst = _make_instance("vm-default", sa_email="123456789-compute@developer.gserviceaccount.com")
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-central1-a", response)])
    result = _check_4_1("my-project")
    assert result.status == CheckStatus.FAIL
    assert "vm-default" in result.evidence


def test_check_4_1_pass_no_service_account():
    inst = _make_instance("vm-nosa")
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-west1-b", response)])
    result = _check_4_1("my-project")
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# _check_4_3 — Block project-wide SSH keys
# ---------------------------------------------------------------------------


def _make_metadata_item(key: str, value: str):
    item = MagicMock()
    item.key = key
    item.value = value
    return item


def test_check_4_3_pass_ssh_keys_blocked():
    items = [_make_metadata_item("block-project-ssh-keys", "true")]
    inst = _make_instance("vm-secure", sa_email="sa@proj.iam.gserviceaccount.com", metadata_items=items)
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-central1-a", response)])
    result = _check_4_3("my-project")
    assert result.status == CheckStatus.PASS


def test_check_4_3_fail_ssh_keys_not_blocked():
    inst = _make_instance("vm-open", sa_email="sa@proj.iam.gserviceaccount.com", metadata_items=[])
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-central1-a", response)])
    result = _check_4_3("my-project")
    assert result.status == CheckStatus.FAIL
    assert "vm-open" in result.evidence


def test_check_4_3_fail_ssh_keys_set_to_false():
    items = [_make_metadata_item("block-project-ssh-keys", "false")]
    inst = _make_instance("vm-false", sa_email="sa@proj.iam.gserviceaccount.com", metadata_items=items)
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-central1-a", response)])
    result = _check_4_3("my-project")
    assert result.status == CheckStatus.FAIL
    assert "vm-false" in result.evidence


def test_check_4_3_fail_no_metadata():
    inst = _make_instance("vm-nometa", sa_email="sa@proj.iam.gserviceaccount.com")
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-east1-b", response)])
    result = _check_4_3("my-project")
    assert result.status == CheckStatus.FAIL
    assert "vm-nometa" in result.evidence


# ---------------------------------------------------------------------------
# _check_6_1 — Cloud SQL require SSL
# ---------------------------------------------------------------------------


def test_check_6_1_pass_ssl_required():
    mock_sqladmin = _mock_sqladmin_with_instances(
        [
            {"name": "db-1", "settings": {"ipConfiguration": {"requireSsl": True}}},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_sqladmin):
        result = _check_6_1("my-project")
    assert result.status == CheckStatus.PASS


def test_check_6_1_fail_ssl_not_required():
    mock_sqladmin = _mock_sqladmin_with_instances(
        [
            {"name": "db-insecure", "settings": {"ipConfiguration": {"requireSsl": False}}},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_sqladmin):
        result = _check_6_1("my-project")
    assert result.status == CheckStatus.FAIL
    assert "db-insecure" in result.evidence


def test_check_6_1_fail_no_ssl_key():
    mock_sqladmin = _mock_sqladmin_with_instances(
        [
            {"name": "db-nokey", "settings": {"ipConfiguration": {}}},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_sqladmin):
        result = _check_6_1("my-project")
    assert result.status == CheckStatus.FAIL
    assert "db-nokey" in result.evidence


def test_check_6_1_pass_multiple_instances_all_ssl():
    mock_sqladmin = _mock_sqladmin_with_instances(
        [
            {"name": "db-a", "settings": {"ipConfiguration": {"requireSsl": True}}},
            {"name": "db-b", "settings": {"ipConfiguration": {"requireSsl": True}}},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_sqladmin):
        result = _check_6_1("my-project")
    assert result.status == CheckStatus.PASS
    assert "2 Cloud SQL" in result.evidence


# ---------------------------------------------------------------------------
# _check_1_1 — Corporate login credentials (gmail check)
# ---------------------------------------------------------------------------


def test_check_1_1_pass_no_gmail_accounts():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/viewer", "members": ["user:alice@corp.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_1("my-project")
    assert result.status == CheckStatus.PASS
    assert "No gmail.com" in result.evidence


def test_check_1_1_fail_gmail_account():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/editor", "members": ["user:dev@gmail.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_1("my-project")
    assert result.status == CheckStatus.FAIL
    assert "dev@gmail.com" in result.evidence


def test_check_1_1_pass_mixed_no_gmail():
    mock_crm = _mock_crm_with_policy(
        [
            {"role": "roles/viewer", "members": ["user:admin@corp.com", "serviceAccount:sa@proj.iam.gserviceaccount.com"]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_1("my-project")
    assert result.status == CheckStatus.PASS


def test_check_1_1_error_on_exception():
    _ensure_googleapiclient_namespace()
    mock_crm = MagicMock()
    mock_crm.projects.return_value.getIamPolicy.return_value.execute.side_effect = Exception("API error")
    with patch("googleapiclient.discovery.build", return_value=mock_crm):
        result = _check_1_1("my-project")
    assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# _check_1_2 — NOT_APPLICABLE (MFA enforcement)
# ---------------------------------------------------------------------------


def test_check_1_2_returns_not_applicable():
    result = _check_1_2("my-project")
    assert result.status == CheckStatus.NOT_APPLICABLE
    assert "MFA" in result.evidence or "manual" in result.evidence.lower() or "Workspace" in result.evidence


# ---------------------------------------------------------------------------
# _check_2_3 — Log metric filter for Project Ownership changes
# ---------------------------------------------------------------------------


def _install_mock_gcp_logging(metrics=None):
    """Install a fake google.cloud.logging_v2 with MetricsServiceV2Client."""
    google_mod, google_cloud = _ensure_google_namespace()
    logging_mod = types.ModuleType("google.cloud.logging_v2")

    mock_client = MagicMock()
    mock_client.return_value.list_log_metrics.return_value = metrics or []
    logging_mod.MetricsServiceV2Client = mock_client

    # Also add ConfigServiceV2Client for other 2.x checks
    mock_config_client = MagicMock()
    logging_mod.ConfigServiceV2Client = mock_config_client

    google_cloud.logging_v2 = logging_mod
    sys.modules["google.cloud.logging_v2"] = logging_mod
    return logging_mod


def _make_log_metric(filter_str: str):
    """Create a mock log metric with a filter string."""
    metric = MagicMock()
    metric.filter = filter_str
    return metric


def test_check_2_3_pass_filter_exists():
    metrics = [_make_log_metric('protoPayload.serviceName="cloudresourcemanager" AND ProjectOwnership')]
    _install_mock_gcp_logging(metrics=metrics)
    result = _check_2_3("my-project")
    assert result.status == CheckStatus.PASS
    assert "exists" in result.evidence.lower() or "Project Ownership" in result.evidence


def test_check_2_3_fail_no_filter():
    metrics = [_make_log_metric("some.unrelated.filter")]
    _install_mock_gcp_logging(metrics=metrics)
    result = _check_2_3("my-project")
    assert result.status == CheckStatus.FAIL
    assert "No log metric" in result.evidence


def test_check_2_3_fail_empty_metrics():
    _install_mock_gcp_logging(metrics=[])
    result = _check_2_3("my-project")
    assert result.status == CheckStatus.FAIL


def test_check_2_3_pass_projectownerinvitee_keyword():
    metrics = [_make_log_metric("resource.type=project AND projectOwnerInvitee")]
    _install_mock_gcp_logging(metrics=metrics)
    result = _check_2_3("my-project")
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# _check_3_3 — DNSSEC enabled for Cloud DNS
# ---------------------------------------------------------------------------


def _mock_dns_with_zones(zones):
    """Install fake googleapiclient and return a DNS mock with given zones."""
    _ensure_googleapiclient_namespace()
    mock_dns = MagicMock()
    mock_dns.managedZones.return_value.list.return_value.execute.return_value = {
        "managedZones": zones,
    }
    return mock_dns


def test_check_3_3_pass_dnssec_enabled():
    zones = [
        {"name": "example-zone", "visibility": "public", "dnssecConfig": {"state": "on"}},
    ]
    mock_dns = _mock_dns_with_zones(zones)
    with patch("googleapiclient.discovery.build", return_value=mock_dns):
        result = _check_3_3("my-project")
    assert result.status == CheckStatus.PASS
    assert "1 public" in result.evidence or "enabled" in result.evidence.lower()


def test_check_3_3_fail_dnssec_not_enabled():
    zones = [
        {"name": "insecure-zone", "visibility": "public", "dnssecConfig": {"state": "off"}},
    ]
    mock_dns = _mock_dns_with_zones(zones)
    with patch("googleapiclient.discovery.build", return_value=mock_dns):
        result = _check_3_3("my-project")
    assert result.status == CheckStatus.FAIL
    assert "insecure-zone" in result.evidence


def test_check_3_3_pass_private_zone_ignored():
    zones = [
        {"name": "private-zone", "visibility": "private", "dnssecConfig": {"state": "off"}},
    ]
    mock_dns = _mock_dns_with_zones(zones)
    with patch("googleapiclient.discovery.build", return_value=mock_dns):
        result = _check_3_3("my-project")
    assert result.status == CheckStatus.PASS


def test_check_3_3_fail_no_dnssec_config():
    zones = [
        {"name": "no-config-zone", "visibility": "public"},
    ]
    mock_dns = _mock_dns_with_zones(zones)
    with patch("googleapiclient.discovery.build", return_value=mock_dns):
        result = _check_3_3("my-project")
    assert result.status == CheckStatus.FAIL
    assert "no-config-zone" in result.evidence


# ---------------------------------------------------------------------------
# _check_4_2 — Default SA with full API access on instances
# ---------------------------------------------------------------------------


def _make_instance_with_scopes(name: str, sa_email: str | None = None, scopes=None):
    """Create a mock compute instance with service account scopes."""
    instance = MagicMock()
    instance.name = name
    if sa_email:
        sa = MagicMock()
        sa.email = sa_email
        sa.scopes = scopes or []
        instance.service_accounts = [sa]
    else:
        instance.service_accounts = []
    instance.network_interfaces = []
    return instance


def test_check_4_2_pass_custom_sa():
    inst = _make_instance_with_scopes("vm-1", sa_email="custom-sa@proj.iam.gserviceaccount.com", scopes=["https://www.googleapis.com/auth/cloud-platform"])
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-central1-a", response)])
    result = _check_4_2("my-project")
    assert result.status == CheckStatus.PASS


def test_check_4_2_fail_default_sa_full_access():
    inst = _make_instance_with_scopes("vm-bad", sa_email="123456-compute@developer.gserviceaccount.com", scopes=["https://www.googleapis.com/auth/cloud-platform"])
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-central1-a", response)])
    result = _check_4_2("my-project")
    assert result.status == CheckStatus.FAIL
    assert "vm-bad" in result.evidence


def test_check_4_2_pass_default_sa_limited_scopes():
    inst = _make_instance_with_scopes("vm-limited", sa_email="123456-compute@developer.gserviceaccount.com", scopes=["https://www.googleapis.com/auth/devstorage.read_only"])
    response = MagicMock()
    response.instances = [inst]
    _install_mock_gcp_compute_extended(instances_aggregated=[("us-central1-a", response)])
    result = _check_4_2("my-project")
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# _check_5_2 — Uniform bucket-level access
# ---------------------------------------------------------------------------


def test_check_5_2_pass_uniform_access_enabled():
    bucket = MagicMock()
    bucket.name = "good-bucket"
    bucket.iam_configuration.uniform_bucket_level_access_enabled = True
    _install_mock_gcp_storage(buckets=[bucket])
    result = _check_5_2("my-project")
    assert result.status == CheckStatus.PASS
    assert "1 bucket" in result.evidence or "uniform" in result.evidence.lower()


def test_check_5_2_fail_uniform_access_disabled():
    bucket = MagicMock()
    bucket.name = "bad-bucket"
    bucket.iam_configuration.uniform_bucket_level_access_enabled = False
    _install_mock_gcp_storage(buckets=[bucket])
    result = _check_5_2("my-project")
    assert result.status == CheckStatus.FAIL
    assert "bad-bucket" in result.evidence


def test_check_5_2_pass_multiple_buckets_all_uniform():
    b1 = MagicMock()
    b1.name = "bucket-a"
    b1.iam_configuration.uniform_bucket_level_access_enabled = True
    b2 = MagicMock()
    b2.name = "bucket-b"
    b2.iam_configuration.uniform_bucket_level_access_enabled = True
    _install_mock_gcp_storage(buckets=[b1, b2])
    result = _check_5_2("my-project")
    assert result.status == CheckStatus.PASS
    assert "2 bucket" in result.evidence


# ---------------------------------------------------------------------------
# _check_6_2 — Cloud SQL instances with public IPs
# ---------------------------------------------------------------------------


def test_check_6_2_pass_no_public_ips():
    mock_sqladmin = _mock_sqladmin_with_instances(
        [
            {"name": "db-private", "ipAddresses": [{"type": "PRIVATE", "ipAddress": "10.0.0.1"}]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_sqladmin):
        result = _check_6_2("my-project")
    assert result.status == CheckStatus.PASS


def test_check_6_2_fail_public_ip():
    mock_sqladmin = _mock_sqladmin_with_instances(
        [
            {"name": "db-public", "ipAddresses": [{"type": "PRIMARY", "ipAddress": "34.1.2.3"}]},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_sqladmin):
        result = _check_6_2("my-project")
    assert result.status == CheckStatus.FAIL
    assert "db-public" in result.evidence


def test_check_6_2_pass_no_ip_addresses():
    mock_sqladmin = _mock_sqladmin_with_instances(
        [
            {"name": "db-noip", "ipAddresses": []},
        ]
    )
    with patch("googleapiclient.discovery.build", return_value=mock_sqladmin):
        result = _check_6_2("my-project")
    assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# _check_7_1 — BigQuery public dataset access
# ---------------------------------------------------------------------------


def _mock_bigquery_with_datasets(datasets_list, dataset_details=None):
    """Install fake googleapiclient and return a BigQuery mock."""
    _ensure_googleapiclient_namespace()
    mock_bq = MagicMock()
    mock_bq.datasets.return_value.list.return_value.execute.return_value = {
        "datasets": datasets_list,
    }
    if dataset_details:
        mock_bq.datasets.return_value.get.return_value.execute.side_effect = dataset_details
    return mock_bq


def test_check_7_1_pass_no_public_datasets():
    datasets = [{"datasetReference": {"datasetId": "private_ds"}}]
    detail = [{"access": [{"role": "READER", "userByEmail": "analyst@corp.com"}]}]
    mock_bq = _mock_bigquery_with_datasets(datasets, dataset_details=detail)
    with patch("googleapiclient.discovery.build", return_value=mock_bq):
        result = _check_7_1("my-project")
    assert result.status == CheckStatus.PASS


def test_check_7_1_fail_allusers_access():
    datasets = [{"datasetReference": {"datasetId": "public_ds"}}]
    detail = [{"access": [{"role": "READER", "specialGroup": "allUsers"}]}]
    mock_bq = _mock_bigquery_with_datasets(datasets, dataset_details=detail)
    with patch("googleapiclient.discovery.build", return_value=mock_bq):
        result = _check_7_1("my-project")
    assert result.status == CheckStatus.FAIL
    assert "public_ds" in result.evidence


def test_check_7_1_fail_allauthenticatedusers_access():
    datasets = [{"datasetReference": {"datasetId": "semi_public"}}]
    detail = [{"access": [{"role": "WRITER", "specialGroup": "allAuthenticatedUsers"}]}]
    mock_bq = _mock_bigquery_with_datasets(datasets, dataset_details=detail)
    with patch("googleapiclient.discovery.build", return_value=mock_bq):
        result = _check_7_1("my-project")
    assert result.status == CheckStatus.FAIL
    assert "semi_public" in result.evidence


def test_check_7_1_pass_empty_datasets():
    mock_bq = _mock_bigquery_with_datasets([], dataset_details=[])
    with patch("googleapiclient.discovery.build", return_value=mock_bq):
        result = _check_7_1("my-project")
    assert result.status == CheckStatus.PASS


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
