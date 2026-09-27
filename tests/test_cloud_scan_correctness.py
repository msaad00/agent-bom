"""Regression tests for cloud-scan correctness defects found on real AWS/Azure/GCP accounts.

Each test pins one defect: scan identity collisions across clouds, push
rollback deleting a pre-existing snapshot, alert formatting aborting a push,
CLI scope not reaching inventory/CIS, S3 public-exposure false positives, GCP
403 misclassification, and Azure CIS checks that passed or failed without
real evidence.
"""

from __future__ import annotations

from types import SimpleNamespace
from typing import Any
from unittest.mock import MagicMock

import pytest
from starlette.testclient import TestClient

from agent_bom.cloud.aws_cis_benchmark import CheckStatus

# ---------------------------------------------------------------------------
# 1. Scan identity
# ---------------------------------------------------------------------------


def test_cloud_only_scans_with_different_scope_get_different_ids() -> None:
    from agent_bom.cli.agents.scan_cmd import _compute_scan_id

    azure = _compute_scan_id(
        pkg_fingerprints=[],
        endpoint_fingerprint="",
        cloud_scope={"azure": {"subscription": "sub-a"}},
        reproducible=True,
    )
    gcp = _compute_scan_id(
        pkg_fingerprints=[],
        endpoint_fingerprint="",
        cloud_scope={"gcp": {"project": "proj-b"}},
        reproducible=True,
    )
    aws_east1 = _compute_scan_id(
        pkg_fingerprints=[], endpoint_fingerprint="", cloud_scope={"aws": {"region": "us-east-1"}}, reproducible=True
    )
    aws_east2 = _compute_scan_id(
        pkg_fingerprints=[], endpoint_fingerprint="", cloud_scope={"aws": {"region": "us-east-2"}}, reproducible=True
    )
    assert len({azure, gcp, aws_east1, aws_east2}) == 4


def test_scan_id_is_unique_per_run_unless_reproducible() -> None:
    from agent_bom.cli.agents.scan_cmd import _compute_scan_id

    kwargs: dict[str, Any] = {"pkg_fingerprints": [], "endpoint_fingerprint": "", "cloud_scope": {"azure": {"subscription": "s"}}}
    assert _compute_scan_id(**kwargs, reproducible=False) != _compute_scan_id(**kwargs, reproducible=False)
    assert _compute_scan_id(**kwargs, reproducible=True) == _compute_scan_id(**kwargs, reproducible=True)


def test_cli_cloud_scope_includes_requested_provider_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cli.agents.scan_cmd import _cloud_scan_scope

    for var in ("AWS_REGION", "AWS_DEFAULT_REGION", "AWS_PROFILE", "AZURE_SUBSCRIPTION_ID", "GOOGLE_CLOUD_PROJECT"):
        monkeypatch.delenv(var, raising=False)
    scope = _cloud_scan_scope(
        providers=["aws"],
        aws_region="us-east-2",
        aws_profile="audit",
        azure_subscription=None,
        gcp_project=None,
    )
    assert scope == {"aws": {"profile": "audit", "region": "us-east-2"}}
    monkeypatch.setenv("GOOGLE_CLOUD_PROJECT", "env-proj")
    assert _cloud_scan_scope(providers=["gcp"], aws_region=None, aws_profile=None, azure_subscription=None, gcp_project=None) == {
        "gcp": {"project": "env-proj"}
    }


# ---------------------------------------------------------------------------
# 1b. Push rollback must never delete a pre-existing snapshot
# ---------------------------------------------------------------------------


@pytest.fixture()
def _push_env(tmp_path, monkeypatch: pytest.MonkeyPatch):
    from agent_bom.api import stores
    from agent_bom.api.fleet_store import InMemoryFleetStore
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.idempotency_store import InMemoryIdempotencyStore
    from agent_bom.api.server import set_fleet_store, set_graph_store, set_job_store
    from agent_bom.api.store import InMemoryJobStore
    from agent_bom.api.stores import set_idempotency_store

    original = (stores._get_store(), stores._get_fleet_store(), stores._get_graph_store(), stores._get_idempotency_store())
    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    set_job_store(InMemoryJobStore())
    set_fleet_store(InMemoryFleetStore())
    set_graph_store(graph_store)
    set_idempotency_store(InMemoryIdempotencyStore())
    yield graph_store
    set_job_store(original[0])
    set_fleet_store(original[1])
    set_graph_store(original[2])
    set_idempotency_store(original[3])


def test_failed_push_does_not_delete_preexisting_snapshot_with_same_scan_id(_push_env, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.server import app
    from agent_bom.graph.container import UnifiedGraph

    graph_store = _push_env
    graph_store.save_graph(UnifiedGraph(scan_id="shared-scan", tenant_id="default"))

    def _fail(_job, _report):
        raise RuntimeError("graph write failed")

    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", _fail)
    response = TestClient(app, raise_server_exceptions=False).post("/v1/results/push", json={"scan_id": "shared-scan", "agents": []})

    assert response.status_code == 503
    assert graph_store.latest_snapshot_id(tenant_id="default") == "shared-scan"


def test_failed_push_still_rolls_back_snapshot_it_created(_push_env, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api.server import app
    from agent_bom.graph.container import UnifiedGraph

    graph_store = _push_env

    def _write_then_fail(_job, report):
        graph_store.save_graph(UnifiedGraph(scan_id=report["scan_id"], tenant_id="default"))
        raise RuntimeError("post-write failure")

    monkeypatch.setattr("agent_bom.api.routes.observability._persist_graph_snapshot", _write_then_fail)
    response = TestClient(app, raise_server_exceptions=False).post("/v1/results/push", json={"scan_id": "fresh-scan", "agents": []})

    assert response.status_code == 503
    assert graph_store.latest_snapshot_id(tenant_id="default") == ""


# ---------------------------------------------------------------------------
# 2. Alert formatting never fails the push
# ---------------------------------------------------------------------------


def test_siem_formatting_tolerates_empty_node_ids() -> None:
    from agent_bom.graph.webhooks import format_alerts_for_siem

    events = format_alerts_for_siem(
        [{"type": "new_attack_path", "severity": "high", "title": "t", "description": "d", "node_ids": [], "scan_id": "s"}]
    )
    assert events[0]["finding_info"]["uid"] == "delta:s:new_attack_path"


def test_siem_formatting_tolerates_sparse_alert() -> None:
    from agent_bom.graph.webhooks import format_alerts_for_siem

    events = format_alerts_for_siem([{"type": "x"}])
    assert events[0]["finding_info"]["title"] == ""


def test_delta_alert_failure_does_not_fail_graph_persist(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.api import pipeline
    from agent_bom.api.graph_store import SQLiteGraphStore
    from agent_bom.api.models import ScanJob, ScanRequest

    graph_store = SQLiteGraphStore(tmp_path / "graph.db")
    monkeypatch.setattr(pipeline, "_get_graph_store", lambda: graph_store)
    monkeypatch.setattr("agent_bom.graph.delta_digest.compute_delta_alerts_from_digest", lambda *_a, **_k: [{"node_ids": []}])
    monkeypatch.setattr(
        "agent_bom.graph.webhooks.dispatch_delta_alerts", lambda *_a, **_k: (_ for _ in ()).throw(IndexError("list index out of range"))
    )
    job = ScanJob(job_id="job-1", tenant_id="default", created_at="2026-09-27T00:00:00Z", request=ScanRequest())

    pipeline._persist_graph_snapshot(job, {"scan_id": "scan-alert", "agents": []})

    assert graph_store.latest_snapshot_id(tenant_id="default") == "scan-alert"


# ---------------------------------------------------------------------------
# 3. CLI scope reaches estate inventory
# ---------------------------------------------------------------------------


def test_inventory_receives_cli_scope(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom import scan_enrichment
    from agent_bom.cloud import aws_inventory, aws_organizations, azure_inventory, gcp_inventory, gcp_organizations

    calls: dict[str, Any] = {}
    monkeypatch.setattr(aws_inventory, "inventory_enabled", lambda: True)
    monkeypatch.setattr(aws_organizations, "org_fanout_enabled", lambda: False)
    monkeypatch.setattr(
        aws_inventory, "discover_inventory", lambda region=None, profile=None, **_k: calls.update(aws=(region, profile)) or {}
    )
    monkeypatch.setattr(azure_inventory, "inventory_enabled", lambda: True)
    monkeypatch.setattr(azure_inventory, "all_subscriptions_enabled", lambda: False)
    monkeypatch.setattr(azure_inventory, "discover_inventory", lambda subscription_id=None, **_k: calls.update(azure=subscription_id) or {})
    monkeypatch.setattr(gcp_inventory, "inventory_enabled", lambda: True)
    monkeypatch.setattr(gcp_inventory, "all_projects_enabled", lambda: False)
    monkeypatch.setattr(gcp_inventory, "discover_inventory", lambda project_id=None, **_k: calls.update(gcp=project_id) or {})
    monkeypatch.setattr(gcp_organizations, "discover_organization", lambda *a, **k: {"status": "disabled"})

    scan_enrichment.collect_cloud_inventory(aws_region="us-east-2", aws_profile="audit", azure_subscription="sub-1", gcp_project="proj-1")

    assert calls == {"aws": ("us-east-2", "audit"), "azure": "sub-1", "gcp": "proj-1"}


# ---------------------------------------------------------------------------
# 4. S3 public exposure requires an actual grant
# ---------------------------------------------------------------------------


class _NoSuchError(Exception):
    pass


def _s3(*, policy_public: bool = False, acl_grants: list | None = None, block: dict | None = None) -> MagicMock:
    s3 = MagicMock()
    s3.get_bucket_policy_status.return_value = {"PolicyStatus": {"IsPublic": policy_public}}
    if policy_public is None:
        s3.get_bucket_policy_status.side_effect = _NoSuchError("NoSuchBucketPolicy")
    s3.get_bucket_acl.return_value = {"Grants": acl_grants or []}
    if block is None:
        s3.get_public_access_block.side_effect = _NoSuchError("NoSuchPublicAccessBlockConfiguration")
    else:
        s3.get_public_access_block.return_value = {"PublicAccessBlockConfiguration": block}
    return s3


_ALL_USERS = {"Grantee": {"Type": "Group", "URI": "http://acs.amazonaws.com/groups/global/AllUsers"}, "Permission": "READ"}
_PARTIAL_BLOCK = {"BlockPublicAcls": True, "IgnorePublicAcls": True, "BlockPublicPolicy": False, "RestrictPublicBuckets": False}
_FULL_BLOCK = dict.fromkeys(_PARTIAL_BLOCK, True)


def test_partial_block_without_grant_is_not_public() -> None:
    from agent_bom.cloud.aws_inventory import _bucket_public

    assert _bucket_public(_s3(policy_public=None, block=_PARTIAL_BLOCK), "b", []) is False


def test_missing_block_with_public_acl_is_public() -> None:
    from agent_bom.cloud.aws_inventory import _bucket_public

    assert _bucket_public(_s3(policy_public=None, acl_grants=[_ALL_USERS]), "b", []) is True


def test_public_policy_neutralized_by_restrict_public_buckets() -> None:
    from agent_bom.cloud.aws_inventory import _bucket_public

    assert _bucket_public(_s3(policy_public=True, block=_FULL_BLOCK), "b", []) is False
    assert _bucket_public(_s3(policy_public=True), "b", [], account_block={"RestrictPublicBuckets": True}) is False
    assert _bucket_public(_s3(policy_public=True, block=_PARTIAL_BLOCK), "b", []) is True


def test_public_acl_neutralized_by_account_ignore_public_acls() -> None:
    from agent_bom.cloud.aws_inventory import _bucket_public

    assert _bucket_public(_s3(policy_public=None, acl_grants=[_ALL_USERS]), "b", [], account_block={"IgnorePublicAcls": True}) is False


# ---------------------------------------------------------------------------
# 5. GCP CIS receives the project
# ---------------------------------------------------------------------------


def test_gcp_cis_receives_cli_project(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cli.agents import _cloud
    from agent_bom.cli.agents._context import ScanContext
    from agent_bom.cloud import gcp_cis_benchmark, gcp_inventory

    seen: dict[str, Any] = {}

    def _fake_run(project_id=None, **_k):
        seen["project"] = project_id
        return gcp_cis_benchmark.GCPCISReport(project_id=project_id or "")

    monkeypatch.setattr(gcp_inventory, "all_projects_enabled", lambda: False)
    monkeypatch.setattr(gcp_cis_benchmark, "run_benchmark", _fake_run)
    ctx = ScanContext(con=MagicMock(), quiet=True)
    _cloud.run_benchmarks(
        ctx,
        skill_only=False,
        verify_model_hashes=False,
        project=None,
        hf_token=None,
        aws_cis_benchmark=False,
        aws_region=None,
        aws_profile=None,
        snowflake_cis_benchmark=False,
        snowflake_authenticator=None,
        azure_cis_benchmark=False,
        azure_subscription=None,
        gcp_cis_benchmark=True,
        gcp_project="proj-cli",
        databricks_security=False,
        aisvs_flag=False,
        vector_db_scan=False,
        gpu_scan_flag=False,
        gpu_k8s_context=None,
        no_dcgm_probe=True,
        smithery_flag=False,
        smithery_token=None,
        mcp_registry_flag=False,
        snyk_flag=False,
        snyk_token=None,
        snyk_org=None,
        cortex_observability=False,
    )
    assert seen["project"] == "proj-cli"


# ---------------------------------------------------------------------------
# 6. GCP billing / API-disabled 403s are not permission gaps
# ---------------------------------------------------------------------------


class _ForbiddenError(Exception):
    status_code = 403


@pytest.mark.parametrize(
    ("message", "expected"),
    [
        ("403 This API method requires billing to be enabled. reason: BILLING_DISABLED", "billing is disabled"),
        (
            "403 Compute Engine API has not been used in project 123 before or it is disabled. reason: SERVICE_DISABLED",
            "API is not enabled",
        ),
    ],
)
def test_gcp_disabled_project_403_is_not_reported_as_missing_role(message: str, expected: str) -> None:
    from agent_bom.cloud.aws_inventory import record_discovery_failure

    warnings: list[str] = []
    missing: list[dict[str, str]] = []
    record_discovery_failure(
        exc=_ForbiddenError(message),
        resource_type="GCE instances",
        permission="compute.instances.list",
        cloud="gcp",
        warnings=warnings,
        missing=missing,
    )
    assert missing == []
    assert expected in warnings[0]
    assert "add it to the read-only policy" not in warnings[0]


def test_real_permission_denied_still_names_the_permission() -> None:
    from agent_bom.cloud.aws_inventory import record_discovery_failure

    warnings: list[str] = []
    missing: list[dict[str, str]] = []
    record_discovery_failure(
        exc=_ForbiddenError("403 Permission 'compute.instances.list' denied"),
        resource_type="GCE instances",
        permission="compute.instances.list",
        cloud="gcp",
        warnings=warnings,
        missing=missing,
    )
    assert missing and "add it to the read-only policy" in warnings[0]


# ---------------------------------------------------------------------------
# 7. Azure SDK enums compared by value
# ---------------------------------------------------------------------------


def test_azure_storage_enum_values_compare_by_value() -> None:
    from azure.mgmt.storage.models import Bypass, DefaultAction, KeySource

    from agent_bom.cloud.azure_cis_benchmark import _check_3_2, _check_3_3, _check_3_8, _check_3_9

    acct = SimpleNamespace(
        name="sa1",
        network_rule_set=SimpleNamespace(default_action=DefaultAction.DENY, bypass=Bypass.AZURE_SERVICES),
        encryption=SimpleNamespace(key_source=KeySource.MICROSOFT_KEYVAULT),
    )
    client = MagicMock()
    client.storage_accounts.list.return_value = [acct]
    for check in (_check_3_2, _check_3_3, _check_3_8, _check_3_9):
        result = check(client)
        assert result.status == CheckStatus.PASS, (check.__name__, result.evidence)


def test_azure_tls_enum_values_compare_by_value() -> None:
    from azure.mgmt.sql.models import MinimalTlsVersion

    from agent_bom.cloud.azure_cis_benchmark import _check_4_2_1

    sql = MagicMock()
    sql.servers.list.return_value = [SimpleNamespace(name="srv", minimal_tls_version=MinimalTlsVersion.ONE2)]
    assert _check_4_2_1(sql).status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 8. Azure checks that were not evaluated must not PASS
# ---------------------------------------------------------------------------


def test_azure_storage_logging_checks_are_not_passed_without_data_plane_evidence() -> None:
    from agent_bom.cloud.azure_cis_benchmark import _check_3_4, _check_3_5, _check_3_6

    client = MagicMock()
    client.storage_accounts.list.return_value = [SimpleNamespace(name="sa1")]
    for check in (_check_3_4, _check_3_5, _check_3_6):
        assert check(client).status == CheckStatus.NO_DATA


def test_azure_zero_resources_is_no_data_not_pass() -> None:
    from agent_bom.cloud.azure_cis_benchmark import _check_3_1, _check_4_2_1, _check_7_1

    sql = MagicMock()
    sql.servers.list.return_value = []
    assert _check_4_2_1(sql).status == CheckStatus.NO_DATA
    storage = MagicMock()
    storage.storage_accounts.list.return_value = []
    assert _check_3_1(storage).status == CheckStatus.NO_DATA
    compute = MagicMock()
    compute.virtual_machines.list_all.return_value = []
    assert _check_7_1(compute).status == CheckStatus.NO_DATA


def test_azure_report_counts_no_data() -> None:
    from agent_bom.cloud.aws_cis_benchmark import CISCheckResult
    from agent_bom.cloud.azure_cis_benchmark import AzureCISReport

    report = AzureCISReport(checks=[CISCheckResult(check_id="3.4", title="t", status=CheckStatus.NO_DATA, severity="medium")])
    assert report.to_dict()["no_data"] == 1


# ---------------------------------------------------------------------------
# 9. Azure MFA checks consult Security Defaults
# ---------------------------------------------------------------------------


def _graph(*, policies: Any, security_defaults: Any) -> Any:
    from agent_bom.cloud.azure_graph import CONDITIONAL_ACCESS_POLICIES_PATH, SECURITY_DEFAULTS_PATH

    def _resolve(value: Any) -> Any:
        if isinstance(value, Exception):
            raise value
        return value

    return SimpleNamespace(
        list=lambda path: _resolve(policies) if path == CONDITIONAL_ACCESS_POLICIES_PATH else [],
        get=lambda path: _resolve(security_defaults) if path == SECURITY_DEFAULTS_PATH else {},
    )


_MFA_CHECKS = ("_check_1_6", "_check_1_8", "_check_1_9", "_check_1_22")


@pytest.mark.parametrize("name", _MFA_CHECKS)
def test_mfa_check_unevaluable_when_no_ca_and_security_defaults_unknown(name: str) -> None:
    from agent_bom.cloud import azure_cis_benchmark
    from agent_bom.cloud.azure_graph import GraphPermissionDeniedError

    result = getattr(azure_cis_benchmark, name)(_graph(policies=[], security_defaults=GraphPermissionDeniedError("denied")))
    assert result.status == CheckStatus.ERROR
    assert "unevaluable" in result.evidence.lower()


@pytest.mark.parametrize("name", _MFA_CHECKS)
def test_mfa_check_passes_when_security_defaults_enabled(name: str) -> None:
    from agent_bom.cloud import azure_cis_benchmark

    result = getattr(azure_cis_benchmark, name)(_graph(policies=[], security_defaults={"isEnabled": True}))
    assert result.status == CheckStatus.PASS
    assert "security defaults" in result.evidence.lower()


@pytest.mark.parametrize("name", _MFA_CHECKS)
def test_mfa_check_fails_when_no_ca_and_security_defaults_disabled(name: str) -> None:
    from agent_bom.cloud import azure_cis_benchmark

    result = getattr(azure_cis_benchmark, name)(_graph(policies=[], security_defaults={"isEnabled": False}))
    assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# P2. Azure 5.1.1 uses the subscription diagnostic-settings API
# ---------------------------------------------------------------------------


def test_azure_5_1_1_works_without_sdk_diagnostic_settings(monkeypatch: pytest.MonkeyPatch) -> None:
    from agent_bom.cloud import azure_cis_benchmark

    monitor = SimpleNamespace()  # azure-mgmt-monitor 7.x has no diagnostic_settings group
    monkeypatch.setattr(
        azure_cis_benchmark,
        "_list_subscription_diagnostic_settings",
        lambda credential, subscription_id: [{"name": "ds1", "properties": {"logs": [{"category": "Administrative", "enabled": True}]}}],
    )
    result = azure_cis_benchmark._check_5_1_1(monitor, "sub-1", credential=object())
    assert result.status == CheckStatus.PASS
    monkeypatch.setattr(azure_cis_benchmark, "_list_subscription_diagnostic_settings", lambda credential, subscription_id: [])
    assert azure_cis_benchmark._check_5_1_1(monitor, "sub-1", credential=object()).status == CheckStatus.FAIL


def test_azure_scan_outcome_partial_when_benchmark_checks_errored() -> None:
    from agent_bom.cli.agents.scan_cmd import _benchmark_scan_issues
    from agent_bom.cloud.aws_cis_benchmark import CISCheckResult
    from agent_bom.cloud.azure_cis_benchmark import AzureCISReport
    from agent_bom.evidence.scan_run import ScanOutcome, ScanRun

    clean = SimpleNamespace(azure_cis_benchmark_report=AzureCISReport(checks=[CISCheckResult("1.1", "t", CheckStatus.PASS, "high")]))
    assert _benchmark_scan_issues(clean) == []
    assert ScanRun(issues=_benchmark_scan_issues(clean)).outcome is ScanOutcome.COMPLETE

    errored = SimpleNamespace(
        azure_cis_benchmark_report=AzureCISReport(
            checks=[CISCheckResult("5.1.1", "t", CheckStatus.ERROR, "medium")], warnings=["subscription x: access denied"]
        )
    )
    issues = _benchmark_scan_issues(errored)
    assert {issue.code for issue in issues} == {"benchmark_checks_errored", "benchmark_warning"}
    assert all(issue.source == "azure" for issue in issues)
    assert ScanRun(issues=issues).outcome is ScanOutcome.PARTIAL


def test_gcp_api_core_error_info_reason_is_classified() -> None:
    from google.api_core import exceptions as gexc
    from google.rpc import error_details_pb2

    from agent_bom.cloud.aws_inventory import classify_project_disabled_error

    exc = gexc.PermissionDenied(
        "Request denied", error_info=error_details_pb2.ErrorInfo(reason="BILLING_DISABLED", domain="googleapis.com")
    )
    assert classify_project_disabled_error(exc) == "billing_disabled"
    denied = gexc.PermissionDenied("Permission 'compute.instances.list' denied on resource")
    assert classify_project_disabled_error(denied) == ""


def test_azure_sql_public_access_enum_compares_by_value() -> None:
    from azure.mgmt.sql.models import ServerNetworkAccessFlag

    from agent_bom.cloud.azure_cis_benchmark import _check_4_1_6

    sql = MagicMock()
    sql.servers.list.return_value = [SimpleNamespace(name="srv", public_network_access=ServerNetworkAccessFlag.DISABLED)]
    assert _check_4_1_6(sql).status == CheckStatus.PASS


def _scan_json(tmp_path, name: str, *extra: str) -> dict:
    import json

    from click.testing import CliRunner

    from agent_bom.cli import main

    inventory = tmp_path / "inventory.json"
    inventory.write_text(
        json.dumps({"schema_version": "1", "agents": [{"name": "fixture-agent", "agent_type": "custom", "mcp_servers": []}]}),
        encoding="utf-8",
    )
    out = tmp_path / f"{name}.json"
    args = ["scan", "--inventory", str(inventory), "--inventory-only", "--no-scan", "--format", "json", "--output", str(out), *extra]
    result = CliRunner().invoke(main, args, catch_exceptions=False)
    assert result.exit_code == 0, result.output
    return json.loads(out.read_text(encoding="utf-8"))


def test_cli_scan_id_unique_per_run_and_stable_when_reproducible(tmp_path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv("SOURCE_DATE_EPOCH", raising=False)
    assert _scan_json(tmp_path, "a")["scan_id"] != _scan_json(tmp_path, "b")["scan_id"]
    assert _scan_json(tmp_path, "c", "--reproducible")["scan_id"] == _scan_json(tmp_path, "d", "--reproducible")["scan_id"]
