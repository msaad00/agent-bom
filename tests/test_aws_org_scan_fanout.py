"""AWS Organizations cross-account scan fan-out (read-only, opt-in).

Covers the AWS analogue of the Azure all-subscriptions and GCP all-projects
fan-out: the inventory + CIS benchmark run once per member account against an
assumed read-only session, merge into the unified graph under the org → account
hierarchy, tolerate a denied account, honour the account cap, and stay OFF by
default. STS AssumeRole and the org enumeration are mocked throughout.
"""

from __future__ import annotations

import sys
import types

import pytest

from agent_bom.cloud import aws_cis_benchmark as aws_cis
from agent_bom.cloud import aws_inventory as aws_inv
from agent_bom.cloud import aws_organizations as aws_orgs
from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISBenchmarkReport, CISCheckResult
from agent_bom.graph.builder import build_unified_graph_from_report


@pytest.fixture(autouse=True)
def _stub_boto3(monkeypatch):
    """Make ``import boto3`` resolve to a stub so the fan-out runs with NO real
    boto3 installed.

    CI's base test env does not install the ``[aws]`` extra, so the module-level
    ``import boto3`` guards in ``discover_all_account_inventories`` /
    ``run_all_account_benchmarks`` would otherwise short-circuit before the mocked
    fan-out runs. The fan-out tests monkeypatch ``assume_account_session`` /
    ``discover_inventory``, so the stub only has to satisfy those import guards.
    Mirrors the established pattern in ``tests/test_aws_organizations.py`` and
    ``tests/cloud/test_cloud_aws_inventory.py``. A test that needs boto3 genuinely
    absent overrides ``sys.modules["boto3"]`` to ``None`` in its own body.
    """
    boto3 = types.ModuleType("boto3")
    boto3.Session = lambda **_kw: None  # type: ignore[attr-defined]
    botocore = types.ModuleType("botocore")
    errs = types.ModuleType("botocore.exceptions")
    errs.NoCredentialsError = type("NoCredentialsError", (Exception,), {})  # type: ignore[attr-defined]
    errs.ClientError = type("ClientError", (Exception,), {})  # type: ignore[attr-defined]
    botocore.exceptions = errs  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "boto3", boto3)
    monkeypatch.setitem(sys.modules, "botocore", botocore)
    monkeypatch.setitem(sys.modules, "botocore.exceptions", errs)


# ---------------------------------------------------------------------------
# Gating — default OFF
# ---------------------------------------------------------------------------


def test_org_fanout_disabled_by_default(monkeypatch) -> None:
    monkeypatch.delenv(aws_orgs.ORG_FANOUT_ENV_FLAG, raising=False)
    assert aws_orgs.org_fanout_enabled() is False


def test_org_fanout_enabled_when_flag_truthy(monkeypatch) -> None:
    monkeypatch.setenv(aws_orgs.ORG_FANOUT_ENV_FLAG, "1")
    assert aws_orgs.org_fanout_enabled() is True


def test_max_accounts_default_and_override(monkeypatch) -> None:
    monkeypatch.delenv("AGENT_BOM_AWS_MAX_ACCOUNTS", raising=False)
    assert aws_orgs.max_accounts() == 200
    monkeypatch.setenv("AGENT_BOM_AWS_MAX_ACCOUNTS", "3")
    assert aws_orgs.max_accounts() == 3
    # A non-positive / unparseable value falls back to the default, never disables the cap.
    monkeypatch.setenv("AGENT_BOM_AWS_MAX_ACCOUNTS", "0")
    assert aws_orgs.max_accounts() == 200
    monkeypatch.setenv("AGENT_BOM_AWS_MAX_ACCOUNTS", "nope")
    assert aws_orgs.max_accounts() == 200


# ---------------------------------------------------------------------------
# list_member_account_ids — ACTIVE-only enumeration
# ---------------------------------------------------------------------------


def test_list_member_account_ids_keeps_only_active(monkeypatch) -> None:
    monkeypatch.setattr(
        aws_orgs,
        "discover_organization",
        lambda profile=None, *, force=False: {
            "status": "ok",
            "accounts": [
                {"id": "111111111111", "status": "ACTIVE"},
                {"id": "222222222222", "status": "SUSPENDED"},
                {"id": "333333333333", "status": "ACTIVE"},
                {"id": "111111111111", "status": "ACTIVE"},  # duplicate collapses
            ],
        },
    )
    assert aws_orgs.list_member_account_ids() == ["111111111111", "333333333333"]


def test_list_member_account_ids_empty_when_not_in_org(monkeypatch) -> None:
    monkeypatch.setattr(aws_orgs, "discover_organization", lambda profile=None, *, force=False: {"status": "not_in_org"})
    assert aws_orgs.list_member_account_ids() == []


# ---------------------------------------------------------------------------
# assume_account_session — STS AssumeRole broker (mocked)
# ---------------------------------------------------------------------------


class _FakeSTS:
    def __init__(self) -> None:
        self.calls: list[dict] = []

    def assume_role(self, **kwargs):
        self.calls.append(kwargs)
        return {
            "Credentials": {
                "AccessKeyId": "ASIA_TEMP",
                "SecretAccessKey": "secret",  # noqa: S106 - test stub, not a real secret
                "SessionToken": "token",
            }
        }


def test_assume_account_session_uses_role_arn_external_id_region(monkeypatch) -> None:
    import boto3

    fake_sts = _FakeSTS()
    built_sessions: list[dict] = []

    class _FakeSession:
        def __init__(self, **kwargs):
            built_sessions.append(kwargs)

        def client(self, name):
            assert name == "sts"
            return fake_sts

    monkeypatch.setattr(boto3, "Session", _FakeSession)
    monkeypatch.setenv(aws_orgs.ORG_ROLE_NAME_ENV, "agent-bom-readonly")
    monkeypatch.setenv(aws_orgs.ORG_EXTERNAL_ID_ENV, "ext-secret")

    aws_orgs.assume_account_session("444444444444", region="us-west-2")

    # AssumeRole presented the per-account read-only role ARN + ExternalId.
    assert fake_sts.calls[0]["RoleArn"] == "arn:aws:iam::444444444444:role/agent-bom-readonly"
    assert fake_sts.calls[0]["ExternalId"] == "ext-secret"
    assert fake_sts.calls[0]["RoleSessionName"]
    # The returned session is backed by the temporary credentials + requested region.
    backed = built_sessions[-1]
    assert backed["aws_access_key_id"] == "ASIA_TEMP"
    assert backed["aws_session_token"] == "token"
    assert backed["region_name"] == "us-west-2"


def test_assume_account_session_omits_external_id_when_unset(monkeypatch) -> None:
    import boto3

    fake_sts = _FakeSTS()
    monkeypatch.setattr(boto3, "Session", lambda **kw: type("S", (), {"client": lambda self, n: fake_sts})())
    monkeypatch.delenv(aws_orgs.ORG_EXTERNAL_ID_ENV, raising=False)

    aws_orgs.assume_account_session("555555555555")
    assert "ExternalId" not in fake_sts.calls[0]


# ---------------------------------------------------------------------------
# Inventory fan-out
# ---------------------------------------------------------------------------


def _inv(account_id: str, *, status: str = "ok") -> dict:
    return {**aws_inv._empty_payload(region="us-east-1"), "status": status, "account_id": account_id}


def test_inventory_fanout_merges_each_account(monkeypatch) -> None:
    monkeypatch.setattr(aws_inv, "inventory_enabled", lambda: True)
    monkeypatch.setattr(aws_orgs, "list_member_account_ids", lambda profile, *, force=False: ["111111111111", "222222222222"])
    monkeypatch.setattr(aws_orgs, "assume_account_session", lambda aid, **kw: f"session::{aid}")

    scanned: list[str] = []

    def _fake_inv(*, session=None, force=False):
        aid = str(session).split("::")[-1]
        scanned.append(aid)
        return _inv(aid)

    monkeypatch.setattr(aws_inv, "discover_inventory", _fake_inv)

    payloads = aws_inv.discover_all_account_inventories()
    assert sorted(scanned) == ["111111111111", "222222222222"]
    assert {p["account_id"] for p in payloads} == {"111111111111", "222222222222"}
    assert all(p["status"] == "ok" for p in payloads)


def test_inventory_fanout_skips_denied_account_with_warning(monkeypatch) -> None:
    monkeypatch.setattr(aws_inv, "inventory_enabled", lambda: True)
    monkeypatch.setattr(aws_orgs, "list_member_account_ids", lambda profile, *, force=False: ["ok-acct", "denied-acct"])

    def _fake_assume(aid, **kw):
        if aid == "denied-acct":
            raise PermissionError("AccessDenied: not authorized to assume role in denied-acct")
        return f"session::{aid}"

    monkeypatch.setattr(aws_orgs, "assume_account_session", _fake_assume)
    monkeypatch.setattr(aws_inv, "discover_inventory", lambda *, session=None, force=False: _inv(str(session).split("::")[-1]))

    payloads = aws_inv.discover_all_account_inventories()
    by_acct = {p["account_id"]: p for p in payloads}
    assert by_acct["ok-acct"]["status"] == "ok"
    assert by_acct["denied-acct"]["status"] == "access_denied"
    assert any("denied-acct skipped" in w for w in by_acct["denied-acct"]["warnings"])


def test_inventory_fanout_honors_cap(monkeypatch) -> None:
    monkeypatch.setattr(aws_inv, "inventory_enabled", lambda: True)
    monkeypatch.setenv("AGENT_BOM_AWS_MAX_ACCOUNTS", "2")
    monkeypatch.setattr(aws_orgs, "list_member_account_ids", lambda profile, *, force=False: ["a1", "a2", "a3", "a4"])
    monkeypatch.setattr(aws_orgs, "assume_account_session", lambda aid, **kw: f"session::{aid}")
    monkeypatch.setattr(aws_inv, "discover_inventory", lambda *, session=None, force=False: _inv(str(session).split("::")[-1]))

    payloads = aws_inv.discover_all_account_inventories()
    assert len(payloads) == 2
    assert {p["account_id"] for p in payloads} == {"a1", "a2"}


def test_inventory_fanout_falls_back_to_single_account(monkeypatch) -> None:
    monkeypatch.setattr(aws_inv, "inventory_enabled", lambda: True)
    monkeypatch.setattr(aws_orgs, "list_member_account_ids", lambda profile, *, force=False: [])
    called: list[bool] = []

    def _single(*, profile=None, force=False):
        called.append(True)
        return _inv("solo")

    monkeypatch.setattr(aws_inv, "discover_inventory", _single)
    payloads = aws_inv.discover_all_account_inventories()
    assert called == [True]
    assert payloads[0]["account_id"] == "solo"


def test_inventory_fanout_disabled_returns_empty(monkeypatch) -> None:
    monkeypatch.setattr(aws_inv, "inventory_enabled", lambda: False)
    assert aws_inv.discover_all_account_inventories() == []


# ---------------------------------------------------------------------------
# Graph merge — per-account payloads stitch under the org hierarchy
# ---------------------------------------------------------------------------


def test_multi_account_inventory_merges_into_org_graph() -> None:
    org = {
        "status": "ok",
        "org_id": "o-xyz",
        "organizational_units": [{"id": "r-root", "name": "Root", "parent_id": "", "is_root": True}],
        "accounts": [
            {"id": "111111111111", "name": "app", "status": "ACTIVE", "ou_id": "r-root"},
            {"id": "222222222222", "name": "data", "status": "ACTIVE", "ou_id": "r-root"},
        ],
        "scps": [],
    }
    inventories = [
        {
            **aws_inv._empty_payload(region="us-east-1"),
            "status": "ok",
            "account_id": "111111111111",
            "buckets": [{"name": "app-bucket", "arn": "arn:aws:s3:::app-bucket", "is_public": False}],
        },
        {
            **aws_inv._empty_payload(region="us-east-1"),
            "status": "ok",
            "account_id": "222222222222",
            "buckets": [{"name": "data-bucket", "arn": "arn:aws:s3:::data-bucket", "is_public": False}],
        },
    ]
    g = build_unified_graph_from_report({"aws_organization": org, "cloud_inventory": inventories})
    # Both member-account nodes exist (from the org hierarchy) and the per-account
    # resources merged in under the same account-id namespace.
    assert "account:aws:111111111111" in g.nodes
    assert "account:aws:222222222222" in g.nodes
    edges = {(e.source, e.target, e.relationship.value) for e in g.edges}
    assert ("org:aws:ou:r-root", "account:aws:111111111111", "contains") in edges
    assert ("org:aws:ou:r-root", "account:aws:222222222222", "contains") in edges


# ---------------------------------------------------------------------------
# summarize_account_scan
# ---------------------------------------------------------------------------


def test_summarize_account_scan_buckets_by_status() -> None:
    summary = aws_orgs.summarize_account_scan(
        [
            {"account_id": "a1", "status": "ok"},
            {"account_id": "a2", "status": "access_denied"},
            {"account_id": "a3", "status": "error"},
            {"account_id": "a4", "status": "ok"},
        ]
    )
    assert summary["accounts_scanned"] == ["a1", "a4"]
    assert summary["accounts_skipped"] == ["a2"]
    assert summary["accounts_errored"] == ["a3"]
    assert summary["total"] == 4


# ---------------------------------------------------------------------------
# CIS benchmark fan-out
# ---------------------------------------------------------------------------


def _cis_report(account_id: str) -> CISBenchmarkReport:
    report = CISBenchmarkReport(account_id=account_id)
    report.checks.append(CISCheckResult(check_id="1.4", title="t", status=CheckStatus.PASS, severity="critical"))
    report.checks.append(CISCheckResult(check_id="3.1", title="t", status=CheckStatus.FAIL, severity="high"))
    return report


def test_cis_fanout_per_account_attribution(monkeypatch) -> None:
    monkeypatch.setattr(aws_orgs, "list_member_account_ids", lambda profile, *, force=False: ["111111111111", "222222222222"])
    monkeypatch.setattr(aws_orgs, "assume_account_session", lambda aid, **kw: f"session::{aid}")

    def _fake_run(*, session=None, checks=None):
        return _cis_report(str(session).split("::")[-1])

    monkeypatch.setattr(aws_cis, "run_benchmark", _fake_run)

    report = aws_cis.run_all_account_benchmarks()
    assert report.accounts_scanned == ["111111111111", "222222222222"]
    assert {c.account_id for c in report.checks} == {"111111111111", "222222222222"}
    assert report.passed == 2
    assert report.failed == 2
    assert report.total == 4
    payload = report.to_dict()
    assert payload["accounts_scanned"] == ["111111111111", "222222222222"]
    assert {c["account_id"] for c in payload["checks"]} == {"111111111111", "222222222222"}


def test_cis_fanout_skips_denied_account_with_warning(monkeypatch) -> None:
    monkeypatch.setattr(aws_orgs, "list_member_account_ids", lambda profile, *, force=False: ["ok-acct", "denied-acct"])

    def _fake_assume(aid, **kw):
        if aid == "denied-acct":
            raise PermissionError("AccessDenied assuming role in denied-acct")
        return f"session::{aid}"

    monkeypatch.setattr(aws_orgs, "assume_account_session", _fake_assume)
    monkeypatch.setattr(aws_cis, "run_benchmark", lambda *, session=None, checks=None: _cis_report(str(session).split("::")[-1]))

    report = aws_cis.run_all_account_benchmarks()
    assert report.accounts_scanned == ["ok-acct"]
    assert {c.account_id for c in report.checks} == {"ok-acct"}
    assert any("denied-acct skipped" in w for w in report.warnings)
    assert report.total == 2


def test_cis_fanout_caps_accounts_with_warning(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_AWS_MAX_ACCOUNTS", "1")
    monkeypatch.setattr(aws_orgs, "list_member_account_ids", lambda profile, *, force=False: ["a1", "a2", "a3"])
    monkeypatch.setattr(aws_orgs, "assume_account_session", lambda aid, **kw: f"session::{aid}")
    monkeypatch.setattr(aws_cis, "run_benchmark", lambda *, session=None, checks=None: _cis_report(str(session).split("::")[-1]))

    report = aws_cis.run_all_account_benchmarks()
    assert report.accounts_scanned == ["a1"]
    assert any("capped at 1 of 3" in w for w in report.warnings)


def test_cis_fanout_falls_back_to_single_account(monkeypatch) -> None:
    monkeypatch.setattr(aws_orgs, "list_member_account_ids", lambda profile, *, force=False: [])
    called: list[bool] = []

    def _single(profile=None, checks=None):
        called.append(True)
        return _cis_report("solo")

    monkeypatch.setattr(aws_cis, "run_benchmark", _single)
    report = aws_cis.run_all_account_benchmarks()
    assert called == [True]
    assert report.account_id == "solo"


# ---------------------------------------------------------------------------
# scan_enrichment wiring — gate routes to the fan-out, off keeps single-account
# ---------------------------------------------------------------------------


def test_scan_enrichment_routes_to_fanout_when_gate_on(monkeypatch) -> None:
    from agent_bom import scan_enrichment

    monkeypatch.setattr(aws_inv, "inventory_enabled", lambda: True)
    monkeypatch.setattr(aws_orgs, "org_fanout_enabled", lambda: True)
    monkeypatch.setattr(aws_inv, "discover_all_account_inventories", lambda: [_inv("111111111111"), _inv("222222222222")])
    monkeypatch.setattr(aws_inv, "discover_inventory", lambda: pytest.fail("single-account path must not run when org gate is on"))
    # Disable the other providers so only AWS contributes.
    monkeypatch.setattr("agent_bom.cloud.azure_inventory.inventory_enabled", lambda: False)
    monkeypatch.setattr("agent_bom.cloud.gcp_inventory.inventory_enabled", lambda: False)

    payloads = scan_enrichment.collect_cloud_inventory()
    assert {p["account_id"] for p in payloads} == {"111111111111", "222222222222"}


def test_scan_enrichment_single_account_when_gate_off(monkeypatch) -> None:
    from agent_bom import scan_enrichment

    monkeypatch.setattr(aws_inv, "inventory_enabled", lambda: True)
    monkeypatch.setattr(aws_orgs, "org_fanout_enabled", lambda: False)
    monkeypatch.setattr(aws_inv, "discover_inventory", lambda: _inv("solo"))
    monkeypatch.setattr(
        aws_inv,
        "discover_all_account_inventories",
        lambda: pytest.fail("fan-out must not run when org gate is off"),
    )
    monkeypatch.setattr("agent_bom.cloud.azure_inventory.inventory_enabled", lambda: False)
    monkeypatch.setattr("agent_bom.cloud.gcp_inventory.inventory_enabled", lambda: False)

    payloads = scan_enrichment.collect_cloud_inventory()
    assert [p["account_id"] for p in payloads] == ["solo"]


def test_enrich_report_attaches_account_scan_summary(monkeypatch) -> None:
    from agent_bom import scan_enrichment
    from agent_bom.models import AIBOMReport

    monkeypatch.setattr(aws_inv, "inventory_enabled", lambda: True)
    monkeypatch.setattr(aws_orgs, "org_fanout_enabled", lambda: True)
    monkeypatch.setattr(
        aws_inv,
        "discover_all_account_inventories",
        lambda: [_inv("111111111111"), _inv("222222222222", status="access_denied")],
    )
    monkeypatch.setattr(
        aws_orgs,
        "discover_organization",
        lambda profile=None, *, force=False: {
            "status": "ok",
            "org_id": "o-xyz",
            "accounts": [{"id": "111111111111", "status": "ACTIVE"}],
        },
    )
    # Silence the other estate sources so only AWS contributes.
    monkeypatch.setattr("agent_bom.cloud.azure_inventory.inventory_enabled", lambda: False)
    monkeypatch.setattr("agent_bom.cloud.gcp_inventory.inventory_enabled", lambda: False)
    monkeypatch.setattr(scan_enrichment, "collect_identity_discovery", lambda: None)
    monkeypatch.setattr(scan_enrichment, "collect_audit_trail", lambda: [])

    report = AIBOMReport(agents=[])
    scan_enrichment.enrich_report_with_estate_discovery(report)

    summary = report.aws_organization_data["account_scan"]
    assert summary["accounts_scanned"] == ["111111111111"]
    assert summary["accounts_skipped"] == ["222222222222"]
    assert summary["total"] == 2


# ---------------------------------------------------------------------------
# boto3 genuinely absent — degrade gracefully, never crash
# ---------------------------------------------------------------------------


def test_fanout_degrades_gracefully_without_boto3(monkeypatch) -> None:
    from agent_bom.cloud.base import CloudDiscoveryError

    # Override the autouse stub: make ``import boto3`` raise (boto3 not installed).
    monkeypatch.setitem(sys.modules, "boto3", None)
    monkeypatch.setattr(aws_inv, "inventory_enabled", lambda: True)

    # Inventory fan-out returns a single boto3_missing payload — never crashes.
    payloads = aws_inv.discover_all_account_inventories(force=True)
    assert len(payloads) == 1
    assert payloads[0]["status"] == "boto3_missing"

    # CIS fan-out raises the documented CloudDiscoveryError (caught by the CLI).
    with pytest.raises(CloudDiscoveryError):
        aws_cis.run_all_account_benchmarks()

    # The AssumeRole broker raises so the caller skips the account with a warning
    # rather than silently succeeding.
    with pytest.raises(ImportError):
        aws_orgs.assume_account_session("111111111111")
