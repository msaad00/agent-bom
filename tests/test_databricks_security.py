"""Tests for Databricks Security Best Practices benchmark checks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.databricks_security import (
    DatabricksSecurityReport,
    _check_1_1,
    _check_1_2,
    _check_2_1,
    _check_2_2,
    _check_2_3,
    _check_3_1,
    _check_4_1,
    _check_5_1,
    _check_5_2,
    run_security_checks,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_ws() -> MagicMock:
    """Return a bare mock WorkspaceClient with all sub-clients as MagicMocks."""
    ws = MagicMock()
    ws.users.list.return_value = []
    ws.ip_access_lists.list.return_value = []
    ws.settings.personal_access_token_expiry.get.return_value = None
    ws.token_management.list.return_value = []
    ws.service_principals.list.return_value = []
    ws.clusters.list.return_value = []
    ws.cluster_policies.list.return_value = []
    ws.metastores.current.return_value = None
    ws.log_delivery.list.return_value = []
    ws.secrets.list_scopes.return_value = []
    return ws


def _user(name: str, is_admin: bool = False) -> MagicMock:
    u = MagicMock()
    u.user_name = name
    u.id = name
    if is_admin:
        role = MagicMock()
        role.value = "admin"
        u.roles = [role]
    else:
        u.roles = []
    return u


def _cluster(
    name: str = "test-cluster",
    state: str = "RUNNING",
    auto_term: int = 60,
    security_mode: str = "USER_ISOLATION",
    source: str = "UI",
) -> MagicMock:
    c = MagicMock()
    c.cluster_name = name
    c.cluster_id = f"id-{name}"
    c.state = state
    c.auto_termination_minutes = auto_term
    c.data_security_mode = security_mode
    c.cluster_source = source
    c.spark_env_vars = {}
    c.no_public_ips = True
    c.aws_attributes = None
    return c


# ---------------------------------------------------------------------------
# DatabricksSecurityReport model
# ---------------------------------------------------------------------------


class TestDatabricksSecurityReport:
    def test_empty_report(self):
        r = DatabricksSecurityReport()
        assert r.passed == 0
        assert r.failed == 0
        assert r.total == 0
        assert r.pass_rate == 0.0

    def test_pass_rate_calculation(self):
        r = DatabricksSecurityReport(
            checks=[
                CISCheckResult(check_id="1.1", title="t1", status=CheckStatus.PASS, severity="high"),
                CISCheckResult(check_id="1.2", title="t2", status=CheckStatus.FAIL, severity="high"),
                CISCheckResult(check_id="1.3", title="t3", status=CheckStatus.PASS, severity="high"),
            ]
        )
        assert r.passed == 2
        assert r.failed == 1
        assert r.pass_rate == pytest.approx(66.7, abs=0.1)

    def test_error_checks_excluded_from_pass_rate(self):
        r = DatabricksSecurityReport(
            checks=[
                CISCheckResult(check_id="1.1", title="t1", status=CheckStatus.PASS, severity="high"),
                CISCheckResult(check_id="1.2", title="t2", status=CheckStatus.ERROR, severity="high"),
            ]
        )
        assert r.pass_rate == 100.0

    def test_to_dict_structure(self):
        r = DatabricksSecurityReport(
            workspace_host="https://adb-123.azuredatabricks.net",
            checks=[
                CISCheckResult(
                    check_id="1.1",
                    title="test",
                    status=CheckStatus.PASS,
                    severity="high",
                    cis_section="1 - IAM",
                )
            ],
        )
        with patch("agent_bom.mitre_attack.tag_cis_check", return_value=[]):
            d = r.to_dict()
        assert d["benchmark"] == "Databricks Security Best Practices"
        assert d["workspace_host"] == "https://adb-123.azuredatabricks.net"
        assert len(d["checks"]) == 1
        assert d["checks"][0]["check_id"] == "1.1"


# ---------------------------------------------------------------------------
# 1.1 — Admin count
# ---------------------------------------------------------------------------


class TestCheck11AdminCount:
    def test_few_admins_passes(self):
        ws = _mock_ws()
        ws.users.list.return_value = [_user("alice", True), _user("bob", True), _user("carol", False)]
        result = _check_1_1(ws)
        assert result.status == CheckStatus.PASS
        assert "2" in result.evidence

    def test_many_admins_fails(self):
        ws = _mock_ws()
        ws.users.list.return_value = [_user(f"admin{i}", True) for i in range(5)]
        result = _check_1_1(ws)
        assert result.status == CheckStatus.FAIL
        assert "5" in result.evidence

    def test_api_error_returns_error(self):
        ws = _mock_ws()
        ws.users.list.side_effect = Exception("403 Forbidden")
        result = _check_1_1(ws)
        assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# 1.2 — IP Access Lists
# ---------------------------------------------------------------------------


class TestCheck12IPAccessLists:
    def test_no_lists_fails(self):
        ws = _mock_ws()
        ws.ip_access_lists.list.return_value = []
        result = _check_1_2(ws)
        assert result.status == CheckStatus.FAIL

    def test_enabled_list_passes(self):
        ws = _mock_ws()
        acl = MagicMock()
        acl.enabled = True
        acl.label = "corp-ips"
        ws.ip_access_lists.list.return_value = [acl]
        result = _check_1_2(ws)
        assert result.status == CheckStatus.PASS

    def test_disabled_list_fails(self):
        ws = _mock_ws()
        acl = MagicMock()
        acl.enabled = False
        acl.label = "corp-ips"
        ws.ip_access_lists.list.return_value = [acl]
        result = _check_1_2(ws)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1 — Auto-termination
# ---------------------------------------------------------------------------


class TestCheck21AutoTermination:
    def test_all_clusters_have_auto_term_passes(self):
        ws = _mock_ws()
        ws.clusters.list.return_value = [_cluster("c1", auto_term=60), _cluster("c2", auto_term=30)]
        result = _check_2_1(ws)
        assert result.status == CheckStatus.PASS

    def test_cluster_without_auto_term_fails(self):
        ws = _mock_ws()
        ws.clusters.list.return_value = [_cluster("c1", auto_term=0), _cluster("c2", auto_term=60)]
        result = _check_2_1(ws)
        assert result.status == CheckStatus.FAIL
        assert "c1" in result.resource_ids

    def test_no_clusters_passes(self):
        ws = _mock_ws()
        ws.clusters.list.return_value = []
        result = _check_2_1(ws)
        assert result.status == CheckStatus.PASS

    def test_job_clusters_excluded(self):
        ws = _mock_ws()
        # Job cluster with no auto-term should not fail the check
        ws.clusters.list.return_value = [_cluster("job-c1", auto_term=0, source="JOB")]
        result = _check_2_1(ws)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 2.2 — No-isolation clusters
# ---------------------------------------------------------------------------


class TestCheck22NoIsolation:
    def test_isolated_clusters_pass(self):
        ws = _mock_ws()
        ws.clusters.list.return_value = [_cluster("c1", security_mode="USER_ISOLATION")]
        result = _check_2_2(ws)
        assert result.status == CheckStatus.PASS

    def test_none_mode_fails(self):
        ws = _mock_ws()
        ws.clusters.list.return_value = [_cluster("c1", security_mode="NONE")]
        result = _check_2_2(ws)
        assert result.status == CheckStatus.FAIL
        assert "c1" in result.resource_ids

    def test_no_running_clusters_passes(self):
        ws = _mock_ws()
        ws.clusters.list.return_value = [_cluster("c1", state="TERMINATED", security_mode="NONE")]
        result = _check_2_2(ws)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 2.3 — Cluster policies
# ---------------------------------------------------------------------------


class TestCheck23ClusterPolicies:
    def test_custom_policies_pass(self):
        ws = _mock_ws()
        policy = MagicMock()
        policy.name = "security-baseline"
        policy.is_default = False
        ws.cluster_policies.list.return_value = [policy]
        result = _check_2_3(ws)
        assert result.status == CheckStatus.PASS

    def test_no_policies_fails(self):
        ws = _mock_ws()
        ws.cluster_policies.list.return_value = []
        result = _check_2_3(ws)
        assert result.status == CheckStatus.FAIL

    def test_only_default_policies_fails(self):
        ws = _mock_ws()
        policy = MagicMock()
        policy.name = "default"
        policy.is_default = True
        ws.cluster_policies.list.return_value = [policy]
        result = _check_2_3(ws)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 3.1 — Unity Catalog
# ---------------------------------------------------------------------------


class TestCheck31UnityCatalog:
    def test_metastore_assigned_passes(self):
        ws = _mock_ws()
        meta = MagicMock()
        meta.metastore_id = "abc-123"
        meta.name = "prod-metastore"
        ws.metastores.current.return_value = meta
        result = _check_3_1(ws)
        assert result.status == CheckStatus.PASS

    def test_no_metastore_fails(self):
        ws = _mock_ws()
        ws.metastores.current.return_value = None
        result = _check_3_1(ws)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 4.1 — Audit Logging
# ---------------------------------------------------------------------------


class TestCheck41AuditLogging:
    def test_active_audit_config_passes(self):
        ws = _mock_ws()
        cfg = MagicMock()
        cfg.log_type = "AUDIT_LOGS"
        cfg.status = "ENABLED"
        ws.log_delivery.list.return_value = [cfg]
        result = _check_4_1(ws)
        assert result.status == CheckStatus.PASS

    def test_no_config_fails(self):
        ws = _mock_ws()
        ws.log_delivery.list.return_value = []
        result = _check_4_1(ws)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 5.1 — Secret Scopes
# ---------------------------------------------------------------------------


class TestCheck51SecretScopes:
    def test_scopes_exist_passes(self):
        ws = _mock_ws()
        scope = MagicMock()
        scope.name = "prod-secrets"
        ws.secrets.list_scopes.return_value = [scope]
        result = _check_5_1(ws)
        assert result.status == CheckStatus.PASS
        assert "prod-secrets" in result.resource_ids

    def test_no_scopes_fails(self):
        ws = _mock_ws()
        ws.secrets.list_scopes.return_value = []
        result = _check_5_1(ws)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 5.2 — Env var credential exposure
# ---------------------------------------------------------------------------


class TestCheck52EnvVarCredentials:
    def test_clean_clusters_pass(self):
        ws = _mock_ws()
        c = _cluster("clean")
        c.spark_env_vars = {"SOME_CONFIG": "value"}
        ws.clusters.list.return_value = [c]
        result = _check_5_2(ws)
        assert result.status == CheckStatus.PASS

    def test_credential_in_env_fails(self):
        ws = _mock_ws()
        c = _cluster("bad-cluster")
        c.spark_env_vars = {"password=supersecret123": ""}
        ws.clusters.list.return_value = [c]
        result = _check_5_2(ws)
        assert result.status == CheckStatus.FAIL
        assert "bad-cluster" in result.resource_ids

    def test_no_clusters_passes(self):
        ws = _mock_ws()
        ws.clusters.list.return_value = []
        result = _check_5_2(ws)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# run_security_checks — integration (mocked SDK)
# ---------------------------------------------------------------------------


class TestRunBenchmark:
    def test_run_security_checks_no_sdk_raises(self):
        with patch.dict("sys.modules", {"databricks": None, "databricks.sdk": None}):
            with pytest.raises(Exception):
                run_security_checks(host="https://example.databricks.com", token="token")

    def test_run_security_checks_returns_report(self):
        ws = _mock_ws()
        mock_sdk = MagicMock()
        mock_sdk.WorkspaceClient.return_value = ws
        with patch.dict("sys.modules", {"databricks": MagicMock(), "databricks.sdk": mock_sdk}):
            report = run_security_checks(host="https://test.databricks.com", token="test-token")
        assert isinstance(report, DatabricksSecurityReport)
        assert report.total == 12  # all 12 checks ran
        assert report.workspace_host == "https://test.databricks.com"

    def test_run_security_checks_all_checks_present(self):
        ws = _mock_ws()
        mock_sdk = MagicMock()
        mock_sdk.WorkspaceClient.return_value = ws
        with patch.dict("sys.modules", {"databricks": MagicMock(), "databricks.sdk": mock_sdk}):
            report = run_security_checks(host="https://test.databricks.com", token="test")
        check_ids = {c.check_id for c in report.checks}
        expected = {"1.1", "1.2", "1.3", "1.4", "2.1", "2.2", "2.3", "2.4", "3.1", "4.1", "5.1", "5.2"}
        assert check_ids == expected


# ---------------------------------------------------------------------------
# Canonical field / key surface + deprecated CIS-named alias (issue #4120)
# ---------------------------------------------------------------------------

_SAMPLE_DB_DATA = {
    "benchmark": "Databricks Security Best Practices",
    "provider": "databricks",
    "checks": [
        {"check_id": "1.1", "title": "Limit admins", "status": "FAIL", "severity": "high"},
    ],
}


class TestDatabricksCanonicalSurface:
    def test_scanresult_alias_round_trips_both_directions(self):
        """The canonical field and the deprecated CIS-named alias are one value."""
        from agent_bom.models import AIBOMReport

        # Write via the canonical field, read via the deprecated alias.
        r = AIBOMReport()
        r.databricks_security_data = _SAMPLE_DB_DATA
        assert r.databricks_cis_benchmark_data is _SAMPLE_DB_DATA
        assert r.databricks_security_data is _SAMPLE_DB_DATA

        # Write via the deprecated alias, read via the canonical field.
        r2 = AIBOMReport()
        r2.databricks_cis_benchmark_data = _SAMPLE_DB_DATA
        assert r2.databricks_security_data is _SAMPLE_DB_DATA
        assert r2.databricks_cis_benchmark_data is _SAMPLE_DB_DATA

    def test_alias_is_not_a_dataclass_constructor_kwarg(self):
        """The alias is a property, not a field — never a second source of truth."""
        import dataclasses

        from agent_bom.models import AIBOMReport

        field_names = {f.name for f in dataclasses.fields(AIBOMReport)}
        assert "databricks_security_data" in field_names
        assert "databricks_cis_benchmark_data" not in field_names

    def test_json_emits_canonical_and_deprecated_keys(self):
        """JSON carries both ``databricks_security`` and the deprecated alias."""
        from agent_bom.models import AIBOMReport
        from agent_bom.output.json_fmt import to_json

        report = AIBOMReport()
        report.databricks_security_data = _SAMPLE_DB_DATA
        out = to_json(report)
        assert out["databricks_security"] == _SAMPLE_DB_DATA
        assert out["databricks_cis_benchmark"] == _SAMPLE_DB_DATA
        assert out["databricks_security"] == out["databricks_cis_benchmark"]

    def test_databricks_check_finding_has_no_cis_framework_tag(self):
        """Databricks is a vendor baseline: no CIS-* tag, best-practice type."""
        from agent_bom.finding import FindingType, cloud_cis_check_to_finding

        check = {
            "check_id": "1.1",
            "title": "Limit workspace admins",
            "status": "FAIL",
            "severity": "high",
            "compliance_tags": [],
        }
        finding = cloud_cis_check_to_finding(check, "databricks")
        assert not any(t.startswith("CIS-") for t in finding.compliance_tags)
        assert finding.compliance_tags == []
        assert finding.finding_type == FindingType.CLOUD_BEST_PRACTICE_FAIL

    def test_databricks_error_check_uses_best_practice_error_type(self):
        from agent_bom.finding import FindingType, cloud_cis_check_to_finding

        check = {"check_id": "1.1", "title": "Limit admins", "status": "ERROR", "severity": "high"}
        finding = cloud_cis_check_to_finding(check, "databricks")
        assert finding.finding_type == FindingType.CLOUD_BEST_PRACTICE_ERROR
        assert not any(t.startswith("CIS-") for t in finding.compliance_tags)
