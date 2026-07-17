"""Tests for CIS Snowflake Benchmark v1.0 checks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus, CISCheckResult
from agent_bom.cloud.snowflake_cis_benchmark import (
    SnowflakeCISReport,
    _check_1_1,
    _check_1_2,
    _check_1_3,
    _check_1_4,
    _check_1_5,
    _check_1_6,
    _check_2_1,
    _check_2_2,
    _check_3_1,
    _check_3_2,
    _check_4_1,
    _check_4_2,
    _check_5_1,
    _check_5_2,
    _preflight_account_usage_source,
    run_benchmark,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _mock_cursor(rows: list[dict], columns: list[str] | None = None) -> MagicMock:
    """Create a mock Snowflake cursor that returns the given rows."""
    cursor = MagicMock()
    if rows:
        if columns is None:
            columns = list(rows[0].keys())
        cursor.description = [(col.upper(), None) for col in columns]
        cursor.fetchall.return_value = [tuple(r[c] for c in columns) for r in rows]
    else:
        cursor.description = [] if columns is not None else None
        cursor.fetchall.return_value = []
    return cursor


def _empty_cursor() -> MagicMock:
    """Cursor that returns no rows."""
    cursor = MagicMock()
    cursor.description = [("col", None)]
    cursor.fetchall.return_value = []
    return cursor


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


class TestSnowflakeCISReport:
    def test_empty_report(self):
        r = SnowflakeCISReport()
        assert r.passed == 0
        assert r.failed == 0
        assert r.total == 0
        assert r.pass_rate == 0.0

    def test_pass_rate_calculation(self):
        r = SnowflakeCISReport(
            checks=[
                CISCheckResult(check_id="1.1", title="test1", status=CheckStatus.PASS, severity="high"),
                CISCheckResult(check_id="1.2", title="test2", status=CheckStatus.FAIL, severity="high"),
                CISCheckResult(check_id="1.3", title="test3", status=CheckStatus.PASS, severity="high"),
            ]
        )
        assert r.passed == 2
        assert r.failed == 1
        assert r.total == 3
        assert r.pass_rate == pytest.approx(66.7, abs=0.1)

    def test_to_dict(self):
        r = SnowflakeCISReport(
            account="myaccount",
            checks=[CISCheckResult(check_id="1.1", title="t", status=CheckStatus.PASS, severity="high")],
        )
        d = r.to_dict()
        assert d["benchmark"] == "CIS Snowflake Foundations"
        assert d["account"] == "myaccount"
        assert d["passed"] == 1
        assert len(d["checks"]) == 1


# ---------------------------------------------------------------------------
# 1.1 — MFA for password users
# ---------------------------------------------------------------------------


class TestCheck11:
    def test_pass_all_mfa(self):
        cursor = _mock_cursor(
            [
                {"name": "ADMIN", "ext_authn_duo": "true", "has_password": "true", "disabled": "false"},
                {"name": "USER1", "ext_authn_duo": "true", "has_password": "true", "disabled": "false"},
            ]
        )
        result = _check_1_1(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_no_mfa(self):
        cursor = _mock_cursor(
            [
                {"name": "ADMIN", "ext_authn_duo": "false", "has_password": "true", "disabled": "false"},
            ]
        )
        result = _check_1_1(cursor)
        assert result.status == CheckStatus.FAIL
        assert "ADMIN" in result.evidence

    def test_pass_no_password_users(self):
        cursor = _empty_cursor()
        result = _check_1_1(cursor)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 1.2 — Password minimum length
# ---------------------------------------------------------------------------


class TestCheck12:
    def test_pass_strong_policy(self):
        with patch(
            "agent_bom.cloud.snowflake_cis_benchmark._live_password_policies",
            return_value=[{"name": "DEFAULT", "password_min_length": 14}],
        ):
            result = _check_1_2(MagicMock())
        assert result.status == CheckStatus.PASS

    def test_fail_weak_policy(self):
        with patch(
            "agent_bom.cloud.snowflake_cis_benchmark._live_password_policies",
            return_value=[{"name": "DEFAULT", "password_min_length": 8}],
        ):
            result = _check_1_2(MagicMock())
        assert result.status == CheckStatus.FAIL

    def test_fail_no_policies(self):
        with patch("agent_bom.cloud.snowflake_cis_benchmark._live_password_policies", return_value=[]):
            result = _check_1_2(MagicMock())
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 1.3 — Session idle timeout
# ---------------------------------------------------------------------------


class TestCheck13:
    def test_pass_within_limit(self):
        cursor = _mock_cursor([{"value": 240}])
        result = _check_1_3(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_exceeds_limit(self):
        cursor = _mock_cursor([{"value": 480}])
        result = _check_1_3(cursor)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 1.4 — ACCOUNTADMIN limit
# ---------------------------------------------------------------------------


class TestCheck14:
    def test_pass_two_admins(self):
        cursor = _mock_cursor(
            [
                {"grantee_name": "ADMIN1", "granted_to": "USER"},
                {"grantee_name": "ADMIN2", "granted_to": "USER"},
            ]
        )
        result = _check_1_4(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_too_many_admins(self):
        cursor = _mock_cursor(
            [
                {"grantee_name": "ADMIN1", "granted_to": "USER"},
                {"grantee_name": "ADMIN2", "granted_to": "USER"},
                {"grantee_name": "ADMIN3", "granted_to": "USER"},
            ]
        )
        result = _check_1_4(cursor)
        assert result.status == CheckStatus.FAIL

    def test_role_hierarchy_grant_is_not_counted_as_a_user(self):
        cursor = _mock_cursor(
            [
                {"grantee_name": "ADMIN1", "granted_to": "USER"},
                {"grantee_name": "SECURITYADMIN", "granted_to": "ROLE"},
            ]
        )
        result = _check_1_4(cursor)
        assert result.status == CheckStatus.PASS
        assert "1 user" in result.evidence


# ---------------------------------------------------------------------------
# 1.5 — Password history
# ---------------------------------------------------------------------------


class TestCheck15:
    def test_pass_history_strong(self):
        with patch(
            "agent_bom.cloud.snowflake_cis_benchmark._live_password_policies",
            return_value=[{"name": "DEFAULT", "password_history": 24}],
        ):
            result = _check_1_5(MagicMock())
        assert result.status == CheckStatus.PASS

    def test_fail_history_weak(self):
        with patch(
            "agent_bom.cloud.snowflake_cis_benchmark._live_password_policies",
            return_value=[{"name": "DEFAULT", "password_history": 5}],
        ):
            result = _check_1_5(MagicMock())
        assert result.status == CheckStatus.FAIL

    def test_fail_no_policies(self):
        with patch("agent_bom.cloud.snowflake_cis_benchmark._live_password_policies", return_value=[]):
            result = _check_1_5(MagicMock())
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 1.6 — Password max age
# ---------------------------------------------------------------------------


class TestCheck16:
    def test_pass_max_age_strong(self):
        with patch(
            "agent_bom.cloud.snowflake_cis_benchmark._live_password_policies",
            return_value=[{"name": "DEFAULT", "password_max_age_days": 90}],
        ):
            result = _check_1_6(MagicMock())
        assert result.status == CheckStatus.PASS

    def test_fail_max_age_too_high(self):
        with patch(
            "agent_bom.cloud.snowflake_cis_benchmark._live_password_policies",
            return_value=[{"name": "DEFAULT", "password_max_age_days": 180}],
        ):
            result = _check_1_6(MagicMock())
        assert result.status == CheckStatus.FAIL

    def test_fail_max_age_zero(self):
        with patch(
            "agent_bom.cloud.snowflake_cis_benchmark._live_password_policies",
            return_value=[{"name": "DEFAULT", "password_max_age_days": 0}],
        ):
            result = _check_1_6(MagicMock())
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1 — Account-level network policy
# ---------------------------------------------------------------------------


class TestCheck21:
    def test_pass_policy_set(self):
        cursor = _mock_cursor([{"value": "MY_NETWORK_POLICY"}])
        result = _check_2_1(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_empty_policy(self):
        cursor = _mock_cursor([{"value": ""}])
        result = _check_2_1(cursor)
        assert result.status == CheckStatus.FAIL

    def test_fail_no_param(self):
        cursor = _empty_cursor()
        result = _check_2_1(cursor)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 2.2 — No 0.0.0.0/0 in network policies
# ---------------------------------------------------------------------------


class TestCheck22:
    def test_pass_restricted(self):
        cursor = _mock_cursor([{"name": "POLICY1", "allowed_ip_list": "10.0.0.0/8,192.168.1.0/24"}])
        result = _check_2_2(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_open(self):
        cursor = _mock_cursor([{"name": "POLICY1", "allowed_ip_list": "0.0.0.0/0"}])
        result = _check_2_2(cursor)
        assert result.status == CheckStatus.FAIL

    def test_not_applicable_no_policies(self):
        cursor = _empty_cursor()
        result = _check_2_2(cursor)
        assert result.status == CheckStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 3.1 — Tri-Secret Secure
# ---------------------------------------------------------------------------


class TestCheck31:
    def test_pass_enabled(self):
        cursor = _mock_cursor([{"value": "true"}])
        result = _check_3_1(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_disabled(self):
        cursor = _mock_cursor([{"value": "false"}])
        result = _check_3_1(cursor)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 3.2 — Data sharing review
# ---------------------------------------------------------------------------


class TestCheck32:
    def test_pass_no_shares(self):
        cursor = _empty_cursor()
        result = _check_3_2(cursor)
        assert result.status == CheckStatus.PASS

    def test_informational_with_shares(self):
        cursor = _mock_cursor([{"name": "SHARE1", "database_name": "DB1", "target_accounts": "ORG.CONSUMER"}])
        result = _check_3_2(cursor)
        # 3.2 is informational — doesn't auto-fail
        assert result.status == CheckStatus.PASS
        assert "1 outbound share" in result.evidence


# ---------------------------------------------------------------------------
# 4.1 — Access history
# ---------------------------------------------------------------------------


class TestCheck41:
    def test_pass_records_exist(self):
        cursor = _mock_cursor([{"cnt": 500}])
        result = _check_4_1(cursor)
        assert result.status == CheckStatus.PASS
        assert "ending 3 hours before scan time" in result.evidence

    def test_fail_no_records(self):
        cursor = _mock_cursor([{"cnt": 0}])
        result = _check_4_1(cursor)
        assert result.status == CheckStatus.FAIL
        assert "ending 3 hours before scan time" in result.evidence

    def test_error_on_exception(self):
        cursor = MagicMock()
        cursor.execute.side_effect = Exception("no privileges")
        result = _check_4_1(cursor)
        assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# 4.2 — Failed login patterns
# ---------------------------------------------------------------------------


class TestCheck42:
    def test_pass_no_failures(self):
        cursor = _empty_cursor()
        result = _check_4_2(cursor)
        assert result.status == CheckStatus.PASS
        assert "ending 2 hours before scan time" in result.evidence

    def test_fail_excessive_failures(self):
        cursor = _mock_cursor([{"user_name": "BADUSER", "fail_count": 25}])
        result = _check_4_2(cursor)
        assert result.status == CheckStatus.FAIL
        assert "BADUSER" in result.evidence
        assert "ending 2 hours before scan time" in result.evidence


# ---------------------------------------------------------------------------
# 5.1 — PUBLIC role grants
# ---------------------------------------------------------------------------


class TestCheck51:
    def test_pass_no_grants(self):
        cursor = _empty_cursor()
        result = _check_5_1(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_public_grants(self):
        cursor = _mock_cursor([{"privilege": "SELECT", "granted_on": "TABLE", "name": "SENSITIVE_DATA"}])
        result = _check_5_1(cursor)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 5.2 — No ACCOUNTADMIN default role
# ---------------------------------------------------------------------------


class TestCheck52:
    def test_pass_no_admin_default(self):
        cursor = _empty_cursor()
        result = _check_5_2(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_admin_default(self):
        cursor = _mock_cursor([{"name": "ADMIN_USER", "default_role": "ACCOUNTADMIN"}])
        result = _check_5_2(cursor)
        assert result.status == CheckStatus.FAIL
        assert "ADMIN_USER" in result.evidence


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


class TestRunBenchmark:
    def test_missing_snowflake_connector(self):
        """run_benchmark raises if snowflake-connector-python is missing."""
        with patch.dict("sys.modules", {"snowflake": None, "snowflake.connector": None}):
            with pytest.raises(Exception):
                run_benchmark(account="test_acct")

    def test_run_benchmark_all_checks(self):
        """Runner executes all checks and returns report."""
        mock_connector = MagicMock()
        mock_errors = MagicMock()
        mock_errors.DatabaseError = Exception

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        # Set up cursor to return empty results for all queries
        mock_cursor.description = [("col", None)]
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value = mock_cursor
        mock_connector.connect.return_value = mock_conn

        import sys

        with patch.dict(
            sys.modules,
            {
                "snowflake": MagicMock(),
                "snowflake.connector": mock_connector,
                "snowflake.connector.errors": mock_errors,
            },
        ):
            with patch.dict("os.environ", {"SNOWFLAKE_ACCOUNT": "test_acct", "SNOWFLAKE_USER": "test_user"}):
                report = run_benchmark(account="test_acct", user="test_user", authenticator="externalbrowser")

        assert report.account == "test_acct"
        assert report.total == 14

    def test_run_benchmark_filter_checks(self):
        """Runner only runs requested checks when filtered."""
        mock_connector = MagicMock()
        mock_errors = MagicMock()
        mock_errors.DatabaseError = Exception

        mock_conn = MagicMock()
        mock_cursor = MagicMock()
        mock_cursor.description = [("col", None)]
        mock_cursor.fetchall.return_value = []
        mock_conn.cursor.return_value = mock_cursor
        mock_connector.connect.return_value = mock_conn

        import sys

        with patch.dict(
            sys.modules,
            {
                "snowflake": MagicMock(),
                "snowflake.connector": mock_connector,
                "snowflake.connector.errors": mock_errors,
            },
        ):
            with patch.dict("os.environ", {"SNOWFLAKE_ACCOUNT": "test_acct", "SNOWFLAKE_USER": "u"}):
                report = run_benchmark(account="test_acct", user="u", checks=["1.1", "2.1"], authenticator="externalbrowser")

        assert report.total == 2


class _SourceAwareCursor:
    def __init__(self, *, source_rows=1, show_rows=None, show_data=None, denied=False, filtered_rows=None, check_rows=None):
        self.source_rows = source_rows
        self.show_rows = source_rows if show_rows is None else show_rows
        self.show_data = show_data
        self.denied = denied
        self.filtered_rows = filtered_rows or []
        self.check_rows = check_rows
        self.description = None
        self._rows = []

    def execute(self, sql):
        normalized = " ".join(sql.lower().split())
        if "source-preflight:" in normalized:
            if self.denied:
                raise RuntimeError("insufficient privileges")
            self.description = [("ROW_COUNT",)]
            self._rows = [(self.source_rows,)]
        elif normalized.startswith("show "):
            if self.show_data is not None:
                columns = list(self.show_data[0]) if self.show_data else ["NAME"]
                self.description = [(column.upper(),) for column in columns]
                self._rows = [tuple(row[column] for column in columns) for row in self.show_data]
            else:
                self.description = [("NAME",), ("DISABLED",)]
                self._rows = [(f"ROW_{index}", "false") for index in range(self.show_rows)]
        elif self.check_rows is not None:
            columns = list(self.check_rows[0]) if self.check_rows else ["CNT"]
            self.description = [(column.upper(),) for column in columns]
            self._rows = [tuple(row[column] for column in columns) for row in self.check_rows]
        else:
            self.description = [("NAME",), ("EXT_AUTHN_DUO",), ("HAS_PASSWORD",), ("DISABLED",)]
            self._rows = [tuple(row[key] for key in ("name", "ext_authn_duo", "has_password", "disabled")) for row in self.filtered_rows]

    def fetchall(self):
        return self._rows


def _run_selected_with_source(cursor, check_id="1.1"):
    import sys

    conn = MagicMock()
    conn.cursor.return_value = cursor
    mock_errors = MagicMock()
    mock_errors.DatabaseError = Exception
    with patch.dict(
        sys.modules,
        {
            "snowflake": MagicMock(),
            "snowflake.connector": MagicMock(),
            "snowflake.connector.errors": mock_errors,
        },
    ):
        return run_benchmark(account="test", checks=[check_id], conn=conn)


def _run_check_11_with_source(cursor):
    return _run_selected_with_source(cursor)


def test_empty_account_usage_source_is_error_not_pass():
    report = _run_check_11_with_source(_SourceAwareCursor(source_rows=0))
    assert report.checks[0].status == CheckStatus.ERROR
    assert report.source_health["users"]["coverage"] == "empty"


def test_source_preflight_does_not_invent_a_current_time_watermark():
    from agent_bom.cloud.snowflake_cis_benchmark import _SOURCE_PROBES

    for sql, _minimum_rows in _SOURCE_PROBES.values():
        assert "AS observed_at" not in sql
        assert "QUERY_HISTORY" not in sql
        assert "LOGIN_HISTORY" not in sql or "MAX(" not in sql


def test_denied_account_usage_source_is_error_not_pass():
    report = _run_check_11_with_source(_SourceAwareCursor(denied=True))
    assert report.checks[0].status == CheckStatus.ERROR
    assert report.source_health["users"]["privilege"] == "unknown"
    assert report.source_health["users"]["query_status"] == "error"


def test_clean_filtered_empty_passes_when_source_is_covered_and_fresh():
    report = _run_check_11_with_source(_SourceAwareCursor(source_rows=2, filtered_rows=[]))
    assert report.checks[0].status == CheckStatus.PASS
    assert "All 0 password-authenticated users" in report.checks[0].evidence


def test_same_count_stale_account_usage_values_cannot_produce_false_pass():
    report = _run_check_11_with_source(
        _SourceAwareCursor(
            source_rows=1,
            show_data=[
                {
                    "name": "ADMIN",
                    "disabled": "false",
                    "has_password": "true",
                    "ext_authn_duo": "false",
                }
            ],
        )
    )
    assert report.source_health["users"]["freshness"] == "control_plane_reconciled"
    assert report.checks[0].status == CheckStatus.FAIL
    assert "ADMIN" in report.checks[0].evidence


def test_empty_login_history_window_is_covered_not_stale():
    health = _preflight_account_usage_source(_SourceAwareCursor(source_rows=0), "login_history")
    assert health["usable"] is True
    assert health["coverage"] == "covered"
    assert health["freshness"] == "bounded_as_of_empty_window"


def test_nonempty_login_history_reports_bounded_as_of_freshness():
    health = _preflight_account_usage_source(_SourceAwareCursor(source_rows=2), "login_history")
    assert health["usable"] is True
    assert health["freshness"] == "bounded_as_of"
    assert health["provider_lag_bound_hours"] == 2


def test_snapshot_source_requires_live_control_plane_reconciliation():
    health = _preflight_account_usage_source(_SourceAwareCursor(source_rows=1), "users")
    assert health["usable"] is True
    assert health["freshness"] == "control_plane_reconciled"
    assert health["provider_lag_bound_hours"] == 2

    stale = _preflight_account_usage_source(_SourceAwareCursor(source_rows=1, show_rows=2), "users")
    assert stale["usable"] is False
    assert stale["freshness"] == "stale"


def test_password_policy_and_access_history_sources_are_preflight_gated():
    from agent_bom.cloud.snowflake_cis_benchmark import _CHECK_SOURCES, _SOURCE_PROBES

    assert _CHECK_SOURCES["1.2"] == "password_policies"
    assert _CHECK_SOURCES["4.1"] == "access_history"
    for source in ("password_policies", "access_history"):
        denied = _preflight_account_usage_source(_SourceAwareCursor(denied=True), source)
        current = _preflight_account_usage_source(_SourceAwareCursor(source_rows=0), source)
        assert denied["usable"] is False
        assert current["usable"] is True
        assert current["freshness"] == (
            "control_plane_reconciled" if source == "password_policies" else "bounded_as_of"
        )
        assert source in _SOURCE_PROBES


def test_password_policy_denied_stale_empty_and_current_semantics():
    denied = _run_selected_with_source(_SourceAwareCursor(denied=True), "1.2")
    assert denied.checks[0].status == CheckStatus.ERROR

    stale = _run_selected_with_source(_SourceAwareCursor(source_rows=1, show_rows=2), "1.2")
    assert stale.checks[0].status == CheckStatus.ERROR
    assert stale.source_health["password_policies"]["freshness"] == "stale"

    empty = _run_selected_with_source(_SourceAwareCursor(source_rows=0, check_rows=[]), "1.2")
    assert empty.checks[0].status == CheckStatus.FAIL
    assert empty.source_health["password_policies"]["freshness"] == "control_plane_reconciled"

    current = _run_selected_with_source(
        _SourceAwareCursor(
            source_rows=1,
            show_data=[
                {
                    "database_name": "SECURITY",
                    "schema_name": "POLICIES",
                    "name": "STRONG",
                }
            ],
            check_rows=[{"property": "PASSWORD_MIN_LENGTH", "value": 14}],
        ),
        "1.2",
    )
    assert current.checks[0].status == CheckStatus.PASS


def test_access_history_denied_empty_and_bounded_current_semantics():
    denied = _run_selected_with_source(_SourceAwareCursor(denied=True), "4.1")
    assert denied.checks[0].status == CheckStatus.ERROR

    empty = _run_selected_with_source(_SourceAwareCursor(source_rows=0, check_rows=[{"cnt": 0}]), "4.1")
    assert empty.checks[0].status == CheckStatus.FAIL
    assert empty.source_health["access_history"]["freshness"] == "bounded_as_of"

    current = _run_selected_with_source(_SourceAwareCursor(source_rows=5, check_rows=[{"cnt": 5}]), "4.1")
    assert current.checks[0].status == CheckStatus.PASS
    assert current.source_health["access_history"]["freshness"] == "bounded_as_of"


def test_snowflake_report_exposes_error_and_evaluation_counts():
    report = _run_check_11_with_source(_SourceAwareCursor(source_rows=0))
    payload = report.to_dict()
    assert payload["errored"] == 1
    assert payload["evaluated"] == 0
    assert payload["not_applicable"] == 0
