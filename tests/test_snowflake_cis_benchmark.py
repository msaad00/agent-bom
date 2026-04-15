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
        cursor = _mock_cursor([{"policy_name": "DEFAULT", "password_min_length": 14}])
        result = _check_1_2(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_weak_policy(self):
        cursor = _mock_cursor([{"policy_name": "DEFAULT", "password_min_length": 8}])
        result = _check_1_2(cursor)
        assert result.status == CheckStatus.FAIL

    def test_fail_no_policies(self):
        cursor = _empty_cursor()
        result = _check_1_2(cursor)
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
                {"grantee_name": "ADMIN1"},
                {"grantee_name": "ADMIN2"},
            ]
        )
        result = _check_1_4(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_too_many_admins(self):
        cursor = _mock_cursor(
            [
                {"grantee_name": "ADMIN1"},
                {"grantee_name": "ADMIN2"},
                {"grantee_name": "ADMIN3"},
            ]
        )
        result = _check_1_4(cursor)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 1.5 — Password history
# ---------------------------------------------------------------------------


class TestCheck15:
    def test_pass_history_strong(self):
        cursor = _mock_cursor([{"policy_name": "DEFAULT", "password_history": 24}])
        result = _check_1_5(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_history_weak(self):
        cursor = _mock_cursor([{"policy_name": "DEFAULT", "password_history": 5}])
        result = _check_1_5(cursor)
        assert result.status == CheckStatus.FAIL

    def test_fail_no_policies(self):
        cursor = _empty_cursor()
        result = _check_1_5(cursor)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 1.6 — Password max age
# ---------------------------------------------------------------------------


class TestCheck16:
    def test_pass_max_age_strong(self):
        cursor = _mock_cursor([{"policy_name": "DEFAULT", "password_max_age_days": 90}])
        result = _check_1_6(cursor)
        assert result.status == CheckStatus.PASS

    def test_fail_max_age_too_high(self):
        cursor = _mock_cursor([{"policy_name": "DEFAULT", "password_max_age_days": 180}])
        result = _check_1_6(cursor)
        assert result.status == CheckStatus.FAIL

    def test_fail_max_age_zero(self):
        cursor = _mock_cursor([{"policy_name": "DEFAULT", "password_max_age_days": 0}])
        result = _check_1_6(cursor)
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
        cursor = _mock_cursor([{"database_name": "DB1", "name": "SHARE1", "kind": "OUTBOUND"}])
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

    def test_fail_no_records(self):
        cursor = _mock_cursor([{"cnt": 0}])
        result = _check_4_1(cursor)
        assert result.status == CheckStatus.FAIL

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

    def test_fail_excessive_failures(self):
        cursor = _mock_cursor([{"user_name": "BADUSER", "fail_count": 25}])
        result = _check_4_2(cursor)
        assert result.status == CheckStatus.FAIL
        assert "BADUSER" in result.evidence


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
