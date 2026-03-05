"""Tests for CIS AWS Foundations Benchmark v3.0 checks."""

from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from agent_bom.cloud.aws_cis_benchmark import (
    CheckStatus,
    CISBenchmarkReport,
    CISCheckResult,
    _check_1_4,
    _check_1_5,
    _check_1_6,
    _check_1_8,
    _check_1_10,
    _check_1_12,
    _check_1_15,
    run_benchmark,
)

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _iam_client(**overrides) -> MagicMock:
    """Create a mock IAM client with sensible defaults."""
    client = MagicMock()
    client.get_account_summary.return_value = {
        "SummaryMap": {
            "AccountAccessKeysPresent": 0,
            "AccountMFAEnabled": 1,
        }
    }
    client.list_virtual_mfa_devices.return_value = {"VirtualMFADevices": []}
    client.get_account_password_policy.return_value = {"PasswordPolicy": {"MinimumPasswordLength": 14}}
    paginator = MagicMock()
    paginator.paginate.return_value = [{"Users": []}]
    client.get_paginator.return_value = paginator
    for k, v in overrides.items():
        setattr(client, k, v)
    return client


# ---------------------------------------------------------------------------
# 1.4 — Root access keys
# ---------------------------------------------------------------------------


class TestCheck14:
    def test_pass_no_root_keys(self):
        client = _iam_client()
        result = _check_1_4(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "1.4"

    def test_fail_root_keys_present(self):
        client = _iam_client()
        client.get_account_summary.return_value = {"SummaryMap": {"AccountAccessKeysPresent": 1}}
        result = _check_1_4(client)
        assert result.status == CheckStatus.FAIL
        assert "1 active access key" in result.evidence


# ---------------------------------------------------------------------------
# 1.5 — Root MFA
# ---------------------------------------------------------------------------


class TestCheck15:
    def test_pass_mfa_enabled(self):
        client = _iam_client()
        result = _check_1_5(client)
        assert result.status == CheckStatus.PASS

    def test_fail_mfa_disabled(self):
        client = _iam_client()
        client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        result = _check_1_5(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 1.6 — Root hardware MFA
# ---------------------------------------------------------------------------


class TestCheck16:
    def test_pass_hardware_mfa(self):
        client = _iam_client()
        result = _check_1_6(client)
        assert result.status == CheckStatus.PASS

    def test_fail_no_mfa_at_all(self):
        client = _iam_client()
        client.get_account_summary.return_value = {"SummaryMap": {"AccountMFAEnabled": 0}}
        result = _check_1_6(client)
        assert result.status == CheckStatus.FAIL
        assert "no MFA at all" in result.evidence

    def test_fail_virtual_mfa(self):
        client = _iam_client()
        client.list_virtual_mfa_devices.return_value = {
            "VirtualMFADevices": [{"SerialNumber": "arn:aws:iam::123456789:mfa/root-account-mfa-device"}]
        }
        result = _check_1_6(client)
        assert result.status == CheckStatus.FAIL
        assert "virtual MFA" in result.evidence


# ---------------------------------------------------------------------------
# 1.8 — Password policy length
# ---------------------------------------------------------------------------


class TestCheck18:
    def test_pass_length_14(self):
        client = _iam_client()
        result = _check_1_8(client)
        assert result.status == CheckStatus.PASS

    def test_fail_length_8(self):
        client = _iam_client()
        client.get_account_password_policy.return_value = {"PasswordPolicy": {"MinimumPasswordLength": 8}}
        result = _check_1_8(client)
        assert result.status == CheckStatus.FAIL
        assert "8" in result.evidence

    def test_fail_no_policy(self):
        """NoSuchEntity means no password policy configured."""
        client = _iam_client()
        exc = Exception("NoSuchEntity")
        exc.response = {"Error": {"Code": "NoSuchEntity", "Message": "..."}}
        client.get_account_password_policy.side_effect = exc
        result = _check_1_8(client)
        assert result.status == CheckStatus.FAIL
        assert "No password policy" in result.evidence


# ---------------------------------------------------------------------------
# 1.10 — Console users MFA
# ---------------------------------------------------------------------------


class TestCheck110:
    def test_pass_no_users(self):
        client = _iam_client()
        result = _check_1_10(client)
        assert result.status == CheckStatus.PASS

    def test_fail_user_without_mfa(self):
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Users": [{"UserName": "alice"}]}]
        client.get_paginator.return_value = paginator
        client.get_login_profile.return_value = {}  # has console access
        client.list_mfa_devices.return_value = {"MFADevices": []}
        result = _check_1_10(client)
        assert result.status == CheckStatus.FAIL
        assert "alice" in result.evidence

    def test_pass_user_no_console(self):
        """User without console access should be skipped."""
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Users": [{"UserName": "bot-user"}]}]
        client.get_paginator.return_value = paginator
        exc = Exception("NoSuchEntity")
        exc.response = {"Error": {"Code": "NoSuchEntity"}}
        client.get_login_profile.side_effect = exc
        result = _check_1_10(client)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 1.12 — Stale credentials
# ---------------------------------------------------------------------------


class TestCheck112:
    def test_pass_no_stale(self):
        client = _iam_client()
        client.generate_credential_report.return_value = {"State": "COMPLETE"}
        client.get_credential_report.return_value = {
            "Content": (
                "user,password_last_used,access_key_1_last_used_date,access_key_2_last_used_date\n"
                "<root_account>,N/A,N/A,N/A\n"
                "alice,2026-03-01T00:00:00+00:00,N/A,N/A\n"
            ).encode()
        }
        result = _check_1_12(client)
        assert result.status == CheckStatus.PASS

    def test_fail_stale_user(self):
        client = _iam_client()
        client.generate_credential_report.return_value = {"State": "COMPLETE"}
        client.get_credential_report.return_value = {
            "Content": (
                "user,password_last_used,access_key_1_last_used_date,access_key_2_last_used_date\n"
                "<root_account>,N/A,N/A,N/A\n"
                "stale-bob,2020-01-01T00:00:00+00:00,N/A,N/A\n"
            ).encode()
        }
        result = _check_1_12(client)
        assert result.status == CheckStatus.FAIL
        assert "stale-bob" in result.evidence


# ---------------------------------------------------------------------------
# 1.15 — Permissions only through groups
# ---------------------------------------------------------------------------


class TestCheck115:
    def test_pass_no_direct_policies(self):
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Users": [{"UserName": "alice"}]}]
        client.get_paginator.return_value = paginator
        client.list_user_policies.return_value = {"PolicyNames": []}
        client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        result = _check_1_15(client)
        assert result.status == CheckStatus.PASS

    def test_fail_inline_policy(self):
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Users": [{"UserName": "admin"}]}]
        client.get_paginator.return_value = paginator
        client.list_user_policies.return_value = {"PolicyNames": ["InlineAdmin"]}
        client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
        result = _check_1_15(client)
        assert result.status == CheckStatus.FAIL
        assert "admin" in result.evidence


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


class TestCISBenchmarkReport:
    def test_empty_report(self):
        report = CISBenchmarkReport()
        assert report.passed == 0
        assert report.failed == 0
        assert report.total == 0
        assert report.pass_rate == 0.0

    def test_mixed_results(self):
        report = CISBenchmarkReport(
            checks=[
                CISCheckResult(check_id="1.4", title="test", status=CheckStatus.PASS, severity="critical"),
                CISCheckResult(check_id="1.5", title="test", status=CheckStatus.FAIL, severity="critical"),
                CISCheckResult(check_id="1.6", title="test", status=CheckStatus.ERROR, severity="critical"),
            ]
        )
        assert report.passed == 1
        assert report.failed == 1
        assert report.total == 3
        assert report.pass_rate == 50.0

    def test_to_dict(self):
        report = CISBenchmarkReport(
            account_id="123456789012",
            region="us-east-1",
            checks=[
                CISCheckResult(check_id="1.4", title="Root keys", status=CheckStatus.PASS, severity="critical"),
            ],
        )
        d = report.to_dict()
        assert d["benchmark"] == "CIS AWS Foundations"
        assert d["benchmark_version"] == "3.0"
        assert d["account_id"] == "123456789012"
        assert len(d["checks"]) == 1
        assert d["checks"][0]["status"] == "pass"


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def _mock_boto3_modules():
    """Patch sys.modules so `import boto3` inside run_benchmark resolves to a mock."""
    mock_boto3 = MagicMock()
    mock_botocore = MagicMock()
    mock_botocore_exc = MagicMock()
    # Create a real-ish ClientError for the except clause
    mock_botocore_exc.ClientError = type(
        "ClientError",
        (Exception,),
        {
            "__init__": lambda self, response, operation_name: (
                setattr(self, "response", response) or super(type(self), self).__init__(str(response))
            ),
        },
    )
    return patch.dict(
        "sys.modules",
        {
            "boto3": mock_boto3,
            "botocore": mock_botocore,
            "botocore.exceptions": mock_botocore_exc,
        },
    ), mock_boto3


class TestRunBenchmark:
    def test_missing_boto3(self):
        with patch.dict("sys.modules", {"boto3": None, "botocore": None, "botocore.exceptions": None}):
            with pytest.raises(Exception, match="boto3"):
                run_benchmark()

    def test_runs_all_checks(self):
        modules_patch, mock_boto3 = _mock_boto3_modules()
        with modules_patch:
            mock_session = MagicMock()
            mock_boto3.Session.return_value = mock_session
            mock_session.region_name = "us-east-1"

            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "111222333444"}

            mock_iam = _iam_client()
            mock_iam.generate_credential_report.return_value = {"State": "COMPLETE"}
            mock_iam.get_credential_report.return_value = {
                "Content": b"user,password_last_used,access_key_1_last_used_date,access_key_2_last_used_date\n"
            }
            mock_iam.list_user_policies.return_value = {"PolicyNames": []}
            mock_iam.list_attached_user_policies.return_value = {"AttachedPolicies": []}

            def client_factory(service, **kwargs):
                if service == "sts":
                    return mock_sts
                return mock_iam

            mock_session.client.side_effect = client_factory

            report = run_benchmark()
            assert report.account_id == "111222333444"
            assert report.total == 7
            assert all(c.status in (CheckStatus.PASS, CheckStatus.FAIL) for c in report.checks)

    def test_filter_checks(self):
        modules_patch, mock_boto3 = _mock_boto3_modules()
        with modules_patch:
            mock_session = MagicMock()
            mock_boto3.Session.return_value = mock_session
            mock_session.region_name = "us-east-1"

            mock_sts = MagicMock()
            mock_sts.get_caller_identity.return_value = {"Account": "123"}
            mock_iam = _iam_client()

            def client_factory(service, **kwargs):
                if service == "sts":
                    return mock_sts
                return mock_iam

            mock_session.client.side_effect = client_factory

            report = run_benchmark(checks=["1.4", "1.5"])
            assert report.total == 2
            assert {c.check_id for c in report.checks} == {"1.4", "1.5"}
