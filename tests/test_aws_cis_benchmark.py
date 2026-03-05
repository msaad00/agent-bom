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
    _check_2_1_1,
    _check_2_1_2,
    _check_2_1_4,
    _check_3_1,
    _check_3_2,
    _check_3_4,
    _check_3_5,
    _check_3_6,
    _check_5_2,
    _check_5_3,
    _check_5_6,
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
# 2.1.1 — S3 account-level public access block
# ---------------------------------------------------------------------------


class TestCheck211:
    def test_pass_all_blocked(self):
        client = MagicMock()
        client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": True,
                "RestrictPublicBuckets": True,
            }
        }
        result = _check_2_1_1(client, "123456789012")
        assert result.status == CheckStatus.PASS

    def test_fail_missing_setting(self):
        client = MagicMock()
        client.get_public_access_block.return_value = {
            "PublicAccessBlockConfiguration": {
                "BlockPublicAcls": True,
                "IgnorePublicAcls": True,
                "BlockPublicPolicy": False,
                "RestrictPublicBuckets": True,
            }
        }
        result = _check_2_1_1(client, "123456789012")
        assert result.status == CheckStatus.FAIL
        assert "BlockPublicPolicy" in result.evidence

    def test_fail_no_config(self):
        client = MagicMock()
        exc = Exception("NoSuchPublicAccessBlockConfiguration")
        exc.response = {"Error": {"Code": "NoSuchPublicAccessBlockConfiguration"}}
        client.get_public_access_block.side_effect = exc
        result = _check_2_1_1(client, "123456789012")
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 2.1.2 — S3 encryption
# ---------------------------------------------------------------------------


class TestCheck212:
    def test_pass_all_encrypted(self):
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "my-bucket"}]}
        client.get_bucket_encryption.return_value = {"ServerSideEncryptionConfiguration": {}}
        result = _check_2_1_2(client)
        assert result.status == CheckStatus.PASS

    def test_fail_unencrypted(self):
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "open-bucket"}]}
        exc = Exception("ServerSideEncryptionConfigurationNotFoundError")
        exc.response = {"Error": {"Code": "ServerSideEncryptionConfigurationNotFoundError"}}
        client.get_bucket_encryption.side_effect = exc
        result = _check_2_1_2(client)
        assert result.status == CheckStatus.FAIL
        assert "open-bucket" in result.evidence


# ---------------------------------------------------------------------------
# 2.1.4 — S3 versioning
# ---------------------------------------------------------------------------


class TestCheck214:
    def test_pass_versioned(self):
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "my-bucket"}]}
        client.get_bucket_versioning.return_value = {"Status": "Enabled"}
        result = _check_2_1_4(client)
        assert result.status == CheckStatus.PASS

    def test_fail_unversioned(self):
        client = MagicMock()
        client.list_buckets.return_value = {"Buckets": [{"Name": "no-ver"}]}
        client.get_bucket_versioning.return_value = {}
        result = _check_2_1_4(client)
        assert result.status == CheckStatus.FAIL
        assert "no-ver" in result.evidence


# ---------------------------------------------------------------------------
# 3.1 — CloudTrail multi-region
# ---------------------------------------------------------------------------


class TestCheck31:
    def test_pass_multi_region_logging(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"TrailARN": "arn:trail", "IsMultiRegionTrail": True, "Name": "main"}]}
        client.get_trail_status.return_value = {"IsLogging": True}
        result = _check_3_1(client)
        assert result.status == CheckStatus.PASS

    def test_fail_no_multi_region(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"TrailARN": "arn:trail", "IsMultiRegionTrail": False, "Name": "local"}]}
        result = _check_3_1(client)
        assert result.status == CheckStatus.FAIL

    def test_fail_not_logging(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"TrailARN": "arn:trail", "IsMultiRegionTrail": True, "Name": "main"}]}
        client.get_trail_status.return_value = {"IsLogging": False}
        result = _check_3_1(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 3.2 — CloudTrail log file validation
# ---------------------------------------------------------------------------


class TestCheck32:
    def test_pass_validation_enabled(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"Name": "main", "LogFileValidationEnabled": True}]}
        result = _check_3_2(client)
        assert result.status == CheckStatus.PASS

    def test_fail_no_validation(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"Name": "main", "TrailARN": "arn:trail", "LogFileValidationEnabled": False}]}
        result = _check_3_2(client)
        assert result.status == CheckStatus.FAIL

    def test_fail_no_trails(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": []}
        result = _check_3_2(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 3.4 — CloudTrail + CloudWatch Logs
# ---------------------------------------------------------------------------


class TestCheck34:
    def test_pass_integrated(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"Name": "main", "CloudWatchLogsLogGroupArn": "arn:logs:group"}]}
        result = _check_3_4(client)
        assert result.status == CheckStatus.PASS

    def test_fail_no_cwl(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"Name": "main", "TrailARN": "arn:trail"}]}
        result = _check_3_4(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 3.5 — Management events recording
# ---------------------------------------------------------------------------


class TestCheck35:
    def test_pass_records_all(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"TrailARN": "arn:trail", "IsMultiRegionTrail": True}]}
        client.get_event_selectors.return_value = {
            "EventSelectors": [{"IncludeManagementEvents": True, "ReadWriteType": "All"}],
            "AdvancedEventSelectors": [],
        }
        result = _check_3_5(client)
        assert result.status == CheckStatus.PASS

    def test_fail_no_multi_region(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"TrailARN": "arn:trail", "IsMultiRegionTrail": False}]}
        result = _check_3_5(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 3.6 — CloudTrail S3 bucket access logging
# ---------------------------------------------------------------------------


class TestCheck36:
    def test_pass_logging_enabled(self):
        s3 = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{"S3BucketName": "ct-bucket"}]}
        s3.get_bucket_logging.return_value = {"LoggingEnabled": {"TargetBucket": "log-bucket"}}
        result = _check_3_6(s3, ct)
        assert result.status == CheckStatus.PASS

    def test_fail_no_logging(self):
        s3 = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{"S3BucketName": "ct-bucket"}]}
        s3.get_bucket_logging.return_value = {}
        result = _check_3_6(s3, ct)
        assert result.status == CheckStatus.FAIL
        assert "ct-bucket" in result.evidence

    def test_not_applicable_no_trails(self):
        s3 = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": []}
        result = _check_3_6(s3, ct)
        assert result.status == CheckStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 5.2 — Security groups admin ports
# ---------------------------------------------------------------------------


class TestCheck52:
    def test_pass_no_open_admin(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-1",
                        "IpPermissions": [{"FromPort": 443, "ToPort": 443, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_2(client)
        assert result.status == CheckStatus.PASS

    def test_fail_ssh_open(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-bad",
                        "IpPermissions": [{"FromPort": 22, "ToPort": 22, "IpRanges": [{"CidrIp": "0.0.0.0/0"}], "Ipv6Ranges": []}],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_2(client)
        assert result.status == CheckStatus.FAIL
        assert "sg-bad" in result.evidence

    def test_fail_rdp_ipv6_open(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-rdp",
                        "IpPermissions": [{"FromPort": 3389, "ToPort": 3389, "IpRanges": [], "Ipv6Ranges": [{"CidrIpv6": "::/0"}]}],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_2(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 5.3 — Default security group restricts all
# ---------------------------------------------------------------------------


class TestCheck53:
    def test_pass_empty_default(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"SecurityGroups": [{"GroupId": "sg-default", "VpcId": "vpc-1", "IpPermissions": [], "IpPermissionsEgress": []}]}
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_3(client)
        assert result.status == CheckStatus.PASS

    def test_fail_inbound_rules(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "SecurityGroups": [
                    {
                        "GroupId": "sg-default",
                        "VpcId": "vpc-1",
                        "IpPermissions": [{"IpProtocol": "-1"}],
                        "IpPermissionsEgress": [],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_3(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 5.6 — VPC flow logs
# ---------------------------------------------------------------------------


class TestCheck56:
    def test_pass_all_vpcs_covered(self):
        client = MagicMock()
        client.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}]}
        client.describe_flow_logs.return_value = {"FlowLogs": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE"}]}
        result = _check_5_6(client)
        assert result.status == CheckStatus.PASS

    def test_fail_missing_flow_log(self):
        client = MagicMock()
        client.describe_vpcs.return_value = {"Vpcs": [{"VpcId": "vpc-1"}, {"VpcId": "vpc-2"}]}
        client.describe_flow_logs.return_value = {"FlowLogs": [{"ResourceId": "vpc-1", "FlowLogStatus": "ACTIVE"}]}
        result = _check_5_6(client)
        assert result.status == CheckStatus.FAIL
        assert "vpc-2" in result.evidence

    def test_not_applicable_no_vpcs(self):
        client = MagicMock()
        client.describe_vpcs.return_value = {"Vpcs": []}
        result = _check_5_6(client)
        assert result.status == CheckStatus.NOT_APPLICABLE


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

            # Generic mock that works for all services
            mock_client = _iam_client()
            mock_client.generate_credential_report.return_value = {"State": "COMPLETE"}
            mock_client.get_credential_report.return_value = {
                "Content": b"user,password_last_used,access_key_1_last_used_date,access_key_2_last_used_date\n"
            }
            mock_client.list_user_policies.return_value = {"PolicyNames": []}
            mock_client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
            # S3
            mock_client.list_buckets.return_value = {"Buckets": []}
            mock_client.get_public_access_block.return_value = {
                "PublicAccessBlockConfiguration": {
                    "BlockPublicAcls": True,
                    "IgnorePublicAcls": True,
                    "BlockPublicPolicy": True,
                    "RestrictPublicBuckets": True,
                }
            }
            # CloudTrail
            mock_client.describe_trails.return_value = {"trailList": []}
            # EC2 — separate mock because paginator returns different structure
            mock_ec2 = MagicMock()
            ec2_paginator = MagicMock()
            ec2_paginator.paginate.return_value = [{"SecurityGroups": []}]
            mock_ec2.get_paginator.return_value = ec2_paginator
            mock_ec2.describe_vpcs.return_value = {"Vpcs": []}
            mock_ec2.describe_flow_logs.return_value = {"FlowLogs": []}

            def client_factory(service, **kwargs):
                if service == "sts":
                    return mock_sts
                if service == "ec2":
                    return mock_ec2
                return mock_client

            mock_session.client.side_effect = client_factory

            report = run_benchmark()
            assert report.account_id == "111222333444"
            # 7 IAM + 2 S3 + 4 CloudTrail + 3 VPC + 1 s3control + 1 s3+cloudtrail = 18
            assert report.total == 18

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
