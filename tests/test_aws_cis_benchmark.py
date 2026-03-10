"""Tests for CIS AWS Foundations Benchmark v3.0 checks."""

from __future__ import annotations

from datetime import datetime, timedelta, timezone
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
    _check_1_9,
    _check_1_10,
    _check_1_12,
    _check_1_14,
    _check_1_15,
    _check_1_16,
    _check_2_1_1,
    _check_2_1_2,
    _check_2_1_4,
    _check_2_2_1,
    _check_2_3_1,
    _check_2_3_2,
    _check_2_4_1,
    _check_3_1,
    _check_3_2,
    _check_3_3,
    _check_3_4,
    _check_3_5,
    _check_3_6,
    _check_3_7,
    _check_4_3,
    _check_4_4,
    _check_4_5,
    _check_5_1,
    _check_5_2,
    _check_5_3,
    _check_5_4,
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
    paginator.paginate.return_value = [{"Users": [], "Policies": []}]
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
# 1.9 — Password reuse prevention
# ---------------------------------------------------------------------------


class TestCheck19:
    def test_pass_reuse_24(self):
        client = _iam_client()
        client.get_account_password_policy.return_value = {"PasswordPolicy": {"PasswordReusePrevention": 24}}
        result = _check_1_9(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "1.9"

    def test_fail_reuse_low(self):
        client = _iam_client()
        client.get_account_password_policy.return_value = {"PasswordPolicy": {"PasswordReusePrevention": 5}}
        result = _check_1_9(client)
        assert result.status == CheckStatus.FAIL
        assert "5" in result.evidence

    def test_fail_no_policy(self):
        client = _iam_client()
        exc = Exception("NoSuchEntity")
        exc.response = {"Error": {"Code": "NoSuchEntity", "Message": "..."}}
        client.get_account_password_policy.side_effect = exc
        result = _check_1_9(client)
        assert result.status == CheckStatus.FAIL
        assert "No password policy" in result.evidence

    def test_fail_reuse_missing_key(self):
        """PasswordReusePrevention key absent defaults to 0."""
        client = _iam_client()
        client.get_account_password_policy.return_value = {"PasswordPolicy": {}}
        result = _check_1_9(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 1.14 — Access key rotation (90 days)
# ---------------------------------------------------------------------------


class TestCheck114:
    def test_pass_fresh_keys(self):
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Users": [{"UserName": "alice"}]}]
        client.get_paginator.return_value = paginator
        client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAIOSFODNN7", "Status": "Active", "CreateDate": datetime.now(tz=timezone.utc)},
            ]
        }
        result = _check_1_14(client)
        assert result.status == CheckStatus.PASS

    def test_fail_old_key(self):
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Users": [{"UserName": "bob"}]}]
        client.get_paginator.return_value = paginator
        old_date = datetime.now(tz=timezone.utc) - timedelta(days=120)
        client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAIOSFODNN7", "Status": "Active", "CreateDate": old_date},
            ]
        }
        result = _check_1_14(client)
        assert result.status == CheckStatus.FAIL
        assert "bob" in result.evidence

    def test_pass_inactive_old_key(self):
        """Inactive keys should not trigger failure."""
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Users": [{"UserName": "carol"}]}]
        client.get_paginator.return_value = paginator
        old_date = datetime.now(tz=timezone.utc) - timedelta(days=120)
        client.list_access_keys.return_value = {
            "AccessKeyMetadata": [
                {"AccessKeyId": "AKIAIOSFODNN7", "Status": "Inactive", "CreateDate": old_date},
            ]
        }
        result = _check_1_14(client)
        assert result.status == CheckStatus.PASS

    def test_pass_no_users(self):
        client = _iam_client()
        result = _check_1_14(client)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 1.16 — No full admin policies (*:*)
# ---------------------------------------------------------------------------


class TestCheck116:
    def test_pass_no_admin_policies(self):
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Policies": []}]
        client.get_paginator.return_value = paginator
        result = _check_1_16(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "1.16"

    def test_fail_admin_policy(self):
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "Policies": [
                    {
                        "PolicyName": "FullAdmin",
                        "Arn": "arn:aws:iam::123456789:policy/FullAdmin",
                        "DefaultVersionId": "v1",
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        client.get_policy_version.return_value = {
            "PolicyVersion": {"Document": {"Statement": [{"Effect": "Allow", "Action": "*", "Resource": "*"}]}}
        }
        result = _check_1_16(client)
        assert result.status == CheckStatus.FAIL
        assert "FullAdmin" in result.evidence

    def test_pass_scoped_policy(self):
        client = _iam_client()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "Policies": [
                    {
                        "PolicyName": "ReadOnly",
                        "Arn": "arn:aws:iam::123456789:policy/ReadOnly",
                        "DefaultVersionId": "v1",
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        client.get_policy_version.return_value = {
            "PolicyVersion": {
                "Document": {"Statement": [{"Effect": "Allow", "Action": "s3:GetObject", "Resource": "arn:aws:s3:::my-bucket/*"}]}
            }
        }
        result = _check_1_16(client)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 2.2.1 — EBS default encryption
# ---------------------------------------------------------------------------


class TestCheck221:
    def test_pass_encryption_enabled(self):
        client = MagicMock()
        client.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": True}
        result = _check_2_2_1(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "2.2.1"

    def test_fail_encryption_disabled(self):
        client = MagicMock()
        client.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": False}
        result = _check_2_2_1(client)
        assert result.status == CheckStatus.FAIL
        assert "not enabled" in result.evidence

    def test_error_on_api_failure(self):
        client = MagicMock()
        exc = Exception("UnauthorizedOperation")
        exc.response = {"Error": {"Code": "UnauthorizedOperation"}}
        client.get_ebs_encryption_by_default.side_effect = exc
        result = _check_2_2_1(client)
        assert result.status == CheckStatus.ERROR


# ---------------------------------------------------------------------------
# 2.3.1 — RDS encryption at rest
# ---------------------------------------------------------------------------


class TestCheck231:
    def test_pass_all_encrypted(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": [{"DBInstanceIdentifier": "db-1", "StorageEncrypted": True}]}]
        client.get_paginator.return_value = paginator
        result = _check_2_3_1(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "2.3.1"

    def test_fail_unencrypted(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": [{"DBInstanceIdentifier": "db-open", "StorageEncrypted": False}]}]
        client.get_paginator.return_value = paginator
        result = _check_2_3_1(client)
        assert result.status == CheckStatus.FAIL
        assert "db-open" in result.evidence

    def test_pass_no_instances(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": []}]
        client.get_paginator.return_value = paginator
        result = _check_2_3_1(client)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 2.3.2 — RDS auto minor version upgrade
# ---------------------------------------------------------------------------


class TestCheck232:
    def test_pass_auto_upgrade_enabled(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": [{"DBInstanceIdentifier": "db-1", "AutoMinorVersionUpgrade": True}]}]
        client.get_paginator.return_value = paginator
        result = _check_2_3_2(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "2.3.2"

    def test_fail_auto_upgrade_disabled(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": [{"DBInstanceIdentifier": "db-old", "AutoMinorVersionUpgrade": False}]}]
        client.get_paginator.return_value = paginator
        result = _check_2_3_2(client)
        assert result.status == CheckStatus.FAIL
        assert "db-old" in result.evidence

    def test_pass_no_instances(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"DBInstances": []}]
        client.get_paginator.return_value = paginator
        result = _check_2_3_2(client)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 2.4.1 — KMS key rotation
# ---------------------------------------------------------------------------


class TestCheck241:
    def test_pass_rotation_enabled(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Keys": [{"KeyId": "key-1"}]}]
        client.get_paginator.return_value = paginator
        client.describe_key.return_value = {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled"}}
        client.get_key_rotation_status.return_value = {"KeyRotationEnabled": True}
        result = _check_2_4_1(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "2.4.1"

    def test_fail_rotation_disabled(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Keys": [{"KeyId": "key-bad"}]}]
        client.get_paginator.return_value = paginator
        client.describe_key.return_value = {"KeyMetadata": {"KeyManager": "CUSTOMER", "KeyState": "Enabled"}}
        client.get_key_rotation_status.return_value = {"KeyRotationEnabled": False}
        result = _check_2_4_1(client)
        assert result.status == CheckStatus.FAIL
        assert "key-bad" in result.evidence

    def test_pass_aws_managed_key_skipped(self):
        """AWS-managed keys should be skipped (not flagged)."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Keys": [{"KeyId": "aws-key-1"}]}]
        client.get_paginator.return_value = paginator
        client.describe_key.return_value = {"KeyMetadata": {"KeyManager": "AWS", "KeyState": "Enabled"}}
        result = _check_2_4_1(client)
        assert result.status == CheckStatus.PASS

    def test_pass_no_keys(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"Keys": []}]
        client.get_paginator.return_value = paginator
        result = _check_2_4_1(client)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 3.3 — CloudTrail S3 bucket not publicly accessible
# ---------------------------------------------------------------------------


class TestCheck33:
    def test_pass_no_public_policy(self):
        s3 = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{"S3BucketName": "ct-bucket"}]}
        exc = Exception("NoSuchBucketPolicy")
        exc.response = {"Error": {"Code": "NoSuchBucketPolicy"}}
        s3.get_bucket_policy.side_effect = exc
        result = _check_3_3(s3, ct)
        assert result.status == CheckStatus.PASS

    def test_fail_public_allow(self):
        import json

        s3 = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{"S3BucketName": "ct-public"}]}
        s3.get_bucket_policy.return_value = {
            "Policy": json.dumps({"Statement": [{"Effect": "Allow", "Principal": "*", "Action": "s3:GetObject", "Resource": "*"}]})
        }
        result = _check_3_3(s3, ct)
        assert result.status == CheckStatus.FAIL
        assert "ct-public" in result.evidence

    def test_pass_public_with_condition(self):
        """Allow with Principal=* but a Condition is not flagged."""
        import json

        s3 = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{"S3BucketName": "ct-bucket"}]}
        s3.get_bucket_policy.return_value = {
            "Policy": json.dumps(
                {
                    "Statement": [
                        {
                            "Effect": "Allow",
                            "Principal": "*",
                            "Action": "s3:GetObject",
                            "Resource": "*",
                            "Condition": {"StringEquals": {"aws:SourceVpce": "vpce-123"}},
                        }
                    ]
                }
            )
        }
        result = _check_3_3(s3, ct)
        assert result.status == CheckStatus.PASS

    def test_not_applicable_no_trails(self):
        s3 = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": []}
        result = _check_3_3(s3, ct)
        assert result.status == CheckStatus.NOT_APPLICABLE


# ---------------------------------------------------------------------------
# 3.7 — CloudTrail KMS encryption
# ---------------------------------------------------------------------------


class TestCheck37:
    def test_pass_kms_encrypted(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"Name": "main", "KmsKeyId": "arn:aws:kms:us-east-1:123:key/abc"}]}
        result = _check_3_7(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "3.7"

    def test_fail_no_kms(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": [{"Name": "main", "TrailARN": "arn:trail"}]}
        result = _check_3_7(client)
        assert result.status == CheckStatus.FAIL
        assert "main" in result.evidence

    def test_fail_no_trails(self):
        client = MagicMock()
        client.describe_trails.return_value = {"trailList": []}
        result = _check_3_7(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 4.3 — Metric filter for root usage
# ---------------------------------------------------------------------------


class TestCheck43:
    def test_pass_root_filter_exists(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"metricFilters": [{"filterPattern": '{ $.userIdentity.type = "Root" && $.userIdentity.invokedBy NOT EXISTS }'}]}
        ]
        client.get_paginator.return_value = paginator
        result = _check_4_3(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "4.3"

    def test_fail_no_root_filter(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"metricFilters": []}]
        client.get_paginator.return_value = paginator
        result = _check_4_3(client)
        assert result.status == CheckStatus.FAIL
        assert "No metric filter" in result.evidence

    def test_fail_unrelated_filter(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"metricFilters": [{"filterPattern": "{ $.errorCode = AccessDenied }"}]}]
        client.get_paginator.return_value = paginator
        result = _check_4_3(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 4.4 — Metric filter for IAM policy changes
# ---------------------------------------------------------------------------


class TestCheck44:
    def test_pass_iam_filter_exists(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "metricFilters": [
                    {
                        "filterPattern": (
                            "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = DeleteRolePolicy) "
                            "|| ($.eventName = DeleteUserPolicy) || ($.eventName = PutGroupPolicy) "
                            "|| ($.eventName = CreatePolicy) }"
                        )
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_4_4(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "4.4"

    def test_fail_no_iam_filter(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"metricFilters": []}]
        client.get_paginator.return_value = paginator
        result = _check_4_4(client)
        assert result.status == CheckStatus.FAIL
        assert "No metric filter" in result.evidence

    def test_fail_too_few_event_matches(self):
        """Filter mentioning only 2 IAM events should not pass (needs >= 3)."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {"metricFilters": [{"filterPattern": "{ ($.eventName = DeleteGroupPolicy) || ($.eventName = CreatePolicy) }"}]}
        ]
        client.get_paginator.return_value = paginator
        result = _check_4_4(client)
        assert result.status == CheckStatus.FAIL


# ---------------------------------------------------------------------------
# 4.5 — Metric filter for CloudTrail config changes
# ---------------------------------------------------------------------------


class TestCheck45:
    def test_pass_ct_filter_exists(self):
        logs = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{"CloudWatchLogsLogGroupArn": "arn:logs:group"}]}
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "metricFilters": [
                    {
                        "filterPattern": (
                            "{ ($.eventName = CreateTrail) || ($.eventName = UpdateTrail) "
                            "|| ($.eventName = DeleteTrail) || ($.eventName = StartLogging) "
                            "|| ($.eventName = StopLogging) }"
                        )
                    }
                ]
            }
        ]
        logs.get_paginator.return_value = paginator
        result = _check_4_5(logs, ct)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "4.5"

    def test_fail_no_cwl_integration(self):
        logs = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{"Name": "main"}]}
        result = _check_4_5(logs, ct)
        assert result.status == CheckStatus.FAIL
        assert "CloudWatch Logs" in result.evidence

    def test_fail_no_ct_filter(self):
        logs = MagicMock()
        ct = MagicMock()
        ct.describe_trails.return_value = {"trailList": [{"CloudWatchLogsLogGroupArn": "arn:logs:group"}]}
        paginator = MagicMock()
        paginator.paginate.return_value = [{"metricFilters": []}]
        logs.get_paginator.return_value = paginator
        result = _check_4_5(logs, ct)
        assert result.status == CheckStatus.FAIL
        assert "No metric filter" in result.evidence


# ---------------------------------------------------------------------------
# 5.1 — NACLs no unrestricted admin ports
# ---------------------------------------------------------------------------


class TestCheck51:
    def test_pass_no_open_nacl(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "NetworkAcls": [
                    {
                        "NetworkAclId": "acl-1",
                        "Entries": [
                            {"Egress": False, "RuleAction": "allow", "CidrBlock": "10.0.0.0/8", "PortRange": {"From": 22, "To": 22}},
                        ],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_1(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "5.1"

    def test_fail_ssh_open(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "NetworkAcls": [
                    {
                        "NetworkAclId": "acl-bad",
                        "Entries": [
                            {"Egress": False, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22}},
                        ],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_1(client)
        assert result.status == CheckStatus.FAIL
        assert "acl-bad" in result.evidence

    def test_fail_rdp_ipv6_open(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "NetworkAcls": [
                    {
                        "NetworkAclId": "acl-v6",
                        "Entries": [
                            {
                                "Egress": False,
                                "RuleAction": "allow",
                                "CidrBlock": "",
                                "Ipv6CidrBlock": "::/0",
                                "PortRange": {"From": 3389, "To": 3389},
                            },
                        ],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_1(client)
        assert result.status == CheckStatus.FAIL
        assert "acl-v6" in result.evidence

    def test_pass_egress_rule_ignored(self):
        """Egress rules should be skipped."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "NetworkAcls": [
                    {
                        "NetworkAclId": "acl-egress",
                        "Entries": [
                            {"Egress": True, "RuleAction": "allow", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22}},
                        ],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_1(client)
        assert result.status == CheckStatus.PASS

    def test_pass_deny_rule_ignored(self):
        """Deny rules should be skipped."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "NetworkAcls": [
                    {
                        "NetworkAclId": "acl-deny",
                        "Entries": [
                            {"Egress": False, "RuleAction": "deny", "CidrBlock": "0.0.0.0/0", "PortRange": {"From": 22, "To": 22}},
                        ],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_1(client)
        assert result.status == CheckStatus.PASS


# ---------------------------------------------------------------------------
# 5.4 — VPC peering least privilege routes
# ---------------------------------------------------------------------------


class TestCheck54:
    def test_pass_specific_cidr(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "RouteTables": [
                    {
                        "RouteTableId": "rtb-1",
                        "Routes": [
                            {"DestinationCidrBlock": "10.0.1.0/24", "VpcPeeringConnectionId": "pcx-123"},
                        ],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_4(client)
        assert result.status == CheckStatus.PASS
        assert result.check_id == "5.4"

    def test_fail_broad_cidr(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "RouteTables": [
                    {
                        "RouteTableId": "rtb-bad",
                        "Routes": [
                            {"DestinationCidrBlock": "0.0.0.0/0", "VpcPeeringConnectionId": "pcx-456"},
                        ],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_4(client)
        assert result.status == CheckStatus.FAIL
        assert "rtb-bad" in result.evidence
        assert "pcx-456" in result.evidence

    def test_pass_no_peering_routes(self):
        """Routes without VpcPeeringConnectionId should be ignored."""
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [
            {
                "RouteTables": [
                    {
                        "RouteTableId": "rtb-normal",
                        "Routes": [
                            {"DestinationCidrBlock": "0.0.0.0/0", "GatewayId": "igw-1"},
                        ],
                    }
                ]
            }
        ]
        client.get_paginator.return_value = paginator
        result = _check_5_4(client)
        assert result.status == CheckStatus.PASS

    def test_pass_empty_route_tables(self):
        client = MagicMock()
        paginator = MagicMock()
        paginator.paginate.return_value = [{"RouteTables": []}]
        client.get_paginator.return_value = paginator
        result = _check_5_4(client)
        assert result.status == CheckStatus.PASS


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

            # Generic mock that works for IAM and S3 services
            mock_client = _iam_client()
            mock_client.generate_credential_report.return_value = {"State": "COMPLETE"}
            mock_client.get_credential_report.return_value = {
                "Content": b"user,password_last_used,access_key_1_last_used_date,access_key_2_last_used_date\n"
            }
            mock_client.list_user_policies.return_value = {"PolicyNames": []}
            mock_client.list_attached_user_policies.return_value = {"AttachedPolicies": []}
            mock_client.list_access_keys.return_value = {"AccessKeyMetadata": []}
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
            ec2_paginator.paginate.return_value = [{"SecurityGroups": [], "NetworkAcls": [], "RouteTables": []}]
            mock_ec2.get_paginator.return_value = ec2_paginator
            mock_ec2.describe_vpcs.return_value = {"Vpcs": []}
            mock_ec2.describe_flow_logs.return_value = {"FlowLogs": []}
            mock_ec2.get_ebs_encryption_by_default.return_value = {"EbsEncryptionByDefault": True}
            # RDS
            mock_rds = MagicMock()
            rds_paginator = MagicMock()
            rds_paginator.paginate.return_value = [{"DBInstances": []}]
            mock_rds.get_paginator.return_value = rds_paginator
            # KMS
            mock_kms = MagicMock()
            kms_paginator = MagicMock()
            kms_paginator.paginate.return_value = [{"Keys": []}]
            mock_kms.get_paginator.return_value = kms_paginator
            # CloudWatch Logs
            mock_logs = MagicMock()
            logs_paginator = MagicMock()
            logs_paginator.paginate.return_value = [{"metricFilters": []}]
            mock_logs.get_paginator.return_value = logs_paginator

            def client_factory(service, **kwargs):
                if service == "sts":
                    return mock_sts
                if service == "ec2":
                    return mock_ec2
                if service == "rds":
                    return mock_rds
                if service == "kms":
                    return mock_kms
                if service == "logs":
                    return mock_logs
                return mock_client

            mock_session.client.side_effect = client_factory

            report = run_benchmark()
            assert report.account_id == "111222333444"
            # 28 _CHECKS + 4 _SPECIAL_CHECKS = 32 total
            assert report.total == 32

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
