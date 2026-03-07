"""CIS AWS Foundations Benchmark v3.0 — live account checks.

Runs read-only AWS API checks against the CIS AWS Foundations Benchmark v3.0
covering IAM, Logging (CloudTrail), Storage (S3), and Networking (VPC).
Each check returns pass/fail with evidence.

Required IAM permissions (all read-only, covered by SecurityAudit policy):
    iam:GetAccountSummary
    iam:GetAccountPasswordPolicy
    iam:ListUsers
    iam:ListMFADevices
    iam:ListVirtualMFADevices
    iam:ListUserPolicies
    iam:ListAttachedUserPolicies
    iam:GenerateCredentialReport
    iam:GetCredentialReport
    cloudtrail:DescribeTrails
    cloudtrail:GetTrailStatus
    cloudtrail:GetEventSelectors
    s3:GetBucketPublicAccessBlock
    s3:GetBucketLogging
    s3:GetBucketVersioning
    s3:GetBucketEncryption
    s3control:GetPublicAccessBlock
    ec2:DescribeSecurityGroups
    ec2:DescribeFlowLogs
    ec2:DescribeVpcs
    logs:DescribeMetricFilters

Install: ``pip install 'agent-bom[aws]'``
"""

from __future__ import annotations

import csv
import io
import logging
import os
import time
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Callable

from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------


class CheckStatus(str, Enum):
    PASS = "pass"
    FAIL = "fail"
    ERROR = "error"
    NOT_APPLICABLE = "not_applicable"


@dataclass
class CISCheckResult:
    """Result of a single CIS AWS Foundations Benchmark check."""

    check_id: str
    title: str
    status: CheckStatus
    severity: str
    evidence: str = ""
    resource_ids: list[str] = field(default_factory=list)
    recommendation: str = ""
    cis_section: str = ""


@dataclass
class CISBenchmarkReport:
    """Aggregated CIS AWS Foundations Benchmark results."""

    benchmark_version: str = "3.0"
    checks: list[CISCheckResult] = field(default_factory=list)
    region: str = ""
    account_id: str = ""

    @property
    def passed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.PASS)

    @property
    def failed(self) -> int:
        return sum(1 for c in self.checks if c.status == CheckStatus.FAIL)

    @property
    def total(self) -> int:
        return len(self.checks)

    @property
    def pass_rate(self) -> float:
        evaluated = sum(1 for c in self.checks if c.status in (CheckStatus.PASS, CheckStatus.FAIL))
        return (self.passed / evaluated * 100) if evaluated else 0.0

    def to_dict(self) -> dict:
        from agent_bom.mitre_attack import tag_cis_check

        return {
            "benchmark": "CIS AWS Foundations",
            "benchmark_version": self.benchmark_version,
            "account_id": self.account_id,
            "region": self.region,
            "pass_rate": round(self.pass_rate, 1),
            "passed": self.passed,
            "failed": self.failed,
            "total": self.total,
            "checks": [
                {
                    "check_id": c.check_id,
                    "title": c.title,
                    "status": c.status.value,
                    "severity": c.severity,
                    "evidence": c.evidence,
                    "resource_ids": c.resource_ids,
                    "recommendation": c.recommendation,
                    "cis_section": c.cis_section,
                    "attack_techniques": tag_cis_check(c),
                }
                for c in self.checks
            ],
        }


# ---------------------------------------------------------------------------
# Individual checks — CIS 1.x (Identity and Access Management)
# ---------------------------------------------------------------------------

_IAM_SECTION = "1 - Identity and Access Management"


def _check_1_4(iam_client: Any) -> CISCheckResult:
    """CIS 1.4 — Ensure no 'root' user account access key exists."""
    result = CISCheckResult(
        check_id="1.4",
        title="Ensure no root user account access key exists",
        status=CheckStatus.PASS,
        severity="critical",
        cis_section=_IAM_SECTION,
        recommendation="Delete root access keys via IAM console > Security credentials.",
    )
    summary = iam_client.get_account_summary()["SummaryMap"]
    root_keys = summary.get("AccountAccessKeysPresent", 0)
    if root_keys > 0:
        result.status = CheckStatus.FAIL
        result.evidence = f"Root account has {root_keys} active access key(s)."
        result.resource_ids = ["arn:aws:iam::root"]
    else:
        result.evidence = "No root access keys found."
    return result


def _check_1_5(iam_client: Any) -> CISCheckResult:
    """CIS 1.5 — Ensure MFA is enabled for the root user account."""
    result = CISCheckResult(
        check_id="1.5",
        title="Ensure MFA is enabled for the root user account",
        status=CheckStatus.PASS,
        severity="critical",
        cis_section=_IAM_SECTION,
        recommendation="Enable MFA for root via IAM console > Security credentials > MFA.",
    )
    summary = iam_client.get_account_summary()["SummaryMap"]
    mfa_enabled = summary.get("AccountMFAEnabled", 0)
    if mfa_enabled == 0:
        result.status = CheckStatus.FAIL
        result.evidence = "Root account does not have MFA enabled."
        result.resource_ids = ["arn:aws:iam::root"]
    else:
        result.evidence = "Root account MFA is enabled."
    return result


def _check_1_6(iam_client: Any) -> CISCheckResult:
    """CIS 1.6 — Ensure hardware MFA is enabled for the root user account."""
    result = CISCheckResult(
        check_id="1.6",
        title="Ensure hardware MFA is enabled for the root user account",
        status=CheckStatus.PASS,
        severity="critical",
        cis_section=_IAM_SECTION,
        recommendation="Replace virtual MFA with a hardware MFA device for root.",
    )
    summary = iam_client.get_account_summary()["SummaryMap"]
    if summary.get("AccountMFAEnabled", 0) == 0:
        result.status = CheckStatus.FAIL
        result.evidence = "Root account has no MFA at all (hardware or virtual)."
        result.resource_ids = ["arn:aws:iam::root"]
        return result

    virtual_devices = iam_client.list_virtual_mfa_devices()["VirtualMFADevices"]
    root_virtual = [d for d in virtual_devices if d.get("SerialNumber", "").endswith(":mfa/root-account-mfa-device")]
    if root_virtual:
        result.status = CheckStatus.FAIL
        result.evidence = "Root uses virtual MFA, not hardware MFA."
        result.resource_ids = [root_virtual[0]["SerialNumber"]]
    else:
        result.evidence = "Root account uses hardware MFA."
    return result


def _check_1_8(iam_client: Any) -> CISCheckResult:
    """CIS 1.8 — Ensure IAM password policy requires minimum length >= 14."""
    result = CISCheckResult(
        check_id="1.8",
        title="Ensure IAM password policy requires minimum length >= 14",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Set minimum password length to 14 via IAM > Account settings.",
    )
    try:
        policy = iam_client.get_account_password_policy()["PasswordPolicy"]
        min_len = policy.get("MinimumPasswordLength", 0)
        if min_len < 14:
            result.status = CheckStatus.FAIL
            result.evidence = f"Minimum password length is {min_len} (required: 14)."
        else:
            result.evidence = f"Minimum password length is {min_len}."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if error_code == "NoSuchEntity":
            result.status = CheckStatus.FAIL
            result.evidence = "No password policy is configured."
        else:
            raise
    return result


def _check_1_10(iam_client: Any) -> CISCheckResult:
    """CIS 1.10 — Ensure MFA is enabled for all IAM users with console access."""
    result = CISCheckResult(
        check_id="1.10",
        title="Ensure MFA is enabled for all IAM users with console access",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_IAM_SECTION,
        recommendation="Enable MFA for all console users via IAM > Users > Security credentials.",
    )
    paginator = iam_client.get_paginator("list_users")
    users_without_mfa = []
    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            try:
                login_profile = iam_client.get_login_profile(UserName=username)  # noqa: F841
            except Exception as exc:
                error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
                if error_code == "NoSuchEntity":
                    continue  # no console access
                raise
            mfa_devices = iam_client.list_mfa_devices(UserName=username)["MFADevices"]
            if not mfa_devices:
                users_without_mfa.append(username)

    if users_without_mfa:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(users_without_mfa)} console user(s) without MFA: {', '.join(users_without_mfa[:5])}"
        if len(users_without_mfa) > 5:
            result.evidence += f" (+{len(users_without_mfa) - 5} more)"
        result.resource_ids = [f"arn:aws:iam::user/{u}" for u in users_without_mfa]
    else:
        result.evidence = "All console users have MFA enabled."
    return result


def _check_1_12(iam_client: Any) -> CISCheckResult:
    """CIS 1.12 — Ensure credentials unused for 45 days or greater are disabled."""
    result = CISCheckResult(
        check_id="1.12",
        title="Ensure credentials unused for 45 days or greater are disabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Disable or remove credentials unused for 45+ days.",
    )
    # Generate credential report (may need to wait for it)
    for _ in range(10):
        resp = iam_client.generate_credential_report()
        if resp.get("State") == "COMPLETE":
            break
        time.sleep(1)

    try:
        report_resp = iam_client.get_credential_report()
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if error_code == "ReportNotPresent":
            result.status = CheckStatus.ERROR
            result.evidence = "Credential report not available."
            return result
        raise

    content = report_resp["Content"]
    if isinstance(content, bytes):
        content = content.decode("utf-8")

    reader = csv.DictReader(io.StringIO(content))
    now = datetime.now(tz=timezone.utc)
    stale_users = []
    threshold_days = 45

    for row in reader:
        username = row.get("user", "<root_account>")
        if username == "<root_account>":
            continue

        last_used = row.get("password_last_used", "N/A")
        key1_used = row.get("access_key_1_last_used_date", "N/A")
        key2_used = row.get("access_key_2_last_used_date", "N/A")

        is_stale = False
        for date_str in [last_used, key1_used, key2_used]:
            if date_str in ("N/A", "no_information", "not_supported", ""):
                continue
            try:
                used_dt = datetime.fromisoformat(date_str.replace("Z", "+00:00"))
                days_unused = (now - used_dt).days
                if days_unused >= threshold_days:
                    is_stale = True
                    break
            except (ValueError, TypeError):
                continue

        if is_stale:
            stale_users.append(username)

    if stale_users:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(stale_users)} user(s) with credentials unused for 45+ days: {', '.join(stale_users[:5])}"
        if len(stale_users) > 5:
            result.evidence += f" (+{len(stale_users) - 5} more)"
        result.resource_ids = [f"arn:aws:iam::user/{u}" for u in stale_users]
    else:
        result.evidence = "No credentials unused for 45+ days."
    return result


def _check_1_15(iam_client: Any) -> CISCheckResult:
    """CIS 1.15 — Ensure IAM users receive permissions only through groups or roles."""
    result = CISCheckResult(
        check_id="1.15",
        title="Ensure IAM users receive permissions only through groups or roles",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Remove inline and directly attached policies from IAM users; use groups instead.",
    )
    paginator = iam_client.get_paginator("list_users")
    users_with_direct = []

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            inline = iam_client.list_user_policies(UserName=username)["PolicyNames"]
            attached = iam_client.list_attached_user_policies(UserName=username)["AttachedPolicies"]
            if inline or attached:
                users_with_direct.append(username)

    if users_with_direct:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(users_with_direct)} user(s) with direct policies: {', '.join(users_with_direct[:5])}"
        if len(users_with_direct) > 5:
            result.evidence += f" (+{len(users_with_direct) - 5} more)"
        result.resource_ids = [f"arn:aws:iam::user/{u}" for u in users_with_direct]
    else:
        result.evidence = "All users receive permissions via groups/roles only."
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 2.x (Storage / S3)
# ---------------------------------------------------------------------------

_STORAGE_SECTION = "2 - Storage"


def _check_2_1_1(s3control_client: Any, account_id: str) -> CISCheckResult:
    """CIS 2.1.1 — Ensure S3 account-level public access block is configured."""
    result = CISCheckResult(
        check_id="2.1.1",
        title="Ensure S3 account-level public access block is configured",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable all four S3 public access block settings at the account level.",
    )
    try:
        config = s3control_client.get_public_access_block(AccountId=account_id)["PublicAccessBlockConfiguration"]
        required = ["BlockPublicAcls", "IgnorePublicAcls", "BlockPublicPolicy", "RestrictPublicBuckets"]
        missing = [k for k in required if not config.get(k, False)]
        if missing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Account public access block missing: {', '.join(missing)}."
        else:
            result.evidence = "All four S3 account-level public access block settings enabled."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if error_code == "NoSuchPublicAccessBlockConfiguration":
            result.status = CheckStatus.FAIL
            result.evidence = "No account-level S3 public access block is configured."
        else:
            raise
    return result


def _check_2_1_2(s3_client: Any) -> CISCheckResult:
    """CIS 2.1.2 — Ensure S3 buckets have server-side encryption enabled."""
    result = CISCheckResult(
        check_id="2.1.2",
        title="Ensure S3 buckets have server-side encryption enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable default encryption (SSE-S3 or SSE-KMS) on all S3 buckets.",
    )
    buckets = s3_client.list_buckets().get("Buckets", [])
    unencrypted = []
    for bucket in buckets:
        name = bucket["Name"]
        try:
            s3_client.get_bucket_encryption(Bucket=name)
        except Exception as exc:
            error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if error_code == "ServerSideEncryptionConfigurationNotFoundError":
                unencrypted.append(name)
            # Skip buckets we can't access (cross-region, etc.)

    if unencrypted:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(unencrypted)} bucket(s) without encryption: {', '.join(unencrypted[:5])}"
        if len(unencrypted) > 5:
            result.evidence += f" (+{len(unencrypted) - 5} more)"
        result.resource_ids = [f"arn:aws:s3:::{b}" for b in unencrypted]
    else:
        result.evidence = f"All {len(buckets)} bucket(s) have server-side encryption enabled."
    return result


def _check_2_1_4(s3_client: Any) -> CISCheckResult:
    """CIS 2.1.4 — Ensure S3 bucket versioning is enabled."""
    result = CISCheckResult(
        check_id="2.1.4",
        title="Ensure S3 bucket versioning is enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_STORAGE_SECTION,
        recommendation="Enable versioning on all S3 buckets for data protection.",
    )
    buckets = s3_client.list_buckets().get("Buckets", [])
    unversioned = []
    for bucket in buckets:
        name = bucket["Name"]
        try:
            versioning = s3_client.get_bucket_versioning(Bucket=name)
            if versioning.get("Status") != "Enabled":
                unversioned.append(name)
        except Exception:
            pass  # skip inaccessible buckets

    if unversioned:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(unversioned)} bucket(s) without versioning: {', '.join(unversioned[:5])}"
        if len(unversioned) > 5:
            result.evidence += f" (+{len(unversioned) - 5} more)"
        result.resource_ids = [f"arn:aws:s3:::{b}" for b in unversioned]
    else:
        result.evidence = f"All {len(buckets)} bucket(s) have versioning enabled."
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 3.x (Logging)
# ---------------------------------------------------------------------------

_LOGGING_SECTION = "3 - Logging"


def _check_3_1(cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.1 — Ensure CloudTrail is enabled in all regions."""
    result = CISCheckResult(
        check_id="3.1",
        title="Ensure CloudTrail is enabled in all regions",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_LOGGING_SECTION,
        recommendation="Create a multi-region trail via CloudTrail console or CLI.",
    )
    trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail", False)]

    if not multi_region:
        result.status = CheckStatus.FAIL
        result.evidence = "No multi-region CloudTrail trail found."
        return result

    # Check at least one is actively logging
    any_logging = False
    for trail in multi_region:
        try:
            status = cloudtrail_client.get_trail_status(Name=trail["TrailARN"])
            if status.get("IsLogging", False):
                any_logging = True
                break
        except Exception:
            continue

    if not any_logging:
        result.status = CheckStatus.FAIL
        result.evidence = "Multi-region trail exists but none are actively logging."
    else:
        result.evidence = "Multi-region CloudTrail is enabled and logging."
    return result


def _check_3_2(cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.2 — Ensure CloudTrail log file validation is enabled."""
    result = CISCheckResult(
        check_id="3.2",
        title="Ensure CloudTrail log file validation is enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_LOGGING_SECTION,
        recommendation="Enable log file validation on all CloudTrail trails.",
    )
    trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    if not trails:
        result.status = CheckStatus.FAIL
        result.evidence = "No CloudTrail trails configured."
        return result

    no_validation = [t["Name"] for t in trails if not t.get("LogFileValidationEnabled", False)]
    if no_validation:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(no_validation)} trail(s) without log file validation: {', '.join(no_validation[:5])}"
        result.resource_ids = [t.get("TrailARN", t["Name"]) for t in trails if not t.get("LogFileValidationEnabled", False)]
    else:
        result.evidence = f"All {len(trails)} trail(s) have log file validation enabled."
    return result


def _check_3_4(cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.4 — Ensure CloudTrail trails are integrated with CloudWatch Logs."""
    result = CISCheckResult(
        check_id="3.4",
        title="Ensure CloudTrail trails are integrated with CloudWatch Logs",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_LOGGING_SECTION,
        recommendation="Configure CloudWatch Logs group for all CloudTrail trails.",
    )
    trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    if not trails:
        result.status = CheckStatus.FAIL
        result.evidence = "No CloudTrail trails configured."
        return result

    no_cwl = [t["Name"] for t in trails if not t.get("CloudWatchLogsLogGroupArn")]
    if no_cwl:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(no_cwl)} trail(s) not integrated with CloudWatch Logs: {', '.join(no_cwl[:5])}"
        result.resource_ids = [t.get("TrailARN", t["Name"]) for t in trails if not t.get("CloudWatchLogsLogGroupArn")]
    else:
        result.evidence = f"All {len(trails)} trail(s) integrated with CloudWatch Logs."
    return result


def _check_3_5(cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.5 — Ensure AWS Config is enabled in all regions."""
    # Note: We check via CloudTrail for management event recording as a proxy.
    # Full Config check requires config:DescribeConfigurationRecorders.
    result = CISCheckResult(
        check_id="3.5",
        title="Ensure CloudTrail records management events in all regions",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_LOGGING_SECTION,
        recommendation="Ensure at least one trail records management read/write events.",
    )
    trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    multi_region = [t for t in trails if t.get("IsMultiRegionTrail", False)]

    if not multi_region:
        result.status = CheckStatus.FAIL
        result.evidence = "No multi-region trail to record management events."
        return result

    has_mgmt_events = False
    for trail in multi_region:
        try:
            selectors = cloudtrail_client.get_event_selectors(TrailName=trail["TrailARN"])
            for es in selectors.get("EventSelectors", []):
                if es.get("IncludeManagementEvents", False) and es.get("ReadWriteType") == "All":
                    has_mgmt_events = True
                    break
            # Also check advanced event selectors
            for aes in selectors.get("AdvancedEventSelectors", []):
                for fs in aes.get("FieldSelectors", []):
                    if fs.get("Field") == "eventCategory" and "Management" in fs.get("Equals", []):
                        has_mgmt_events = True
                        break
        except Exception:
            continue
        if has_mgmt_events:
            break

    if not has_mgmt_events:
        result.status = CheckStatus.FAIL
        result.evidence = "No multi-region trail records all management events."
    else:
        result.evidence = "Multi-region trail records all management read/write events."
    return result


def _check_3_6(s3_client: Any, cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.6 — Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket."""
    result = CISCheckResult(
        check_id="3.6",
        title="Ensure S3 bucket access logging is enabled on the CloudTrail S3 bucket",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_LOGGING_SECTION,
        recommendation="Enable S3 server access logging on CloudTrail destination buckets.",
    )
    trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    if not trails:
        result.status = CheckStatus.NOT_APPLICABLE
        result.evidence = "No CloudTrail trails configured."
        return result

    ct_buckets = {t["S3BucketName"] for t in trails if t.get("S3BucketName")}
    no_logging = []
    for bucket_name in ct_buckets:
        try:
            logging_conf = s3_client.get_bucket_logging(Bucket=bucket_name)
            if not logging_conf.get("LoggingEnabled"):
                no_logging.append(bucket_name)
        except Exception:
            pass  # skip inaccessible

    if no_logging:
        result.status = CheckStatus.FAIL
        result.evidence = f"CloudTrail S3 bucket(s) without access logging: {', '.join(no_logging)}"
        result.resource_ids = [f"arn:aws:s3:::{b}" for b in no_logging]
    else:
        result.evidence = "All CloudTrail S3 buckets have access logging enabled."
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 5.x (Networking)
# ---------------------------------------------------------------------------

_NETWORKING_SECTION = "5 - Networking"


def _check_5_2(ec2_client: Any) -> CISCheckResult:
    """CIS 5.2 — Ensure no security groups allow ingress from 0.0.0.0/0 to remote admin ports."""
    result = CISCheckResult(
        check_id="5.2",
        title="Ensure no security groups allow unrestricted ingress to admin ports (22, 3389)",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_NETWORKING_SECTION,
        recommendation="Restrict SSH (22) and RDP (3389) to specific IP ranges.",
    )
    admin_ports = {22, 3389}
    open_sgs = []

    paginator = ec2_client.get_paginator("describe_security_groups")
    for page in paginator.paginate():
        for sg in page["SecurityGroups"]:
            for perm in sg.get("IpPermissions", []):
                from_port = perm.get("FromPort", 0)
                to_port = perm.get("ToPort", 0)
                # Check if any admin port falls in this range
                if not any(from_port <= p <= to_port for p in admin_ports):
                    continue
                # Check for 0.0.0.0/0 or ::/0
                for ip_range in perm.get("IpRanges", []):
                    if ip_range.get("CidrIp") == "0.0.0.0/0":
                        open_sgs.append(f"{sg['GroupId']} (port {from_port}-{to_port})")
                        break
                for ip_range in perm.get("Ipv6Ranges", []):
                    if ip_range.get("CidrIpv6") == "::/0":
                        open_sgs.append(f"{sg['GroupId']} (port {from_port}-{to_port}, IPv6)")
                        break

    # Deduplicate
    open_sgs = list(dict.fromkeys(open_sgs))

    if open_sgs:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(open_sgs)} security group(s) with unrestricted admin access: {', '.join(open_sgs[:5])}"
        if len(open_sgs) > 5:
            result.evidence += f" (+{len(open_sgs) - 5} more)"
        result.resource_ids = open_sgs[:20]
    else:
        result.evidence = "No security groups allow unrestricted ingress to SSH/RDP."
    return result


def _check_5_3(ec2_client: Any) -> CISCheckResult:
    """CIS 5.3 — Ensure the default security group of every VPC restricts all traffic."""
    result = CISCheckResult(
        check_id="5.3",
        title="Ensure the default security group of every VPC restricts all traffic",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_NETWORKING_SECTION,
        recommendation="Remove all inbound and outbound rules from default security groups.",
    )
    paginator = ec2_client.get_paginator("describe_security_groups")
    open_defaults = []

    for page in paginator.paginate(Filters=[{"Name": "group-name", "Values": ["default"]}]):
        for sg in page["SecurityGroups"]:
            if sg.get("IpPermissions") or sg.get("IpPermissionsEgress"):
                # Check if egress is only the default "allow all" rule
                egress_only_default = len(sg.get("IpPermissionsEgress", [])) == 1 and sg["IpPermissionsEgress"][0].get("IpProtocol") == "-1"
                if sg.get("IpPermissions") or not egress_only_default:
                    open_defaults.append(f"{sg['GroupId']} (VPC: {sg.get('VpcId', 'unknown')})")

    if open_defaults:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(open_defaults)} default security group(s) with rules: {', '.join(open_defaults[:5])}"
        if len(open_defaults) > 5:
            result.evidence += f" (+{len(open_defaults) - 5} more)"
        result.resource_ids = open_defaults[:20]
    else:
        result.evidence = "All default security groups restrict all traffic."
    return result


def _check_5_6(ec2_client: Any) -> CISCheckResult:
    """CIS 5.6 — Ensure VPC flow logging is enabled in all VPCs."""
    result = CISCheckResult(
        check_id="5.6",
        title="Ensure VPC flow logging is enabled in all VPCs",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_NETWORKING_SECTION,
        recommendation="Enable VPC Flow Logs for all VPCs (reject or all traffic).",
    )
    vpcs = ec2_client.describe_vpcs().get("Vpcs", [])
    if not vpcs:
        result.status = CheckStatus.NOT_APPLICABLE
        result.evidence = "No VPCs found."
        return result

    vpc_ids = {v["VpcId"] for v in vpcs}

    # Get all flow logs and find which VPCs are covered
    flow_logs = ec2_client.describe_flow_logs(Filters=[{"Name": "resource-type", "Values": ["VPC"]}]).get("FlowLogs", [])
    covered_vpcs = {fl["ResourceId"] for fl in flow_logs if fl.get("FlowLogStatus") == "ACTIVE"}

    missing = vpc_ids - covered_vpcs
    if missing:
        result.status = CheckStatus.FAIL
        missing_list = sorted(missing)
        result.evidence = f"{len(missing)} VPC(s) without flow logging: {', '.join(missing_list[:5])}"
        if len(missing_list) > 5:
            result.evidence += f" (+{len(missing_list) - 5} more)"
        result.resource_ids = missing_list[:20]
    else:
        result.evidence = f"All {len(vpcs)} VPC(s) have flow logging enabled."
    return result


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

_CHECKS: list[tuple[str, Callable]] = [
    ("iam", _check_1_4),
    ("iam", _check_1_5),
    ("iam", _check_1_6),
    ("iam", _check_1_8),
    ("iam", _check_1_10),
    ("iam", _check_1_12),
    ("iam", _check_1_15),
    ("s3", _check_2_1_2),
    ("s3", _check_2_1_4),
    ("cloudtrail", _check_3_1),
    ("cloudtrail", _check_3_2),
    ("cloudtrail", _check_3_4),
    ("cloudtrail", _check_3_5),
    ("ec2", _check_5_2),
    ("ec2", _check_5_3),
    ("ec2", _check_5_6),
]

# Checks that need special handling (multiple clients or account_id)
_SPECIAL_CHECKS: list[tuple[str, Callable]] = [
    ("s3control", _check_2_1_1),  # needs account_id
    ("s3+cloudtrail", _check_3_6),  # needs both s3 and cloudtrail clients
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_benchmark(
    region: str | None = None,
    profile: str | None = None,
    checks: list[str] | None = None,
) -> CISBenchmarkReport:
    """Run CIS AWS Foundations Benchmark v3.0 checks.

    Uses the standard boto3 credential chain.  Only read APIs are called.

    Args:
        region: AWS region (defaults to AWS_DEFAULT_REGION or us-east-1).
        profile: AWS credential profile name.
        checks: Optional list of check IDs to run (e.g. ``["1.4", "1.5"]``).
            Runs all checks if *None*.

    Returns:
        CISBenchmarkReport with per-check pass/fail results.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        raise CloudDiscoveryError("boto3 is required for CIS AWS Benchmark checks. Install with: pip install 'agent-bom[aws]'")

    session_kwargs: dict[str, Any] = {}
    if region:
        session_kwargs["region_name"] = region
    if profile:
        session_kwargs["profile_name"] = profile

    session = boto3.Session(**session_kwargs)
    resolved_region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    # Get account ID for the report
    account_id = ""
    try:
        sts = session.client("sts", region_name=resolved_region)
        account_id = sts.get_caller_identity()["Account"]
    except Exception:
        pass  # non-fatal

    report = CISBenchmarkReport(region=resolved_region, account_id=account_id)

    # Lazy client cache (one per service)
    clients: dict[str, Any] = {}

    def _get_client(svc: str) -> Any:
        if svc not in clients:
            clients[svc] = session.client(svc, region_name=resolved_region)
        return clients[svc]

    def _extract_check_id(fn: Callable) -> str:
        return fn.__doc__.split("—")[0].strip().replace("CIS ", "") if fn.__doc__ else ""

    def _extract_title(fn: Callable) -> str:
        parts = fn.__doc__.split("—") if fn.__doc__ else ["", ""]
        return parts[1].strip().rstrip(".") if len(parts) > 1 else ""

    def _run_check(check_id: str, check_fn: Callable, *args: Any) -> None:
        if checks and check_id not in checks:
            return
        try:
            check_result = check_fn(*args)
            report.checks.append(check_result)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            report.checks.append(
                CISCheckResult(
                    check_id=check_id,
                    title=_extract_title(check_fn),
                    status=CheckStatus.ERROR,
                    severity="unknown",
                    evidence=f"AWS API error: {code} — {exc.response['Error'].get('Message', '')}",
                )
            )
        except Exception as exc:
            logger.warning("CIS check %s failed: %s", check_id, exc)

    # Standard checks (single client)
    for service, check_fn in _CHECKS:
        _run_check(_extract_check_id(check_fn), check_fn, _get_client(service))

    # Special checks requiring multiple clients or account_id
    # 2.1.1 — needs s3control + account_id
    _run_check("2.1.1", _check_2_1_1, _get_client("s3control"), account_id)
    # 3.6 — needs s3 + cloudtrail
    _run_check("3.6", _check_3_6, _get_client("s3"), _get_client("cloudtrail"))

    # Sort checks by check_id for consistent output
    report.checks.sort(key=lambda c: [int(x) if x.isdigit() else x for x in c.check_id.replace(".", " ").split()])

    return report
