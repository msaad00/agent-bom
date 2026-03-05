"""CIS AWS Foundations Benchmark v3.0 — live account checks.

Runs read-only AWS API checks against the IAM section of the CIS AWS
Foundations Benchmark v3.0.  Each check returns pass/fail with evidence.

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

    for service, check_fn in _CHECKS:
        check_id = check_fn.__doc__.split("—")[0].strip().replace("CIS ", "") if check_fn.__doc__ else ""
        if checks and check_id not in checks:
            continue

        if service not in clients:
            clients[service] = session.client(service, region_name=resolved_region)

        try:
            result = check_fn(clients[service])
            report.checks.append(result)
        except ClientError as exc:
            code = exc.response["Error"]["Code"]
            report.checks.append(
                CISCheckResult(
                    check_id=check_id,
                    title=check_fn.__doc__.split("—")[1].strip().rstrip(".") if check_fn.__doc__ else "",
                    status=CheckStatus.ERROR,
                    severity="unknown",
                    evidence=f"AWS API error: {code} — {exc.response['Error'].get('Message', '')}",
                    cis_section=_IAM_SECTION,
                )
            )
        except Exception as exc:
            logger.warning("CIS check %s failed: %s", check_id, exc)

    return report
