"""CIS AWS Foundations Benchmark v3.0 — live account checks.

Runs read-only AWS API checks against the CIS AWS Foundations Benchmark v3.0
covering IAM, Storage (S3, EBS, RDS, KMS), Logging (CloudTrail),
Monitoring (CloudWatch Logs), and Networking (VPC).
Each check returns pass/fail with evidence.

Required IAM permissions (all read-only, covered by SecurityAudit policy):
    iam:GetAccountSummary
    iam:GetAccountPasswordPolicy
    iam:ListUsers
    iam:ListMFADevices
    iam:ListVirtualMFADevices
    iam:ListUserPolicies
    iam:ListAttachedUserPolicies
    iam:ListAccessKeys
    iam:ListPolicies
    iam:GetPolicyVersion
    iam:GenerateCredentialReport
    iam:GetCredentialReport
    iam:ListEntitiesForPolicy
    account:GetContactInformation
    account:GetAlternateContact
    access-analyzer:ListAnalyzers
    cloudtrail:DescribeTrails
    cloudtrail:GetTrailStatus
    cloudtrail:GetEventSelectors
    s3:GetBucketPublicAccessBlock
    s3:GetBucketLogging
    s3:GetBucketVersioning
    s3:GetBucketEncryption
    s3:GetBucketPolicy
    s3control:GetPublicAccessBlock
    ec2:DescribeSecurityGroups
    ec2:DescribeFlowLogs
    ec2:DescribeVpcs
    ec2:DescribeNetworkAcls
    ec2:DescribeRouteTables
    ec2:DescribeInstances
    ec2:GetEbsEncryptionByDefault
    rds:DescribeDBInstances
    kms:ListKeys
    kms:GetKeyRotationStatus
    kms:DescribeKey
    logs:DescribeMetricFilters
    cloudwatch:DescribeAlarms
    securityhub:DescribeHub

Install: ``pip install 'agent-bom[aws]'``
"""

from __future__ import annotations

import logging
import os
from typing import Any, Callable

from agent_bom.security import sanitize_text

from .aws_cis._base import (
    _AWS_RETRY_CONFIG,
    CheckStatus,
    CISBenchmarkReport,
    CISCheckResult,
    _aws_client_config,
    _safe_error_evidence,
    finalize_read_coverage,
)
from .aws_cis.iam_access import (
    _check_1_9,
    _check_1_10,
    _check_1_11,
    _check_1_12,
    _check_1_13,
    _check_1_14,
    _check_1_15,
    _check_1_16,
    _check_1_17,
    _check_1_19,
    _check_1_20,
    _check_1_22,
)
from .aws_cis.iam_account import (
    _IAM_SECTION,
    _check_1_1,
    _check_1_2,
    _check_1_3,
    _check_1_4,
    _check_1_5,
    _check_1_6,
    _check_1_7,
    _check_1_8,
)
from .aws_cis.logging_checks import (
    _LOGGING_SECTION,
    _check_3_1,
    _check_3_2,
    _check_3_3,
    _check_3_4,
    _check_3_5,
    _check_3_6,
    _check_3_7,
    _check_3_9,
)
from .aws_cis.monitoring import (
    _MONITORING_SECTION,
    _check_4_1,
    _check_4_2,
    _check_4_3,
    _check_4_4,
    _check_4_5,
    _check_4_6,
    _check_4_7,
    _require_targeting_alarm,
)
from .aws_cis.monitoring_changes import (
    _check_4_8,
    _check_4_9,
    _check_4_10,
    _check_4_11,
    _check_4_12,
    _check_4_13,
    _check_4_14,
    _check_4_15,
    _check_4_16,
)
from .aws_cis.networking import (
    _NETWORKING_SECTION,
    _check_5_1,
    _check_5_2,
    _check_5_3,
    _check_5_4,
    _check_5_5,
)
from .aws_cis.runner import (
    _MAX_CIS_FANOUT_WORKERS,
    _REGIONAL_CIS_CHECK_IDS,
    _STATUS_RANK,
    _demote_passes_to_unknown,
    _mark_report_partial_for_evidence_gaps,
    _merge_regional_cis_check,
)
from .aws_cis.storage import (
    _STORAGE_SECTION,
    _check_2_1_1,
    _check_2_1_2,
    _check_2_1_3,
    _check_2_1_4,
    _check_2_2_1,
    _check_2_3_1,
    _check_2_3_2,
    _check_2_4_1,
)
from .base import CloudDiscoveryError

# Re-exported so callers, tests and monkeypatch targets keep using this module.
__all__ = [
    "CISBenchmarkReport",
    "CISCheckResult",
    "CheckStatus",
    "_AWS_RETRY_CONFIG",
    "_CHECKS",
    "_IAM_SECTION",
    "_LOGGING_SECTION",
    "_MAX_CIS_FANOUT_WORKERS",
    "_MONITORING_ALARM_CHECKS",
    "_MONITORING_SECTION",
    "_NETWORKING_SECTION",
    "_REGIONAL_CIS_CHECK_IDS",
    "_SPECIAL_CHECKS",
    "_STATUS_RANK",
    "_STORAGE_SECTION",
    "_aws_client_config",
    "_check_1_1",
    "_check_1_10",
    "_check_1_11",
    "_check_1_12",
    "_check_1_13",
    "_check_1_14",
    "_check_1_15",
    "_check_1_16",
    "_check_1_17",
    "_check_1_19",
    "_check_1_2",
    "_check_1_20",
    "_check_1_22",
    "_check_1_3",
    "_check_1_4",
    "_check_1_5",
    "_check_1_6",
    "_check_1_7",
    "_check_1_8",
    "_check_1_9",
    "_check_2_1_1",
    "_check_2_1_2",
    "_check_2_1_3",
    "_check_2_1_4",
    "_check_2_2_1",
    "_check_2_3_1",
    "_check_2_3_2",
    "_check_2_4_1",
    "_check_3_1",
    "_check_3_10",
    "_check_3_11",
    "_check_3_2",
    "_check_3_3",
    "_check_3_4",
    "_check_3_5",
    "_check_3_6",
    "_check_3_7",
    "_check_3_9",
    "_check_4_1",
    "_check_4_10",
    "_check_4_11",
    "_check_4_12",
    "_check_4_13",
    "_check_4_14",
    "_check_4_15",
    "_check_4_16",
    "_check_4_2",
    "_check_4_3",
    "_check_4_4",
    "_check_4_5",
    "_check_4_6",
    "_check_4_7",
    "_check_4_8",
    "_check_4_9",
    "_check_5_1",
    "_check_5_2",
    "_check_5_3",
    "_check_5_4",
    "_check_5_5",
    "_demote_passes_to_unknown",
    "_mark_report_partial_for_evidence_gaps",
    "_merge_regional_cis_check",
    "_require_targeting_alarm",
    "_safe_error_evidence",
    "finalize_read_coverage",
    "run_all_account_benchmarks",
    "run_benchmark",
    "run_benchmark_all_regions",
]

logger = logging.getLogger(__name__)


def _check_3_10(cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.10 — S3 object-level write-event logging enabled."""
    result = CISCheckResult(
        check_id="3.10",
        title="S3 object-level write-event logging enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_LOGGING_SECTION,
        recommendation="Enable S3 object-level write event logging in at least one CloudTrail trail.",
    )
    try:
        trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            result.status = CheckStatus.FAIL
            result.evidence = "No CloudTrail trails configured."
            return result

        found = False
        for trail in trails:
            try:
                selectors = cloudtrail_client.get_event_selectors(TrailName=trail["TrailARN"])
                # Check standard event selectors
                for es in selectors.get("EventSelectors", []):
                    for dr in es.get("DataResources", []):
                        if dr.get("Type") == "AWS::S3::Object":
                            rw = es.get("ReadWriteType", "")
                            if rw in ("WriteOnly", "All"):
                                found = True
                                break
                    if found:
                        break
                # Check advanced event selectors
                for aes in selectors.get("AdvancedEventSelectors", []):
                    has_s3 = False
                    has_write = False
                    for fs in aes.get("FieldSelectors", []):
                        if fs.get("Field") == "resources.type" and "AWS::S3::Object" in fs.get("Equals", []):
                            has_s3 = True
                        if fs.get("Field") == "readOnly" and "false" in [str(v).lower() for v in fs.get("Equals", [])]:
                            has_write = True
                    if has_s3 and has_write:
                        found = True
                        break
            except Exception:
                continue
            if found:
                break

        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No trail has S3 object-level write event logging enabled."
        else:
            result.evidence = "S3 object-level write event logging is enabled."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check object-level logging: {error_code or exc}"
    return result


def _check_3_11(cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.11 — S3 object-level read-event logging enabled."""
    result = CISCheckResult(
        check_id="3.11",
        title="S3 object-level read-event logging enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_LOGGING_SECTION,
        recommendation="Enable S3 object-level read event logging in at least one CloudTrail trail.",
    )
    try:
        trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
        if not trails:
            result.status = CheckStatus.FAIL
            result.evidence = "No CloudTrail trails configured."
            return result

        found = False
        for trail in trails:
            try:
                selectors = cloudtrail_client.get_event_selectors(TrailName=trail["TrailARN"])
                for es in selectors.get("EventSelectors", []):
                    for dr in es.get("DataResources", []):
                        if dr.get("Type") == "AWS::S3::Object":
                            rw = es.get("ReadWriteType", "")
                            if rw in ("ReadOnly", "All"):
                                found = True
                                break
                    if found:
                        break
                for aes in selectors.get("AdvancedEventSelectors", []):
                    has_s3 = False
                    has_read = False
                    for fs in aes.get("FieldSelectors", []):
                        if fs.get("Field") == "resources.type" and "AWS::S3::Object" in fs.get("Equals", []):
                            has_s3 = True
                        if fs.get("Field") == "readOnly" and "true" in [str(v).lower() for v in fs.get("Equals", [])]:
                            has_read = True
                    if has_s3 and has_read:
                        found = True
                        break
            except Exception:
                continue
            if found:
                break

        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No trail has S3 object-level read event logging enabled."
        else:
            result.evidence = "S3 object-level read event logging is enabled."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check object-level logging: {error_code or exc}"
    return result


# ---------------------------------------------------------------------------
# Check registry
# ---------------------------------------------------------------------------

_CHECKS: list[tuple[str, Callable]] = [
    # IAM (section 1)
    ("iam", _check_1_4),
    ("iam", _check_1_5),
    ("iam", _check_1_6),
    ("iam", _check_1_7),
    ("iam", _check_1_8),
    ("iam", _check_1_9),
    ("iam", _check_1_10),
    ("iam", _check_1_11),
    ("iam", _check_1_12),
    ("iam", _check_1_13),
    ("iam", _check_1_14),
    ("iam", _check_1_15),
    ("iam", _check_1_16),
    ("iam", _check_1_17),
    ("iam", _check_1_22),
    # Storage (section 2)
    ("s3", _check_2_1_2),
    ("s3", _check_2_1_3),
    ("s3", _check_2_1_4),
    ("ec2", _check_2_2_1),
    ("rds", _check_2_3_1),
    ("rds", _check_2_3_2),
    ("kms", _check_2_4_1),
    # Logging (section 3)
    ("cloudtrail", _check_3_1),
    ("cloudtrail", _check_3_2),
    ("cloudtrail", _check_3_4),
    ("cloudtrail", _check_3_5),
    ("cloudtrail", _check_3_7),
    ("cloudtrail", _check_3_10),
    ("cloudtrail", _check_3_11),
    # Monitoring (section 4)
    ("logs", _check_4_1),
    ("logs", _check_4_2),
    ("logs", _check_4_4),
    ("logs", _check_4_6),
    ("logs", _check_4_7),
    ("logs", _check_4_8),
    ("logs", _check_4_9),
    ("logs", _check_4_10),
    ("logs", _check_4_11),
    ("logs", _check_4_12),
    ("logs", _check_4_13),
    ("logs", _check_4_14),
    ("logs", _check_4_15),
    # Networking (section 5)
    ("ec2", _check_5_1),
    ("ec2", _check_5_2),
    ("ec2", _check_5_3),
    ("ec2", _check_5_4),
    ("ec2", _check_5_5),
]

_MONITORING_ALARM_CHECKS = {check_fn for service, check_fn in _CHECKS if service == "logs"}

# Checks that need special handling (multiple clients or account_id)
_SPECIAL_CHECKS: list[tuple[str, Callable]] = [
    ("account", _check_1_1),  # needs account client
    ("account", _check_1_2),  # needs account client
    ("manual", _check_1_3),  # manual check, no client needed
    ("ec2", _check_1_19),  # needs ec2 client (special: IAM section but ec2 service)
    ("accessanalyzer", _check_1_20),  # needs access-analyzer client
    ("s3control", _check_2_1_1),  # needs account_id
    ("s3+cloudtrail", _check_3_3),  # needs both s3 and cloudtrail clients
    ("s3+cloudtrail", _check_3_6),  # needs both s3 and cloudtrail clients
    ("ec2", _check_3_9),  # VPC flow logging (logging section but ec2 service)
    ("logs+cloudtrail", _check_4_5),  # needs logs + cloudtrail clients
    ("logs+cloudwatch", _check_4_3),  # needs logs + cloudwatch clients
    ("securityhub", _check_4_16),  # needs securityhub client
]


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_benchmark(
    region: str | None = None,
    profile: str | None = None,
    checks: list[str] | None = None,
    *,
    session: Any = None,
    region_scope_complete: bool = False,
) -> CISBenchmarkReport:
    """Run CIS AWS Foundations Benchmark v3.0 checks.

    Uses the standard boto3 credential chain.  Only read APIs are called.

    Args:
        region: AWS region (defaults to AWS_DEFAULT_REGION or us-east-1).
        profile: AWS credential profile name.
        checks: Optional list of check IDs to run (e.g. ``["1.4", "1.5"]``).
            Runs all checks if *None*.
        session: Optional pre-built boto3 session (e.g. the read-only session
            the credential broker assumes from a stored connection). When
            supplied it provides credentials; ``region`` may still select the
            regional client target while ``profile`` is ignored.
        region_scope_complete: Internal fan-out proof. False for a direct
            selected-region call; true only when the enabled-region wrapper has
            established the complete region set.

    Returns:
        CISBenchmarkReport with per-check pass/fail results.
    """
    try:
        import boto3
        from botocore.exceptions import ClientError
    except ImportError:
        raise CloudDiscoveryError("boto3 is required for CIS AWS Benchmark checks. Install with: pip install 'agent-bom[aws]'")

    if session is None:
        session_kwargs: dict[str, Any] = {}
        if region:
            session_kwargs["region_name"] = region
        if profile:
            session_kwargs["profile_name"] = profile

        session = boto3.Session(**session_kwargs)
    resolved_region = region or session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")

    # Get account ID for the report
    account_id = ""
    client_config = _aws_client_config()
    try:
        sts_kwargs = {"region_name": resolved_region}
        if client_config is not None:
            sts_kwargs["config"] = client_config
        sts = session.client("sts", **sts_kwargs)
        account_id = sts.get_caller_identity()["Account"]
    except Exception as exc:
        # Account ID lookup is non-fatal; continue with empty value
        logger.debug("Could not get AWS account ID: %s", sanitize_text(exc))

    report = CISBenchmarkReport(
        region=resolved_region,
        account_id=account_id,
        accounts_scanned=[account_id] if account_id else [],
        regions_scanned=[resolved_region],
        completeness="complete" if region_scope_complete and account_id else ("partial" if account_id else "unavailable"),
        scope="enabled-regions" if region_scope_complete else "selected-region",
    )

    # Lazy client cache (one per service)
    clients: dict[str, Any] = {}

    def _get_client(svc: str) -> Any:
        if svc not in clients:
            client_kwargs = {"region_name": resolved_region}
            if client_config is not None:
                client_kwargs["config"] = client_config
            clients[svc] = session.client(svc, **client_kwargs)
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
            logger.warning("CIS check %s failed: %s", check_id, sanitize_text(exc))
            report.checks.append(
                CISCheckResult(
                    check_id=check_id,
                    title=_extract_title(check_fn),
                    status=CheckStatus.ERROR,
                    severity="unknown",
                    evidence=f"Check failed: {type(exc).__name__}: {exc}",
                )
            )

    # Standard checks (single client)
    for service, check_fn in _CHECKS:
        args = (_get_client(service), _get_client("cloudwatch")) if check_fn in _MONITORING_ALARM_CHECKS else (_get_client(service),)
        _run_check(_extract_check_id(check_fn), check_fn, *args)

    # Special checks requiring multiple clients, account_id, or no client
    _run_check("1.1", _check_1_1, _get_client("account"))
    _run_check("1.2", _check_1_2, _get_client("account"))
    _run_check("1.3", _check_1_3)
    _run_check("1.19", _check_1_19, _get_client("ec2"))
    _run_check("1.20", _check_1_20, _get_client("accessanalyzer"))
    _run_check("2.1.1", _check_2_1_1, _get_client("s3control"), account_id)
    _run_check("3.3", _check_3_3, _get_client("s3"), _get_client("cloudtrail"))
    _run_check("3.6", _check_3_6, _get_client("s3"), _get_client("cloudtrail"))
    _run_check("3.9", _check_3_9, _get_client("ec2"))
    _run_check("4.3", _check_4_3, _get_client("logs"), _get_client("cloudwatch"))
    _run_check("4.5", _check_4_5, _get_client("logs"), _get_client("cloudtrail"), _get_client("cloudwatch"))
    _run_check("4.16", _check_4_16, _get_client("securityhub"))

    if not account_id:
        report.warnings.append("AWS account identity could not be verified; affirmative CIS results were withheld.")
        for check in report.checks:
            if check.status in {CheckStatus.PASS, CheckStatus.NO_DATA}:
                check.status = CheckStatus.ERROR
                check.evidence = (
                    "AWS account identity could not be verified with STS GetCallerIdentity; "
                    "PASS withheld because the evaluated account boundary is unknown."
                )

    # Sort checks by check_id for consistent output
    report.checks.sort(key=lambda c: [int(x) if x.isdigit() else x for x in c.check_id.replace(".", " ").split()])

    # Structured remediation per #665 — every check gets a non-empty
    # ``remediation`` dict (schema in ``cis_remediation``).
    from agent_bom.cloud.cis_remediation import attach_all

    attach_all(report, cloud="aws")

    if account_id and not region_scope_complete:
        _demote_passes_to_unknown(
            report,
            check_ids=_REGIONAL_CIS_CHECK_IDS,
            reason=(
                "Only one selected region was evaluated. Run the enabled-region benchmark "
                "before certifying regional CIS controls across all enabled AWS regions."
            ),
        )

    _mark_report_partial_for_evidence_gaps(report)

    return report


def run_benchmark_all_regions(
    region: str | None = None,
    profile: str | None = None,
    checks: list[str] | None = None,
    *,
    regions: list[str] | None = None,
    session: Any = None,
) -> CISBenchmarkReport:
    """Run CIS AWS checks across every enabled region in the account.

    Global IAM/S3/account checks run once on the home region; regional checks
    (EC2, RDS, KMS, logging, networking) fan out to each enabled region.
    """
    try:
        import boto3
    except ImportError:
        raise CloudDiscoveryError("boto3 is required for CIS AWS Benchmark checks. Install with: pip install 'agent-bom[aws]'")

    from agent_bom.cloud.aws_inventory import _resolve_region_list
    from agent_bom.cloud.normalization import sanitize_discovery_warning

    if session is None:
        session_kwargs: dict[str, Any] = {}
        if region:
            session_kwargs["region_name"] = region
        if profile:
            session_kwargs["profile_name"] = profile
        session = boto3.Session(**session_kwargs)
    default_region = session.region_name or os.environ.get("AWS_DEFAULT_REGION", "us-east-1")
    scan_warnings: list[str] = []
    region_list = _resolve_region_list(session, default_region, regions=regions, warnings=scan_warnings)
    if len(region_list) <= 1:
        complete = not scan_warnings
        report = run_benchmark(
            region=default_region,
            profile=profile,
            checks=checks,
            session=session,
            region_scope_complete=complete,
        )
        report.regions_scanned = list(region_list)
        report.scope = "enabled-regions"
        if not report.account_id:
            report.completeness = "unavailable"
        elif not complete or report.completeness != "complete":
            report.completeness = "partial"
        else:
            report.completeness = "complete"
        report.warnings.extend(scan_warnings)
        if not complete:
            _demote_passes_to_unknown(
                report,
                check_ids=_REGIONAL_CIS_CHECK_IDS,
                reason="Region enumeration was incomplete; PASS is unavailable for regional CIS controls.",
            )
        return report

    home_region = region_list[0]
    merged = run_benchmark(
        region=home_region,
        profile=profile,
        checks=checks,
        session=session,
        region_scope_complete=True,
    )
    merged.regions_scanned = list(region_list)
    merged.region = f"multi:{','.join(region_list)}"
    merged.warnings.extend(scan_warnings)
    merged.scope = "enabled-regions"
    if not merged.account_id:
        merged.completeness = "unavailable"
    elif scan_warnings or merged.completeness != "complete":
        merged.completeness = "partial"
    else:
        merged.completeness = "complete"

    if checks is None:
        regional_ids = sorted(_REGIONAL_CIS_CHECK_IDS)
    else:
        regional_ids = [check_id for check_id in checks if check_id in _REGIONAL_CIS_CHECK_IDS]
    if not regional_ids:
        return merged

    by_id = {check.check_id: check for check in merged.checks}
    regional_failures = False
    for scan_region in region_list[1:]:
        try:
            partial = run_benchmark(
                region=scan_region,
                profile=profile,
                checks=regional_ids,
                session=session,
                region_scope_complete=True,
            )
        except Exception as exc:  # noqa: BLE001
            regional_failures = True
            merged.warnings.append(f"CIS benchmark skipped region {scan_region}: {sanitize_discovery_warning(exc)}")
            continue
        if partial.completeness != "complete":
            regional_failures = True
        for check in partial.checks:
            prev = by_id.get(check.check_id)
            if prev is None:
                by_id[check.check_id] = check
            else:
                by_id[check.check_id] = _merge_regional_cis_check(prev, check, scan_region)

    merged.checks = sorted(
        by_id.values(),
        key=lambda c: [int(x) if x.isdigit() else x for x in c.check_id.replace(".", " ").split()],
    )
    from agent_bom.cloud.cis_remediation import attach_all

    attach_all(merged, cloud="aws")
    if scan_warnings or regional_failures:
        merged.completeness = "partial" if merged.account_id else "unavailable"
        _demote_passes_to_unknown(
            merged,
            check_ids=_REGIONAL_CIS_CHECK_IDS,
            reason="Region enumeration was incomplete; PASS is unavailable for regional CIS controls.",
        )
    _mark_report_partial_for_evidence_gaps(merged)
    return merged


def run_all_account_benchmarks(
    checks: list[str] | None = None,
    profile: str | None = None,
    *,
    session: Any = None,
    external_id: str | None = None,
    role_name: str | None = None,
) -> CISBenchmarkReport:
    """Run the CIS AWS benchmark for EVERY member account of the organization.

    The CIS counterpart of
    :func:`agent_bom.cloud.aws_inventory.discover_all_account_inventories`: it
    reuses the same member-account enumeration
    (:func:`agent_bom.cloud.aws_organizations.list_member_account_ids`) and the
    same read-only AssumeRole broker
    (:func:`agent_bom.cloud.aws_organizations.assume_account_session`) so the
    benchmark covers the identical estate the inventory fan-out does. Each account
    is benchmarked concurrently (bounded thread pool) and the per-account results
    are aggregated into one :class:`CISBenchmarkReport` with every check tagged by
    its ``account_id``.

    ``session`` / ``external_id`` / ``role_name`` mirror the inventory fan-out so
    Connections org scans can reuse the brokered management session.

    Read-only and partial-permission tolerant: an account whose read-only role
    cannot be assumed is skipped with a warning rather than failing the whole run.
    Falls back to a single ambient-credential benchmark when no org is visible (a
    standalone account).

    Raises:
        CloudDiscoveryError: if boto3 is not installed.
    """
    from concurrent.futures import ThreadPoolExecutor, as_completed

    from agent_bom.cloud import aws_organizations

    from .normalization import sanitize_discovery_warning

    try:
        import boto3  # noqa: F401
    except ImportError:
        raise CloudDiscoveryError("boto3 is required for CIS AWS Benchmark checks. Install with: pip install 'agent-bom[aws]'")

    try:
        account_ids = aws_organizations.list_member_account_ids(profile, force=True, session=session)
    except Exception as exc:  # noqa: BLE001 — org enumeration failure must degrade, not crash
        logger.warning("AWS org account enumeration failed: %s", sanitize_text(sanitize_discovery_warning(exc)))
        account_ids = []

    if not account_ids:
        # Standalone account (not in an org) — single-account benchmark.
        return run_benchmark_all_regions(profile=profile, checks=checks, session=session)

    cap = aws_organizations.max_accounts()
    capped = account_ids[:cap]

    aggregate = CISBenchmarkReport(
        account_id=", ".join(capped),
        scope="organization-enabled-regions",
        completeness="complete",
    )
    scope_partial = len(account_ids) > cap
    if len(account_ids) > cap:
        aggregate.warnings.append(
            f"AWS multi-account CIS benchmark capped at {cap} of {len(account_ids)} accounts (set AGENT_BOM_AWS_MAX_ACCOUNTS to raise)."
        )

    def _run_one(account_id: str) -> tuple[str, CISBenchmarkReport]:
        assumed = aws_organizations.assume_account_session(
            account_id,
            profile=profile,
            role_name=role_name,
            external_id=external_id,
            base_session=session,
        )
        return account_id, run_benchmark_all_regions(session=assumed, checks=checks)

    # Deterministic aggregation: collect per-account reports keyed by id, then
    # merge in enumeration order so output is stable across runs.
    reports: dict[str, CISBenchmarkReport] = {}
    with ThreadPoolExecutor(max_workers=min(_MAX_CIS_FANOUT_WORKERS, len(capped))) as executor:
        future_to_account = {executor.submit(_run_one, aid): aid for aid in capped}
        for future in as_completed(future_to_account):
            account_id = future_to_account[future]
            try:
                _aid, account_report = future.result()
                reports[account_id] = account_report
            except Exception as exc:  # noqa: BLE001 — one unreadable account must not sink the rest
                scope_partial = True
                aggregate.warnings.append(f"Account {account_id} skipped: {sanitize_discovery_warning(exc)}")

    for account_id in capped:
        merged = reports.get(account_id)
        if merged is None:
            continue
        aggregate.accounts_scanned.append(account_id)
        for scan_region in merged.regions_scanned:
            if scan_region not in aggregate.regions_scanned:
                aggregate.regions_scanned.append(scan_region)
        if merged.completeness != "complete":
            scope_partial = True
        for check in merged.checks:
            check.account_id = account_id
            aggregate.checks.append(check)
        aggregate.warnings.extend(merged.warnings)

    if not aggregate.accounts_scanned:
        aggregate.completeness = "unavailable"
    elif scope_partial:
        aggregate.completeness = "partial"

    return aggregate
