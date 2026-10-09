"""CIS AWS 3.1-3.9 — CloudTrail, config and flow-log logging checks."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_text

from ..aws_inventory import is_access_denied_error
from ._base import CheckStatus, CISCheckResult, finalize_read_coverage, logger

# ---------------------------------------------------------------------------
# Individual checks — CIS 3.x (Logging)
# ---------------------------------------------------------------------------

_LOGGING_SECTION = "3 - Logging"


def _check_3_1(cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.1 — CloudTrail enabled in all regions."""
    result = CISCheckResult(
        check_id="3.1",
        title="CloudTrail enabled in all regions",
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
    """CIS 3.2 — CloudTrail log file validation enabled."""
    result = CISCheckResult(
        check_id="3.2",
        title="CloudTrail log file validation enabled",
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
    """CIS 3.4 — CloudTrail integrated with CloudWatch Logs."""
    result = CISCheckResult(
        check_id="3.4",
        title="CloudTrail integrated with CloudWatch Logs",
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
    """CIS 3.5 — CloudTrail records management events in all regions."""
    # Note: We check via CloudTrail for management event recording as a proxy.
    # Full Config check requires config:DescribeConfigurationRecorders.
    result = CISCheckResult(
        check_id="3.5",
        title="CloudTrail records management events in all regions",
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
    """CIS 3.6 — Access logging enabled on CloudTrail S3 bucket."""
    result = CISCheckResult(
        check_id="3.6",
        title="Access logging enabled on CloudTrail S3 bucket",
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
    inspected = 0
    denied: list[str] = []
    for bucket_name in ct_buckets:
        try:
            logging_conf = s3_client.get_bucket_logging(Bucket=bucket_name)
            inspected += 1
            if not logging_conf.get("LoggingEnabled"):
                no_logging.append(bucket_name)
        except Exception as exc:
            # Skip inaccessible buckets
            if is_access_denied_error(exc):
                denied.append(bucket_name)
            logger.debug("Could not check logging for bucket %s: %s", bucket_name, sanitize_text(exc))

    if no_logging:
        result.status = CheckStatus.FAIL
        result.evidence = f"CloudTrail S3 bucket(s) without access logging: {', '.join(no_logging)}"
        result.resource_ids = [f"arn:aws:s3:::{b}" for b in no_logging]
    else:
        finalize_read_coverage(
            result,
            inspected=inspected,
            denied=denied,
            permission="s3:GetBucketLogging",
            resource_kind="CloudTrail bucket",
            pass_evidence="All CloudTrail S3 buckets have access logging enabled.",
        )
    return result


def _check_3_3(s3_client: Any, cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.3 — CloudTrail S3 bucket not publicly accessible."""
    result = CISCheckResult(
        check_id="3.3",
        title="CloudTrail S3 bucket not publicly accessible",
        status=CheckStatus.PASS,
        severity="critical",
        cis_section=_LOGGING_SECTION,
        recommendation="Remove public access from CloudTrail S3 bucket policies and enable public access blocks.",
    )
    import json as _json

    trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    if not trails:
        result.status = CheckStatus.NOT_APPLICABLE
        result.evidence = "No CloudTrail trails configured."
        return result

    ct_buckets = {t["S3BucketName"] for t in trails if t.get("S3BucketName")}
    public_buckets: list[str] = []
    inspected = 0
    denied: list[str] = []

    for bucket_name in ct_buckets:
        try:
            policy_resp = s3_client.get_bucket_policy(Bucket=bucket_name)
            inspected += 1
            policy_doc = _json.loads(policy_resp["Policy"])
            for stmt in policy_doc.get("Statement", []):
                principal = stmt.get("Principal", {})
                if principal == "*" or (isinstance(principal, dict) and principal.get("AWS") == "*"):
                    if stmt.get("Effect") == "Allow":
                        condition = stmt.get("Condition", {})
                        if not condition:
                            public_buckets.append(bucket_name)
                            break
        except Exception as exc:
            error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
            if error_code == "NoSuchBucketPolicy":
                # No policy = not public via policy — a successful determination.
                inspected += 1
                continue
            if is_access_denied_error(exc):
                denied.append(bucket_name)
                continue
            logger.debug("Could not check bucket policy for %s: %s", bucket_name, sanitize_text(exc))

    if public_buckets:
        result.status = CheckStatus.FAIL
        result.evidence = f"CloudTrail S3 bucket(s) with public policy: {', '.join(public_buckets)}"
        result.resource_ids = [f"arn:aws:s3:::{b}" for b in public_buckets]
    else:
        finalize_read_coverage(
            result,
            inspected=inspected,
            denied=denied,
            permission="s3:GetBucketPolicy",
            resource_kind="CloudTrail bucket",
            pass_evidence="No CloudTrail S3 buckets have public bucket policies.",
        )
    return result


def _check_3_7(cloudtrail_client: Any) -> CISCheckResult:
    """CIS 3.7 — CloudTrail logs encrypted with KMS CMK."""
    result = CISCheckResult(
        check_id="3.7",
        title="CloudTrail logs encrypted with KMS CMK",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_LOGGING_SECTION,
        recommendation="Configure KMS CMK encryption on all CloudTrail trails.",
    )
    trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
    if not trails:
        result.status = CheckStatus.FAIL
        result.evidence = "No CloudTrail trails configured."
        return result

    no_kms = [t["Name"] for t in trails if not t.get("KmsKeyId")]
    if no_kms:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(no_kms)} trail(s) not encrypted with KMS CMK: {', '.join(no_kms[:5])}"
        if len(no_kms) > 5:
            result.evidence += f" (+{len(no_kms) - 5} more)"
        result.resource_ids = [t.get("TrailARN", t["Name"]) for t in trails if not t.get("KmsKeyId")]
    else:
        result.evidence = f"All {len(trails)} trail(s) are encrypted with KMS CMK."
    return result


def _check_3_9(ec2_client: Any) -> CISCheckResult:
    """CIS 3.9 — VPC flow logging enabled in all VPCs."""
    result = CISCheckResult(
        check_id="3.9",
        title="VPC flow logging enabled in all VPCs",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_LOGGING_SECTION,
        recommendation="Enable VPC Flow Logs for all VPCs (reject or all traffic).",
    )
    vpcs = ec2_client.describe_vpcs().get("Vpcs", [])
    if not vpcs:
        result.status = CheckStatus.NOT_APPLICABLE
        result.evidence = "No VPCs found."
        return result

    vpc_ids = {v["VpcId"] for v in vpcs}
    flow_logs = ec2_client.describe_flow_logs(
        Filters=[{"Name": "resource-type", "Values": ["VPC"]}],
    ).get("FlowLogs", [])
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
