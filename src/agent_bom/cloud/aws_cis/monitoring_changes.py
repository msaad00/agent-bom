"""CIS AWS 4.8-4.16 — resource-change metric-filter alarms and Security Hub."""

from __future__ import annotations

from typing import Any

from ._base import CheckStatus, CISCheckResult, _safe_error_evidence
from .monitoring import _MONITORING_SECTION, _require_targeting_alarm


def _check_4_8(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.8 — Metric filter and alarm for S3 bucket policy changes."""
    result = CISCheckResult(
        check_id="4.8",
        title="Metric filter and alarm for S3 bucket policy changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for S3 bucket policy changes.",
    )
    s3_event_names = [
        "PutBucketAcl",
        "PutBucketPolicy",
        "PutBucketCors",
        "PutBucketLifecycle",
        "PutBucketReplication",
        "DeleteBucketPolicy",
        "DeleteBucketCors",
        "DeleteBucketLifecycle",
        "DeleteBucketReplication",
    ]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in s3_event_names if e in pattern)
                if matches >= 3:
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for S3 bucket policy changes."
        else:
            result.evidence = "Metric filter for S3 bucket policy changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in s3_event_names if event in pattern) >= 3,
        )
    return result


def _check_4_9(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.9 — Metric filter and alarm for AWS Config changes."""
    result = CISCheckResult(
        check_id="4.9",
        title="Metric filter and alarm for AWS Config changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for AWS Config changes.",
    )
    config_event_names = [
        "StopConfigurationRecorder",
        "DeleteDeliveryChannel",
        "PutDeliveryChannel",
        "PutConfigurationRecorder",
    ]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in config_event_names if e in pattern)
                if matches >= 2:
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for AWS Config changes."
        else:
            result.evidence = "Metric filter for AWS Config changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in config_event_names if event in pattern) >= 2,
        )
    return result


def _check_4_10(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.10 — Metric filter and alarm for security group changes."""
    result = CISCheckResult(
        check_id="4.10",
        title="Metric filter and alarm for security group changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for security group changes.",
    )
    sg_event_names = [
        "AuthorizeSecurityGroupIngress",
        "AuthorizeSecurityGroupEgress",
        "RevokeSecurityGroupIngress",
        "RevokeSecurityGroupEgress",
        "CreateSecurityGroup",
        "DeleteSecurityGroup",
    ]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in sg_event_names if e in pattern)
                if matches >= 3:
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for security group changes."
        else:
            result.evidence = "Metric filter for security group changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in sg_event_names if event in pattern) >= 3,
        )
    return result


def _check_4_11(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.11 — Metric filter and alarm for NACL changes."""
    result = CISCheckResult(
        check_id="4.11",
        title="Metric filter and alarm for NACL changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for NACL changes.",
    )
    nacl_event_names = [
        "CreateNetworkAcl",
        "CreateNetworkAclEntry",
        "DeleteNetworkAcl",
        "DeleteNetworkAclEntry",
        "ReplaceNetworkAclEntry",
        "ReplaceNetworkAclAssociation",
    ]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in nacl_event_names if e in pattern)
                if matches >= 3:
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for NACL changes."
        else:
            result.evidence = "Metric filter for NACL changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in nacl_event_names if event in pattern) >= 3,
        )
    return result


def _check_4_12(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.12 — Metric filter and alarm for network gateway changes."""
    result = CISCheckResult(
        check_id="4.12",
        title="Metric filter and alarm for network gateway changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for network gateway changes.",
    )
    gw_event_names = [
        "CreateCustomerGateway",
        "DeleteCustomerGateway",
        "AttachInternetGateway",
        "CreateInternetGateway",
        "DeleteInternetGateway",
        "DetachInternetGateway",
    ]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in gw_event_names if e in pattern)
                if matches >= 3:
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for network gateway changes."
        else:
            result.evidence = "Metric filter for network gateway changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in gw_event_names if event in pattern) >= 3,
        )
    return result


def _check_4_13(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.13 — Metric filter and alarm for route table changes."""
    result = CISCheckResult(
        check_id="4.13",
        title="Metric filter and alarm for route table changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for route table changes.",
    )
    rt_event_names = [
        "CreateRoute",
        "CreateRouteTable",
        "ReplaceRoute",
        "ReplaceRouteTableAssociation",
        "DeleteRouteTable",
        "DeleteRoute",
        "DisassociateRouteTable",
    ]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in rt_event_names if e in pattern)
                if matches >= 3:
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for route table changes."
        else:
            result.evidence = "Metric filter for route table changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in rt_event_names if event in pattern) >= 3,
        )
    return result


def _check_4_14(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.14 — Metric filter and alarm for VPC changes."""
    result = CISCheckResult(
        check_id="4.14",
        title="Metric filter and alarm for VPC changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for VPC changes.",
    )
    vpc_event_names = [
        "CreateVpc",
        "DeleteVpc",
        "ModifyVpcAttribute",
        "AcceptVpcPeeringConnection",
        "CreateVpcPeeringConnection",
        "DeleteVpcPeeringConnection",
        "RejectVpcPeeringConnection",
        "AttachClassicLinkVpc",
        "DetachClassicLinkVpc",
        "DisableVpcClassicLink",
        "EnableVpcClassicLink",
    ]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in vpc_event_names if e in pattern)
                if matches >= 3:
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for VPC changes."
        else:
            result.evidence = "Metric filter for VPC changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in vpc_event_names if event in pattern) >= 3,
        )
    return result


def _check_4_15(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.15 — Metric filter and alarm for AWS Organizations changes."""
    result = CISCheckResult(
        check_id="4.15",
        title="Metric filter and alarm for AWS Organizations changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for AWS Organizations changes.",
    )
    org_event_names = [
        "InviteAccountToOrganization",
        "LeaveOrganization",
        "CreateOrganization",
        "DeleteOrganization",
        "AcceptHandshake",
        "CreateAccount",
        "RemoveAccountFromOrganization",
    ]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in org_event_names if e in pattern)
                if matches >= 2:
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for AWS Organizations changes."
        else:
            result.evidence = "Metric filter for AWS Organizations changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = _safe_error_evidence("Could not query metric filters.", error_code)
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in org_event_names if event in pattern) >= 2,
        )
    return result


def _check_4_16(securityhub_client: Any) -> CISCheckResult:
    """CIS 4.16 — AWS Security Hub enabled."""
    result = CISCheckResult(
        check_id="4.16",
        title="AWS Security Hub enabled",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Enable AWS Security Hub in all regions.",
    )
    try:
        resp = securityhub_client.describe_hub()
        if resp.get("HubArn"):
            result.evidence = f"Security Hub is enabled: {resp['HubArn']}"
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "Security Hub is not enabled."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if error_code in ("InvalidAccessException", "ResourceNotFoundException", "SubscriptionRequiredException"):
            # Security Hub not subscribed/enabled — this is a control FAIL with
            # actionable guidance, not an opaque API error. SubscriptionRequired
            # is AWS's signal that the service is simply not turned on.
            result.status = CheckStatus.FAIL
            result.evidence = "Security Hub not enabled — enable it to evaluate this control."
        else:
            result.status = CheckStatus.ERROR
            result.evidence = _safe_error_evidence("Could not check Security Hub.", error_code)
    return result
