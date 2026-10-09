"""CIS AWS 4.1-4.7 — identity and audit metric-filter alarm checks."""

from __future__ import annotations

from typing import Any, Callable

from agent_bom.security import sanitize_text

from ._base import CheckStatus, CISCheckResult, _safe_error_evidence, logger

# ---------------------------------------------------------------------------
# Individual checks — CIS 4.x (Monitoring)
# ---------------------------------------------------------------------------

_MONITORING_SECTION = "4 - Monitoring"


def _require_targeting_alarm(
    result: CISCheckResult,
    logs_client: Any,
    cloudwatch_client: Any,
    *,
    matches_filter: Callable[[str], bool],
) -> CISCheckResult:
    """Require a usable metric transform and an alarm targeting its metric."""
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        transforms: list[tuple[str, str]] = []
        for page in paginator.paginate():
            for metric_filter in page.get("metricFilters", []):
                pattern = str(metric_filter.get("filterPattern", ""))
                if not matches_filter(pattern):
                    continue
                for transform in metric_filter.get("metricTransformations", []):
                    metric_name = str(transform.get("metricName", "")).strip()
                    namespace = str(transform.get("metricNamespace", "")).strip()
                    if metric_name and namespace:
                        transforms.append((metric_name, namespace))
        if not transforms:
            result.status = CheckStatus.FAIL
            result.evidence = "A matching metric filter exists, but it has no usable metric transformation."
            return result
        for metric_name, namespace in dict.fromkeys(transforms):
            response = cloudwatch_client.describe_alarms_for_metric(
                MetricName=metric_name,
                Namespace=namespace,
            )
            if response.get("MetricAlarms", []):
                result.evidence = f"{result.evidence.rstrip('.')} and a targeting CloudWatch alarm exists."
                return result
        result.status = CheckStatus.FAIL
        result.evidence = "A matching metric filter exists, but no CloudWatch alarm targets its metric."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        logger.debug("Could not verify metric alarm: %s (%s)", type(exc).__name__, error_code)
        result.status = CheckStatus.ERROR
        result.evidence = _safe_error_evidence("Could not query metric filters and alarms.", error_code)
    return result


def _check_4_3(logs_client: Any, cloudwatch_client: Any) -> CISCheckResult:
    """CIS 4.3 — Metric filter and alarm for root account usage."""
    result = CISCheckResult(
        check_id="4.3",
        title="Metric filter and alarm for root account usage",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for root account usage.",
    )
    root_patterns = [
        '$.userIdentity.type = "Root"',
        "userIdentity.type",
        "Root",
    ]

    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        metric_transforms: list[tuple[str, str]] = []
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                # Check if the filter pattern references root identity
                if any(p.lower() in pattern.lower() for p in root_patterns[:2]):
                    for transform in mf.get("metricTransformations", []):
                        name = str(transform.get("metricName", "")).strip()
                        namespace = str(transform.get("metricNamespace", "")).strip()
                        if name and namespace:
                            metric_transforms.append((name, namespace))

        if not metric_transforms:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter with a usable metric transformation found for root account usage."
        else:
            alarm_found = False
            for metric_name, namespace in metric_transforms:
                response = cloudwatch_client.describe_alarms_for_metric(
                    MetricName=metric_name,
                    Namespace=namespace,
                )
                if response.get("MetricAlarms", []):
                    alarm_found = True
                    break
            if alarm_found:
                result.evidence = "Metric filter and CloudWatch alarm for root account usage exist."
            else:
                result.status = CheckStatus.FAIL
                result.evidence = "A root account usage metric filter exists, but no CloudWatch alarm targets its metric."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        logger.debug("Could not check metric filters: %s (%s)", sanitize_text(exc), error_code)
        result.status = CheckStatus.ERROR
        result.evidence = _safe_error_evidence("Could not query metric filters and alarms.", error_code)
    return result


def _check_4_4(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.4 — Metric filter and alarm for IAM policy changes."""
    result = CISCheckResult(
        check_id="4.4",
        title="Metric filter and alarm for IAM policy changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for IAM policy changes.",
    )
    iam_event_names = [
        "DeleteGroupPolicy",
        "DeleteRolePolicy",
        "DeleteUserPolicy",
        "PutGroupPolicy",
        "PutRolePolicy",
        "PutUserPolicy",
        "CreatePolicy",
        "DeletePolicy",
        "AttachRolePolicy",
        "DetachRolePolicy",
        "AttachUserPolicy",
        "DetachUserPolicy",
        "AttachGroupPolicy",
        "DetachGroupPolicy",
    ]

    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                # A proper filter checks at least a few IAM policy event names
                matches = sum(1 for e in iam_event_names if e in pattern)
                if matches >= 3:
                    found = True
                    break
            if found:
                break

        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for IAM policy changes."
        else:
            result.evidence = "Metric filter for IAM policy changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        logger.debug("Could not check metric filters: %s (%s)", sanitize_text(exc), error_code)
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in iam_event_names if event in pattern) >= 3,
        )
    return result


def _check_4_5(logs_client: Any, cloudtrail_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.5 — Metric filter and alarm for CloudTrail config changes."""
    result = CISCheckResult(
        check_id="4.5",
        title="Metric filter and alarm for CloudTrail config changes",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for CloudTrail configuration changes.",
    )
    ct_event_names = [
        "CreateTrail",
        "UpdateTrail",
        "DeleteTrail",
        "StartLogging",
        "StopLogging",
    ]

    try:
        # First find the log group(s) used by CloudTrail
        trails = cloudtrail_client.describe_trails(includeShadowTrails=False).get("trailList", [])
        log_group_arns = {t.get("CloudWatchLogsLogGroupArn", "") for t in trails if t.get("CloudWatchLogsLogGroupArn")}

        if not log_group_arns:
            result.status = CheckStatus.FAIL
            result.evidence = "No CloudTrail trails integrated with CloudWatch Logs."
            return result

        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in ct_event_names if e in pattern)
                if matches >= 3:
                    found = True
                    break
            if found:
                break

        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for CloudTrail configuration changes."
        else:
            result.evidence = "Metric filter for CloudTrail configuration changes exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        logger.debug("Could not check metric filters: %s (%s)", sanitize_text(exc), error_code)
        result.status = CheckStatus.ERROR
        result.evidence = _safe_error_evidence("Could not query metric filters.", error_code)
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: sum(1 for event in ct_event_names if event in pattern) >= 3,
        )
    return result


def _check_4_1(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.1 — Metric filter and alarm for unauthorized API calls."""
    result = CISCheckResult(
        check_id="4.1",
        title="Metric filter and alarm for unauthorized API calls",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for unauthorized API calls.",
    )
    patterns = ["UnauthorizedAccess", "AccessDenied"]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                if any(p.lower() in pattern.lower() for p in patterns):
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for unauthorized API calls."
        else:
            result.evidence = "Metric filter for unauthorized API calls exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: any(token.lower() in pattern.lower() for token in patterns),
        )
    return result


def _check_4_2(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.2 — Metric filter and alarm for console sign-in without MFA."""
    result = CISCheckResult(
        check_id="4.2",
        title="Metric filter and alarm for console sign-in without MFA",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for console sign-in without MFA.",
    )
    patterns = ["ConsoleLogin", "MFAUsed"]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                if all(p.lower() in pattern.lower() for p in patterns):
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for console sign-in without MFA."
        else:
            result.evidence = "Metric filter for console sign-in without MFA exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: all(token.lower() in pattern.lower() for token in patterns),
        )
    return result


def _check_4_6(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.6 — Metric filter and alarm for console auth failures."""
    result = CISCheckResult(
        check_id="4.6",
        title="Metric filter and alarm for console auth failures",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for console authentication failures.",
    )
    patterns = ["ConsoleLogin", "Failed"]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                if all(p.lower() in pattern.lower() for p in patterns):
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for console authentication failures."
        else:
            result.evidence = "Metric filter for console authentication failures exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: all(token.lower() in pattern.lower() for token in patterns),
        )
    return result


def _check_4_7(logs_client: Any, cloudwatch_client: Any = None) -> CISCheckResult:
    """CIS 4.7 — Metric filter and alarm for CMK disable or deletion."""
    result = CISCheckResult(
        check_id="4.7",
        title="Metric filter and alarm for CMK disable or deletion",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_MONITORING_SECTION,
        recommendation="Create a CloudWatch metric filter and alarm for KMS key disabling/deletion.",
    )
    kms_event_names = ["DisableKey", "ScheduleKeyDeletion"]
    try:
        paginator = logs_client.get_paginator("describe_metric_filters")
        found = False
        for page in paginator.paginate():
            for mf in page.get("metricFilters", []):
                pattern = mf.get("filterPattern", "")
                matches = sum(1 for e in kms_event_names if e in pattern)
                if matches >= 1:
                    found = True
                    break
            if found:
                break
        if not found:
            result.status = CheckStatus.FAIL
            result.evidence = "No metric filter found for CMK disabling/deletion."
        else:
            result.evidence = "Metric filter for CMK disabling/deletion exists."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not query metric filters: {error_code or exc}"
    if result.status is CheckStatus.PASS:
        return _require_targeting_alarm(
            result,
            logs_client,
            cloudwatch_client,
            matches_filter=lambda pattern: any(event in pattern for event in kms_event_names),
        )
    return result
