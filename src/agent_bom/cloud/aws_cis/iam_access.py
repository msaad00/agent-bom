"""CIS AWS 1.9-1.22 — credential, key, policy and access-analyzer checks."""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime, timezone
from typing import Any

from ..aws_inventory import is_access_denied_error
from ._base import CheckStatus, CISCheckResult, _safe_error_evidence, finalize_read_coverage, logger
from .iam_account import _IAM_SECTION


def _check_1_10(iam_client: Any) -> CISCheckResult:
    """CIS 1.10 — MFA on all console-access IAM users."""
    result = CISCheckResult(
        check_id="1.10",
        title="MFA on all console-access IAM users",
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


def _check_1_11(iam_client: Any) -> CISCheckResult:
    """CIS 1.11 — No access keys created at user setup."""
    result = CISCheckResult(
        check_id="1.11",
        title="No access keys created at user setup",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Remove access keys created at user creation time; create keys only when needed.",
    )
    # Generate credential report
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
    users_with_initial_keys: list[str] = []

    for row in reader:
        username = row.get("user", "<root_account>")
        if username == "<root_account>":
            continue
        user_creation = row.get("user_creation_time", "")
        for key_idx in ("1", "2"):
            key_active = row.get(f"access_key_{key_idx}_active", "false")
            key_last_rotated = row.get(f"access_key_{key_idx}_last_rotated", "N/A")
            if key_active != "true":
                continue
            if key_last_rotated in ("N/A", "not_supported", ""):
                continue
            # If key creation time matches user creation time (same minute), flag it
            try:
                user_dt = datetime.fromisoformat(user_creation.replace("Z", "+00:00"))
                key_dt = datetime.fromisoformat(key_last_rotated.replace("Z", "+00:00"))
                # Within 2 minutes suggests created at initial setup
                if abs((key_dt - user_dt).total_seconds()) < 120:
                    users_with_initial_keys.append(username)
                    break
            except (ValueError, TypeError):
                continue

    if users_with_initial_keys:
        result.status = CheckStatus.FAIL
        result.evidence = (
            f"{len(users_with_initial_keys)} user(s) with access keys created at setup: {', '.join(users_with_initial_keys[:5])}"
        )
        if len(users_with_initial_keys) > 5:
            result.evidence += f" (+{len(users_with_initial_keys) - 5} more)"
        result.resource_ids = [f"arn:aws:iam::user/{u}" for u in users_with_initial_keys]
    else:
        result.evidence = "No users have access keys created during initial setup."
    return result


def _check_1_12(iam_client: Any) -> CISCheckResult:
    """CIS 1.12 — Credentials unused 45+ days disabled."""
    result = CISCheckResult(
        check_id="1.12",
        title="Credentials unused 45+ days disabled",
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
                if days_unused > threshold_days:
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


def _check_1_13(iam_client: Any) -> CISCheckResult:
    """CIS 1.13 — At most one active access key per IAM user."""
    result = CISCheckResult(
        check_id="1.13",
        title="At most one active access key per IAM user",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Remove extra active access keys so each user has at most one.",
    )
    paginator = iam_client.get_paginator("list_users")
    multi_key_users: list[str] = []

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys = iam_client.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            active_keys = [k for k in keys if k.get("Status") == "Active"]
            if len(active_keys) > 1:
                multi_key_users.append(username)

    if multi_key_users:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(multi_key_users)} user(s) with multiple active access keys: {', '.join(multi_key_users[:5])}"
        if len(multi_key_users) > 5:
            result.evidence += f" (+{len(multi_key_users) - 5} more)"
        result.resource_ids = [f"arn:aws:iam::user/{u}" for u in multi_key_users]
    else:
        result.evidence = "All IAM users have at most one active access key."
    return result


def _check_1_15(iam_client: Any) -> CISCheckResult:
    """CIS 1.15 — IAM permissions granted via groups or roles only."""
    result = CISCheckResult(
        check_id="1.15",
        title="IAM permissions granted via groups or roles only",
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


def _check_1_9(iam_client: Any) -> CISCheckResult:
    """CIS 1.9 — IAM password policy blocks password reuse."""
    result = CISCheckResult(
        check_id="1.9",
        title="IAM password policy blocks password reuse",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Set password reuse prevention to 24 or greater in IAM > Account settings.",
    )
    try:
        policy = iam_client.get_account_password_policy()["PasswordPolicy"]
        reuse_count = policy.get("PasswordReusePrevention", 0)
        if reuse_count < 24:
            result.status = CheckStatus.FAIL
            result.evidence = f"Password reuse prevention is {reuse_count} (required: >= 24)."
        else:
            result.evidence = f"Password reuse prevention is set to {reuse_count}."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if error_code == "NoSuchEntity":
            result.status = CheckStatus.FAIL
            result.evidence = "No password policy is configured."
        else:
            raise
    return result


def _check_1_14(iam_client: Any) -> CISCheckResult:
    """CIS 1.14 — Access keys rotated within 90 days."""
    result = CISCheckResult(
        check_id="1.14",
        title="Access keys rotated within 90 days",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Rotate access keys older than 90 days via IAM > Users > Security credentials.",
    )
    paginator = iam_client.get_paginator("list_users")
    stale_keys: list[str] = []
    now = datetime.now(tz=timezone.utc)

    for page in paginator.paginate():
        for user in page["Users"]:
            username = user["UserName"]
            keys = iam_client.list_access_keys(UserName=username).get("AccessKeyMetadata", [])
            for key in keys:
                if key.get("Status") != "Active":
                    continue
                create_date = key.get("CreateDate")
                if create_date and (now - create_date).days > 90:
                    stale_keys.append(f"{username}/{key['AccessKeyId']}")

    if stale_keys:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(stale_keys)} access key(s) older than 90 days: {', '.join(stale_keys[:5])}"
        if len(stale_keys) > 5:
            result.evidence += f" (+{len(stale_keys) - 5} more)"
        result.resource_ids = stale_keys[:20]
    else:
        result.evidence = "All active access keys are younger than 90 days."
    return result


def _check_1_16(iam_client: Any) -> CISCheckResult:
    """CIS 1.16 — No full-admin IAM policies attached."""
    result = CISCheckResult(
        check_id="1.16",
        title="No full-admin IAM policies attached",
        status=CheckStatus.PASS,
        severity="critical",
        cis_section=_IAM_SECTION,
        recommendation="Remove or scope down policies that grant '*' on '*' resources.",
    )
    import json as _json

    paginator = iam_client.get_paginator("list_policies")
    admin_policies: list[str] = []
    inspected = 0
    denied: list[str] = []

    for page in paginator.paginate(Scope="Local", OnlyAttached=True):
        for policy in page["Policies"]:
            version_id = policy.get("DefaultVersionId", "v1")
            try:
                version = iam_client.get_policy_version(
                    PolicyArn=policy["Arn"],
                    VersionId=version_id,
                )["PolicyVersion"]
                inspected += 1
                doc = version.get("Document", {})
                # Document may be URL-encoded JSON string
                if isinstance(doc, str):
                    from urllib.parse import unquote

                    doc = _json.loads(unquote(doc))
                statements = doc.get("Statement", [])
                if isinstance(statements, dict):
                    statements = [statements]
                for stmt in statements:
                    if stmt.get("Effect") != "Allow":
                        continue
                    actions = stmt.get("Action", [])
                    resources = stmt.get("Resource", [])
                    if isinstance(actions, str):
                        actions = [actions]
                    if isinstance(resources, str):
                        resources = [resources]
                    if "*" in actions and "*" in resources:
                        admin_policies.append(policy["PolicyName"])
                        break
            except Exception as exc:
                if is_access_denied_error(exc):
                    denied.append(policy.get("PolicyName") or policy.get("Arn", "unknown"))
                logger.debug("Could not inspect policy %s", policy.get("Arn"))

    if admin_policies:
        result.status = CheckStatus.FAIL
        result.evidence = f"{len(admin_policies)} attached policy(ies) with full admin: {', '.join(admin_policies[:5])}"
        if len(admin_policies) > 5:
            result.evidence += f" (+{len(admin_policies) - 5} more)"
        result.resource_ids = admin_policies[:20]
    else:
        finalize_read_coverage(
            result,
            inspected=inspected,
            denied=denied,
            permission="iam:GetPolicyVersion",
            resource_kind="policy",
            pass_evidence="No attached customer-managed policies grant full '*:*' admin privileges.",
        )
    return result


def _check_1_17(iam_client: Any) -> CISCheckResult:
    """CIS 1.17 — Support role exists for AWS Support incidents."""
    result = CISCheckResult(
        check_id="1.17",
        title="Support role exists for AWS Support incidents",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Create an IAM role with AWSSupportAccess policy attached.",
    )
    try:
        resp = iam_client.list_entities_for_policy(
            PolicyArn="arn:aws:iam::aws:policy/AWSSupportAccess",
        )
        roles = resp.get("PolicyRoles", [])
        groups = resp.get("PolicyGroups", [])
        users = resp.get("PolicyUsers", [])
        if not roles and not groups and not users:
            result.status = CheckStatus.FAIL
            result.evidence = "AWSSupportAccess policy is not attached to any entity."
        else:
            entities = [r["RoleName"] for r in roles] + [g["GroupName"] for g in groups] + [u["UserName"] for u in users]
            result.evidence = f"AWSSupportAccess is attached to: {', '.join(entities[:5])}"
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check AWSSupportAccess attachment: {error_code or exc}"
    return result


def _check_1_19(ec2_client: Any) -> CISCheckResult:
    """CIS 1.19 — Instance roles used for resource access."""
    result = CISCheckResult(
        check_id="1.19",
        title="Instance roles used for resource access",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Attach IAM instance profiles to all EC2 instances instead of embedding credentials.",
    )
    try:
        paginator = ec2_client.get_paginator("describe_instances")
        no_role: list[str] = []
        for page in paginator.paginate():
            for reservation in page["Reservations"]:
                for instance in reservation["Instances"]:
                    state = instance.get("State", {}).get("Name", "")
                    if state == "terminated":
                        continue
                    if not instance.get("IamInstanceProfile"):
                        no_role.append(instance["InstanceId"])

        if no_role:
            result.status = CheckStatus.FAIL
            result.evidence = f"{len(no_role)} running instance(s) without IAM instance profile: {', '.join(no_role[:5])}"
            if len(no_role) > 5:
                result.evidence += f" (+{len(no_role) - 5} more)"
            result.resource_ids = no_role[:20]
        else:
            result.evidence = "All running EC2 instances have IAM instance profiles."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = _safe_error_evidence("Could not check EC2 instances.", error_code)
    return result


def _check_1_20(accessanalyzer_client: Any) -> CISCheckResult:
    """CIS 1.20 — IAM Access Analyzer enabled in all regions."""
    result = CISCheckResult(
        check_id="1.20",
        title="IAM Access Analyzer enabled in all regions",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Enable IAM Access Analyzer in every region via the IAM console.",
    )
    try:
        resp = accessanalyzer_client.list_analyzers(type="ACCOUNT")
        analyzers = resp.get("analyzers", [])
        active = [a for a in analyzers if a.get("status") == "ACTIVE"]
        if not active:
            result.status = CheckStatus.FAIL
            result.evidence = "No active IAM Access Analyzer found in this region."
        else:
            result.evidence = f"IAM Access Analyzer is active: {active[0].get('name', 'unnamed')}"
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = _safe_error_evidence("Could not check IAM Access Analyzer.", error_code)
    return result


def _check_1_22(iam_client: Any) -> CISCheckResult:
    """CIS 1.22 — AWSCloudShellFullAccess access restricted."""
    result = CISCheckResult(
        check_id="1.22",
        title="AWSCloudShellFullAccess access restricted",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Remove AWSCloudShellFullAccess from users/groups/roles that do not need it.",
    )
    try:
        resp = iam_client.list_entities_for_policy(
            PolicyArn="arn:aws:iam::aws:policy/AWSCloudShellFullAccess",
        )
        roles = resp.get("PolicyRoles", [])
        groups = resp.get("PolicyGroups", [])
        users = resp.get("PolicyUsers", [])
        entities = [r["RoleName"] for r in roles] + [g["GroupName"] for g in groups] + [u["UserName"] for u in users]
        if entities:
            result.status = CheckStatus.FAIL
            result.evidence = f"AWSCloudShellFullAccess is attached to {len(entities)} entity(ies): {', '.join(entities[:5])}"
            if len(entities) > 5:
                result.evidence += f" (+{len(entities) - 5} more)"
            result.resource_ids = entities[:20]
        else:
            result.evidence = "AWSCloudShellFullAccess is not attached to any entity."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check AWSCloudShellFullAccess: {error_code or exc}"
    return result
