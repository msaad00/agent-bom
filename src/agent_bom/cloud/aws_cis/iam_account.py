"""CIS AWS 1.1-1.8 — account contacts, root and password-policy checks."""

from __future__ import annotations

import csv
import io
import time
from datetime import datetime, timezone
from typing import Any

from ._base import CheckStatus, CISCheckResult, _safe_error_evidence

# ---------------------------------------------------------------------------
# Individual checks — CIS 1.x (Identity and Access Management)
# ---------------------------------------------------------------------------

_IAM_SECTION = "1 - Identity and Access Management"


def _check_1_1(account_client: Any) -> CISCheckResult:
    """CIS 1.1 — Account contact details kept current."""
    result = CISCheckResult(
        check_id="1.1",
        title="Account contact details kept current",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Ensure account contact details are current via AWS Account settings.",
    )
    try:
        contact = account_client.get_contact_information()
        info = contact.get("ContactInformation", {})
        if not info.get("FullName") or not info.get("PhoneNumber"):
            result.status = CheckStatus.FAIL
            result.evidence = "Account contact information is incomplete."
        else:
            result.evidence = "Account contact details are configured."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        result.status = CheckStatus.ERROR
        result.evidence = _safe_error_evidence("Could not retrieve contact information.", error_code)
    return result


def _check_1_2(account_client: Any) -> CISCheckResult:
    """CIS 1.2 — Security contact information registered."""
    result = CISCheckResult(
        check_id="1.2",
        title="Security contact information registered",
        status=CheckStatus.PASS,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Register a security contact via AWS Account > Alternate contacts.",
    )
    try:
        resp = account_client.get_alternate_contact(AlternateContactType="SECURITY")
        contact = resp.get("AlternateContact", {})
        if not contact.get("EmailAddress"):
            result.status = CheckStatus.FAIL
            result.evidence = "Security alternate contact has no email address."
        else:
            result.evidence = "Security alternate contact is registered."
    except Exception as exc:
        error_code = getattr(exc, "response", {}).get("Error", {}).get("Code", "")
        if error_code == "ResourceNotFoundException":
            result.status = CheckStatus.FAIL
            result.evidence = "No security alternate contact is registered."
        else:
            result.status = CheckStatus.ERROR
            result.evidence = _safe_error_evidence("Could not retrieve security contact.", error_code)
    return result


def _check_1_3() -> CISCheckResult:
    """CIS 1.3 — Root not reliant on security questions alone."""
    return CISCheckResult(
        check_id="1.3",
        title="Root not reliant on security questions alone",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        cis_section=_IAM_SECTION,
        recommendation="Enable MFA for root and do not rely solely on security questions.",
        evidence="Manual check — cannot be verified programmatically.",
    )


def _check_1_4(iam_client: Any) -> CISCheckResult:
    """CIS 1.4 — No root account access keys."""
    result = CISCheckResult(
        check_id="1.4",
        title="No root account access keys",
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
    """CIS 1.5 — Root account MFA enabled."""
    result = CISCheckResult(
        check_id="1.5",
        title="Root account MFA enabled",
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
    """CIS 1.6 — Hardware MFA for root account."""
    result = CISCheckResult(
        check_id="1.6",
        title="Hardware MFA for root account",
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


def _check_1_7(iam_client: Any) -> CISCheckResult:
    """CIS 1.7 — Root user not used for daily tasks."""
    result = CISCheckResult(
        check_id="1.7",
        title="Root user not used for daily tasks",
        status=CheckStatus.PASS,
        severity="high",
        cis_section=_IAM_SECTION,
        recommendation="Avoid using the root account; use IAM users or roles instead.",
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
    now = datetime.now(tz=timezone.utc)

    for row in reader:
        if row.get("user") != "<root_account>":
            continue
        last_used = row.get("password_last_used", "N/A")
        if last_used in ("N/A", "no_information", "not_supported", ""):
            result.evidence = "Root account password has never been used (or no data)."
            break
        try:
            used_dt = datetime.fromisoformat(last_used.replace("Z", "+00:00"))
            days_ago = (now - used_dt).days
            if days_ago <= 90:
                result.status = CheckStatus.FAIL
                result.evidence = f"Root account was last used {days_ago} day(s) ago."
            else:
                result.evidence = f"Root account last used {days_ago} days ago (>90 days)."
        except (ValueError, TypeError):
            result.evidence = f"Could not parse root last-used date: {last_used}"
        break
    return result


def _check_1_8(iam_client: Any) -> CISCheckResult:
    """CIS 1.8 — IAM password policy minimum length >= 14."""
    result = CISCheckResult(
        check_id="1.8",
        title="IAM password policy minimum length >= 14",
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
