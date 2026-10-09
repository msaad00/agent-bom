"""CIS Azure section 2 — Microsoft Defender for Cloud plan checks."""

from __future__ import annotations

from typing import Any

from ..aws_cis_benchmark import CheckStatus, CISCheckResult
from ._base import (
    _DEFENDER_SECTION,
)


def _check_2_1(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.1 — Ensure Microsoft Defender for Servers is enabled."""
    result = CISCheckResult(
        check_id="2.1",
        title="Microsoft Defender for Servers enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Servers (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="VirtualMachines")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for Servers is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for Servers pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Defender for Servers pricing: {exc}"
    return result


def _check_2_2(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.2 — Ensure Microsoft Defender for App Services is enabled."""
    result = CISCheckResult(
        check_id="2.2",
        title="Microsoft Defender for App Services enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for App Services (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="AppServices")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for App Services is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for App Services pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Defender for App Services pricing: {exc}"
    return result


def _check_2_3(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.3 — Ensure Microsoft Defender for SQL Servers is enabled."""
    result = CISCheckResult(
        check_id="2.3",
        title="Microsoft Defender for Azure SQL Databases enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for SQL Servers (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="SqlServers")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for SQL Servers is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for SQL Servers pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Defender for SQL Servers pricing: {exc}"
    return result


def _check_2_4(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.4 — Ensure Microsoft Defender for Storage is enabled."""
    result = CISCheckResult(
        check_id="2.4",
        title="Microsoft Defender for Storage enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Storage (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="StorageAccounts")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for Storage is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for Storage pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Defender for Storage pricing: {exc}"
    return result


def _check_2_5(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.5 — Ensure Microsoft Defender for Key Vault is enabled."""
    result = CISCheckResult(
        check_id="2.5",
        title="Microsoft Defender for Key Vault enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Key Vault (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="KeyVaults")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for Key Vault is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for Key Vault pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Defender for Key Vault pricing: {exc}"
    return result


def _check_2_6(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.6 — Ensure Microsoft Defender for DNS is enabled."""
    result = CISCheckResult(
        check_id="2.6",
        title="Microsoft Defender for DNS enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for DNS (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="Dns")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for DNS is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for DNS pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        # DNS Defender may not be available in all subscriptions
        result.status = CheckStatus.NOT_APPLICABLE
        result.evidence = f"Microsoft Defender for DNS may not be available for this subscription: {exc}"
    return result


def _check_2_7(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.7 — Ensure Microsoft Defender for Resource Manager is enabled."""
    result = CISCheckResult(
        check_id="2.7",
        title="Microsoft Defender for Resource Manager enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Resource Manager (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="Arm")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for Resource Manager is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for Resource Manager pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Defender for Resource Manager pricing: {exc}"
    return result


def _check_2_8(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.8 — Ensure Microsoft Defender for Open-Source Databases is enabled."""
    result = CISCheckResult(
        check_id="2.8",
        title="Microsoft Defender for open-source relational DBs enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Open-Source Relational Databases (Standard tier) in Defender for Cloud > Environment settings.",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="OpenSourceRelationalDatabases")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for Open-Source Relational Databases is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for Open-Source Relational Databases pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Defender for Open-Source Relational Databases pricing: {exc}"
    return result


def _check_2_9(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.9 — Ensure Microsoft Defender for Cosmos DB is enabled."""
    result = CISCheckResult(
        check_id="2.9",
        title="Microsoft Defender for Cosmos DB enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Cosmos DB (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="CosmosDbs")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for Cosmos DB is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for Cosmos DB pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Defender for Cosmos DB pricing: {exc}"
    return result


def _check_2_10(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.10 — Ensure Microsoft Defender for Containers is enabled."""
    result = CISCheckResult(
        check_id="2.10",
        title="Microsoft Defender for Containers enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Containers (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(scope_id=f"/subscriptions/{subscription_id}", pricing_name="Containers")
        tier = getattr(pricing, "pricing_tier", "") or ""
        if tier.lower() == "standard":
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Defender for Containers is enabled (Standard tier)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"Microsoft Defender for Containers pricing tier is '{tier}', expected 'Standard'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Defender for Containers pricing: {exc}"
    return result


def _check_2_11(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.11 — Ensure auto-provisioning of Log Analytics agent is set to On."""
    result = CISCheckResult(
        check_id="2.11",
        title="Log Analytics agent auto-provisioning enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable auto-provisioning of the Log Analytics agent in Defender for Cloud > Environment settings > Auto provisioning.",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_DEFENDER_SECTION,
    )
    try:
        settings = list(security_client.auto_provisioning_settings.list())
        for setting in settings:
            if (getattr(setting, "name", "") or "").lower() == "default":
                auto_provision = getattr(setting, "auto_provision", "") or ""
                if auto_provision.lower() == "on":
                    result.status = CheckStatus.PASS
                    result.evidence = "Auto-provisioning of the Log Analytics agent is enabled."
                else:
                    result.status = CheckStatus.FAIL
                    result.evidence = f"Auto-provisioning of the Log Analytics agent is '{auto_provision}', expected 'On'."
                return result
        result.status = CheckStatus.FAIL
        result.evidence = "No default auto-provisioning setting found."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check auto-provisioning settings: {exc}"
    return result


def _check_2_12(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.12 — Ensure additional email addresses are configured for security alerts."""
    result = CISCheckResult(
        check_id="2.12",
        title="Security contact email addresses configured",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Configure additional email addresses in Defender for Cloud > Environment settings > Email notifications.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        contacts = list(security_client.security_contacts.list())
        has_emails = False
        for contact in contacts:
            emails = getattr(contact, "emails", "") or ""
            if emails.strip():
                has_emails = True
                break
        if has_emails:
            result.status = CheckStatus.PASS
            result.evidence = "Additional email addresses are configured for security contact notifications."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No additional email addresses configured for security contact notifications."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check security contact settings: {exc}"
    return result


def _check_2_13(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.13 — Ensure email notification for high severity alerts is enabled."""
    result = CISCheckResult(
        check_id="2.13",
        title="Email notification for high-severity alerts enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable email notifications for high severity alerts in Defender for Cloud > Environment settings > Email notifications.",  # noqa: E501 (CIS remediation/log-filter string — kept verbatim for copy-paste)
        cis_section=_DEFENDER_SECTION,
    )
    try:
        contacts = list(security_client.security_contacts.list())
        notifications_on = False
        for contact in contacts:
            alert_notifications = getattr(contact, "alert_notifications", None)
            if alert_notifications:
                state = getattr(alert_notifications, "state", "") or ""
                if state.lower() == "on":
                    notifications_on = True
                    break
            # Fallback for older API versions
            elif (getattr(contact, "alert_notifications_state", "") or "").lower() == "on":
                notifications_on = True
                break
        if notifications_on:
            result.status = CheckStatus.PASS
            result.evidence = "Email notifications for high severity alerts are enabled."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "Email notifications for high severity alerts are not enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check security alert notification settings: {exc}"
    return result
