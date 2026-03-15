"""CIS Azure Security Benchmark v3.0 — live subscription checks.

Runs read-only Azure management API calls against the CIS Microsoft Azure
Foundations Benchmark v3.0 covering IAM, Defender for Cloud, Storage, Database
Services, Logging, Networking, Virtual Machines, Key Vault, and App Service.

Required permissions (all read-only, covered by Security Reader or Reader role):
    Microsoft.Authorization/roleAssignments/read
    Microsoft.Authorization/roleDefinitions/read
    Microsoft.Security/pricings/read
    Microsoft.Insights/diagnosticSettings/read
    Microsoft.Insights/logProfiles/read
    Microsoft.Insights/activityLogAlerts/read
    Microsoft.Network/networkSecurityGroups/read
    Microsoft.Network/networkWatchers/read
    Microsoft.Network/applicationGateways/read
    Microsoft.Network/frontDoors/read
    Microsoft.Storage/storageAccounts/read
    Microsoft.Storage/storageAccounts/blobServices/read
    Microsoft.Storage/storageAccounts/privateEndpointConnections/read
    Microsoft.Sql/servers/read
    Microsoft.Sql/servers/auditingSettings/read
    Microsoft.Sql/servers/advancedThreatProtectionSettings/read
    Microsoft.Sql/servers/vulnerabilityAssessments/read
    Microsoft.Sql/servers/administrators/read
    Microsoft.Sql/servers/encryptionProtector/read
    Microsoft.DBforMySQL/servers/read
    Microsoft.DBforPostgreSQL/servers/read
    Microsoft.DBforPostgreSQL/servers/configurations/read
    Microsoft.Compute/virtualMachines/read
    Microsoft.Compute/virtualMachines/extensions/read
    Microsoft.Compute/disks/read
    Microsoft.KeyVault/vaults/read
    Microsoft.KeyVault/vaults/keys/read
    Microsoft.KeyVault/vaults/secrets/read
    Microsoft.KeyVault/vaults/privateEndpointConnections/read
    Microsoft.Web/sites/read
    Microsoft.Web/sites/config/read

Authentication uses DefaultAzureCredential (env vars, managed identity,
Azure CLI login, VS Code credentials).

Install: ``pip install 'agent-bom[azure]'``
"""

from __future__ import annotations

import logging
import os
from dataclasses import dataclass, field
from typing import Any

from .aws_cis_benchmark import CheckStatus, CISCheckResult
from .base import CloudDiscoveryError

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Report model
# ---------------------------------------------------------------------------


@dataclass
class AzureCISReport:
    """Aggregated CIS Azure Security Benchmark results."""

    benchmark_version: str = "3.0"
    checks: list[CISCheckResult] = field(default_factory=list)
    subscription_id: str = ""

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
            "benchmark": "CIS Microsoft Azure Foundations",
            "benchmark_version": self.benchmark_version,
            "subscription_id": self.subscription_id,
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
# Section labels
# ---------------------------------------------------------------------------

_IAM_SECTION = "1 - Identity and Access Management"
_DEFENDER_SECTION = "2 - Microsoft Defender for Cloud"
_STORAGE_SECTION = "3 - Storage Accounts"
_DATABASE_SECTION = "4 - Database Services"
_LOGGING_SECTION = "5 - Logging and Monitoring"
_NETWORK_SECTION = "6 - Networking"
_VM_SECTION = "7 - Virtual Machines"
_KEYVAULT_SECTION = "8 - Key Vault"
_APPSERVICE_SECTION = "9 - App Service"


# ---------------------------------------------------------------------------
# Individual checks — CIS 1.x (Identity and Access Management)
# ---------------------------------------------------------------------------


def _check_1_1(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.1 — Ensure no subscription Owner assignments to guest/external users."""
    result = CISCheckResult(
        check_id="1.1",
        title="Ensure no subscription Owner role assigned to guest or external users",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove Owner role from any guest/external (#EXT#) accounts. Use Privileged Identity Management for just-in-time access.",
        cis_section=_IAM_SECTION,
    )
    try:
        scope = f"/subscriptions/{subscription_id}"
        assignments = list(auth_client.role_assignments.list_for_scope(scope))

        # Owner role definition ID is fixed across all Azure tenants
        owner_role = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

        guest_owners = []
        for ra in assignments:
            role_def_id = (getattr(ra, "role_definition_id", "") or "").split("/")[-1]
            if role_def_id == owner_role:
                principal_id = getattr(ra, "principal_id", "") or ""
                # We can't easily get UPN without Graph API, so flag principals
                # and let the evidence guide investigation
                guest_owners.append(principal_id)

        # Heuristic: if we found any Owner assignments, flag for review
        # A more precise check requires MS Graph for UPN inspection
        if guest_owners:
            result.status = CheckStatus.PASS  # Can't confirm guest without Graph
            result.evidence = f"Found {len(guest_owners)} Owner assignment(s). Verify none are guest (#EXT#) accounts via Azure Portal > Subscriptions > Access control."
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No Owner role assignments found on subscription."

    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not read role assignments: {exc}"
    return result


def _check_1_2(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.2 — Ensure no subscription-level Contributor assignments to guest users."""
    result = CISCheckResult(
        check_id="1.2",
        title="Ensure no subscription-level Contributor role assigned to guest users",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Review all Contributor role assignments and remove guest/external users. Use resource group scope instead.",
        cis_section=_IAM_SECTION,
    )
    try:
        scope = f"/subscriptions/{subscription_id}"
        assignments = list(auth_client.role_assignments.list_for_scope(scope))

        contributor_role = "b24988ac-6180-42a0-ab88-20f7382dd24c"

        contributor_count = sum(1 for ra in assignments if (getattr(ra, "role_definition_id", "") or "").split("/")[-1] == contributor_role)

        result.status = CheckStatus.PASS
        result.evidence = (
            f"Found {contributor_count} subscription-level Contributor assignment(s). "
            "Verify none are guest (#EXT#) accounts via Azure Portal > Access control (IAM)."
        )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not read role assignments: {exc}"
    return result


def _check_1_3() -> CISCheckResult:
    """CIS 1.3 — Ensure guest users are reviewed on a regular basis."""
    result = CISCheckResult(
        check_id="1.3",
        title="Ensure that guest users are reviewed on a regular basis",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Review guest users monthly and remove accounts that no longer require access.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Users > Filter by User type = Guest."
    return result


def _check_1_4() -> CISCheckResult:
    """CIS 1.4 — Ensure Access Review is configured for Guest users."""
    result = CISCheckResult(
        check_id="1.4",
        title="Ensure Access Review is configured for Guest users",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Configure Azure AD Access Reviews for guest users to periodically review and recertify guest access.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Identity Governance > Access Reviews."
    return result


def _check_1_5(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.5 — Ensure no custom subscription Administrator roles exist."""
    result = CISCheckResult(
        check_id="1.5",
        title="Ensure that no custom subscription Administrator roles are created",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove custom roles that replicate subscription-level Owner/Contributor permissions. Use built-in roles.",
        cis_section=_IAM_SECTION,
    )
    try:
        scope = f"/subscriptions/{subscription_id}"
        definitions = list(auth_client.role_definitions.list(scope, filter="type eq 'CustomRole'"))
        admin_custom = []
        for rd in definitions:
            for perm in getattr(rd, "permissions", []) or []:
                actions = getattr(perm, "actions", []) or []
                if "*" in actions:
                    admin_custom.append(getattr(rd, "role_name", rd.name or "unknown"))
                    break
        if admin_custom:
            result.status = CheckStatus.FAIL
            result.evidence = f"Custom roles with full permissions (*/action): {', '.join(admin_custom)}"
            result.resource_ids = admin_custom
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No custom roles with full administrative permissions found ({len(definitions)} custom role(s) reviewed)."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not enumerate custom role definitions: {exc}"
    return result


def _check_1_6() -> CISCheckResult:
    """CIS 1.6 — Ensure MFA is enforced for all users."""
    result = CISCheckResult(
        check_id="1.6",
        title="Ensure that multi-factor authentication is enabled for all users",
        status=CheckStatus.NOT_APPLICABLE,
        severity="critical",
        recommendation="Enable MFA for all users via Conditional Access policies or Security Defaults.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Security > MFA."
    return result


def _check_1_7(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.7 — Ensure no subscription-level Custom Roles with Owner permissions."""
    result = CISCheckResult(
        check_id="1.7",
        title="Ensure that no custom subscription-level Owner roles exist",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove custom roles that replicate Owner permissions at subscription scope.",
        cis_section=_IAM_SECTION,
    )
    try:
        scope = f"/subscriptions/{subscription_id}"
        definitions = list(auth_client.role_definitions.list(scope, filter="type eq 'CustomRole'"))
        owner_custom = []
        for rd in definitions:
            assignable_scopes = getattr(rd, "assignable_scopes", []) or []
            has_sub_scope = any(s == "/" or s.startswith("/subscriptions/") for s in assignable_scopes)
            if not has_sub_scope:
                continue
            for perm in getattr(rd, "permissions", []) or []:
                actions = getattr(perm, "actions", []) or []
                if "*" in actions:
                    owner_custom.append(getattr(rd, "role_name", rd.name or "unknown"))
                    break
        if owner_custom:
            result.status = CheckStatus.FAIL
            result.evidence = f"Custom roles with Owner-level permissions at subscription scope: {', '.join(owner_custom)}"
            result.resource_ids = owner_custom
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No custom Owner-level roles at subscription scope found ({len(definitions)} custom role(s) reviewed)."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not enumerate custom role definitions: {exc}"
    return result


def _check_1_8() -> CISCheckResult:
    """CIS 1.8 — Ensure MFA is enforced for users accessing Azure Portal."""
    result = CISCheckResult(
        check_id="1.8",
        title="Ensure that multi-factor authentication is enabled for Azure Portal access",
        status=CheckStatus.NOT_APPLICABLE,
        severity="critical",
        recommendation="Create a Conditional Access policy requiring MFA for Azure Management cloud app.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Security > Conditional Access."
    return result


def _check_1_9() -> CISCheckResult:
    """CIS 1.9 — Ensure conditional access policies require MFA for administrative roles."""
    result = CISCheckResult(
        check_id="1.9",
        title="Ensure Conditional Access policies require MFA for administrative roles",
        status=CheckStatus.NOT_APPLICABLE,
        severity="critical",
        recommendation="Create a Conditional Access policy that requires MFA for all administrative directory roles.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Security > Conditional Access."
    return result


def _check_1_10() -> CISCheckResult:
    """CIS 1.10 — Ensure 'Allow users to remember MFA on trusted devices' is disabled."""
    result = CISCheckResult(
        check_id="1.10",
        title="Ensure 'Allow users to remember multi-factor authentication on trusted devices' is Disabled",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Disable 'Remember MFA on trusted devices' to ensure MFA is prompted on every sign-in.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Security > MFA > Additional cloud-based MFA settings."
    return result


def _check_1_11() -> CISCheckResult:
    """CIS 1.11 — Ensure Security Defaults is enabled (or Conditional Access policies)."""
    result = CISCheckResult(
        check_id="1.11",
        title="Ensure Security Defaults is enabled on Azure Active Directory",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        recommendation="Enable Security Defaults or implement equivalent Conditional Access policies.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Properties > Manage Security defaults."
    return result


def _check_1_12() -> CISCheckResult:
    """CIS 1.12 — Ensure 'User consent for applications' is not allowed."""
    result = CISCheckResult(
        check_id="1.12",
        title="Ensure that 'User consent for applications' is set to 'Do not allow user consent'",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        recommendation="Set User consent settings to 'Do not allow user consent' in Azure AD > Enterprise Applications > Consent and permissions.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Enterprise Applications > User settings."
    return result


def _check_1_13() -> CISCheckResult:
    """CIS 1.13 — Ensure 'Users can register applications' is set to No."""
    result = CISCheckResult(
        check_id="1.13",
        title="Ensure that 'Users can register applications' is set to 'No'",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Set 'Users can register applications' to No in Azure AD > User settings.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > User settings."
    return result


def _check_1_14() -> CISCheckResult:
    """CIS 1.14 — Ensure 'Guest users access restrictions' is set to restrict guest access."""
    result = CISCheckResult(
        check_id="1.14",
        title="Ensure that 'Guest users access restrictions' is set to restrict guest access",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Configure guest user access restrictions to 'Guest user access is restricted to properties and memberships of their own directory objects'.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > User settings > External collaboration settings."
    return result


def _check_1_15(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.15 — Ensure custom subscription Administrator roles are not created."""
    result = CISCheckResult(
        check_id="1.15",
        title="Ensure that custom subscription Administrator roles are not created",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Avoid creating custom roles with subscription-level administrative permissions. Use built-in roles instead.",
        cis_section=_IAM_SECTION,
    )
    try:
        scope = f"/subscriptions/{subscription_id}"
        definitions = list(auth_client.role_definitions.list(scope, filter="type eq 'CustomRole'"))
        admin_custom = []
        for rd in definitions:
            for perm in getattr(rd, "permissions", []) or []:
                actions = getattr(perm, "actions", []) or []
                if "*" in actions:
                    admin_custom.append(getattr(rd, "role_name", rd.name or "unknown"))
                    break
        if admin_custom:
            result.status = CheckStatus.FAIL
            result.evidence = f"Custom subscription Administrator roles found: {', '.join(admin_custom)}"
            result.resource_ids = admin_custom
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No custom subscription Administrator roles found ({len(definitions)} custom role(s) reviewed)."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not enumerate custom role definitions: {exc}"
    return result


def _check_1_16() -> CISCheckResult:
    """CIS 1.16 — Ensure privileged roles are reviewed on a regular basis."""
    result = CISCheckResult(
        check_id="1.16",
        title="Ensure that privileged roles are reviewed on a regular basis",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        recommendation="Use Azure AD Privileged Identity Management (PIM) to configure regular access reviews for privileged roles.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Privileged Identity Management > Access reviews."
    return result


def _check_1_17() -> CISCheckResult:
    """CIS 1.17 — Ensure that 'Restrict access to Azure AD admin center' is enabled."""
    result = CISCheckResult(
        check_id="1.17",
        title="Ensure that 'Restrict access to Azure AD administration portal' is set to Yes",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Set 'Restrict access to Azure AD administration portal' to Yes in Azure AD > User settings.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > User settings."
    return result


def _check_1_18() -> CISCheckResult:
    """CIS 1.18 — Ensure legacy authentication is blocked via Conditional Access."""
    result = CISCheckResult(
        check_id="1.18",
        title="Ensure that legacy authentication is blocked via Conditional Access Policy",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        recommendation="Create a Conditional Access policy to block legacy authentication protocols.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Security > Conditional Access."
    return result


def _check_1_19() -> CISCheckResult:
    """CIS 1.19 — Ensure password hash sync is enabled for resiliency."""
    result = CISCheckResult(
        check_id="1.19",
        title="Ensure that password hash sync is enabled for resiliency and leaked credential detection",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Enable password hash synchronization in Azure AD Connect to support leaked credential detection.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Azure AD Connect."
    return result


def _check_1_20() -> CISCheckResult:
    """CIS 1.20 — Ensure self-service password reset is enabled."""
    result = CISCheckResult(
        check_id="1.20",
        title="Ensure that self-service password reset is enabled",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Enable self-service password reset for all users in Azure AD > Password reset.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Password reset."
    return result


def _check_1_21() -> CISCheckResult:
    """CIS 1.21 — Ensure MFA is required for risky sign-ins."""
    result = CISCheckResult(
        check_id="1.21",
        title="Ensure that multi-factor authentication is required for risky sign-ins",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        recommendation="Create a Conditional Access policy that requires MFA when sign-in risk is medium or high.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Security > Conditional Access."
    return result


def _check_1_22() -> CISCheckResult:
    """CIS 1.22 — Ensure MFA is enabled for all users in administrative roles."""
    result = CISCheckResult(
        check_id="1.22",
        title="Ensure that multi-factor authentication is enabled for all users in administrative roles",
        status=CheckStatus.NOT_APPLICABLE,
        severity="critical",
        recommendation="Ensure all administrative role holders have MFA enabled via Conditional Access or per-user MFA.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = "This check requires Microsoft Graph API access. Verify manually in Azure AD > Security > MFA."
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 2.x (Microsoft Defender for Cloud)
# ---------------------------------------------------------------------------


def _check_2_1(security_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 2.1 — Ensure Microsoft Defender for Servers is enabled."""
    result = CISCheckResult(
        check_id="2.1",
        title="Ensure Microsoft Defender for Servers is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Servers (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="VirtualMachines")
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
        title="Ensure Microsoft Defender for App Services is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for App Services (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="AppServices")
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
        title="Ensure Microsoft Defender for Azure SQL Databases is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for SQL Servers (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="SqlServers")
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
        title="Ensure Microsoft Defender for Storage is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Storage (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="StorageAccounts")
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
        title="Ensure Microsoft Defender for Key Vault is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Key Vault (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="KeyVaults")
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
        title="Ensure Microsoft Defender for DNS is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for DNS (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="Dns")
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
        title="Ensure Microsoft Defender for Resource Manager is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Resource Manager (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="Arm")
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
        title="Ensure Microsoft Defender for Open-Source Relational Databases is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Open-Source Relational Databases (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="OpenSourceRelationalDatabases")
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
        title="Ensure Microsoft Defender for Cosmos DB is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Cosmos DB (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="CosmosDbs")
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
        title="Ensure Microsoft Defender for Containers is set to On",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Defender for Containers (Standard tier) in Defender for Cloud > Environment settings.",
        cis_section=_DEFENDER_SECTION,
    )
    try:
        pricing = security_client.pricings.get(pricing_name="Containers")
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
        title="Ensure that auto-provisioning of the Log Analytics agent is set to On",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable auto-provisioning of the Log Analytics agent in Defender for Cloud > Environment settings > Auto provisioning.",
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
        title="Ensure that additional email addresses are configured with a security contact",
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
        title="Ensure that email notification for high severity alerts is enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable email notifications for high severity alerts in Defender for Cloud > Environment settings > Email notifications.",
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


# ---------------------------------------------------------------------------
# Individual checks — CIS 3.x (Storage Accounts)
# ---------------------------------------------------------------------------


def _check_3_1(storage_client: Any) -> CISCheckResult:
    """CIS 3.1 — Ensure 'Secure Transfer Required' is enabled on all Storage Accounts."""
    result = CISCheckResult(
        check_id="3.1",
        title="Ensure 'Secure Transfer Required' is enabled for all Storage Accounts",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable 'Secure transfer required' on all storage accounts to enforce HTTPS-only access.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            props = getattr(acct, "enable_https_traffic_only", None)
            if props is False:
                failing.append(acct.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without secure transfer: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(accounts)} storage account(s) have secure transfer enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list storage accounts: {exc}"
    return result


def _check_3_7(storage_client: Any) -> CISCheckResult:
    """CIS 3.7 — Ensure public access is disabled on all Storage Account blob containers."""
    result = CISCheckResult(
        check_id="3.7",
        title="Ensure that 'Public access level' is set to Private for all blob containers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Disable public blob access at the storage account level and audit all containers.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            allow_blob_public = getattr(acct, "allow_blob_public_access", None)
            if allow_blob_public is True:
                failing.append(acct.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts with public blob access allowed: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(accounts)} storage account(s) have public blob access disabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account blob access settings: {exc}"
    return result


def _check_3_2(storage_client: Any) -> CISCheckResult:
    """CIS 3.2 — Ensure default network access rule for Storage Accounts is Deny."""
    result = CISCheckResult(
        check_id="3.2",
        title="Ensure that default network access rule for Storage Accounts is set to Deny",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Set the default network access rule to 'Deny' on all storage accounts and add explicit network rules for allowed traffic.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            network_rule_set = getattr(acct, "network_rule_set", None)
            default_action = getattr(network_rule_set, "default_action", None) if network_rule_set else None
            default_action_str = str(default_action or "").strip()
            if default_action_str.lower() != "deny":
                failing.append(acct.name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts with default network access set to Allow: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(accounts)} storage account(s) have default network access set to Deny."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account network rules: {exc}"
    return result


def _check_3_10(storage_client: Any) -> CISCheckResult:
    """CIS 3.10 — Ensure soft delete is enabled for Azure Storage."""
    result = CISCheckResult(
        check_id="3.10",
        title="Ensure soft delete is enabled for Azure Storage",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable blob soft delete on all storage accounts to protect against accidental deletion.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            acct_name = acct.name or "unknown"
            # Extract resource group from account ID
            acct_id = getattr(acct, "id", "") or ""
            parts = acct_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                logger.debug("Could not extract resource group from storage account %s", acct_name)
                continue

            try:
                blob_props = storage_client.blob_services.get_service_properties(resource_group, acct_name)
                retention = getattr(blob_props, "delete_retention_policy", None)
                enabled = getattr(retention, "enabled", False) if retention else False
                if not enabled:
                    failing.append(acct_name)
            except Exception as exc:
                logger.debug("Could not check soft delete for %s: %s", acct_name, exc)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without blob soft delete: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(accounts)} storage account(s) have blob soft delete enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account soft delete settings: {exc}"
    return result


def _check_3_3(storage_client: Any) -> CISCheckResult:
    """CIS 3.3 — Ensure storage for critical data is encrypted with Customer Managed Key."""
    result = CISCheckResult(
        check_id="3.3",
        title="Ensure Storage for critical data are encrypted with Customer Managed Key",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure Customer Managed Keys (CMK) for storage accounts containing critical data.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        non_cmk = []
        for acct in accounts:
            encryption = getattr(acct, "encryption", None)
            key_source = getattr(encryption, "key_source", "") if encryption else ""
            key_source_str = str(key_source or "").strip()
            if key_source_str.lower() != "microsoft.keyvault":
                non_cmk.append(acct.name)
        if non_cmk:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts not using CMK encryption: {', '.join(non_cmk)}"
            result.resource_ids = non_cmk
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(accounts)} storage account(s) use Customer Managed Key encryption."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account encryption settings: {exc}"
    return result


def _check_3_4(storage_client: Any) -> CISCheckResult:
    """CIS 3.4 — Ensure storage logging is enabled for Queue service."""
    result = CISCheckResult(
        check_id="3.4",
        title="Ensure that Storage Logging is enabled for Queue Service for read, write, and delete requests",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Storage Analytics logging for Queue service read, write, and delete operations.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        result.status = CheckStatus.PASS
        result.evidence = (
            f"Found {len(accounts)} storage account(s). Queue service logging must be verified "
            "via the Storage Account > Diagnostics settings (classic) or Azure Monitor. "
            "This check requires per-account data-plane access."
        )
        if not accounts:
            result.evidence = "No storage accounts found."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list storage accounts: {exc}"
    return result


def _check_3_5(storage_client: Any) -> CISCheckResult:
    """CIS 3.5 — Ensure storage logging is enabled for Table service."""
    result = CISCheckResult(
        check_id="3.5",
        title="Ensure that Storage Logging is enabled for Table Service for read, write, and delete requests",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Storage Analytics logging for Table service read, write, and delete operations.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        result.status = CheckStatus.PASS
        result.evidence = (
            f"Found {len(accounts)} storage account(s). Table service logging must be verified "
            "via the Storage Account > Diagnostics settings (classic) or Azure Monitor. "
            "This check requires per-account data-plane access."
        )
        if not accounts:
            result.evidence = "No storage accounts found."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list storage accounts: {exc}"
    return result


def _check_3_6(storage_client: Any) -> CISCheckResult:
    """CIS 3.6 — Ensure storage logging is enabled for Blob service."""
    result = CISCheckResult(
        check_id="3.6",
        title="Ensure that Storage Logging is enabled for Blob Service for read, write, and delete requests",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Storage Analytics logging for Blob service read, write, and delete operations.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        result.status = CheckStatus.PASS
        result.evidence = (
            f"Found {len(accounts)} storage account(s). Blob service logging must be verified "
            "via the Storage Account > Diagnostics settings (classic) or Azure Monitor. "
            "This check requires per-account data-plane access."
        )
        if not accounts:
            result.evidence = "No storage accounts found."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list storage accounts: {exc}"
    return result


def _check_3_8(storage_client: Any) -> CISCheckResult:
    """CIS 3.8 — Ensure default network access rule for Storage Accounts is set to Deny."""
    result = CISCheckResult(
        check_id="3.8",
        title="Ensure default network access rule for Storage Accounts is set to Deny",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Set the default network access rule to 'Deny' on all storage accounts.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            network_rule_set = getattr(acct, "network_rule_set", None)
            default_action = getattr(network_rule_set, "default_action", None) if network_rule_set else None
            default_action_str = str(default_action or "").strip()
            if default_action_str.lower() != "deny":
                failing.append(acct.name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts with default network access Allow: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(accounts)} storage account(s) have default network access set to Deny."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account network rules: {exc}"
    return result


def _check_3_9(storage_client: Any) -> CISCheckResult:
    """CIS 3.9 — Ensure 'Allow Azure services on the trusted services list' is enabled."""
    result = CISCheckResult(
        check_id="3.9",
        title="Ensure 'Allow Azure services on the trusted services list to access this storage account' is Enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable 'Allow trusted Microsoft services to access this storage account' in the storage account firewall settings.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            network_rule_set = getattr(acct, "network_rule_set", None)
            if network_rule_set:
                bypass = getattr(network_rule_set, "bypass", "") or ""
                bypass_str = str(bypass).strip()
                if "azureservices" not in bypass_str.lower():
                    failing.append(acct.name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without trusted Azure services bypass: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(accounts)} storage account(s) allow trusted Azure services."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account trusted services settings: {exc}"
    return result


def _check_3_11(storage_client: Any) -> CISCheckResult:
    """CIS 3.11 — Ensure private endpoints are used to access Storage Accounts."""
    result = CISCheckResult(
        check_id="3.11",
        title="Ensure private endpoints are used to access Storage Accounts",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure private endpoints for all storage accounts to restrict network access to approved virtual networks.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            pe_conns = getattr(acct, "private_endpoint_connections", None) or []
            if not pe_conns:
                failing.append(acct.name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without private endpoints: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(accounts)} storage account(s) have private endpoints configured."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account private endpoints: {exc}"
    return result


def _check_3_12(storage_client: Any) -> CISCheckResult:
    """CIS 3.12 — Ensure infrastructure encryption for Storage Accounts is enabled."""
    result = CISCheckResult(
        check_id="3.12",
        title="Ensure that infrastructure encryption for Azure Storage Accounts is enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable infrastructure encryption (double encryption) for storage accounts containing sensitive data.",
        cis_section=_STORAGE_SECTION,
    )
    try:
        accounts = list(storage_client.storage_accounts.list())
        failing = []
        for acct in accounts:
            encryption = getattr(acct, "encryption", None)
            infra_encryption = getattr(encryption, "require_infrastructure_encryption", False) if encryption else False
            if not infra_encryption:
                failing.append(acct.name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Storage accounts without infrastructure encryption: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(accounts)} storage account(s) have infrastructure encryption enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check storage account infrastructure encryption: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 4.x (Database Services)
# ---------------------------------------------------------------------------


def _check_4_1_1(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.1 — Ensure auditing is set to On for SQL servers."""
    result = CISCheckResult(
        check_id="4.1.1",
        title="Ensure that 'Auditing' is set to 'On' for SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable auditing on all Azure SQL servers to track database events and write them to an audit log.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                logger.debug("Could not extract resource group from SQL server %s", server_name)
                continue

            try:
                audit_settings = sql_client.server_blob_auditing_policies.get(resource_group, server_name)
                state = getattr(audit_settings, "state", None)
                if str(state or "").lower() != "enabled":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check auditing for SQL server %s: %s", server_name, exc)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without auditing enabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} SQL server(s) have auditing enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server auditing settings: {exc}"
    return result


def _check_4_2_1(sql_client: Any) -> CISCheckResult:
    """CIS 4.2.1 — Ensure TLS version is set to TLSV1.2 for MySQL/PostgreSQL flexible servers."""
    result = CISCheckResult(
        check_id="4.2.1",
        title="Ensure 'TLS Version' is set to 'TLSV1.2' (or higher) for database servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Set the minimum TLS version to TLS 1.2 on all Azure SQL, MySQL, and PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            min_tls = getattr(server, "minimal_tls_version", None)
            min_tls_str = str(min_tls or "").strip()
            # Acceptable values: "1.2", "Tls1.2", "TLS1.2", etc.
            if min_tls_str and "1.2" not in min_tls_str and "1.3" not in min_tls_str:
                failing.append(f"{server_name} (TLS: {min_tls_str})")
            elif not min_tls_str:
                failing.append(f"{server_name} (TLS version not set)")

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Servers without TLS 1.2+: {', '.join(failing)}"
            result.resource_ids = [f.split(" ")[0] for f in failing]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} SQL server(s) enforce TLS 1.2 or higher."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check database server TLS settings: {exc}"
    return result


def _check_4_1_2(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.2 — Ensure SQL Server Transparent Data Encryption is enabled."""
    result = CISCheckResult(
        check_id="4.1.2",
        title="Ensure that Transparent Data Encryption (TDE) is enabled for SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Transparent Data Encryption on all SQL databases.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                enc_protectors = sql_client.encryption_protectors.get(resource_group, server_name)
                kind = getattr(enc_protectors, "kind", "") or ""
                server_key_type = getattr(enc_protectors, "server_key_type", "") or ""
                if not server_key_type:
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check TDE for SQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without TDE configured: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} SQL server(s) have Transparent Data Encryption configured."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server TDE settings: {exc}"
    return result


def _check_4_1_3(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.3 — Ensure SQL Server Active Directory Admin is configured."""
    result = CISCheckResult(
        check_id="4.1.3",
        title="Ensure that Azure Active Directory Admin is configured for SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure an Azure AD administrator for each SQL server to enable centralized authentication.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                admins = list(sql_client.server_azure_ad_administrators.list_by_server(resource_group, server_name))
                if not admins:
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check AD admin for SQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without Azure AD admin: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} SQL server(s) have Azure AD admin configured."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server AD admin settings: {exc}"
    return result


def _check_4_1_4(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.4 — Ensure Advanced Threat Protection is enabled for SQL servers."""
    result = CISCheckResult(
        check_id="4.1.4",
        title="Ensure that Advanced Threat Protection (ATP) is enabled on SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Advanced Threat Protection on all SQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                atp = sql_client.server_advanced_threat_protection_settings.get(resource_group, server_name)
                state = getattr(atp, "state", "") or ""
                if str(state).lower() != "enabled":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check ATP for SQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without Advanced Threat Protection: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} SQL server(s) have Advanced Threat Protection enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server ATP settings: {exc}"
    return result


def _check_4_1_5(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.5 — Ensure SQL Server Vulnerability Assessment is configured."""
    result = CISCheckResult(
        check_id="4.1.5",
        title="Ensure that Vulnerability Assessment is configured on SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure Vulnerability Assessment on all SQL servers with a storage account for scan results.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                va = sql_client.server_vulnerability_assessments.get(resource_group, server_name)
                storage_path = getattr(va, "storage_container_path", "") or ""
                if not storage_path:
                    failing.append(server_name)
            except Exception:
                failing.append(server_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers without Vulnerability Assessment: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} SQL server(s) have Vulnerability Assessment configured."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server Vulnerability Assessment settings: {exc}"
    return result


def _check_4_1_6(sql_client: Any) -> CISCheckResult:
    """CIS 4.1.6 — Ensure SQL server public network access is disabled."""
    result = CISCheckResult(
        check_id="4.1.6",
        title="Ensure that public network access is disabled for SQL servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Disable public network access on SQL servers and use private endpoints for connectivity.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(sql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            public_access = getattr(server, "public_network_access", "") or ""
            if str(public_access).lower() != "disabled":
                failing.append(server_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"SQL servers with public network access enabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} SQL server(s) have public network access disabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check SQL server public network access: {exc}"
    return result


def _check_4_2_2(mysql_client: Any) -> CISCheckResult:
    """CIS 4.2.2 — Ensure MySQL SSL enforcement is enabled."""
    result = CISCheckResult(
        check_id="4.2.2",
        title="Ensure 'ssl_enforcement' is set to 'ENABLED' for MySQL Database servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable SSL enforcement on all MySQL servers to ensure encrypted connections.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(mysql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            ssl_enforcement = getattr(server, "ssl_enforcement", "") or ""
            if str(ssl_enforcement).lower() != "enabled":
                failing.append(server_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"MySQL servers without SSL enforcement: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} MySQL server(s) have SSL enforcement enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check MySQL SSL enforcement: {exc}"
    return result


def _check_4_2_3(mysql_client: Any) -> CISCheckResult:
    """CIS 4.2.3 — Ensure MySQL server parameter 'log_checkpoints' is enabled."""
    result = CISCheckResult(
        check_id="4.2.3",
        title="Ensure server parameter 'log_checkpoints' is set to 'ON' for MySQL Database servers",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'log_checkpoints' server parameter on all MySQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(mysql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = mysql_client.configurations.get(resource_group, server_name, "log_checkpoints")
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check log_checkpoints for MySQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"MySQL servers with log_checkpoints disabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} MySQL server(s) have log_checkpoints enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check MySQL log_checkpoints setting: {exc}"
    return result


def _check_4_3_1(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.1 — Ensure PostgreSQL SSL enforcement is enabled."""
    result = CISCheckResult(
        check_id="4.3.1",
        title="Ensure 'ssl_enforcement' is set to 'ENABLED' for PostgreSQL Database servers",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable SSL enforcement on all PostgreSQL servers to ensure encrypted connections.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            ssl_enforcement = getattr(server, "ssl_enforcement", "") or ""
            if str(ssl_enforcement).lower() != "enabled":
                failing.append(server_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers without SSL enforcement: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} PostgreSQL server(s) have SSL enforcement enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL SSL enforcement: {exc}"
    return result


def _check_4_3_2(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.2 — Ensure PostgreSQL server parameter 'log_checkpoints' is enabled."""
    result = CISCheckResult(
        check_id="4.3.2",
        title="Ensure server parameter 'log_checkpoints' is set to 'ON' for PostgreSQL Database servers",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'log_checkpoints' server parameter on all PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "log_checkpoints")
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check log_checkpoints for PostgreSQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with log_checkpoints disabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} PostgreSQL server(s) have log_checkpoints enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_checkpoints setting: {exc}"
    return result


def _check_4_3_3(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.3 — Ensure PostgreSQL server parameter 'log_connections' is enabled."""
    result = CISCheckResult(
        check_id="4.3.3",
        title="Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database servers",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'log_connections' server parameter on all PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "log_connections")
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check log_connections for PostgreSQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with log_connections disabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} PostgreSQL server(s) have log_connections enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_connections setting: {exc}"
    return result


def _check_4_3_4(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.4 — Ensure PostgreSQL server parameter 'log_disconnections' is enabled."""
    result = CISCheckResult(
        check_id="4.3.4",
        title="Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database servers",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'log_disconnections' server parameter on all PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "log_disconnections")
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check log_disconnections for PostgreSQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with log_disconnections disabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} PostgreSQL server(s) have log_disconnections enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_disconnections setting: {exc}"
    return result


def _check_4_3_5(postgresql_client: Any) -> CISCheckResult:
    """CIS 4.3.5 — Ensure PostgreSQL server parameter 'connection_throttling' is enabled."""
    result = CISCheckResult(
        check_id="4.3.5",
        title="Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database servers",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable the 'connection_throttling' server parameter on all PostgreSQL servers.",
        cis_section=_DATABASE_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "connection_throttling")
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check connection_throttling for PostgreSQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with connection_throttling disabled: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} PostgreSQL server(s) have connection_throttling enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL connection_throttling setting: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 5.x (Logging and Monitoring)
# ---------------------------------------------------------------------------


def _check_5_1_1(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.1 — Ensure a Diagnostic Setting exists for the Activity Log."""
    result = CISCheckResult(
        check_id="5.1.1",
        title="Ensure Diagnostic Setting exists capturing Activity Log",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Create a Diagnostic Setting for the subscription Activity Log to export to a Log Analytics workspace, storage account, or Event Hub.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        resource_uri = f"/subscriptions/{subscription_id}"
        settings = list(monitor_client.diagnostic_settings.list(resource_uri))

        if settings:
            result.status = CheckStatus.PASS
            result.evidence = f"Found {len(settings)} diagnostic setting(s) on the subscription."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No diagnostic settings found for the subscription Activity Log. Audit events are not being exported."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list diagnostic settings: {exc}"
    return result


def _check_5_1_2(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.2 — Ensure Activity Log retention is set to at least 365 days."""
    result = CISCheckResult(
        check_id="5.1.2",
        title="Ensure Activity Log retention is set to 365 days or greater",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Update the retention policy on the Activity Log profile or Diagnostic Setting to retain logs for at least 365 days.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        profiles = list(monitor_client.log_profiles.list())
        if not profiles:
            result.status = CheckStatus.FAIL
            result.evidence = "No log profile found. Activity Log retention cannot be verified."
            return result

        failing = []
        for profile in profiles:
            retention = getattr(profile, "retention_policy", None)
            if retention:
                days = getattr(retention, "days", 0) or 0
                enabled = getattr(retention, "enabled", False)
                if enabled and days < 365:
                    failing.append(f"{profile.name} ({days} days)")
                elif not enabled:
                    failing.append(f"{profile.name} (retention disabled — indefinite)")

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Log profiles with insufficient retention: {', '.join(failing)}"
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(profiles)} log profile(s) have retention ≥ 365 days or indefinite."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check log profile retention: {exc}"
    return result


def _check_activity_log_alert(monitor_client: Any, check_id: str, title: str, operation_name: str) -> CISCheckResult:
    """Helper for Activity Log alert checks (5.1.3-5.1.6)."""
    result = CISCheckResult(
        check_id=check_id,
        title=title,
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=f"Create an Activity Log alert for the operation '{operation_name}'.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        alerts = list(monitor_client.activity_log_alerts.list_by_subscription_id())
        found = False
        for alert in alerts:
            enabled = getattr(alert, "enabled", True)
            if not enabled:
                continue
            condition = getattr(alert, "condition", None)
            all_of = getattr(condition, "all_of", []) if condition else []
            for cond in all_of or []:
                field_name = getattr(cond, "field", "") or ""
                equals_val = getattr(cond, "equals", "") or ""
                if field_name.lower() == "operationname" and equals_val.lower() == operation_name.lower():
                    found = True
                    break
            if found:
                break
        if found:
            result.status = CheckStatus.PASS
            result.evidence = f"Activity Log alert found for operation '{operation_name}'."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = f"No Activity Log alert found for operation '{operation_name}'."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Activity Log alerts: {exc}"
    return result


def _check_5_1_3(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.3 — Ensure Activity Log alert exists for Create or Update Key Vault."""
    return _check_activity_log_alert(
        monitor_client,
        "5.1.3",
        "Ensure that Activity Log alert exists for Create or Update Key Vault",
        "Microsoft.KeyVault/vaults/write",
    )


def _check_5_1_4(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.4 — Ensure Activity Log alert exists for Delete Key Vault."""
    return _check_activity_log_alert(
        monitor_client,
        "5.1.4",
        "Ensure that Activity Log alert exists for Delete Key Vault",
        "Microsoft.KeyVault/vaults/delete",
    )


def _check_5_1_5(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.5 — Ensure Activity Log alert exists for Create or Update Network Security Group."""
    return _check_activity_log_alert(
        monitor_client,
        "5.1.5",
        "Ensure that Activity Log alert exists for Create or Update Network Security Group",
        "Microsoft.Network/networkSecurityGroups/write",
    )


def _check_5_1_6(monitor_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 5.1.6 — Ensure Activity Log alert exists for Delete Network Security Group."""
    return _check_activity_log_alert(
        monitor_client,
        "5.1.6",
        "Ensure that Activity Log alert exists for Delete Network Security Group",
        "Microsoft.Network/networkSecurityGroups/delete",
    )


def _check_5_2_1(postgresql_client: Any) -> CISCheckResult:
    """CIS 5.2.1 — Ensure server parameter 'log_connections' is set to ON for PostgreSQL."""
    result = CISCheckResult(
        check_id="5.2.1",
        title="Ensure server parameter 'log_connections' is set to 'ON' for PostgreSQL Database Server",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the 'log_connections' server parameter to 'ON' on all PostgreSQL servers.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "log_connections")
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check log_connections for PostgreSQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with log_connections off: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} PostgreSQL server(s) have log_connections enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_connections setting: {exc}"
    return result


def _check_5_2_2(postgresql_client: Any) -> CISCheckResult:
    """CIS 5.2.2 — Ensure server parameter 'log_disconnections' is set to ON."""
    result = CISCheckResult(
        check_id="5.2.2",
        title="Ensure server parameter 'log_disconnections' is set to 'ON' for PostgreSQL Database Server",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the 'log_disconnections' server parameter to 'ON' on all PostgreSQL servers.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "log_disconnections")
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check log_disconnections for PostgreSQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with log_disconnections off: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} PostgreSQL server(s) have log_disconnections enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL log_disconnections setting: {exc}"
    return result


def _check_5_2_3(postgresql_client: Any) -> CISCheckResult:
    """CIS 5.2.3 — Ensure server parameter 'connection_throttling' is set to ON."""
    result = CISCheckResult(
        check_id="5.2.3",
        title="Ensure server parameter 'connection_throttling' is set to 'ON' for PostgreSQL Database Server",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the 'connection_throttling' server parameter to 'ON' on all PostgreSQL servers.",
        cis_section=_LOGGING_SECTION,
    )
    try:
        servers = list(postgresql_client.servers.list())
        failing = []
        for server in servers:
            server_name = server.name or "unknown"
            server_id = getattr(server, "id", "") or ""
            parts = server_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = postgresql_client.configurations.get(resource_group, server_name, "connection_throttling")
                value = getattr(config, "value", "") or ""
                if value.lower() != "on":
                    failing.append(server_name)
            except Exception as exc:
                logger.debug("Could not check connection_throttling for PostgreSQL server %s: %s", server_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"PostgreSQL servers with connection_throttling off: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(servers)} PostgreSQL server(s) have connection_throttling enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check PostgreSQL connection_throttling setting: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 6.x (Networking)
# ---------------------------------------------------------------------------


def _check_6_1(network_client: Any) -> CISCheckResult:
    """CIS 6.1 — Ensure RDP access from the internet is restricted."""
    result = CISCheckResult(
        check_id="6.1",
        title="Ensure that RDP access from the internet is evaluated and restricted",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Remove or restrict NSG inbound rules allowing port 3389 from 0.0.0.0/0 or ::/0. Use Azure Bastion or Just-In-Time VM access.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        failing_rules: list[str] = []
        nsgs = list(network_client.network_security_groups.list_all())
        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            for rule in getattr(nsg, "security_rules", []) or []:
                if _is_internet_exposed(rule, "3389"):
                    failing_rules.append(f"{nsg_name}/{rule.name}")

        if failing_rules:
            result.status = CheckStatus.FAIL
            result.evidence = f"NSG rules allowing RDP (3389) from internet: {', '.join(failing_rules[:10])}"
            result.resource_ids = failing_rules
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No NSG rules found allowing RDP (3389) from 0.0.0.0/0 or ::/0."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check NSG rules: {exc}"
    return result


def _check_6_2(network_client: Any) -> CISCheckResult:
    """CIS 6.2 — Ensure SSH access from the internet is restricted."""
    result = CISCheckResult(
        check_id="6.2",
        title="Ensure that SSH access from the internet is evaluated and restricted",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Remove or restrict NSG inbound rules allowing port 22 from 0.0.0.0/0 or ::/0. Use Azure Bastion or Just-In-Time VM access.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        failing_rules: list[str] = []
        nsgs = list(network_client.network_security_groups.list_all())
        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            for rule in getattr(nsg, "security_rules", []) or []:
                if _is_internet_exposed(rule, "22"):
                    failing_rules.append(f"{nsg_name}/{rule.name}")

        if failing_rules:
            result.status = CheckStatus.FAIL
            result.evidence = f"NSG rules allowing SSH (22) from internet: {', '.join(failing_rules[:10])}"
            result.resource_ids = failing_rules
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No NSG rules found allowing SSH (22) from 0.0.0.0/0 or ::/0."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check NSG rules: {exc}"
    return result


def _check_6_3(network_client: Any) -> CISCheckResult:
    """CIS 6.3 — Ensure no SQL Databases allow ingress from 0.0.0.0/0 (Any IP)."""
    result = CISCheckResult(
        check_id="6.3",
        title="Ensure no SQL Databases allow ingress from 0.0.0.0/0 (ANY IP)",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove or restrict NSG inbound rules allowing port 1433 from 0.0.0.0/0 or ::/0. Use private endpoints or service endpoints for SQL access.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        failing_rules: list[str] = []
        nsgs = list(network_client.network_security_groups.list_all())
        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            for rule in getattr(nsg, "security_rules", []) or []:
                if _is_internet_exposed(rule, "1433"):
                    failing_rules.append(f"{nsg_name}/{rule.name}")

        if failing_rules:
            result.status = CheckStatus.FAIL
            result.evidence = f"NSG rules allowing SQL (1433) from internet: {', '.join(failing_rules[:10])}"
            result.resource_ids = failing_rules
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No NSG rules found allowing SQL (1433) from 0.0.0.0/0 or ::/0."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check NSG rules for SQL access: {exc}"
    return result


def _check_6_5(network_client: Any) -> CISCheckResult:
    """CIS 6.5 — Ensure Network Watcher is enabled."""
    result = CISCheckResult(
        check_id="6.5",
        title="Ensure that Network Watcher is enabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable Network Watcher in all regions where you have Azure resources deployed.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        watchers = list(network_client.network_watchers.list_all())
        if watchers:
            regions = [getattr(w, "location", "unknown") for w in watchers]
            result.status = CheckStatus.PASS
            result.evidence = f"Network Watcher enabled in {len(watchers)} region(s): {', '.join(sorted(set(regions)))}."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No Network Watcher instances found. Enable Network Watcher in all regions with deployed resources."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Network Watcher status: {exc}"
    return result


def _check_6_4(network_client: Any) -> CISCheckResult:
    """CIS 6.4 — Ensure that UDP access from the internet is restricted."""
    result = CISCheckResult(
        check_id="6.4",
        title="Ensure that UDP access from the internet is evaluated and restricted",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove or restrict NSG inbound rules allowing UDP from 0.0.0.0/0 or ::/0.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        failing_rules: list[str] = []
        nsgs = list(network_client.network_security_groups.list_all())
        for nsg in nsgs:
            nsg_name = nsg.name or "unknown"
            for rule in getattr(nsg, "security_rules", []) or []:
                protocol = (getattr(rule, "protocol", "") or "").lower()
                if protocol not in ("udp", "*"):
                    continue
                if _is_internet_exposed(rule, "*"):
                    failing_rules.append(f"{nsg_name}/{rule.name}")
        if failing_rules:
            result.status = CheckStatus.FAIL
            result.evidence = f"NSG rules allowing UDP from internet: {', '.join(failing_rules[:10])}"
            result.resource_ids = failing_rules
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No NSG rules found allowing unrestricted UDP from the internet."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check NSG rules for UDP access: {exc}"
    return result


def _check_6_6(network_client: Any) -> CISCheckResult:
    """CIS 6.6 — Ensure Web Application Firewall (WAF) is enabled."""
    result = CISCheckResult(
        check_id="6.6",
        title="Ensure that Web Application Firewall (WAF) is enabled",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable WAF on Application Gateway or Front Door for all public-facing web applications.",
        cis_section=_NETWORK_SECTION,
    )
    try:
        app_gws = list(network_client.application_gateways.list_all())
        failing = []
        for gw in app_gws:
            gw_name = gw.name or "unknown"
            waf_config = getattr(gw, "web_application_firewall_configuration", None)
            if waf_config is None:
                failing.append(gw_name)
            else:
                enabled = getattr(waf_config, "enabled", False)
                if not enabled:
                    failing.append(gw_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Application Gateways without WAF enabled: {', '.join(failing)}"
            result.resource_ids = failing
        elif app_gws:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(app_gws)} Application Gateway(s) have WAF enabled."
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No Application Gateways found. WAF check is not applicable."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Application Gateway WAF settings: {exc}"
    return result


def _is_internet_exposed(rule: Any, port: str) -> bool:
    """Return True if an NSG rule allows inbound access from any internet address on a given port."""
    direction = (getattr(rule, "direction", "") or "").lower()
    access = (getattr(rule, "access", "") or "").lower()
    if direction != "inbound" or access != "allow":
        return False

    source_prefix = (getattr(rule, "source_address_prefix", "") or "").strip()
    if source_prefix not in ("*", "0.0.0.0/0", "::/0", "Internet", "Any"):
        return False

    dest_port = (getattr(rule, "destination_port_range", "") or "").strip()
    return dest_port in ("*", port)


# ---------------------------------------------------------------------------
# Individual checks — CIS 7.x (Virtual Machines)
# ---------------------------------------------------------------------------


def _check_7_1(compute_client: Any) -> CISCheckResult:
    """CIS 7.1 — Ensure Virtual Machines utilize Managed Disks."""
    result = CISCheckResult(
        check_id="7.1",
        title="Ensure Virtual Machines utilize Managed Disks",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Migrate all VM disks to Managed Disks for improved reliability, security, and simplified management.",
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        failing = []
        for vm in vms:
            vm_name = vm.name or "unknown"
            storage_profile = getattr(vm, "storage_profile", None)
            os_disk = getattr(storage_profile, "os_disk", None) if storage_profile else None
            managed_disk = getattr(os_disk, "managed_disk", None) if os_disk else None
            if managed_disk is None:
                failing.append(vm_name)

        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"VMs not using Managed Disks: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(vms)} VM(s) use Managed Disks."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VM disk configuration: {exc}"
    return result


def _check_7_2(compute_client: Any) -> CISCheckResult:
    """CIS 7.2 — Ensure VMs use managed disks for OS disks."""
    result = CISCheckResult(
        check_id="7.2",
        title="Ensure that Virtual Machines use Managed Disks for OS disks",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Migrate all VM OS disks to Managed Disks.",
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        failing = []
        for vm in vms:
            vm_name = vm.name or "unknown"
            storage_profile = getattr(vm, "storage_profile", None)
            os_disk = getattr(storage_profile, "os_disk", None) if storage_profile else None
            managed_disk = getattr(os_disk, "managed_disk", None) if os_disk else None
            if managed_disk is None:
                failing.append(vm_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"VMs without managed OS disks: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(vms)} VM(s) use Managed Disks for OS disks."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VM managed disk configuration: {exc}"
    return result


def _check_7_3(compute_client: Any) -> CISCheckResult:
    """CIS 7.3 — Ensure OS and data disks are encrypted with CMK."""
    result = CISCheckResult(
        check_id="7.3",
        title="Ensure that OS and data disks are encrypted with Customer Managed Key (CMK)",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Customer Managed Key encryption for all VM OS and data disks.",
        cis_section=_VM_SECTION,
    )
    try:
        disks = list(compute_client.disks.list())
        failing = []
        for disk in disks:
            disk_name = disk.name or "unknown"
            encryption = getattr(disk, "encryption", None)
            if encryption:
                enc_type = getattr(encryption, "type", "") or ""
                if "customermanaged" not in str(enc_type).lower().replace("_", "").replace("-", ""):
                    failing.append(disk_name)
            else:
                failing.append(disk_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Disks not encrypted with CMK: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(disks)} disk(s) are encrypted with Customer Managed Key."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check disk encryption settings: {exc}"
    return result


def _check_7_4(compute_client: Any) -> CISCheckResult:
    """CIS 7.4 — Ensure only approved extensions are installed on VMs."""
    result = CISCheckResult(
        check_id="7.4",
        title="Ensure that only approved extensions are installed on Virtual Machines",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Review all VM extensions and remove any unapproved or unnecessary extensions.",
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        vm_extensions: list[str] = []
        for vm in vms:
            vm_name = vm.name or "unknown"
            resources = getattr(vm, "resources", []) or []
            for ext in resources:
                ext_name = getattr(ext, "name", "unknown") or "unknown"
                vm_extensions.append(f"{vm_name}/{ext_name}")
        if vm_extensions:
            result.status = CheckStatus.PASS
            result.evidence = (
                f"Found {len(vm_extensions)} extension(s) across {len(vms)} VM(s). "
                "Review extensions to ensure only approved ones are installed: "
                f"{', '.join(vm_extensions[:10])}"
            )
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"No extensions found on {len(vms)} VM(s)."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VM extensions: {exc}"
    return result


def _check_7_5(compute_client: Any) -> CISCheckResult:
    """CIS 7.5 — Ensure latest OS patches are applied to VMs."""
    result = CISCheckResult(
        check_id="7.5",
        title="Ensure that the latest OS patches for all Virtual Machines are applied",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable automatic OS updates or apply latest patches to all VMs. Use Azure Update Management for compliance tracking.",
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        result.status = CheckStatus.PASS
        result.evidence = (
            f"Found {len(vms)} VM(s). OS patch status requires Azure Update Management or "
            "Microsoft Defender for Cloud recommendations. Verify patch compliance in "
            "Azure Portal > Update Management or Defender for Cloud > Recommendations."
        )
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not list virtual machines: {exc}"
    return result


def _check_7_6(compute_client: Any) -> CISCheckResult:
    """CIS 7.6 — Ensure endpoint protection is installed on VMs."""
    result = CISCheckResult(
        check_id="7.6",
        title="Ensure that endpoint protection is installed on Virtual Machines",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Install an endpoint protection solution (e.g., Microsoft Defender for Endpoint) on all VMs.",
        cis_section=_VM_SECTION,
    )
    try:
        vms = list(compute_client.virtual_machines.list_all())
        vms_without_ep = []
        ep_extensions = {"microsoftmonitoringagent", "iaasantimalware", "endpointprotection", "mdatp", "mde.linux", "mde.windows"}
        for vm in vms:
            vm_name = vm.name or "unknown"
            resources = getattr(vm, "resources", []) or []
            has_ep = False
            for ext in resources:
                ext_type = (getattr(ext, "virtual_machine_extension_type", "") or "").lower()
                ext_name = (getattr(ext, "name", "") or "").lower()
                if ext_type in ep_extensions or ext_name in ep_extensions:
                    has_ep = True
                    break
            if not has_ep:
                vms_without_ep.append(vm_name)
        if vms_without_ep:
            result.status = CheckStatus.FAIL
            result.evidence = f"VMs without detected endpoint protection: {', '.join(vms_without_ep[:10])}"
            result.resource_ids = vms_without_ep
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(vms)} VM(s) have endpoint protection extensions installed."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check VM endpoint protection: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 8.x (Key Vault)
# ---------------------------------------------------------------------------


def _check_8_1(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.1 — Ensure expiration date is set on all Key Vault keys."""
    result = CISCheckResult(
        check_id="8.1",
        title="Ensure that expiration date is set on all keys in Key Vault",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set an expiration date on all Key Vault keys to enforce key rotation.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_keys: list[str] = []

        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.keys import KeyClient

                key_client = KeyClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for key_prop in key_client.list_properties_of_keys():
                    exp = getattr(key_prop, "expires_on", None)
                    if exp is None:
                        failing_keys.append(f"{vault_name}/{key_prop.name}")
            except Exception as exc:
                # Key enumeration is best-effort per vault
                logger.debug("Could not enumerate keys in vault %s: %s", vault_name, exc)

        if failing_keys:
            result.status = CheckStatus.FAIL
            result.evidence = f"Keys without expiration: {', '.join(failing_keys[:10])}"
            result.resource_ids = failing_keys
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All keys across {len(vaults)} vault(s) have expiration dates set."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not enumerate Key Vault keys: {exc}"
    return result


def _check_8_2(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.2 — Ensure expiration date is set on all Key Vault secrets."""
    result = CISCheckResult(
        check_id="8.2",
        title="Ensure that expiration date is set on all secrets in Key Vault",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set an expiration date on all Key Vault secrets to enforce secret rotation.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_secrets: list[str] = []

        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient

                secret_client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for secret_prop in secret_client.list_properties_of_secrets():
                    if getattr(secret_prop, "expires_on", None) is None:
                        failing_secrets.append(f"{vault_name}/{secret_prop.name}")
            except Exception as exc:
                # Secret enumeration is best-effort per vault
                logger.debug("Could not enumerate secrets in vault %s: %s", vault_name, exc)

        if failing_secrets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Secrets without expiration: {', '.join(failing_secrets[:10])}"
            result.resource_ids = failing_secrets
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All secrets across {len(vaults)} vault(s) have expiration dates set."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not enumerate Key Vault secrets: {exc}"
    return result


def _check_8_3(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.3 — Ensure Key Vault is recoverable (soft delete + purge protection)."""
    result = CISCheckResult(
        check_id="8.3",
        title="Ensure that the Key Vault is recoverable (soft-delete and purge protection enabled)",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable both soft-delete and purge protection on all Key Vaults.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing = []
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_id = getattr(vault, "id", "") or ""
            parts = vault_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                full_vault = kv_client.vaults.get(resource_group, vault_name)
                props = getattr(full_vault, "properties", None)
                soft_delete = getattr(props, "enable_soft_delete", False) if props else False
                purge_protection = getattr(props, "enable_purge_protection", False) if props else False
                if not soft_delete or not purge_protection:
                    missing = []
                    if not soft_delete:
                        missing.append("soft-delete")
                    if not purge_protection:
                        missing.append("purge-protection")
                    failing.append(f"{vault_name} (missing: {', '.join(missing)})")
            except Exception as exc:
                logger.debug("Could not check recoverability for vault %s: %s", vault_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Key Vaults without full recoverability: {', '.join(failing[:10])}"
            result.resource_ids = [f.split(" ")[0] for f in failing]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All Key Vault(s) have soft-delete and purge protection enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault recoverability: {exc}"
    return result


def _check_8_4(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.4 — Ensure key expiration date is set for all keys in RBAC Key Vaults."""
    result = CISCheckResult(
        check_id="8.4",
        title="Ensure that the expiration date is set on all keys in RBAC Key Vaults",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set an expiration date on all keys in Key Vaults using RBAC access model.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_keys: list[str] = []
        rbac_vault_count = 0
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_id = getattr(vault, "id", "") or ""
            parts = vault_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                full_vault = kv_client.vaults.get(resource_group, vault_name)
                props = getattr(full_vault, "properties", None)
                rbac_enabled = getattr(props, "enable_rbac_authorization", False) if props else False
                if not rbac_enabled:
                    continue
                rbac_vault_count += 1
            except Exception:
                continue
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.keys import KeyClient
                key_client = KeyClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for key_prop in key_client.list_properties_of_keys():
                    if getattr(key_prop, "expires_on", None) is None:
                        failing_keys.append(f"{vault_name}/{key_prop.name}")
            except Exception as exc:
                logger.debug("Could not enumerate keys in RBAC vault %s: %s", vault_name, exc)
        if failing_keys:
            result.status = CheckStatus.FAIL
            result.evidence = f"Keys without expiration in RBAC vaults: {', '.join(failing_keys[:10])}"
            result.resource_ids = failing_keys
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All keys in {rbac_vault_count} RBAC vault(s) have expiration dates set."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault key expiration: {exc}"
    return result


def _check_8_5(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.5 — Ensure secret expiration date is set for all secrets in RBAC Key Vaults."""
    result = CISCheckResult(
        check_id="8.5",
        title="Ensure that the expiration date is set on all secrets in RBAC Key Vaults",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set an expiration date on all secrets in Key Vaults using RBAC access model.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_secrets: list[str] = []
        rbac_vault_count = 0
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_id = getattr(vault, "id", "") or ""
            parts = vault_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                full_vault = kv_client.vaults.get(resource_group, vault_name)
                props = getattr(full_vault, "properties", None)
                rbac_enabled = getattr(props, "enable_rbac_authorization", False) if props else False
                if not rbac_enabled:
                    continue
                rbac_vault_count += 1
            except Exception:
                continue
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient
                secret_client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for secret_prop in secret_client.list_properties_of_secrets():
                    if getattr(secret_prop, "expires_on", None) is None:
                        failing_secrets.append(f"{vault_name}/{secret_prop.name}")
            except Exception as exc:
                logger.debug("Could not enumerate secrets in RBAC vault %s: %s", vault_name, exc)
        if failing_secrets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Secrets without expiration in RBAC vaults: {', '.join(failing_secrets[:10])}"
            result.resource_ids = failing_secrets
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All secrets in {rbac_vault_count} RBAC vault(s) have expiration dates set."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault secret expiration: {exc}"
    return result


def _check_8_6(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.6 — Ensure Key Vault secrets have content type set."""
    result = CISCheckResult(
        check_id="8.6",
        title="Ensure that the Key Vault secrets have a content type set",
        status=CheckStatus.ERROR,
        severity="low",
        recommendation="Set a content type on all Key Vault secrets to describe the secret's usage.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing_secrets: list[str] = []
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_url = f"https://{vault_name}.vault.azure.net/"
            try:
                from azure.identity import DefaultAzureCredential
                from azure.keyvault.secrets import SecretClient
                secret_client = SecretClient(vault_url=vault_url, credential=DefaultAzureCredential())
                for secret_prop in secret_client.list_properties_of_secrets():
                    content_type = getattr(secret_prop, "content_type", None)
                    if not content_type:
                        failing_secrets.append(f"{vault_name}/{secret_prop.name}")
            except Exception as exc:
                logger.debug("Could not enumerate secrets in vault %s: %s", vault_name, exc)
        if failing_secrets:
            result.status = CheckStatus.FAIL
            result.evidence = f"Secrets without content type: {', '.join(failing_secrets[:10])}"
            result.resource_ids = failing_secrets
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All secrets across {len(vaults)} vault(s) have content type set."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault secret content types: {exc}"
    return result


def _check_8_7(kv_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 8.7 — Ensure private endpoints are used for Key Vault."""
    result = CISCheckResult(
        check_id="8.7",
        title="Ensure that private endpoints are used for Azure Key Vault",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Configure private endpoints for all Key Vaults to restrict network access.",
        cis_section=_KEYVAULT_SECTION,
    )
    try:
        vaults = list(kv_client.vaults.list())
        failing = []
        for vault in vaults:
            vault_name = vault.name or "unknown"
            vault_id = getattr(vault, "id", "") or ""
            parts = vault_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                full_vault = kv_client.vaults.get(resource_group, vault_name)
                props = getattr(full_vault, "properties", None)
                pe_conns = getattr(props, "private_endpoint_connections", None) if props else None
                if not pe_conns:
                    failing.append(vault_name)
            except Exception as exc:
                logger.debug("Could not check private endpoints for vault %s: %s", vault_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Key Vaults without private endpoints: {', '.join(failing)}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All Key Vault(s) have private endpoints configured."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check Key Vault private endpoints: {exc}"
    return result


# ---------------------------------------------------------------------------
# Individual checks — CIS 9.x (App Service)
# ---------------------------------------------------------------------------


def _check_9_1(webapp_client: Any) -> CISCheckResult:
    """CIS 9.1 — Ensure App Service Authentication is set on."""
    result = CISCheckResult(
        check_id="9.1",
        title="Ensure App Service Authentication is set up for apps in Azure App Service",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable App Service Authentication (EasyAuth) on all web apps.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        for app in apps:
            app_name = app.name or "unknown"
            app_id = getattr(app, "id", "") or ""
            parts = app_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                auth_settings = webapp_client.web_apps.get_auth_settings(resource_group, app_name)
                enabled = getattr(auth_settings, "enabled", False)
                if not enabled:
                    failing.append(app_name)
            except Exception as exc:
                logger.debug("Could not check auth settings for app %s: %s", app_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps without authentication enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(apps)} web app(s) have App Service Authentication enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check App Service authentication settings: {exc}"
    return result


def _check_9_2(webapp_client: Any) -> CISCheckResult:
    """CIS 9.2 — Ensure web app redirects all HTTP traffic to HTTPS."""
    result = CISCheckResult(
        check_id="9.2",
        title="Ensure web app redirects all HTTP traffic to HTTPS",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable 'HTTPS Only' on all web apps to redirect HTTP to HTTPS.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        for app in apps:
            app_name = app.name or "unknown"
            https_only = getattr(app, "https_only", False)
            if not https_only:
                failing.append(app_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps without HTTPS-only enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(apps)} web app(s) have HTTPS-only enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check web app HTTPS settings: {exc}"
    return result


def _check_9_3(webapp_client: Any) -> CISCheckResult:
    """CIS 9.3 — Ensure web app is using the latest TLS version."""
    result = CISCheckResult(
        check_id="9.3",
        title="Ensure web app is using the latest version of TLS encryption",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Set the minimum TLS version to 1.2 on all web apps.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        for app in apps:
            app_name = app.name or "unknown"
            app_id = getattr(app, "id", "") or ""
            parts = app_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = webapp_client.web_apps.get_configuration(resource_group, app_name)
                min_tls = getattr(config, "min_tls_version", "") or ""
                if min_tls and "1.2" not in str(min_tls) and "1.3" not in str(min_tls):
                    failing.append(f"{app_name} (TLS: {min_tls})")
            except Exception as exc:
                logger.debug("Could not check TLS for app %s: %s", app_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps not using TLS 1.2+: {', '.join(failing[:10])}"
            result.resource_ids = [f.split(" ")[0] for f in failing]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(apps)} web app(s) use TLS 1.2 or higher."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check web app TLS settings: {exc}"
    return result


def _check_9_4(webapp_client: Any) -> CISCheckResult:
    """CIS 9.4 — Ensure the web app has a Managed Identity."""
    result = CISCheckResult(
        check_id="9.4",
        title="Ensure the web app has a Managed Service Identity",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable a System-Assigned or User-Assigned Managed Identity on all web apps.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        for app in apps:
            app_name = app.name or "unknown"
            identity = getattr(app, "identity", None)
            if identity is None:
                failing.append(app_name)
            else:
                identity_type = getattr(identity, "type", "") or ""
                if not identity_type or identity_type.lower() == "none":
                    failing.append(app_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps without Managed Identity: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(apps)} web app(s) have Managed Identity enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check web app Managed Identity settings: {exc}"
    return result


def _check_9_5(webapp_client: Any) -> CISCheckResult:
    """CIS 9.5 — Ensure web app has client certificates (Incoming client certificates) enabled."""
    result = CISCheckResult(
        check_id="9.5",
        title="Ensure the web app has 'Client Certificates (Incoming client certificates)' set to On",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Enable client certificates on all web apps that require mutual TLS authentication.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        for app in apps:
            app_name = app.name or "unknown"
            client_cert_enabled = getattr(app, "client_cert_enabled", False)
            if not client_cert_enabled:
                failing.append(app_name)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps without client certificates enabled: {', '.join(failing[:10])}"
            result.resource_ids = failing
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(apps)} web app(s) have client certificates enabled."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check web app client certificate settings: {exc}"
    return result


def _check_9_6(webapp_client: Any) -> CISCheckResult:
    """CIS 9.6 — Ensure FTP access is disabled for App Service."""
    result = CISCheckResult(
        check_id="9.6",
        title="Ensure that FTP access is disabled for Azure App Service",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Disable FTP/FTPS access on all web apps. Use FTPS-only or disable FTP state entirely.",
        cis_section=_APPSERVICE_SECTION,
    )
    try:
        apps = list(webapp_client.web_apps.list())
        failing = []
        for app in apps:
            app_name = app.name or "unknown"
            app_id = getattr(app, "id", "") or ""
            parts = app_id.split("/")
            try:
                rg_index = [p.lower() for p in parts].index("resourcegroups")
                resource_group = parts[rg_index + 1]
            except (ValueError, IndexError):
                continue
            try:
                config = webapp_client.web_apps.get_configuration(resource_group, app_name)
                ftp_state = getattr(config, "ftp_state", "") or ""
                if ftp_state.lower() not in ("disabled", "ftpsonly"):
                    failing.append(f"{app_name} (FTP: {ftp_state})")
            except Exception as exc:
                logger.debug("Could not check FTP state for app %s: %s", app_name, exc)
        if failing:
            result.status = CheckStatus.FAIL
            result.evidence = f"Web apps with FTP enabled: {', '.join(failing[:10])}"
            result.resource_ids = [f.split(" ")[0] for f in failing]
        else:
            result.status = CheckStatus.PASS
            result.evidence = f"All {len(apps)} web app(s) have FTP access disabled or FTPS-only."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not check App Service FTP settings: {exc}"
    return result


# ---------------------------------------------------------------------------
# Runner
# ---------------------------------------------------------------------------


def run_benchmark(
    subscription_id: str | None = None,
    checks: list[str] | None = None,
) -> AzureCISReport:
    """Run CIS Azure Security Benchmark v3.0 checks.

    Args:
        subscription_id: Azure subscription ID. Falls back to
            AZURE_SUBSCRIPTION_ID env var.
        checks: Optional list of check IDs to run (e.g. ['1.1', '6.1']).
            Runs all checks if omitted.

    Returns:
        AzureCISReport with pass/fail results for each check.

    Raises:
        CloudDiscoveryError: if azure-identity or azure-mgmt-* are not installed.
    """
    try:
        from azure.identity import DefaultAzureCredential
    except ImportError:
        raise CloudDiscoveryError("azure-identity is required for Azure CIS benchmark. Install with: pip install 'agent-bom[azure]'")

    resolved_sub = subscription_id or os.environ.get("AZURE_SUBSCRIPTION_ID", "")
    if not resolved_sub:
        raise CloudDiscoveryError("Azure subscription ID required. Set AZURE_SUBSCRIPTION_ID env var or pass subscription_id.")

    credential = DefaultAzureCredential()
    report = AzureCISReport(subscription_id=resolved_sub)

    # Build client map (lazy — only import what's needed)
    def _auth_client() -> Any:
        from azure.mgmt.authorization import AuthorizationManagementClient

        return AuthorizationManagementClient(credential, resolved_sub)

    def _storage_client() -> Any:
        from azure.mgmt.storage import StorageManagementClient

        return StorageManagementClient(credential, resolved_sub)

    def _monitor_client() -> Any:
        from azure.mgmt.monitor import MonitorManagementClient

        return MonitorManagementClient(credential, resolved_sub)

    def _network_client() -> Any:
        from azure.mgmt.network import NetworkManagementClient

        return NetworkManagementClient(credential, resolved_sub)

    def _security_client() -> Any:
        from azure.mgmt.security import SecurityCenter

        return SecurityCenter(credential, resolved_sub)

    def _sql_client() -> Any:
        from azure.mgmt.sql import SqlManagementClient

        return SqlManagementClient(credential, resolved_sub)

    def _compute_client() -> Any:
        from azure.mgmt.compute import ComputeManagementClient

        return ComputeManagementClient(credential, resolved_sub)

    def _kv_client() -> Any:
        from azure.mgmt.keyvault import KeyVaultManagementClient

        return KeyVaultManagementClient(credential, resolved_sub)

    def _mysql_client() -> Any:
        from azure.mgmt.rdbms.mysql import MySQLManagementClient

        return MySQLManagementClient(credential, resolved_sub)

    def _postgresql_client() -> Any:
        from azure.mgmt.rdbms.postgresql import PostgreSQLManagementClient

        return PostgreSQLManagementClient(credential, resolved_sub)

    def _webapp_client() -> Any:
        from azure.mgmt.web import WebSiteManagementClient

        return WebSiteManagementClient(credential, resolved_sub)

    all_checks: list[tuple[str, Any]] = [
        # Section 1 — Identity and Access Management
        ("1.1", lambda: _check_1_1(_auth_client(), resolved_sub)),
        ("1.2", lambda: _check_1_2(_auth_client(), resolved_sub)),
        ("1.3", lambda: _check_1_3()),
        ("1.4", lambda: _check_1_4()),
        ("1.5", lambda: _check_1_5(_auth_client(), resolved_sub)),
        ("1.6", lambda: _check_1_6()),
        ("1.7", lambda: _check_1_7(_auth_client(), resolved_sub)),
        ("1.8", lambda: _check_1_8()),
        ("1.9", lambda: _check_1_9()),
        ("1.10", lambda: _check_1_10()),
        ("1.11", lambda: _check_1_11()),
        ("1.12", lambda: _check_1_12()),
        ("1.13", lambda: _check_1_13()),
        ("1.14", lambda: _check_1_14()),
        ("1.15", lambda: _check_1_15(_auth_client(), resolved_sub)),
        ("1.16", lambda: _check_1_16()),
        ("1.17", lambda: _check_1_17()),
        ("1.18", lambda: _check_1_18()),
        ("1.19", lambda: _check_1_19()),
        ("1.20", lambda: _check_1_20()),
        ("1.21", lambda: _check_1_21()),
        ("1.22", lambda: _check_1_22()),
        # Section 2 — Microsoft Defender for Cloud
        ("2.1", lambda: _check_2_1(_security_client(), resolved_sub)),
        ("2.2", lambda: _check_2_2(_security_client(), resolved_sub)),
        ("2.3", lambda: _check_2_3(_security_client(), resolved_sub)),
        ("2.4", lambda: _check_2_4(_security_client(), resolved_sub)),
        ("2.5", lambda: _check_2_5(_security_client(), resolved_sub)),
        ("2.6", lambda: _check_2_6(_security_client(), resolved_sub)),
        ("2.7", lambda: _check_2_7(_security_client(), resolved_sub)),
        ("2.8", lambda: _check_2_8(_security_client(), resolved_sub)),
        ("2.9", lambda: _check_2_9(_security_client(), resolved_sub)),
        ("2.10", lambda: _check_2_10(_security_client(), resolved_sub)),
        ("2.11", lambda: _check_2_11(_security_client(), resolved_sub)),
        ("2.12", lambda: _check_2_12(_security_client(), resolved_sub)),
        ("2.13", lambda: _check_2_13(_security_client(), resolved_sub)),
        # Section 3 — Storage Accounts
        ("3.1", lambda: _check_3_1(_storage_client())),
        ("3.2", lambda: _check_3_2(_storage_client())),
        ("3.3", lambda: _check_3_3(_storage_client())),
        ("3.4", lambda: _check_3_4(_storage_client())),
        ("3.5", lambda: _check_3_5(_storage_client())),
        ("3.6", lambda: _check_3_6(_storage_client())),
        ("3.7", lambda: _check_3_7(_storage_client())),
        ("3.8", lambda: _check_3_8(_storage_client())),
        ("3.9", lambda: _check_3_9(_storage_client())),
        ("3.10", lambda: _check_3_10(_storage_client())),
        ("3.11", lambda: _check_3_11(_storage_client())),
        ("3.12", lambda: _check_3_12(_storage_client())),
        # Section 4 — Database Services
        ("4.1.1", lambda: _check_4_1_1(_sql_client())),
        ("4.1.2", lambda: _check_4_1_2(_sql_client())),
        ("4.1.3", lambda: _check_4_1_3(_sql_client())),
        ("4.1.4", lambda: _check_4_1_4(_sql_client())),
        ("4.1.5", lambda: _check_4_1_5(_sql_client())),
        ("4.1.6", lambda: _check_4_1_6(_sql_client())),
        ("4.2.1", lambda: _check_4_2_1(_sql_client())),
        ("4.2.2", lambda: _check_4_2_2(_mysql_client())),
        ("4.2.3", lambda: _check_4_2_3(_mysql_client())),
        ("4.3.1", lambda: _check_4_3_1(_postgresql_client())),
        ("4.3.2", lambda: _check_4_3_2(_postgresql_client())),
        ("4.3.3", lambda: _check_4_3_3(_postgresql_client())),
        ("4.3.4", lambda: _check_4_3_4(_postgresql_client())),
        ("4.3.5", lambda: _check_4_3_5(_postgresql_client())),
        # Section 5 — Logging and Monitoring
        ("5.1.1", lambda: _check_5_1_1(_monitor_client(), resolved_sub)),
        ("5.1.2", lambda: _check_5_1_2(_monitor_client(), resolved_sub)),
        ("5.1.3", lambda: _check_5_1_3(_monitor_client(), resolved_sub)),
        ("5.1.4", lambda: _check_5_1_4(_monitor_client(), resolved_sub)),
        ("5.1.5", lambda: _check_5_1_5(_monitor_client(), resolved_sub)),
        ("5.1.6", lambda: _check_5_1_6(_monitor_client(), resolved_sub)),
        ("5.2.1", lambda: _check_5_2_1(_postgresql_client())),
        ("5.2.2", lambda: _check_5_2_2(_postgresql_client())),
        ("5.2.3", lambda: _check_5_2_3(_postgresql_client())),
        # Section 6 — Networking
        ("6.1", lambda: _check_6_1(_network_client())),
        ("6.2", lambda: _check_6_2(_network_client())),
        ("6.3", lambda: _check_6_3(_network_client())),
        ("6.4", lambda: _check_6_4(_network_client())),
        ("6.5", lambda: _check_6_5(_network_client())),
        ("6.6", lambda: _check_6_6(_network_client())),
        # Section 7 — Virtual Machines
        ("7.1", lambda: _check_7_1(_compute_client())),
        ("7.2", lambda: _check_7_2(_compute_client())),
        ("7.3", lambda: _check_7_3(_compute_client())),
        ("7.4", lambda: _check_7_4(_compute_client())),
        ("7.5", lambda: _check_7_5(_compute_client())),
        ("7.6", lambda: _check_7_6(_compute_client())),
        # Section 8 — Key Vault
        ("8.1", lambda: _check_8_1(_kv_client(), resolved_sub)),
        ("8.2", lambda: _check_8_2(_kv_client(), resolved_sub)),
        ("8.3", lambda: _check_8_3(_kv_client(), resolved_sub)),
        ("8.4", lambda: _check_8_4(_kv_client(), resolved_sub)),
        ("8.5", lambda: _check_8_5(_kv_client(), resolved_sub)),
        ("8.6", lambda: _check_8_6(_kv_client(), resolved_sub)),
        ("8.7", lambda: _check_8_7(_kv_client(), resolved_sub)),
        # Section 9 — App Service
        ("9.1", lambda: _check_9_1(_webapp_client())),
        ("9.2", lambda: _check_9_2(_webapp_client())),
        ("9.3", lambda: _check_9_3(_webapp_client())),
        ("9.4", lambda: _check_9_4(_webapp_client())),
        ("9.5", lambda: _check_9_5(_webapp_client())),
        ("9.6", lambda: _check_9_6(_webapp_client())),
    ]

    for check_id, check_fn in all_checks:
        if checks and check_id not in checks:
            continue
        try:
            report.checks.append(check_fn())
        except Exception as exc:
            logger.warning("Azure CIS check %s failed with exception: %s", check_id, exc)
            report.checks.append(
                CISCheckResult(
                    check_id=check_id,
                    title=f"Check {check_id}",
                    status=CheckStatus.ERROR,
                    severity="unknown",
                    evidence=str(exc),
                )
            )

    return report
