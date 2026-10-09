"""CIS Azure section 1 (identity and access) — Entra directory and Conditional Access controls 1.11-1.22."""

from __future__ import annotations

from typing import Any

from ..aws_cis_benchmark import CheckStatus, CISCheckResult
from ..azure_graph import (
    AUTHORIZATION_POLICY_PATH,
    CONDITIONAL_ACCESS_POLICIES_PATH,
    RESTRICTED_GUEST_ROLE_TEMPLATE_ID,
    SECURITY_DEFAULTS_PATH,
    GraphError,
)
from ._base import (
    _IAM_SECTION,
    _ca_client_app_types,
    _ca_enabled,
    _ca_grant_controls,
    _ca_included_roles,
    _ca_sign_in_risk_levels,
    _mark_unevaluable,
    _resolve_without_conditional_access,
)


def _check_1_11(graph: Any) -> CISCheckResult:
    """CIS Azure 1.11 — Microsoft Entra security defaults enabled (Microsoft Graph)."""
    result = CISCheckResult(
        check_id="1.11",
        title="Security Defaults enabled on Azure AD",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Enable Microsoft Entra security defaults, or enforce the equivalent controls through Conditional Access.",
        cis_section=_IAM_SECTION,
    )
    try:
        policy = graph.get(SECURITY_DEFAULTS_PATH)
        if bool(policy.get("isEnabled")):
            result.status = CheckStatus.PASS
            result.evidence = "Microsoft Entra security defaults are enabled for the tenant."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = (
                "Microsoft Entra security defaults are disabled. If baseline MFA/legacy-auth protection is instead enforced "
                "via Conditional Access, confirm those policies satisfy this control."
            )
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_12(graph: Any) -> CISCheckResult:
    """CIS Azure 1.12 — user consent to applications is disabled (Microsoft Graph authorization policy)."""
    result = CISCheckResult(
        check_id="1.12",
        title="User consent for applications disallowed",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Remove app consent grants from the default user role so only admins can consent to application permissions.",
        cis_section=_IAM_SECTION,
    )
    try:
        policy = graph.get(AUTHORIZATION_POLICY_PATH)
        perms = policy.get("defaultUserRolePermissions") or {}
        granted = perms.get("permissionGrantPoliciesAssigned") if isinstance(perms, dict) else None
        assigned = [str(g) for g in granted] if isinstance(granted, list) else []
        if not assigned:
            result.status = CheckStatus.PASS
            result.evidence = (
                "User consent to applications is disabled (no app-consent grant policies are assigned to the default user role)."
            )
        else:
            result.status = CheckStatus.FAIL
            result.evidence = (
                f"User consent to applications is permitted — {len(assigned)} app-consent "
                f"grant policy(ies) assigned: {', '.join(assigned[:5])}."
            )
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_13(graph: Any) -> CISCheckResult:
    """CIS Azure 1.13 — non-admin users cannot register applications (Microsoft Graph authorization policy)."""
    result = CISCheckResult(
        check_id="1.13",
        title="User app registration disabled",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Set the default user role so it cannot create (register) applications; delegate app registration to specific roles."
        ),
        cis_section=_IAM_SECTION,
    )
    try:
        policy = graph.get(AUTHORIZATION_POLICY_PATH)
        perms = policy.get("defaultUserRolePermissions") or {}
        allowed = bool(perms.get("allowedToCreateApps")) if isinstance(perms, dict) else True
        if not allowed:
            result.status = CheckStatus.PASS
            result.evidence = "The default user role cannot register applications (allowedToCreateApps is false)."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = (
                "The default user role can register applications (allowedToCreateApps is true) — any user can create app registrations."
            )
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_14(graph: Any) -> CISCheckResult:
    """CIS Azure 1.14 — guest access is set to the most restrictive role (Microsoft Graph authorization policy)."""
    result = CISCheckResult(
        check_id="1.14",
        title="Guest user access restricted",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Set the guest user role to 'Restricted Guest User' so guests can only read their own directory objects.",
        cis_section=_IAM_SECTION,
    )
    try:
        policy = graph.get(AUTHORIZATION_POLICY_PATH)
        guest_role = str(policy.get("guestUserRoleId") or "").strip().lower()
        if guest_role == RESTRICTED_GUEST_ROLE_TEMPLATE_ID.lower():
            result.status = CheckStatus.PASS
            result.evidence = "Guest access is set to the most restrictive role (Restricted Guest User)."
        elif guest_role:
            result.status = CheckStatus.FAIL
            result.evidence = f"Guest access is not restricted to the most limited role (guestUserRoleId={guest_role})."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "The tenant authorization policy does not restrict guest access to the Restricted Guest User role."
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_15(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.15 — Ensure custom subscription Administrator roles are not created."""
    result = CISCheckResult(
        check_id="1.15",
        title="Custom subscription Administrator roles absent",
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
        title="Privileged roles reviewed regularly",
        status=CheckStatus.NOT_APPLICABLE,
        severity="high",
        recommendation="Use Azure AD Privileged Identity Management (PIM) to configure regular access reviews for privileged roles.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = (
        "Manual — Privileged Identity Management access-review configuration for privileged roles is not reliably "
        "derivable from a stable Microsoft Graph v1.0 read. Verify in the Microsoft Entra admin center under PIM > Access reviews."
    )
    return result


def _check_1_17() -> CISCheckResult:
    """CIS 1.17 — Ensure that 'Restrict access to Azure AD admin center' is enabled."""
    result = CISCheckResult(
        check_id="1.17",
        title="Access to Azure AD admin portal restricted",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Set 'Restrict access to Azure AD administration portal' to Yes in Azure AD > User settings.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = (
        "Manual — the 'restrict access to the Microsoft Entra administration portal' user setting is not exposed by a "
        "stable Microsoft Graph v1.0 read API. Verify in the Microsoft Entra admin center under User settings."
    )
    return result


def _check_1_18(graph: Any) -> CISCheckResult:
    """CIS Azure 1.18 — legacy authentication blocked via Conditional Access (Microsoft Graph)."""
    result = CISCheckResult(
        check_id="1.18",
        title="Legacy authentication blocked via Conditional Access",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Create an enabled Conditional Access policy that targets legacy client app types and blocks access.",
        cis_section=_IAM_SECTION,
    )
    _legacy_clients = {"exchangeactivesync", "other"}
    try:
        policies = graph.list(CONDITIONAL_ACCESS_POLICIES_PATH)
        matching = [
            p for p in policies if _ca_enabled(p) and (_legacy_clients & set(_ca_client_app_types(p))) and "block" in _ca_grant_controls(p)
        ]
        if matching:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(matching)} enabled Conditional Access policy(ies) block legacy authentication clients."
            result.resource_ids = [str(p.get("displayName") or p.get("id")) for p in matching[:10]]
        else:
            _resolve_without_conditional_access(
                result, graph, policies, control="blocks legacy authentication clients (exchangeActiveSync / other)"
            )
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_19() -> CISCheckResult:
    """CIS 1.19 — Ensure password hash sync is enabled for resiliency."""
    result = CISCheckResult(
        check_id="1.19",
        title="Password hash sync enabled",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Enable password hash synchronization in Azure AD Connect to support leaked credential detection.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = (
        "Manual — password hash synchronization status is only exposed by the beta Microsoft Graph "
        "onPremisesSynchronization resource, not a stable v1.0 read. Verify in Azure AD Connect / Entra Connect Sync."
    )
    return result


def _check_1_20() -> CISCheckResult:
    """CIS 1.20 — Ensure self-service password reset is enabled."""
    result = CISCheckResult(
        check_id="1.20",
        title="Self-service password reset enabled",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Enable self-service password reset for all users in Azure AD > Password reset.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = (
        "Manual — the tenant self-service password reset enablement setting is not exposed by a stable Microsoft Graph "
        "v1.0 read API. Verify in the Microsoft Entra admin center under Password reset."
    )
    return result


def _check_1_21(graph: Any) -> CISCheckResult:
    """CIS Azure 1.21 — MFA required for risky sign-ins via Conditional Access (Microsoft Graph)."""
    result = CISCheckResult(
        check_id="1.21",
        title="MFA required for risky sign-ins",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation="Create an enabled Conditional Access policy that requires MFA when the sign-in risk level is medium or high.",
        cis_section=_IAM_SECTION,
    )
    try:
        policies = graph.list(CONDITIONAL_ACCESS_POLICIES_PATH)
        matching = [p for p in policies if _ca_enabled(p) and _ca_sign_in_risk_levels(p) and "mfa" in _ca_grant_controls(p)]
        if matching:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(matching)} enabled Conditional Access policy(ies) require MFA for risky sign-ins."
            result.resource_ids = [str(p.get("displayName") or p.get("id")) for p in matching[:10]]
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No enabled Conditional Access policy requires MFA based on sign-in risk level."
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_22(graph: Any) -> CISCheckResult:
    """CIS Azure 1.22 — MFA enforced for administrative role holders via Conditional Access (Microsoft Graph)."""
    result = CISCheckResult(
        check_id="1.22",
        title="MFA enabled for all admin-role users",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Enforce MFA for administrative directory roles with an enabled Conditional Access policy that targets those roles.",
        cis_section=_IAM_SECTION,
    )
    try:
        policies = graph.list(CONDITIONAL_ACCESS_POLICIES_PATH)
        matching = [p for p in policies if _ca_enabled(p) and _ca_included_roles(p) and "mfa" in _ca_grant_controls(p)]
        if matching:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(matching)} enabled Conditional Access policy(ies) enforce MFA for administrative role holders."
            result.resource_ids = [str(p.get("displayName") or p.get("id")) for p in matching[:10]]
        else:
            _resolve_without_conditional_access(
                result, graph, policies, control="enforces MFA for users holding administrative directory roles"
            )
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result
