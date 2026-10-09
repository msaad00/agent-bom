"""CIS Azure section 1 (identity and access) — role assignment and core Entra controls 1.1-1.10."""

from __future__ import annotations

from typing import Any

from agent_bom.security import sanitize_error

from ..aws_cis_benchmark import CheckStatus, CISCheckResult
from ..azure_graph import (
    ACCESS_REVIEW_DEFINITIONS_PATH,
    AZURE_MANAGEMENT_APP_ID,
    CONDITIONAL_ACCESS_POLICIES_PATH,
    GraphError,
)
from ._base import (
    _IAM_SECTION,
    _ca_enabled,
    _ca_grant_controls,
    _ca_included_apps,
    _ca_included_roles,
    _ca_included_users,
    _mark_unevaluable,
    _resolve_without_conditional_access,
)


def _check_1_1(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.1 — Ensure no subscription Owner assignments to guest/external users."""
    result = CISCheckResult(
        check_id="1.1",
        title="No subscription Owner role for guest/external users",
        status=CheckStatus.ERROR,
        severity="high",
        recommendation=(
            "Remove Owner role from any guest/external (#EXT#) accounts. Use Privileged Identity Management for just-in-time access."
        ),
        cis_section=_IAM_SECTION,
    )
    try:
        scope = f"/subscriptions/{subscription_id}"
        assignments = list(auth_client.role_assignments.list_for_scope(scope))

        # Owner role definition ID is fixed across all Azure tenants
        owner_role = "8e3af657-a8ff-443c-a75c-2fe8c4bcb635"

        owner_assignments = []
        for ra in assignments:
            role_def_id = (getattr(ra, "role_definition_id", "") or "").split("/")[-1]
            if role_def_id == owner_role:
                principal_id = getattr(ra, "principal_id", "") or ""
                # We can't easily get UPN without Graph API, so flag principals
                # and let the evidence guide investigation
                owner_assignments.append(principal_id)

        if owner_assignments:
            result.status = CheckStatus.ERROR
            result.evidence = (
                f"Cannot evaluate guest/external identity for {len(owner_assignments)} Owner assignment(s): "
                "Microsoft Graph identity evidence is unavailable. Verify the principals in Azure Portal "
                "before treating this control as passed."
            )
            result.resource_ids = [principal_id for principal_id in owner_assignments if principal_id]
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No Owner role assignments found on subscription."

    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not read Owner role assignments: {sanitize_error(exc, generic=True)}"
    return result


def _check_1_2(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.2 — Ensure no subscription-level Contributor assignments to guest users."""
    result = CISCheckResult(
        check_id="1.2",
        title="No subscription Contributor role for guest users",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Review all Contributor role assignments and remove guest/external users. Use resource group scope instead.",
        cis_section=_IAM_SECTION,
    )
    try:
        scope = f"/subscriptions/{subscription_id}"
        assignments = list(auth_client.role_assignments.list_for_scope(scope))

        contributor_role = "b24988ac-6180-42a0-ab88-20f7382dd24c"

        contributor_assignments = [
            getattr(ra, "principal_id", "") or ""
            for ra in assignments
            if (getattr(ra, "role_definition_id", "") or "").split("/")[-1] == contributor_role
        ]
        if contributor_assignments:
            result.status = CheckStatus.ERROR
            result.evidence = (
                f"Cannot evaluate guest/external identity for {len(contributor_assignments)} Contributor assignment(s): "
                "Microsoft Graph identity evidence is unavailable. Verify the principals in Azure Portal "
                "before treating this control as passed."
            )
            result.resource_ids = [principal_id for principal_id in contributor_assignments if principal_id]
        else:
            result.status = CheckStatus.PASS
            result.evidence = "No subscription-level Contributor role assignments found."
    except Exception as exc:
        result.status = CheckStatus.ERROR
        result.evidence = f"Could not read Contributor role assignments: {sanitize_error(exc, generic=True)}"
    return result


def _guest_scoped_access_reviews(graph: Any) -> tuple[int, list[str]]:
    """Return (total definitions, names of definitions scoped to guest users).

    Reads ``/identityGovernance/accessReviews/definitions`` and flags any
    definition whose scope references guest accounts (``userType eq 'Guest'``).
    """
    import json as _json

    definitions = graph.list(ACCESS_REVIEW_DEFINITIONS_PATH)
    guest_reviews: list[str] = []
    for definition in definitions:
        scope_blob = _json.dumps(definition.get("scope") or definition).lower()
        if "guest" in scope_blob:
            guest_reviews.append(str(definition.get("displayName") or definition.get("id") or "access-review"))
    return len(definitions), guest_reviews


def _check_1_3(graph: Any) -> CISCheckResult:
    """CIS Azure 1.3 — recurring review of guest accounts (Microsoft Graph access reviews)."""
    result = CISCheckResult(
        check_id="1.3",
        title="Guest users reviewed regularly",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation=(
            "Configure a recurring Microsoft Entra access review scoped to guest users and remove access that is no longer needed."
        ),
        cis_section=_IAM_SECTION,
    )
    try:
        total, guest_reviews = _guest_scoped_access_reviews(graph)
        if guest_reviews:
            result.status = CheckStatus.PASS
            result.evidence = (
                f"{len(guest_reviews)} access review(s) scoped to guest accounts are configured: {', '.join(guest_reviews[:5])}."
            )
            result.resource_ids = guest_reviews[:10]
        elif total:
            result.status = CheckStatus.FAIL
            result.evidence = f"{total} access review definition(s) exist but none is scoped to guest accounts."
        else:
            result.status = CheckStatus.FAIL
            result.evidence = "No Microsoft Entra access review definitions are configured — guest access is not being reviewed."
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_4(graph: Any) -> CISCheckResult:
    """CIS Azure 1.4 — an access review is configured for guest users (Microsoft Graph)."""
    result = CISCheckResult(
        check_id="1.4",
        title="Access Review configured for guest users",
        status=CheckStatus.ERROR,
        severity="medium",
        recommendation="Create a Microsoft Entra access review that recertifies guest user access on a recurring schedule.",
        cis_section=_IAM_SECTION,
    )
    try:
        total, guest_reviews = _guest_scoped_access_reviews(graph)
        if guest_reviews:
            result.status = CheckStatus.PASS
            result.evidence = f"A guest-scoped access review is configured ({len(guest_reviews)} definition(s))."
            result.resource_ids = guest_reviews[:10]
        else:
            result.status = CheckStatus.FAIL
            result.evidence = (
                f"No access review is scoped to guest users ({total} definition(s) found overall)."
                if total
                else "No access review definitions are configured for guest users."
            )
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_5(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.5 — Ensure no custom subscription Administrator roles exist."""
    result = CISCheckResult(
        check_id="1.5",
        title="No custom subscription Administrator roles",
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


def _check_1_6(graph: Any) -> CISCheckResult:
    """CIS Azure 1.6 — MFA enforced for all users via Conditional Access (Microsoft Graph)."""
    result = CISCheckResult(
        check_id="1.6",
        title="MFA enabled for all users",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Enable an enabled Conditional Access policy that requires MFA for all users (or enable Security Defaults).",
        cis_section=_IAM_SECTION,
    )
    try:
        policies = graph.list(CONDITIONAL_ACCESS_POLICIES_PATH)
        matching = [p for p in policies if _ca_enabled(p) and "all" in _ca_included_users(p) and "mfa" in _ca_grant_controls(p)]
        if matching:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(matching)} enabled Conditional Access policy(ies) require MFA for all users."
            result.resource_ids = [str(p.get("displayName") or p.get("id")) for p in matching[:10]]
        else:
            _resolve_without_conditional_access(result, graph, policies, control="requires MFA for all users")
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_7(auth_client: Any, subscription_id: str) -> CISCheckResult:
    """CIS 1.7 — Ensure no subscription-level Custom Roles with Owner permissions."""
    result = CISCheckResult(
        check_id="1.7",
        title="No custom subscription-level Owner roles",
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


def _check_1_8(graph: Any) -> CISCheckResult:
    """CIS Azure 1.8 — MFA required for the Azure management app via Conditional Access (Microsoft Graph)."""
    result = CISCheckResult(
        check_id="1.8",
        title="MFA enabled for Azure Portal access",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation=(
            "Create an enabled Conditional Access policy that requires MFA for the Microsoft Azure Management cloud app (or all apps)."
        ),
        cis_section=_IAM_SECTION,
    )
    try:
        policies = graph.list(CONDITIONAL_ACCESS_POLICIES_PATH)
        matching = [
            p
            for p in policies
            if _ca_enabled(p) and "mfa" in _ca_grant_controls(p) and ({AZURE_MANAGEMENT_APP_ID, "all"} & set(_ca_included_apps(p)))
        ]
        if matching:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(matching)} enabled Conditional Access policy(ies) require MFA for the Azure management app."
            result.resource_ids = [str(p.get("displayName") or p.get("id")) for p in matching[:10]]
        else:
            _resolve_without_conditional_access(
                result, graph, policies, control="requires MFA for the Microsoft Azure Management cloud app"
            )
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_9(graph: Any) -> CISCheckResult:
    """CIS Azure 1.9 — Conditional Access requires MFA for administrative roles (Microsoft Graph)."""
    result = CISCheckResult(
        check_id="1.9",
        title="Conditional Access requires MFA for admin roles",
        status=CheckStatus.ERROR,
        severity="critical",
        recommendation="Create an enabled Conditional Access policy that targets directory roles and requires MFA.",
        cis_section=_IAM_SECTION,
    )
    try:
        policies = graph.list(CONDITIONAL_ACCESS_POLICIES_PATH)
        matching = [p for p in policies if _ca_enabled(p) and _ca_included_roles(p) and "mfa" in _ca_grant_controls(p)]
        if matching:
            result.status = CheckStatus.PASS
            result.evidence = f"{len(matching)} enabled Conditional Access policy(ies) require MFA for administrative directory roles."
            result.resource_ids = [str(p.get("displayName") or p.get("id")) for p in matching[:10]]
        else:
            _resolve_without_conditional_access(result, graph, policies, control="requires MFA for administrative directory roles")
    except GraphError as exc:
        return _mark_unevaluable(result, exc)
    return result


def _check_1_10() -> CISCheckResult:
    """CIS 1.10 — Ensure 'Allow users to remember MFA on trusted devices' is disabled."""
    result = CISCheckResult(
        check_id="1.10",
        title="Remember-MFA on trusted devices disabled",
        status=CheckStatus.NOT_APPLICABLE,
        severity="medium",
        recommendation="Disable 'Remember MFA on trusted devices' to ensure MFA is prompted on every sign-in.",
        cis_section=_IAM_SECTION,
    )
    result.evidence = (
        "Manual — the legacy per-tenant 'remember MFA on trusted devices' setting is not exposed by a stable Microsoft "
        "Graph v1.0 read API. Verify in the Microsoft Entra admin center under Security > MFA > Additional cloud-based MFA settings."
    )
    return result
