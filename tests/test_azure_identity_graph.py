"""Fixture-driven tests for the Microsoft Graph-based Azure identity controls.

Each newly-automated CIS Azure 1.x identity control (issue #4120) is exercised
against recorded Microsoft Graph v1.0 JSON:

* a *good* fixture -> PASS,
* a *bad* fixture -> FAIL,
* denied / unreadable Graph evidence -> ERROR (``unevaluable``), never a false PASS.

No live Azure credentials are used; a fake Graph client returns recorded
responses (or raises the typed Graph errors).
"""

from __future__ import annotations

import pytest

from agent_bom.cloud.aws_cis_benchmark import CheckStatus
from agent_bom.cloud.azure_cis_benchmark import (
    _check_1_3,
    _check_1_4,
    _check_1_6,
    _check_1_8,
    _check_1_9,
    _check_1_11,
    _check_1_12,
    _check_1_13,
    _check_1_14,
    _check_1_18,
    _check_1_21,
    _check_1_22,
    run_benchmark,
)
from agent_bom.cloud.azure_graph import (
    ACCESS_REVIEW_DEFINITIONS_PATH,
    AUTHORIZATION_POLICY_PATH,
    AZURE_MANAGEMENT_APP_ID,
    CONDITIONAL_ACCESS_POLICIES_PATH,
    RESTRICTED_GUEST_ROLE_TEMPLATE_ID,
    SECURITY_DEFAULTS_PATH,
    AzureGraphClient,
    GraphPermissionDenied,
    GraphUnavailable,
)

_MISSING = object()


class FakeGraph:
    """Returns recorded Graph responses; a stored Exception is raised instead."""

    def __init__(self, *, gets: dict | None = None, lists: dict | None = None) -> None:
        self._gets = gets or {}
        self._lists = lists or {}

    def get(self, path: str):
        value = self._gets.get(path, _MISSING)
        if isinstance(value, Exception):
            raise value
        if value is _MISSING:
            raise GraphUnavailable(f"no fixture for GET {path}")
        return value

    def list(self, path: str):
        value = self._lists.get(path, _MISSING)
        if isinstance(value, Exception):
            raise value
        if value is _MISSING:
            raise GraphUnavailable(f"no fixture for LIST {path}")
        return value


def _ca(**policies_key):
    return {CONDITIONAL_ACCESS_POLICIES_PATH: list(policies_key["policies"])}


# ---------------------------------------------------------------------------
# Conditional Access controls: 1.6, 1.8, 1.9, 1.18, 1.21, 1.22
# ---------------------------------------------------------------------------

_MFA_ALL = {
    "displayName": "Require MFA for all users",
    "state": "enabled",
    "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": ["All"]}},
    "grantControls": {"builtInControls": ["mfa"], "operator": "OR"},
}
_MFA_MGMT = {
    "displayName": "Require MFA for Azure management",
    "state": "enabled",
    "conditions": {"users": {"includeUsers": ["All"]}, "applications": {"includeApplications": [AZURE_MANAGEMENT_APP_ID]}},
    "grantControls": {"builtInControls": ["mfa"], "operator": "OR"},
}
_MFA_ADMIN = {
    "displayName": "Require MFA for admin roles",
    "state": "enabled",
    "conditions": {"users": {"includeUsers": ["None"], "includeRoles": ["62e90394-69f5-4237-9190-012177145e10"]}},
    "grantControls": {"builtInControls": ["mfa"], "operator": "OR"},
}
_BLOCK_LEGACY = {
    "displayName": "Block legacy auth",
    "state": "enabled",
    "conditions": {"users": {"includeUsers": ["All"]}, "clientAppTypes": ["exchangeActiveSync", "other"]},
    "grantControls": {"builtInControls": ["block"], "operator": "OR"},
}
_MFA_RISKY = {
    "displayName": "MFA for risky sign-ins",
    "state": "enabled",
    "conditions": {"users": {"includeUsers": ["All"]}, "signInRiskLevels": ["high", "medium"]},
    "grantControls": {"builtInControls": ["mfa"], "operator": "OR"},
}
# A report-only policy carries the right controls but does NOT enforce them.
_MFA_ALL_REPORT_ONLY = {**_MFA_ALL, "state": "enabledForReportingButNotEnforced"}
_UNRELATED = {"displayName": "Grant from trusted locations", "state": "enabled", "conditions": {}, "grantControls": {}}


@pytest.mark.parametrize(
    ("check", "good_policy"),
    [
        (_check_1_6, _MFA_ALL),
        (_check_1_8, _MFA_MGMT),
        (_check_1_9, _MFA_ADMIN),
        (_check_1_18, _BLOCK_LEGACY),
        (_check_1_21, _MFA_RISKY),
        (_check_1_22, _MFA_ADMIN),
    ],
)
def test_ca_control_passes_on_matching_enabled_policy(check, good_policy):
    graph = FakeGraph(lists={CONDITIONAL_ACCESS_POLICIES_PATH: [_UNRELATED, good_policy]})
    result = check(graph)
    assert result.status == CheckStatus.PASS, result.evidence
    assert result.resource_ids


@pytest.mark.parametrize(
    "check",
    [_check_1_6, _check_1_8, _check_1_9, _check_1_18, _check_1_21, _check_1_22],
)
def test_ca_control_fails_when_no_matching_policy(check):
    graph = FakeGraph(lists={CONDITIONAL_ACCESS_POLICIES_PATH: [_UNRELATED]})
    result = check(graph)
    assert result.status == CheckStatus.FAIL, result.evidence


@pytest.mark.parametrize(
    ("check", "report_only_policy"),
    [
        (_check_1_6, _MFA_ALL_REPORT_ONLY),
        (_check_1_9, {**_MFA_ADMIN, "state": "enabledForReportingButNotEnforced"}),
        (_check_1_18, {**_BLOCK_LEGACY, "state": "disabled"}),
    ],
)
def test_ca_control_does_not_pass_on_report_only_or_disabled(check, report_only_policy):
    graph = FakeGraph(lists={CONDITIONAL_ACCESS_POLICIES_PATH: [report_only_policy]})
    result = check(graph)
    assert result.status == CheckStatus.FAIL, result.evidence


@pytest.mark.parametrize(
    "check",
    [_check_1_6, _check_1_8, _check_1_9, _check_1_18, _check_1_21, _check_1_22],
)
def test_ca_control_unevaluable_on_permission_denied(check):
    graph = FakeGraph(lists={CONDITIONAL_ACCESS_POLICIES_PATH: GraphPermissionDenied("denied")})
    result = check(graph)
    assert result.status == CheckStatus.ERROR
    assert "unevaluable" in result.evidence.lower()
    assert result.status != CheckStatus.PASS


# ---------------------------------------------------------------------------
# Authorization policy controls: 1.12, 1.13, 1.14
# ---------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("check", "good_policy", "bad_policy"),
    [
        (
            _check_1_12,
            {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": []}},
            {"defaultUserRolePermissions": {"permissionGrantPoliciesAssigned": ["managePermissionGrantsForSelf.abc"]}},
        ),
        (
            _check_1_13,
            {"defaultUserRolePermissions": {"allowedToCreateApps": False}},
            {"defaultUserRolePermissions": {"allowedToCreateApps": True}},
        ),
        (
            _check_1_14,
            {"guestUserRoleId": RESTRICTED_GUEST_ROLE_TEMPLATE_ID},
            {"guestUserRoleId": "a0b1b346-4d3e-4e8b-98f8-753987be4970"},
        ),
    ],
)
def test_authorization_policy_control(check, good_policy, bad_policy):
    good = FakeGraph(gets={AUTHORIZATION_POLICY_PATH: good_policy})
    assert check(good).status == CheckStatus.PASS
    bad = FakeGraph(gets={AUTHORIZATION_POLICY_PATH: bad_policy})
    assert check(bad).status == CheckStatus.FAIL
    denied = FakeGraph(gets={AUTHORIZATION_POLICY_PATH: GraphPermissionDenied("denied")})
    denied_result = check(denied)
    assert denied_result.status == CheckStatus.ERROR
    assert denied_result.status != CheckStatus.PASS


# ---------------------------------------------------------------------------
# Security defaults: 1.11
# ---------------------------------------------------------------------------


def test_security_defaults_pass_fail_unevaluable():
    assert _check_1_11(FakeGraph(gets={SECURITY_DEFAULTS_PATH: {"isEnabled": True}})).status == CheckStatus.PASS
    assert _check_1_11(FakeGraph(gets={SECURITY_DEFAULTS_PATH: {"isEnabled": False}})).status == CheckStatus.FAIL
    uneval = _check_1_11(FakeGraph(gets={SECURITY_DEFAULTS_PATH: GraphUnavailable("boom")}))
    assert uneval.status == CheckStatus.ERROR
    assert uneval.status != CheckStatus.PASS


# ---------------------------------------------------------------------------
# Access reviews: 1.3, 1.4
# ---------------------------------------------------------------------------

_GUEST_REVIEW = {"displayName": "Quarterly guest review", "scope": {"query": "/groups/x/members/microsoft.graph.user/?$filter=(userType eq 'Guest')"}}
_GROUP_REVIEW = {"displayName": "Group owners review", "scope": {"query": "/groups/x/owners"}}


@pytest.mark.parametrize("check", [_check_1_3, _check_1_4])
def test_access_review_control(check):
    good = FakeGraph(lists={ACCESS_REVIEW_DEFINITIONS_PATH: [_GROUP_REVIEW, _GUEST_REVIEW]})
    assert check(good).status == CheckStatus.PASS
    # definitions exist but none guest-scoped -> FAIL (never a false pass)
    partial = FakeGraph(lists={ACCESS_REVIEW_DEFINITIONS_PATH: [_GROUP_REVIEW]})
    assert check(partial).status == CheckStatus.FAIL
    empty = FakeGraph(lists={ACCESS_REVIEW_DEFINITIONS_PATH: []})
    assert check(empty).status == CheckStatus.FAIL
    denied = FakeGraph(lists={ACCESS_REVIEW_DEFINITIONS_PATH: GraphPermissionDenied("denied")})
    denied_result = check(denied)
    assert denied_result.status == CheckStatus.ERROR
    assert denied_result.status != CheckStatus.PASS


# ---------------------------------------------------------------------------
# AzureGraphClient — token, pagination, permission mapping
# ---------------------------------------------------------------------------


class _Resp:
    def __init__(self, status: int, payload) -> None:
        self.status_code = status
        self._payload = payload

    def json(self):
        return self._payload


class _FakeHTTP:
    def __init__(self, routes: dict) -> None:
        self._routes = routes

    def get(self, url: str, headers=None):
        route = self._routes[url]
        if isinstance(route, Exception):
            raise route
        return route


class _FakeToken:
    token = "fake-token"


class _FakeCredential:
    def __init__(self) -> None:
        self.scopes: list = []

    def get_token(self, *scopes):
        self.scopes.append(scopes)
        return _FakeToken()


def test_graph_client_paginates_collection():
    base = "https://graph.microsoft.com/v1.0"
    routes = {
        f"{base}/identity/conditionalAccess/policies": _Resp(
            200, {"value": [{"id": "1"}], "@odata.nextLink": f"{base}/identity/conditionalAccess/policies?page=2"}
        ),
        f"{base}/identity/conditionalAccess/policies?page=2": _Resp(200, {"value": [{"id": "2"}]}),
    }
    cred = _FakeCredential()
    client = AzureGraphClient(cred, http_client=_FakeHTTP(routes))
    items = client.list(CONDITIONAL_ACCESS_POLICIES_PATH)
    assert [i["id"] for i in items] == ["1", "2"]
    # the Graph .default scope was requested (read-only, brokered via the credential)
    assert cred.scopes


def test_graph_client_maps_403_to_permission_denied():
    base = "https://graph.microsoft.com/v1.0"
    routes = {f"{base}/policies/authorizationPolicy": _Resp(403, {})}
    client = AzureGraphClient(_FakeCredential(), http_client=_FakeHTTP(routes))
    with pytest.raises(GraphPermissionDenied):
        client.get(AUTHORIZATION_POLICY_PATH)


def test_graph_client_maps_500_to_unavailable():
    base = "https://graph.microsoft.com/v1.0"
    routes = {f"{base}/policies/authorizationPolicy": _Resp(500, {})}
    client = AzureGraphClient(_FakeCredential(), http_client=_FakeHTTP(routes))
    with pytest.raises(GraphUnavailable):
        client.get(AUTHORIZATION_POLICY_PATH)


# ---------------------------------------------------------------------------
# run_benchmark wiring: identity controls are unevaluable (not PASS) with no creds
# ---------------------------------------------------------------------------


def test_run_benchmark_identity_controls_fail_closed_without_graph():
    """A run with a credential that cannot reach Graph must NOT pass 1.6/1.12."""

    class _DeadCredential:
        def get_token(self, *scopes):  # noqa: D401 — always fails, exercises fail-closed path
            raise RuntimeError("no network")

    report = run_benchmark(subscription_id="sub-test", checks=["1.6", "1.12", "1.14"], credential=_DeadCredential())
    by_id = {c.check_id: c for c in report.checks}
    for cid in ("1.6", "1.12", "1.14"):
        assert by_id[cid].status != CheckStatus.PASS
        assert by_id[cid].status == CheckStatus.ERROR
