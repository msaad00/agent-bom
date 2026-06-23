"""_discover_role_assignments resolves RBAC assignments + role names offline."""

from __future__ import annotations

import sys
import types

import pytest


class _Assignment:
    def __init__(self, principal_id, principal_type, role_definition_id, scope):
        self.principal_id = principal_id
        self.principal_type = principal_type
        self.role_definition_id = role_definition_id
        self.scope = scope


class _RoleDef:
    def __init__(self, role_name):
        self.role_name = role_name


class _RoleAssignments:
    def list_for_subscription(self):
        return [
            _Assignment(
                "pid-mi",
                "ServicePrincipal",
                "/rd/contributor",
                "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
            ),
            _Assignment("pid-user", "User", "/rd/reader", "/subscriptions/sub1"),
            _Assignment("", "User", "/rd/reader", "/subscriptions/sub1"),  # no principal → skipped
        ]


class _RoleDefinitions:
    def __init__(self):
        self.calls = 0

    def get_by_id(self, rid):
        self.calls += 1
        return _RoleDef("Contributor" if "contributor" in rid else "Reader")


class _AuthzClient:
    _defs = _RoleDefinitions()

    def __init__(self, *a, **k):
        self.role_assignments = _RoleAssignments()
        self.role_definitions = _AuthzClient._defs


@pytest.fixture(autouse=True)
def _stub_authz(monkeypatch):
    mgmt = types.ModuleType("azure.mgmt.authorization")
    mgmt.AuthorizationManagementClient = _AuthzClient
    monkeypatch.setitem(sys.modules, "azure", sys.modules.get("azure") or types.ModuleType("azure"))
    monkeypatch.setitem(sys.modules, "azure.mgmt", sys.modules.get("azure.mgmt") or types.ModuleType("azure.mgmt"))
    monkeypatch.setitem(sys.modules, "azure.mgmt.authorization", mgmt)


def test_role_assignments_parsed_and_role_names_resolved() -> None:
    from agent_bom.cloud.azure_inventory import _discover_role_assignments

    warnings: list[str] = []
    out = _discover_role_assignments(object(), "sub1", warnings=warnings)
    by_pid = {a["principal_id"]: a for a in out}
    assert set(by_pid) == {"pid-mi", "pid-user"}  # blank principal skipped
    assert by_pid["pid-mi"]["role_name"] == "Contributor"
    assert by_pid["pid-mi"]["scope"].endswith("/vaults/kv1")
    assert by_pid["pid-user"]["role_name"] == "Reader"
    assert by_pid["pid-mi"]["principal_type"] == "serviceprincipal"


def test_role_name_cache_avoids_duplicate_lookups() -> None:
    from agent_bom.cloud.azure_inventory import _discover_role_assignments

    _AuthzClient._defs.calls = 0
    _discover_role_assignments(object(), "sub1", warnings=[])
    # 2 distinct role-definition ids → at most 2 lookups despite repeated reader use.
    assert _AuthzClient._defs.calls <= 2


def test_missing_sdk_is_graceful(monkeypatch) -> None:
    monkeypatch.setitem(sys.modules, "azure.mgmt.authorization", None)
    from agent_bom.cloud.azure_inventory import _discover_role_assignments

    warnings: list[str] = []
    out = _discover_role_assignments(object(), "sub1", warnings=warnings)
    assert out == []
    assert any("azure-mgmt-authorization" in w for w in warnings)
