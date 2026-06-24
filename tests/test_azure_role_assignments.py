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


# ── Graph: HAS_PERMISSION edges from role assignments ────────────────────
def _rbac_inventory() -> dict:
    return {
        "status": "ok",
        "provider": "azure",
        "account_id": "sub1",
        # an inventoried resource the assignment scope should match by resource_id
        "key_vaults": [
            {
                "name": "kv1",
                "id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
                "resource_id": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
            }
        ],
        "role_assignments": [
            # one SP with two roles on the SAME resource → one aggregated edge
            {
                "principal_id": "sp-1",
                "principal_type": "serviceprincipal",
                "role_name": "Key Vault Administrator",
                "scope": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
            },
            {
                "principal_id": "sp-1",
                "principal_type": "serviceprincipal",
                "role_name": "Reader",
                "scope": "/subscriptions/sub1/resourceGroups/rg/providers/Microsoft.KeyVault/vaults/kv1",
            },
            # subscription-scoped Owner → account node, privileged
            {"principal_id": "usr-1", "principal_type": "user", "role_name": "Owner", "scope": "/subscriptions/sub1"},
            # resource-group scope → RG node
            {
                "principal_id": "sp-2",
                "principal_type": "serviceprincipal",
                "role_name": "Contributor",
                "scope": "/subscriptions/sub1/resourceGroups/rg",
            },
        ],
    }


def _rbac_graph():
    from agent_bom.graph.builder import build_unified_graph_from_report

    g = build_unified_graph_from_report({"cloud_inventory": _rbac_inventory()})
    edges = [e for e in g.edges if e.relationship.value == "has_permission"]
    return g, edges


def test_multiple_roles_same_scope_aggregate_to_one_edge() -> None:
    g, edges = _rbac_graph()
    kv_edges = [e for e in edges if e.target.endswith("kv1") or "kv1" in e.target]
    assert len(kv_edges) == 1
    assert set(kv_edges[0].evidence["roles"]) == {"Key Vault Administrator", "Reader"}
    assert kv_edges[0].evidence["privileged"] is True  # Key Vault Administrator


def test_assignment_scope_matches_inventoried_resource_node() -> None:
    _, edges = _rbac_graph()
    targets = {e.target for e in edges}
    # the kv assignment lands on the SAME node id the inventory created, not a thin one
    assert "cloud_resource:azure:secret_store:kv1" in targets


def test_subscription_scope_targets_account_node_and_is_privileged() -> None:
    _, edges = _rbac_graph()
    owner = [e for e in edges if "Owner" in e.evidence.get("roles", [])]
    assert owner and owner[0].target == "account:azure:sub1"
    assert owner[0].evidence["privileged"] is True


def test_resource_group_scope_creates_rg_node() -> None:
    g, edges = _rbac_graph()
    assert "cloud_resource:azure:resource_group:rg" in g.nodes
    rg_edge = [e for e in edges if e.target == "cloud_resource:azure:resource_group:rg"]
    assert rg_edge and "Contributor" in rg_edge[0].evidence["roles"]


def test_no_role_assignments_is_noop() -> None:
    from agent_bom.graph.builder import build_unified_graph_from_report

    inv = {**_rbac_inventory(), "role_assignments": []}
    g = build_unified_graph_from_report({"cloud_inventory": inv})
    assert not [e for e in g.edges if e.relationship.value == "has_permission"]
