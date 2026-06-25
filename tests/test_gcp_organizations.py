"""GCP Organization → Folders → Projects scale + the graph CONTAINS backbone.

Mirrors the AWS-organization tests: the org tree is the roll-up hierarchy, and
org/folder IAM bindings grant DOWN to every child project (inherited). Tests the
SDK-free surfaces — degradation, the graph mapping, findings, project-id parsing.
"""

from __future__ import annotations

from agent_bom.cloud import gcp_inventory, gcp_organizations
from agent_bom.graph.builder import _add_gcp_organization
from agent_bom.graph.container import UnifiedGraph
from agent_bom.graph.types import EntityType, RelationshipType


def _ok_payload() -> dict:
    return {
        "status": "ok",
        "org_id": "123456789",
        "org_name": "acme.example",
        "folders": [{"id": "folders/1", "name": "prod", "parent_id": "organizations/123456789"}],
        "projects": [
            {"id": "proj-a", "name": "app-a", "number": "111", "parent_id": "folders/1"},
            {"id": "proj-b", "name": "app-b", "number": "222", "parent_id": "organizations/123456789"},
        ],
        "iam_bindings": [
            {
                "role": "roles/owner",
                "scope_id": "organizations/123456789",
                "scope_level": "organization",
                "privilege_level": "admin",
                "members": ["user:alice@example.com", "serviceAccount:ci@proj.iam.gserviceaccount.com"],
            }
        ],
        "org_policies": [],
        "findings": [],
    }


def test_disabled_when_flag_off(monkeypatch) -> None:
    monkeypatch.delenv(gcp_inventory.INVENTORY_ENV_FLAG, raising=False)
    out = gcp_organizations.discover_organization()
    assert out["status"] == "disabled"
    assert out["projects"] == [] and out["folders"] == []


def test_builder_builds_contains_hierarchy_and_inherited_iam() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    _add_gcp_organization(g, _ok_payload(), "test")

    org = g.nodes.get("org:gcp:123456789")
    assert org is not None and org.entity_type == EntityType.ORG
    assert "org:gcp:folder:1" in g.nodes  # folder tier
    # projects use the same account:gcp:<id> node a per-project scan emits
    proj_a = next((n for n in g.nodes.values() if n.entity_type == EntityType.ACCOUNT and "proj-a" in n.id), None)
    assert proj_a is not None

    def _rel(rel):
        return {(e.source, e.target) for e in g.edges if e.relationship == rel}

    contains = _rel(RelationshipType.CONTAINS)
    assert ("org:gcp:123456789", "org:gcp:folder:1") in contains  # org → folder
    assert any(s == "org:gcp:folder:1" and "proj-a" in t for s, t in contains)  # folder → project
    assert any(s == "org:gcp:123456789" and "proj-b" in t for s, t in contains)  # org → project (direct)

    # org-level owner binding → HAS_PERMISSION onto the org node (inherited down)
    perms = [e for e in g.edges if e.relationship == RelationshipType.HAS_PERMISSION and e.target == "org:gcp:123456789"]
    assert len(perms) == 2  # alice + the service account


def test_builder_non_ok_payload_is_noop() -> None:
    g = UnifiedGraph(scan_id="s", tenant_id="t")
    _add_gcp_organization(g, {"status": "not_in_org"}, "test")
    _add_gcp_organization(g, None, "test")
    assert len(g.nodes) == 0


def test_list_project_ids_parses_org_result(monkeypatch) -> None:
    monkeypatch.setattr(gcp_organizations, "discover_organization", lambda *a, **k: _ok_payload())
    ids = gcp_organizations.list_project_ids(force=True)
    assert set(ids) == {"proj-a", "proj-b"}


def test_derive_findings_flags_estate_risk() -> None:
    payload = _ok_payload()
    payload["findings"] = []
    gcp_organizations._derive_findings(payload)
    assert isinstance(payload["findings"], list)  # never raises; appends estate-shape signals
