"""AI-system blueprint API: CRUD-ish reads, create/seed, and the approval workflow.

The test env defaults the no-auth role to admin (conftest), so the write routes
resolve as admin unless a test lowers ``AGENT_BOM_NO_AUTH_ROLE`` to prove the
RBAC gate (a non-privileged role cannot approve).
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.blueprint_store import InMemoryBlueprintStore, set_blueprint_store


@pytest.fixture()
def client():
    from agent_bom.api.server import app

    set_blueprint_store(InMemoryBlueprintStore())
    try:
        yield TestClient(app)
    finally:
        set_blueprint_store(None)


def _create(client: TestClient) -> str:
    resp = client.post(
        "/v1/governance/blueprints",
        json={"name": "Planner system", "owner": "appsec", "composition": {"tools": ["repo_read"], "agents": ["planner"]}},
    )
    assert resp.status_code == 201, resp.text
    return resp.json()["blueprint"]["blueprint_id"]


def test_create_list_and_get_blueprint(client):
    bid = _create(client)

    listing = client.get("/v1/governance/blueprints").json()
    assert listing["schema_version"] == "governance.blueprints.v1"
    assert listing["tenant_id"] == "default"
    assert any(b["blueprint_id"] == bid for b in listing["blueprints"])

    detail = client.get(f"/v1/governance/blueprints/{bid}").json()
    assert detail["blueprint"]["approval_status"] == "draft"
    assert detail["versions"][0]["version"] == 1
    assert detail["versions"][0]["composition"]["tools"] == ["repo_read"]

    assert client.get("/v1/governance/blueprints/nope").status_code == 404


def test_seed_endpoint_is_idempotent(client):
    first = client.post("/v1/governance/blueprints/seed").json()
    assert first["seeded_count"] == 5
    second = client.post("/v1/governance/blueprints/seed").json()
    assert second["seeded_count"] == 0
    listing = client.get("/v1/governance/blueprints").json()
    assert listing["count"] == 5
    assert all(b["approval_status"] == "approved" for b in listing["blueprints"])


def test_approval_workflow_via_api(client):
    bid = _create(client)
    # draft -> pending
    submit = client.post(f"/v1/governance/blueprints/{bid}/versions/1/submit")
    assert submit.status_code == 200, submit.text
    assert submit.json()["version"]["status"] == "pending"
    # pending -> approved, approver recorded
    approve = client.post(f"/v1/governance/blueprints/{bid}/versions/1/approve", json={"note": "ok"})
    assert approve.status_code == 200, approve.text
    version = approve.json()["version"]
    assert version["status"] == "approved" and version["approver"]
    # re-approving an immutable version is a 400
    assert client.post(f"/v1/governance/blueprints/{bid}/versions/1/approve").status_code == 400


def test_new_draft_version_and_diff(client):
    bid = _create(client)
    v2 = client.post(f"/v1/governance/blueprints/{bid}/versions", json={"composition": {"tools": ["graph_query"]}})
    assert v2.status_code == 201, v2.text
    assert v2.json()["version"]["version"] == 2
    diff = client.get(f"/v1/governance/blueprints/{bid}/diff?from_version=1&to_version=2").json()["diff"]
    assert diff["axes"]["tools"]["added"] == ["graph_query"]
    assert diff["axes"]["tools"]["removed"] == ["repo_read"]


def test_reject_workflow(client):
    bid = _create(client)
    client.post(f"/v1/governance/blueprints/{bid}/versions/1/submit")
    reject = client.post(f"/v1/governance/blueprints/{bid}/versions/1/reject", json={"note": "too broad"})
    assert reject.status_code == 200, reject.text
    assert reject.json()["version"]["status"] == "rejected"


def test_submit_missing_version_404(client):
    bid = _create(client)
    assert client.post(f"/v1/governance/blueprints/{bid}/versions/9/submit").status_code == 404


# ── RBAC: only the admin/config role may approve ─────────────────────────────


def test_non_privileged_role_cannot_approve(client, monkeypatch):
    bid = _create(client)
    client.post(f"/v1/governance/blueprints/{bid}/versions/1/submit")
    # Lower the ambient no-auth role to a non-admin contributor; approval is
    # gated on the admin ("config") capability and must be refused.
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "analyst")
    denied = client.post(f"/v1/governance/blueprints/{bid}/versions/1/approve")
    assert denied.status_code == 403, denied.text
    # the version remains pending — a denied approval takes no effect
    assert client.get(f"/v1/governance/blueprints/{bid}/versions/1").json()["version"]["status"] == "pending"


def test_viewer_role_cannot_create(client, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "viewer")
    resp = client.post("/v1/governance/blueprints", json={"name": "x", "owner": "o"})
    assert resp.status_code == 403, resp.text


# ── tenant isolation ─────────────────────────────────────────────────────────


def test_blueprints_are_tenant_isolated(client, monkeypatch):
    # default tenant creates a blueprint
    bid = _create(client)
    # a request attributed to another tenant (trusted-proxy identity) cannot see it
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", "x" * 40)
    headers = {
        "X-Agent-Bom-Role": "admin",
        "X-Agent-Bom-Tenant-ID": "other-tenant",
        "X-Agent-Bom-Proxy-Secret": "x" * 40,
    }
    listing = client.get("/v1/governance/blueprints", headers=headers)
    assert listing.status_code == 200, listing.text
    assert all(b["blueprint_id"] != bid for b in listing.json()["blueprints"])
    assert listing.json()["tenant_id"] == "other-tenant"
