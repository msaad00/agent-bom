from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from agent_bom.api import server as api_server
from agent_bom.api.scim_store import InMemorySCIMStore
from agent_bom.api.server import app
from agent_bom.api.stores import _get_scim_store, set_scim_store


@pytest.fixture
def scim_client(monkeypatch: pytest.MonkeyPatch) -> TestClient:
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "scim-secret")
    monkeypatch.setenv("AGENT_BOM_SCIM_TENANT_ID", "tenant-alpha")
    set_scim_store(InMemorySCIMStore())
    api_server.configure_api(api_key=None)
    return TestClient(app)


def _headers(token: str = "scim-secret") -> dict[str, str]:
    return {"Authorization": f"Bearer {token}"}


def test_scim_requires_dedicated_bearer_token(scim_client: TestClient) -> None:
    missing = scim_client.get("/scim/v2/Users")
    assert missing.status_code == 401

    wrong = scim_client.get("/scim/v2/Users", headers=_headers("wrong"))
    assert wrong.status_code == 401

    allowed = scim_client.get("/scim/v2/Users", headers=_headers())
    assert allowed.status_code == 200
    assert allowed.json()["totalResults"] == 0


def test_scim_discovery_endpoints(scim_client: TestClient) -> None:
    service_provider = scim_client.get("/scim/v2/ServiceProviderConfig", headers=_headers())
    assert service_provider.status_code == 200
    assert service_provider.json()["patch"]["supported"] is True

    schemas = scim_client.get("/scim/v2/Schemas", headers=_headers())
    assert schemas.status_code == 200
    schema_ids = {resource["id"] for resource in schemas.json()["Resources"]}
    assert "urn:ietf:params:scim:schemas:core:2.0:User" in schema_ids
    assert "urn:ietf:params:scim:schemas:core:2.0:Group" in schema_ids

    resource_types = scim_client.get("/scim/v2/ResourceTypes", headers=_headers())
    assert resource_types.status_code == 200
    assert {resource["id"] for resource in resource_types.json()["Resources"]} == {"User", "Group"}


def test_scim_user_create_list_patch_and_deactivate(scim_client: TestClient) -> None:
    created = scim_client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={
            "userName": "alice@example.com",
            "externalId": "emp-123",
            "displayName": "Alice Example",
            "active": True,
            "emails": [{"value": "alice@example.com", "primary": True}],
            "tenant_id": "attacker-tenant",
        },
    )
    assert created.status_code == 201
    user = created.json()
    user_id = user["id"]
    assert user["userName"] == "alice@example.com"
    assert user["active"] is True

    duplicate = scim_client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={"userName": "alice@example.com", "externalId": "emp-123"},
    )
    assert duplicate.status_code == 409

    listed = scim_client.get('/scim/v2/Users?filter=userName eq "alice@example.com"', headers=_headers())
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 1
    assert listed.json()["Resources"][0]["id"] == user_id

    patched = scim_client.patch(
        f"/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "schemas": ["urn:ietf:params:scim:api:messages:2.0:PatchOp"],
            "Operations": [{"op": "replace", "path": "active", "value": False}],
        },
    )
    assert patched.status_code == 200
    assert patched.json()["active"] is False

    replaced = scim_client.put(
        f"/scim/v2/Users/{user_id}",
        headers=_headers(),
        json={
            "userName": "alice.renamed@example.com",
            "externalId": "emp-123",
            "displayName": "Alice Renamed",
            "active": True,
        },
    )
    assert replaced.status_code == 200
    assert replaced.json()["userName"] == "alice.renamed@example.com"
    assert replaced.json()["active"] is True

    deleted = scim_client.delete(f"/scim/v2/Users/{user_id}", headers=_headers())
    assert deleted.status_code == 204

    fetched = scim_client.get(f"/scim/v2/Users/{user_id}", headers=_headers())
    assert fetched.status_code == 200
    assert fetched.json()["active"] is False


def test_scim_group_create_patch_and_delete(scim_client: TestClient) -> None:
    user = scim_client.post(
        "/scim/v2/Users",
        headers=_headers(),
        json={"userName": "bob@example.com", "externalId": "emp-456"},
    ).json()
    created = scim_client.post(
        "/scim/v2/Groups",
        headers=_headers(),
        json={
            "displayName": "Agent Operators",
            "externalId": "grp-ops",
            "members": [{"value": user["id"], "display": "bob@example.com"}],
        },
    )
    assert created.status_code == 201
    group_id = created.json()["id"]

    listed = scim_client.get('/scim/v2/Groups?filter=displayName eq "Agent Operators"', headers=_headers())
    assert listed.status_code == 200
    assert listed.json()["totalResults"] == 1

    patched = scim_client.patch(
        f"/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={"Operations": [{"op": "replace", "path": "displayName", "value": "Agent Security Operators"}]},
    )
    assert patched.status_code == 200
    assert patched.json()["displayName"] == "Agent Security Operators"

    replaced = scim_client.put(
        f"/scim/v2/Groups/{group_id}",
        headers=_headers(),
        json={"displayName": "Identity Operators", "members": []},
    )
    assert replaced.status_code == 200
    assert replaced.json()["displayName"] == "Identity Operators"
    assert replaced.json()["members"] == []

    deleted = scim_client.delete(f"/scim/v2/Groups/{group_id}", headers=_headers())
    assert deleted.status_code == 204
    assert scim_client.get(f"/scim/v2/Groups/{group_id}", headers=_headers()).status_code == 404


def test_scim_store_fails_closed_without_postgres_for_multi_replica(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("AGENT_BOM_SCIM_BEARER_TOKEN", "scim-secret")
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", "2")
    set_scim_store(None)

    with pytest.raises(RuntimeError, match="AGENT_BOM_POSTGRES_URL"):
        _get_scim_store()
