"""Effective-role enforcement for pure self-hosted no-auth deployments.

Disabling authentication must not disable authorization.  Credential-less
requests are assigned ``AGENT_BOM_NO_AUTH_ROLE`` and pass through the same
route-role matrix as authenticated principals.
"""

from __future__ import annotations

from collections.abc import Iterator

import pytest
from starlette.testclient import TestClient

from agent_bom.api import server as api_server
from agent_bom.api.auth import KeyStore, get_key_store, set_key_store
from agent_bom.api.server import app


@pytest.fixture
def pure_no_auth_client(monkeypatch: pytest.MonkeyPatch) -> Iterator[TestClient]:
    original_store = get_key_store()
    set_key_store(KeyStore())
    monkeypatch.setattr(api_server, "_env_api_keys_seeded", False)
    monkeypatch.setattr(api_server, "_runtime_api_key_seeded", False)
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    monkeypatch.delenv("AGENT_BOM_API_KEY", raising=False)
    monkeypatch.delenv("AGENT_BOM_API_KEYS", raising=False)
    monkeypatch.delenv("AGENT_BOM_DEMO_ESTATE", raising=False)
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "viewer")
    monkeypatch.setattr("agent_bom.config.DEMO_ESTATE", False)
    api_server.configure_api(api_key=None, allow_unauthenticated=True)
    try:
        with TestClient(app) as client:
            yield client
    finally:
        set_key_store(original_store)
        monkeypatch.setattr(api_server, "_env_api_keys_seeded", False)
        monkeypatch.setattr(api_server, "_runtime_api_key_seeded", False)
        api_server.configure_api(api_key=None)


def test_pure_no_auth_viewer_gets_effective_session_and_read_only_routes(
    pure_no_auth_client: TestClient,
) -> None:
    session = pure_no_auth_client.get("/v1/auth/me")
    assert session.status_code == 200
    assert session.json()["auth_method"] == "anonymous"
    assert session.json()["role"] == "viewer"
    assert session.json()["role_summary"]["capabilities"] == ["inventory.read"]

    assert pure_no_auth_client.get("/v1/sources").status_code == 200
    assert pure_no_auth_client.get("/v1/schedules").status_code == 200
    assert pure_no_auth_client.get("/v1/scan/drivers").status_code == 200


@pytest.mark.parametrize(
    ("method", "path", "payload"),
    [
        ("POST", "/v1/sources", {"display_name": "repo", "kind": "scan.repo"}),
        ("PUT", "/v1/sources/missing", {"description": "changed"}),
        ("DELETE", "/v1/sources/missing", None),
        (
            "POST",
            "/v1/schedules",
            {"name": "daily", "cron_expression": "0 0 * * *", "scan_config": {}},
        ),
        ("PUT", "/v1/schedules/missing/toggle", None),
        ("DELETE", "/v1/schedules/missing", None),
        ("POST", "/v1/scan", {"dry_run": True}),
        ("POST", "/v1/scan/missing/cancel", None),
        ("DELETE", "/v1/scan/missing", None),
    ],
)
def test_pure_no_auth_viewer_cannot_mutate_sources_schedules_or_scans(
    pure_no_auth_client: TestClient,
    method: str,
    path: str,
    payload: dict[str, object] | None,
) -> None:
    response = pure_no_auth_client.request(method, path, json=payload)
    assert response.status_code == 403
    assert "anonymous access has viewer" in response.json()["detail"]


def test_pure_no_auth_analyst_uses_the_route_role_matrix(
    pure_no_auth_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "analyst")

    session = pure_no_auth_client.get("/v1/auth/me").json()
    assert session["role"] == "analyst"
    assert {"scan.run", "sources.manage"}.issubset(session["role_summary"]["capabilities"])

    created = pure_no_auth_client.post(
        "/v1/sources",
        json={"display_name": "repo", "kind": "scan.repo"},
    )
    assert created.status_code == 201
    source_id = created.json()["source_id"]
    assert (
        pure_no_auth_client.put(
            f"/v1/sources/{source_id}",
            json={"description": "updated"},
        ).status_code
        == 200
    )
    # Source deletion and job deletion are protected admin operations.
    assert pure_no_auth_client.delete(f"/v1/sources/{source_id}").status_code == 403
    assert pure_no_auth_client.delete("/v1/scan/missing").status_code == 403
    # Analyst reaches scan request validation instead of being rejected by RBAC.
    assert pure_no_auth_client.post("/v1/scan", json={"unknown": True}).status_code == 422


def test_pure_no_auth_admin_can_use_protected_source_mutations(
    pure_no_auth_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "admin")

    session = pure_no_auth_client.get("/v1/auth/me").json()
    assert session["role"] == "admin"
    created = pure_no_auth_client.post(
        "/v1/sources",
        json={"display_name": "repo", "kind": "scan.repo"},
    )
    assert created.status_code == 201
    assert pure_no_auth_client.delete(f"/v1/sources/{created.json()['source_id']}").status_code == 204


def test_demo_estate_clamps_pure_no_auth_admin_to_viewer(
    pure_no_auth_client: TestClient,
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "admin")
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    monkeypatch.setattr("agent_bom.config.DEMO_ESTATE", True)

    session = pure_no_auth_client.get("/v1/auth/me").json()
    assert session["role"] == "viewer"
    denied = pure_no_auth_client.post(
        "/v1/sources",
        json={"display_name": "repo", "kind": "scan.repo"},
    )
    assert denied.status_code == 403
    assert "anonymous access has viewer" in denied.json()["detail"]


def test_demo_estate_clamp_uses_runtime_environment_not_stale_config(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    from agent_bom.rbac import Role, _no_auth_role

    monkeypatch.setattr("agent_bom.config.DEMO_ESTATE", False)
    monkeypatch.setenv("AGENT_BOM_NO_AUTH_ROLE", "admin")
    monkeypatch.setenv("AGENT_BOM_DEMO_ESTATE", "1")
    assert _no_auth_role() is Role.VIEWER
