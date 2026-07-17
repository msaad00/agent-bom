"""Tests for the GET /v1/self-posture operator self-audit endpoint."""

from __future__ import annotations

from starlette.testclient import TestClient

from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


def test_self_posture_route_is_registered_under_read_permission() -> None:
    # The route carries the same require_authenticated_permission("read")
    # dependency as the other v1 read routes (enforcement itself is covered by
    # the auth-boundary suite); assert it is wired into the v1 surface.
    from agent_bom.api.routes.self_posture import router

    paths = {getattr(route, "path", "") for route in router.routes}
    assert "/self-posture" in paths
    assert router.dependencies, "self-posture router must carry an auth dependency"


def test_self_posture_returns_honest_report() -> None:
    client = TestClient(app)
    resp = client.get("/v1/self-posture", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    body = resp.json()

    assert body["schema_version"] == 1
    assert body["overall_status"] in {"hardened", "action_advised", "needs_review", "at_risk"}
    assert isinstance(body["checks"], list) and body["checks"]

    ids = {c["id"] for c in body["checks"]}
    assert {
        "auth.api_authentication",
        "database.rls_isolation",
        "audit.hmac_integrity",
        "supply_chain.dependency_surface",
    } <= ids

    for check in body["checks"]:
        assert check["status"] in {"pass", "fail", "warn", "unknown"}
        assert check["title"] and check["detail"]
