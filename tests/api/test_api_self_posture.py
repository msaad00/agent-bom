"""Tests for the GET /v1/self-posture operator self-audit endpoint."""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom.api.governance_audit_log import (
    ACTION_IDENTITY_DORMANT_REVOKE,
    InMemoryGovernanceAuditLog,
    make_governance_audit_record,
    set_governance_audit_log,
)
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH_HEADERS = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


@pytest.fixture(autouse=True)
def _reset_governance_audit_log():
    set_governance_audit_log(InMemoryGovernanceAuditLog())
    yield
    set_governance_audit_log(None)


def _check(body: dict, check_id: str) -> dict:
    return {c["id"]: c for c in body["checks"]}[check_id]


def _seed_governance_action(tenant_id: str, target_id: str) -> None:
    from agent_bom.api.governance_audit_log import get_governance_audit_log

    record = make_governance_audit_record(
        tenant_id=tenant_id,
        actor="cleanup-loop",
        action=ACTION_IDENTITY_DORMANT_REVOKE,
        target_type="agent_identity",
        target_id=target_id,
        reason="dormant beyond retention",
        before_state="active",
        after_state="revoked",
        observed_at="2026-07-18T00:00:00Z",
        window_key="2026-07-18T00:00:00Z",
    )
    get_governance_audit_log().append(record)


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


def test_self_posture_surfaces_tenant_audit_chain_integrity() -> None:
    # A tenant with a verified governance chain reads as pass, reconciled to the
    # store's own verify_chain — not an independently-invented number.
    _seed_governance_action("default", "agent-a")
    _seed_governance_action("default", "agent-b")

    client = TestClient(app)
    resp = client.get("/v1/self-posture", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    check = _check(resp.json(), "governance.audit_chain_integrity")
    assert check["status"] == "pass"
    assert check["category"] == "governance"


def test_self_posture_empty_audit_chain_is_unknown_never_pass() -> None:
    # No governance actions recorded for this tenant -> honest unknown, never a
    # fabricated "healthy" from an absent signal (§7/§11).
    client = TestClient(app)
    resp = client.get("/v1/self-posture", headers=_AUTH_HEADERS)
    assert resp.status_code == 200
    check = _check(resp.json(), "governance.audit_chain_integrity")
    assert check["status"] == "unknown"


def test_self_posture_audit_chain_is_tenant_isolated() -> None:
    # Seed a chain for tenant "alpha" only; tenant "beta" must NOT inherit it —
    # its audit-chain integrity stays unknown (no cross-tenant leak).
    _seed_governance_action("alpha", "agent-x")

    client = TestClient(app)
    alpha = client.get("/v1/self-posture", headers=proxy_headers(tenant="alpha"))
    beta = client.get("/v1/self-posture", headers=proxy_headers(tenant="beta"))
    assert alpha.status_code == 200 and beta.status_code == 200
    assert _check(alpha.json(), "governance.audit_chain_integrity")["status"] == "pass"
    assert _check(beta.json(), "governance.audit_chain_integrity")["status"] == "unknown"
