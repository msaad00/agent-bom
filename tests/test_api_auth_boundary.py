"""Regression tests for control-plane auth boundary bypasses."""

from starlette.testclient import TestClient

from agent_bom.api.server import app

PROXY_SECRET = "test-proxy-secret"


def test_gateway_policy_create_rejects_spoofed_role_without_attestation() -> None:
    client = TestClient(app)
    response = client.post(
        "/v1/gateway/policies",
        json={"name": "spoofed", "mode": "enforce", "rules": [{"id": "r1", "action": "block", "block_tools": ["exec"]}]},
        headers={"X-Agent-Bom-Role": "admin", "X-Agent-Bom-Tenant-ID": "tenant-alpha"},
    )

    assert response.status_code == 401


def test_enterprise_read_routes_reject_spoofed_proxy_headers_without_attestation() -> None:
    client = TestClient(app)
    headers = {"X-Agent-Bom-Role": "viewer", "X-Agent-Bom-Tenant-ID": "tenant-alpha"}

    assert client.get("/v1/posture", headers=headers).status_code == 401
    assert client.get("/metrics", headers=headers).status_code == 401
    assert client.get("/v1/compliance/owasp-llm/report", headers=headers).status_code == 401


def test_attested_proxy_headers_are_accepted_when_explicitly_enabled(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    client = TestClient(app)

    response = client.get(
        "/v1/posture",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
            "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
        },
    )

    assert response.status_code == 200


def test_attested_proxy_headers_reject_wrong_secret(monkeypatch) -> None:
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    client = TestClient(app)

    response = client.get(
        "/v1/posture",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
            "X-Agent-Bom-Proxy-Secret": "wrong",
        },
    )

    assert response.status_code == 401
