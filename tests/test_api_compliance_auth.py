"""Defense-in-depth auth tests for compliance and posture routes."""

from starlette.testclient import TestClient

from agent_bom.api.server import app


def test_posture_requires_authenticated_context() -> None:
    client = TestClient(app)
    resp = client.get("/v1/posture")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


def test_posture_accepts_trusted_proxy_headers() -> None:
    client = TestClient(app)
    resp = client.get(
        "/v1/posture",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        },
    )
    assert resp.status_code == 200
    assert resp.json()["grade"] == "N/A"


def test_posture_proxy_auth_requires_tenant_header() -> None:
    client = TestClient(app)
    resp = client.get(
        "/v1/posture",
        headers={
            "X-Agent-Bom-Role": "viewer",
        },
    )
    assert resp.status_code == 401
    assert "X-Agent-Bom-Tenant-ID" in resp.json()["detail"]


def test_compliance_export_requires_authenticated_context() -> None:
    client = TestClient(app)
    resp = client.get("/v1/compliance")
    assert resp.status_code == 401
    assert "Authentication required" in resp.json()["detail"]


def test_compliance_export_accepts_trusted_proxy_headers() -> None:
    client = TestClient(app)
    resp = client.get(
        "/v1/compliance/owasp-llm/report",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Tenant-ID": "tenant-alpha",
        },
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["framework"] == "owasp-llm"
    assert body["tenant_id"] == "tenant-alpha"
