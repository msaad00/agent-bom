"""Defense-in-depth auth tests for compliance and posture routes."""

from datetime import datetime, timezone

from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store

PROXY_SECRET = "test-proxy-secret-with-32-plus-bytes"


def _proxy_headers(role: str = "viewer", tenant: str = "tenant-alpha") -> dict[str, str]:
    return {
        "X-Agent-Bom-Role": role,
        "X-Agent-Bom-Tenant-ID": tenant,
        "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
    }


def setup_module() -> None:
    import os

    os.environ["AGENT_BOM_TRUST_PROXY_AUTH"] = "1"
    os.environ["AGENT_BOM_TRUST_PROXY_AUTH_SECRET"] = PROXY_SECRET


def teardown_module() -> None:
    import os

    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH", None)
    os.environ.pop("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", None)


def test_posture_requires_authenticated_context() -> None:
    client = TestClient(app)
    resp = client.get("/v1/posture")
    assert resp.status_code == 401
    assert "Unauthorized" in resp.json()["detail"]


def test_posture_accepts_trusted_proxy_headers() -> None:
    client = TestClient(app)
    resp = client.get(
        "/v1/posture",
        headers=_proxy_headers(),
    )
    assert resp.status_code == 200
    assert resp.json()["grade"] == "N/A"


def test_posture_proxy_auth_requires_tenant_header() -> None:
    client = TestClient(app)
    resp = client.get(
        "/v1/posture",
        headers={
            "X-Agent-Bom-Role": "viewer",
            "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
        },
    )
    assert resp.status_code == 401
    assert "X-Agent-Bom-Tenant-ID" in resp.json()["detail"]


def test_compliance_export_requires_authenticated_context() -> None:
    client = TestClient(app)
    resp = client.get("/v1/compliance")
    assert resp.status_code == 401
    assert "Unauthorized" in resp.json()["detail"]


def test_compliance_export_accepts_trusted_proxy_headers() -> None:
    client = TestClient(app)
    resp = client.get(
        "/v1/compliance/owasp-llm/report",
        headers=_proxy_headers(),
    )
    assert resp.status_code == 200
    body = resp.json()
    assert body["framework"] == "owasp-llm"
    assert body["tenant_id"] == "tenant-alpha"


def test_compliance_export_end_to_end_returns_real_evidence() -> None:
    """Full stack: seed a real ScanJob, hit the FastAPI route, verify evidence wires.

    Guards against the regression where `_build_controls` and `_evidence_for_control`
    disagree on the control dict shape (code vs tags) — a bug that can only be caught
    by exercising the real producer path through the real router, not by mocking
    `get_compliance`.
    """
    store = InMemoryJobStore()
    now = datetime.now(timezone.utc).isoformat()
    job = ScanJob(
        job_id="e2e-scan",
        tenant_id="tenant-alpha",
        status=JobStatus.DONE,
        created_at=now,
        completed_at=now,
        request=ScanRequest(),
    )
    job.result = {
        "scan_id": "e2e-scan",
        "blast_radius": [
            {
                "vulnerability_id": "CVE-2024-9999",
                "package": "axios@1.4.0",
                "severity": "high",
                "fixed_version": "1.7.4",
                "owasp_tags": ["LLM01"],
                "affected_agents": ["claude-desktop"],
            }
        ],
    }
    store.put(job)
    previous_store = _stores._store  # preserve prior backend (may be None or a real one)
    set_job_store(store)
    try:
        client = TestClient(app)
        resp = client.get(
            "/v1/compliance/owasp-llm/report",
            headers=_proxy_headers(),
        )
        assert resp.status_code == 200
        body = resp.json()
        exported = {c["control_id"]: c for c in body["controls"]}
        assert exported["LLM01"]["finding_count"] == 1
        assert exported["LLM01"]["control_id"] == "LLM01"
        assert exported["LLM01"]["evidence"][0]["vulnerability_id"] == "CVE-2024-9999"
        assert exported["LLM01"]["evidence"][0]["control_tag"] == "LLM01"
        assert resp.headers.get("X-Agent-Bom-Compliance-Report-Signature")
    finally:
        # Restore whatever was configured before this test — including None,
        # which lets _get_store() recreate a fresh default on next access.
        _stores._store = previous_store
