"""API-level cross-tenant isolation matrix.

End-to-end TestClient tests that seed data for two tenants and assert
that every RBAC-guarded enterprise endpoint returns ONLY the authed
tenant's data — no cross-tenant leakage via HTTP.

Scope note: only routes protected by the RBAC dependency
(`require_authenticated_permission`) resolve tenant from the
`X-Agent-Bom-Tenant-ID` proxy header, so this matrix covers the
compliance, posture, and compliance-export surfaces. Fleet and scan
routes are covered at the handler level in
`tests/test_api_tenant_isolation.py` — they authenticate tenant via API
key middleware, which requires a seeded key store that isn't part of
this matrix.

Complements:
- tests/test_api_tenant_isolation.py (handler-level unit tests, all routes)
- tests/test_clickhouse_tenant_isolation.py (store-layer contract)
- tests/test_cross_tenant_leakage.py (concurrent-write + store shape)
"""

from __future__ import annotations

from datetime import datetime, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api import stores as _stores
from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
from agent_bom.api.server import app
from agent_bom.api.store import InMemoryJobStore
from agent_bom.api.stores import set_job_store


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _seed_tenant_scan(store: InMemoryJobStore, tenant: str, *, vuln_id: str, tags: dict) -> None:
    job = ScanJob(
        job_id=f"{tenant}-scan",
        tenant_id=tenant,
        status=JobStatus.DONE,
        created_at=_now(),
        completed_at=_now(),
        request=ScanRequest(),
    )
    job.result = {
        "scan_id": f"{tenant}-scan",
        "blast_radius": [
            {
                "vulnerability_id": vuln_id,
                "package": "axios@1.4.0",
                "severity": "high",
                "fixed_version": "1.7.4",
                "affected_agents": [f"{tenant}-agent"],
                **tags,
            }
        ],
    }
    store.put(job)


@pytest.fixture
def two_tenants_seeded():
    """Seed tenant-alpha with CVE-AAAA and tenant-beta with CVE-BBBB in the job store."""
    job_store = InMemoryJobStore()
    _seed_tenant_scan(job_store, "tenant-alpha", vuln_id="CVE-AAAA", tags={"owasp_tags": ["LLM01"], "soc2_tags": ["CC6.1"]})
    _seed_tenant_scan(job_store, "tenant-beta", vuln_id="CVE-BBBB", tags={"owasp_tags": ["LLM02"], "soc2_tags": ["CC7.1"]})

    prev_job_store = _stores._store
    set_job_store(job_store)
    try:
        yield
    finally:
        _stores._store = prev_job_store


def _client_for(tenant: str) -> TestClient:
    client = TestClient(app)
    client.headers.update(
        {
            "X-Agent-Bom-Role": "admin",
            "X-Agent-Bom-Tenant-ID": tenant,
        }
    )
    return client


# ─── Compliance posture ─────────────────────────────────────────────────────


def test_compliance_posture_returns_only_authed_tenant(two_tenants_seeded) -> None:
    alpha_resp = _client_for("tenant-alpha").get("/v1/compliance")
    beta_resp = _client_for("tenant-beta").get("/v1/compliance")
    assert alpha_resp.status_code == 200
    assert beta_resp.status_code == 200

    # Alpha tagged LLM01 + CC6.1. Beta tagged LLM02 + CC7.1. Neither should surface the other's CVE.
    alpha_body = alpha_resp.text
    beta_body = beta_resp.text
    assert "CVE-BBBB" not in alpha_body, "tenant-alpha compliance leaks tenant-beta CVE"
    assert "CVE-AAAA" not in beta_body, "tenant-beta compliance leaks tenant-alpha CVE"


# ─── Compliance evidence bundle ─────────────────────────────────────────────


def test_compliance_evidence_bundle_returns_only_authed_tenant(two_tenants_seeded) -> None:
    alpha = _client_for("tenant-alpha").get("/v1/compliance/owasp-llm/report").json()
    beta = _client_for("tenant-beta").get("/v1/compliance/owasp-llm/report").json()

    assert alpha["tenant_id"] == "tenant-alpha"
    assert beta["tenant_id"] == "tenant-beta"

    alpha_text = str(alpha)
    beta_text = str(beta)
    assert "CVE-BBBB" not in alpha_text, "tenant-alpha bundle leaks tenant-beta CVE"
    assert "CVE-AAAA" not in beta_text, "tenant-beta bundle leaks tenant-alpha CVE"

    # Each bundle's evidence must only reference its own tenant's scan.
    for control in alpha["controls"]:
        for ev in control.get("evidence", []):
            assert ev.get("scan_id") != "tenant-beta-scan"
    for control in beta["controls"]:
        for ev in control.get("evidence", []):
            assert ev.get("scan_id") != "tenant-alpha-scan"


# ─── Posture (RBAC-guarded) ─────────────────────────────────────────────────


def test_posture_counts_are_tenant_scoped(two_tenants_seeded) -> None:
    alpha = _client_for("tenant-alpha").get("/v1/posture/counts").json()
    beta = _client_for("tenant-beta").get("/v1/posture/counts").json()

    # Each tenant seeded exactly one high-severity finding; totals must be 1+1, never 2.
    alpha_total = int(alpha.get("total", 0))
    beta_total = int(beta.get("total", 0))
    assert alpha_total <= 1, f"tenant-alpha posture counted tenant-beta: total={alpha_total}"
    assert beta_total <= 1, f"tenant-beta posture counted tenant-alpha: total={beta_total}"


def test_posture_credentials_are_tenant_scoped(two_tenants_seeded) -> None:
    """Credential-risk endpoint must not surface other tenants' credential names."""
    alpha = _client_for("tenant-alpha").get("/v1/posture/credentials")
    beta = _client_for("tenant-beta").get("/v1/posture/credentials")
    assert alpha.status_code == 200
    assert beta.status_code == 200
    assert "tenant-beta" not in alpha.text, "credential posture leaks tenant-beta"
    assert "tenant-alpha" not in beta.text, "credential posture leaks tenant-alpha"
