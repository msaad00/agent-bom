"""API tests for GET /v1/mitre/coverage (#3892).

Coverage reflects the technique tags actually carried by the tenant's
findings. An empty estate returns honest zeros with real catalogue
denominators, and tenants are isolated from each other.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

from agent_bom import atlas
from agent_bom.api.compliance_hub_store import get_compliance_hub_store, reset_compliance_hub_store
from agent_bom.api.server import app
from agent_bom.mitre_attack import get_attack_techniques
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


@pytest.fixture(autouse=True)
def _reset_store():
    from agent_bom.api.server import set_job_store
    from agent_bom.api.store import InMemoryJobStore

    reset_compliance_hub_store()
    set_job_store(InMemoryJobStore())
    yield
    reset_compliance_hub_store()
    set_job_store(InMemoryJobStore())


def _client(tenant: str = "tenant-alpha", role: str = "admin") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def _attack_id() -> str:
    return next(iter(get_attack_techniques()))


def _atlas_id() -> str:
    return next(iter(atlas.ATLAS_TECHNIQUES))


def _frameworks(payload: dict) -> dict:
    return {f["framework"]: f for f in payload["frameworks"]}


def test_empty_estate_returns_honest_zeros() -> None:
    resp = _client().get("/v1/mitre/coverage")
    assert resp.status_code == 200
    body = resp.json()
    assert body["finding_count"] == 0
    frameworks = _frameworks(body)
    assert set(frameworks) == {"mitre_attack", "mitre_atlas", "mitre_maestro"}
    for fw in frameworks.values():
        assert fw["covered_count"] == 0
        assert fw["coverage_pct"] == 0.0
        assert fw["covered_techniques"] == []
        assert fw["catalogue_total"] > 0
    assert "safe" in body["uncovered_definition"].lower()


def test_coverage_reflects_hub_finding_tags() -> None:
    tid = _attack_id()
    aid = _atlas_id()
    get_compliance_hub_store().add(
        "tenant-alpha",
        [
            {"id": "hub-1", "severity": "high", "attack_tags": [tid], "atlas_tags": [aid], "source": "huggingface"},
            {"id": "hub-2", "severity": "low", "attack_tags": [tid]},
        ],
    )
    body = _client().get("/v1/mitre/coverage").json()
    frameworks = _frameworks(body)

    attack = frameworks["mitre_attack"]
    assert attack["covered_count"] == 1
    covered = attack["covered_techniques"][0]
    assert covered["id"] == tid
    assert covered["finding_count"] == 2
    assert set(covered["finding_refs"]) == {"hub-1", "hub-2"}

    atlas_fw = frameworks["mitre_atlas"]
    assert atlas_fw["covered_count"] == 1
    assert atlas_fw["covered_techniques"][0]["id"] == aid

    maestro = frameworks["mitre_maestro"]
    kc1 = [t for t in maestro["covered_techniques"] if t["id"] == "KC1"]
    assert kc1 and kc1[0]["finding_count"] == 1


def test_tenant_isolation() -> None:
    tid = _attack_id()
    get_compliance_hub_store().add("tenant-alpha", [{"id": "a1", "attack_tags": [tid]}])

    beta = _client(tenant="tenant-beta").get("/v1/mitre/coverage").json()
    assert _frameworks(beta)["mitre_attack"]["covered_count"] == 0

    alpha = _client(tenant="tenant-alpha").get("/v1/mitre/coverage").json()
    assert _frameworks(alpha)["mitre_attack"]["covered_count"] == 1


def test_unknown_technique_tags_do_not_inflate_coverage() -> None:
    get_compliance_hub_store().add(
        "tenant-alpha",
        [{"id": "a1", "attack_tags": ["T0000000", "bogus"], "atlas_tags": ["AML.T9999"]}],
    )
    body = _client().get("/v1/mitre/coverage").json()
    frameworks = _frameworks(body)
    assert frameworks["mitre_attack"]["covered_count"] == 0
    assert frameworks["mitre_atlas"]["covered_count"] == 0


def test_read_gated_endpoint_serves_read_roles() -> None:
    # The endpoint is gated on the "read" permission. viewer/analyst/admin all
    # hold it; a viewer must be able to read coverage (read-only surface).
    body = _client(role="viewer").get("/v1/mitre/coverage").json()
    assert set(_frameworks(body)) == {"mitre_attack", "mitre_atlas", "mitre_maestro"}
