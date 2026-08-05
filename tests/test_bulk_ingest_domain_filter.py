"""Findings ingested through the connector API must be filterable by domain.

``POST /v1/findings/bulk`` is the agent-native ingest path: a caller that
already has normalized findings posts them directly. Those findings reached the
findings list fine, but ``?domain=`` returned **nothing** for them — the posture
lane taxonomy, which is how the product slices findings everywhere, was blind to
the entire connector path. A customer onboarding through the documented API got
a findings list that could not be sliced.

Asserted end-to-end through the route rather than on the mapping helper, because
the helper is only half the story: the scope filter runs on enriched rows inside
the store, so a unit test on the mapping could pass while the API still returned
an empty page.
"""

from __future__ import annotations

import pytest
from starlette.testclient import TestClient

KEY = {"X-API-Key": "domainfilterkey0123456789ab"}


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch, tmp_path):
    monkeypatch.setenv("AGENT_BOM_DB", str(tmp_path / "domain-filter.db"))
    monkeypatch.setenv("AGENT_BOM_API_KEYS", "domainfilterkey0123456789ab:analyst")
    monkeypatch.setenv("AGENT_BOM_RATE_LIMIT_KEY", "domain-filter-key")

    from agent_bom.api import compliance_hub_store as hub_mod
    from agent_bom.api import server as api_server
    from agent_bom.api import stores as api_stores
    from agent_bom.api.compliance_hub_store import set_compliance_hub_store
    from agent_bom.api.findings_count_cache import reset_findings_count_cache

    api_server._runtime_api_key_seeded = False
    api_server._shutting_down = False
    original_store = api_stores._store
    original_graph = api_stores._graph_store
    original_hub = hub_mod._HUB_STORE
    api_stores._store = None
    api_stores._graph_store = None
    set_compliance_hub_store(None)
    reset_findings_count_cache()
    try:
        with TestClient(api_server.app) as c:
            yield c
    finally:
        api_stores._store = original_store
        api_stores._graph_store = original_graph
        set_compliance_hub_store(original_hub)
        reset_findings_count_cache()


def _ingest(client: TestClient, findings: list[dict], *, source: str) -> None:
    resp = client.post("/v1/findings/bulk", headers=KEY, json={"findings": findings, "source": source})
    assert resp.status_code == 201, resp.text


def test_bulk_ingested_findings_are_reachable_by_domain(client: TestClient) -> None:
    """A CVE posted through the connector API belongs to the vuln lane.

    ``source`` here is the endpoint's own default label, which is NOT a
    ``FindingSource`` member. That is the point: the label describes provenance,
    and it must not decide whether the finding has a security domain.
    """
    _ingest(
        client,
        [
            {
                "id": f"conn-{i}",
                "finding_type": "CVE",
                "severity": "high",
                "title": f"CVE-2026-200{i} in pkg-{i}",
                "package_name": f"pkg-{i}",
                "package_version": "1.0.0",
                "provider": "aws",
                "cvss_score": 7.5,
            }
            for i in range(5)
        ],
        source="api",
    )

    everything = client.get("/v1/findings", headers=KEY, params={"limit": 50}).json()
    assert len(everything.get("findings") or []) == 5, everything

    scoped = client.get("/v1/findings", headers=KEY, params={"limit": 50, "domain": "vuln"}).json()
    assert len(scoped.get("findings") or []) == 5, "CVE findings ingested via /v1/findings/bulk are invisible to ?domain=vuln"


def test_bulk_ingest_routes_each_type_to_its_own_lane(client: TestClient) -> None:
    """The lane must follow the finding's type, not the connector's name."""
    _ingest(
        client,
        [
            {"id": "t-cve", "finding_type": "CVE", "severity": "high", "title": "CVE-2026-3001", "package_name": "p"},
            {"id": "t-secret", "finding_type": "CREDENTIAL_EXPOSURE", "severity": "critical", "title": "AWS key in repo"},
            {"id": "t-ciem", "finding_type": "CIEM_OVER_PRIVILEGE", "severity": "high", "title": "Unused write grants"},
        ],
        source="acme-connector",
    )

    for domain, expected_id in (("vuln", "t-cve"), ("aspm", "t-secret"), ("cspm", "t-ciem")):
        page = client.get("/v1/findings", headers=KEY, params={"limit": 50, "domain": domain}).json()
        ids = {row.get("id") for row in page.get("findings") or []}
        assert expected_id in ids, f"{expected_id} did not reach the {domain} lane: {sorted(ids)}"
