from __future__ import annotations

import json
import sqlite3

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app, configure_api
from agent_bom.db.schema import init_db
from agent_bom.intel_lookup import list_intel_sources, lookup_advisory, match_packages
from agent_bom.mcp_tools.intel import intel_lookup_impl, intel_match_impl, intel_sources_impl
from tests.auth_helpers import PROXY_SECRET

VIEWER_HEADERS = {
    "X-Agent-Bom-Role": "viewer",
    "X-Agent-Bom-Tenant-ID": "tenant-alpha",
    "X-Agent-Bom-Proxy-Secret": PROXY_SECRET,
}


@pytest.fixture
def intel_db(tmp_path, monkeypatch: pytest.MonkeyPatch):
    db_path = tmp_path / "intel.db"
    monkeypatch.setenv("AGENT_BOM_DB_PATH", str(db_path))
    conn = init_db(db_path)
    _seed_intel(conn)
    conn.close()
    return db_path


@pytest.fixture
def intel_client(monkeypatch: pytest.MonkeyPatch, intel_db):  # noqa: ANN001
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH", "1")
    monkeypatch.setenv("AGENT_BOM_TRUST_PROXY_AUTH_SECRET", PROXY_SECRET)
    configure_api(api_key=None)
    try:
        with TestClient(app) as client:
            yield client
    finally:
        monkeypatch.delenv("AGENT_BOM_TRUST_PROXY_AUTH", raising=False)
        configure_api(api_key=None)


def _seed_intel(conn: sqlite3.Connection) -> None:
    conn.execute(
        """
        INSERT INTO vulns (
            id, summary, severity, cvss_score, cvss_vector, fixed_version,
            cwe_ids, aliases, published, modified, source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "GHSA-abcd-1234-wxyz",
            "requests test advisory",
            "high",
            8.1,
            "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:N",
            "2.32.0",
            "CWE-79,CWE-352",
            "CVE-2026-12345",
            "2026-05-01T00:00:00+00:00",
            "2026-05-02T00:00:00+00:00",
            "ghsa",
        ),
    )
    conn.execute(
        """
        INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("GHSA-abcd-1234-wxyz", "pypi", "requests", "0", "2.32.0", ""),
    )
    conn.execute(
        "INSERT INTO epss_scores(cve_id, probability, percentile, updated_at) VALUES (?, ?, ?, ?)",
        ("CVE-2026-12345", 0.91, 99.1, "2026-05-03T00:00:00+00:00"),
    )
    conn.execute(
        "INSERT INTO kev_entries(cve_id, date_added, due_date, product, vendor_project) VALUES (?, ?, ?, ?, ?)",
        ("CVE-2026-12345", "2026-05-04", "2026-06-04", "requests", "python"),
    )
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        ("ghsa", "2026-05-05T00:00:00+00:00", 1),
    )
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        ("epss", "2026-05-05T00:00:00+00:00", 1),
    )
    conn.commit()


def test_list_intel_sources_includes_feed_run_metadata(intel_db) -> None:  # noqa: ANN001
    body = list_intel_sources(db_path=intel_db)

    assert body["schema_version"] == "intel.sources.v1"
    ghsa = next(source for source in body["sources"] if source["source_id"] == "ghsa")
    assert ghsa["tier"] == 1
    assert ghsa["feed_run"]["last_synced"] == "2026-05-05T00:00:00+00:00"
    assert ghsa["feed_run"]["record_count"] == 1


def test_lookup_advisory_by_alias_returns_evidence_links(intel_db) -> None:  # noqa: ANN001
    body = lookup_advisory("CVE-2026-12345", db_path=intel_db)

    assert body["found"] is True
    advisory = body["advisory"]
    assert advisory["id"] == "GHSA-abcd-1234-wxyz"
    assert advisory["canonical_ids"]["cves"] == ["CVE-2026-12345"]
    assert advisory["canonical_ids"]["cwes"] == ["CWE-352", "CWE-79"]
    assert advisory["epss_probability"] == pytest.approx(0.91)
    assert advisory["is_kev"] is True
    assert any(link["kind"] == "cve" for link in advisory["evidence_links"])
    assert advisory["affected"][0]["package_name"] == "requests"


def test_match_packages_returns_inventory_linked_advisories(intel_db) -> None:  # noqa: ANN001
    body = match_packages(
        [{"purl": "pkg:pypi/requests@2.31.0", "inventory_ref": "pkg-1"}],
        db_path=intel_db,
    )

    assert body["schema_version"] == "intel.match.v1"
    assert body["matched_packages"] == 1
    match = body["matches"][0]
    assert match["package"]["inventory_ref"] == "pkg-1"
    assert match["match_count"] == 1
    advisory = match["advisories"][0]
    assert advisory["epss_probability"] == pytest.approx(0.91)
    assert advisory["is_kev"] is True
    assert any(link["kind"] == "cwe" for link in match["evidence_links"])


def test_intel_api_routes_are_read_only_and_tenant_scoped(intel_client: TestClient) -> None:
    sources = intel_client.get("/v1/intel/sources", headers=VIEWER_HEADERS)
    assert sources.status_code == 200
    assert sources.json()["count"] >= 3

    advisory = intel_client.get("/v1/intel/advisories/CVE-2026-12345", headers=VIEWER_HEADERS)
    assert advisory.status_code == 200
    assert advisory.json()["found"] is True

    match = intel_client.post(
        "/v1/intel/match",
        headers=VIEWER_HEADERS,
        json={"packages": [{"ecosystem": "pypi", "name": "requests", "version": "2.31.0"}]},
    )
    assert match.status_code == 200
    assert match.json()["matched_packages"] == 1


def test_intel_api_match_validates_package_shape(intel_client: TestClient) -> None:
    response = intel_client.post("/v1/intel/match", headers=VIEWER_HEADERS, json={"packages": [{"name": "requests"}]})

    assert response.status_code == 422
    assert "ecosystem" in response.json()["detail"]


@pytest.mark.asyncio
async def test_mcp_intel_tools_return_agent_native_json(intel_db) -> None:  # noqa: ANN001
    lookup = json.loads(await intel_lookup_impl(advisory_id="CVE-2026-12345"))
    assert lookup["found"] is True

    match = json.loads(await intel_match_impl(purl="pkg:pypi/requests@2.31.0"))
    assert match["matched_packages"] == 1

    sources = json.loads(await intel_sources_impl())
    assert sources["schema_version"] == "intel.sources.v1"
