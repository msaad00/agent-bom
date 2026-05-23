from __future__ import annotations

import json
import sqlite3
from datetime import UTC, datetime
from types import SimpleNamespace

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app, configure_api
from agent_bom.db.schema import init_db
from agent_bom.intel_fetch import (
    GovernedIntelFetchError,
    fetch_governed_raw_artifact,
    store_raw_artifact,
)
from agent_bom.intel_lookup import build_daily_brief, list_intel_sources, lookup_advisory, match_packages
from agent_bom.mcp_tools.intel import intel_daily_brief_impl, intel_lookup_impl, intel_match_impl, intel_sources_impl
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
        """
        INSERT INTO vulns (
            id, summary, severity, cvss_score, cvss_vector, fixed_version,
            cwe_ids, aliases, published, modified, source
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            "CVE-2026-55555",
            "vendor GPU advisory",
            "high",
            7.8,
            "",
            "6.2",
            "CWE-119",
            "",
            "2026-05-04T00:00:00+00:00",
            "2026-05-05T00:00:00+00:00",
            "amd_psirt",
        ),
    )
    conn.execute(
        """
        INSERT INTO affected(vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
        VALUES (?, ?, ?, ?, ?, ?)
        """,
        ("CVE-2026-55555", "pypi", "rocm-smi-lib", "0", "6.2", ""),
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
        "INSERT INTO kev_entries(cve_id, date_added, due_date, product, vendor_project) VALUES (?, ?, ?, ?, ?)",
        ("CVE-2026-55555", "2026-05-21", "2026-06-21", "rocm-smi-lib", "gpu"),
    )
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        ("ghsa", "2026-05-05T00:00:00+00:00", 1),
    )
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        ("epss", "2026-05-05T00:00:00+00:00", 1),
    )
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count, metadata_json) VALUES (?, ?, ?, ?)",
        (
            "amd_psirt",
            "2026-05-05T00:00:00+00:00",
            1,
            '{"validation_status":"experimental_seed_plus_guarded_refresh","content_hash":"sha256:test"}',
        ),
    )
    conn.commit()


def test_list_intel_sources_includes_feed_run_metadata(intel_db) -> None:  # noqa: ANN001
    body = list_intel_sources(db_path=intel_db)

    assert body["schema_version"] == "intel.sources.v1"
    ghsa = next(source for source in body["sources"] if source["source_id"] == "ghsa")
    assert ghsa["tier"] == 1
    assert ghsa["source_url"]
    assert ghsa["license_or_terms_url"]
    assert ghsa["robots_policy"] == "api_or_osv_mirror"
    assert ghsa["support_status"] == "supported"
    assert ghsa["feed_run"]["last_synced"] == "2026-05-05T00:00:00+00:00"
    assert ghsa["feed_run"]["record_count"] == 1

    amd = next(source for source in body["sources"] if source["source_id"] == "amd_psirt")
    assert amd["support_status"] == "experimental"
    assert amd["validation_status"] == "experimental_seed_plus_guarded_refresh"
    assert amd["feed_run"]["content_hash"] == "sha256:test"


def test_lookup_advisory_by_alias_returns_evidence_links(intel_db) -> None:  # noqa: ANN001
    body = lookup_advisory("CVE-2026-12345", db_path=intel_db)

    assert body["found"] is True
    advisory = body["advisory"]
    assert advisory["id"] == "GHSA-abcd-1234-wxyz"
    assert advisory["canonical_ids"]["cves"] == ["CVE-2026-12345"]
    assert advisory["canonical_ids"]["cwes"] == ["CWE-352", "CWE-79"]
    assert advisory["epss_probability"] == pytest.approx(0.91)
    assert advisory["is_kev"] is True
    assert advisory["match_method"] == "id_or_alias"
    assert advisory["match_confidence"] == "high"
    assert advisory["source_policy"]["support_status"] == "supported"
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
    assert advisory["match_method"] == "inventory_native_package"
    assert advisory["match_confidence"] == "high"
    assert any(link["kind"] == "cwe" for link in match["evidence_links"])


def test_daily_brief_summarizes_local_sources_without_scraping_claims(intel_db) -> None:  # noqa: ANN001
    body = build_daily_brief(
        [
            {"purl": "pkg:pypi/requests@2.31.0", "inventory_ref": "pkg-1"},
            {"ecosystem": "pypi", "name": "rocm-smi-lib", "version": "6.1", "inventory_ref": "gpu-1"},
        ],
        db_path=intel_db,
        now=datetime(2026, 5, 22, tzinfo=UTC),
    )

    assert body["schema_version"] == "intel.daily_brief.v1"
    assert body["inputs"]["epss_threshold"] == 0.7
    assert any(item["id"] == "CVE-2026-55555" for item in body["sections"]["kev_last_24h"])
    assert body["sections"]["high_epss_inventory"][0]["advisory"]["id"] == "GHSA-abcd-1234-wxyz"
    assert body["sections"]["vendor_advisories"][0]["advisory"]["source"] == "amd_psirt"
    assert body["source_registry"]["feed_runs"]["amd_psirt"]["support_status"] == "experimental"
    assert "Vendor webpage scraping is not shipped" in body["limitations"][1]


def test_daily_brief_matches_governed_telemetry_and_tenant_profile(intel_db) -> None:  # noqa: ANN001
    body = build_daily_brief(
        [{"purl": "pkg:pypi/requests@2.31.0", "inventory_ref": "pkg-1"}],
        telemetry_indicators=[
            {
                "indicator": "198.51.100.42",
                "type": "ipv4",
                "hit_count": 3,
                "telemetry_hits": ["runtime-session-1"],
                "source_url": "https://example.invalid/ioc-feed",
                "license": "internal-use",
                "fetched_at": "2026-05-22T00:00:00+00:00",
                "content_hash": "sha256:ioc",
            }
        ],
        campaign_activity=[
            {
                "name": "gpu-targeting-campaign",
                "sectors": ["ai infrastructure"],
                "geos": ["us"],
                "source_url": "https://example.invalid/campaign",
                "license": "link-only",
            }
        ],
        ransomware_claims=[
            {
                "group": "example-extortion",
                "victim_sectors": ["ai infrastructure"],
                "victim_geos": ["us"],
                "source_url": "https://example.invalid/ransomware",
                "license": "link-only",
            }
        ],
        tenant_profile={"sectors": ["AI Infrastructure"], "geos": ["US"], "tenant_ref": "tenant-alpha"},
        db_path=intel_db,
        now=datetime(2026, 5, 22, tzinfo=UTC),
    )

    assert body["inputs"]["telemetry_configured"] is True
    assert body["inputs"]["sector_geo_configured"] is True
    assert body["sections"]["ioc_telemetry_hits"][0]["match_method"] == "telemetry_indicator_exact"
    assert body["sections"]["ioc_telemetry_hits"][0]["evidence"]["content_hash"] == "sha256:ioc"
    assert body["sections"]["campaign_matches"][0]["matched_on"] == ["sector", "geo"]
    assert body["sections"]["ransomware_sector_matches"][0]["group"] == "example-extortion"


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

    brief = intel_client.post(
        "/v1/intel/daily-brief",
        headers=VIEWER_HEADERS,
        json={
            "packages": [{"ecosystem": "pypi", "name": "requests", "version": "2.31.0"}],
            "telemetry_indicators": [{"indicator": "198.51.100.42", "hit_count": 1}],
            "tenant_profile": {"sectors": ["AI Infrastructure"]},
        },
    )
    assert brief.status_code == 200
    assert brief.json()["schema_version"] == "intel.daily_brief.v1"
    assert brief.json()["sections"]["ioc_telemetry_hits"][0]["indicator"] == "198.51.100.42"


def test_intel_api_match_validates_package_shape(intel_client: TestClient) -> None:
    response = intel_client.post("/v1/intel/match", headers=VIEWER_HEADERS, json={"packages": [{"name": "requests"}]})

    assert response.status_code == 422
    assert "ecosystem" in response.json()["detail"]


def test_intel_api_match_value_errors_use_single_error_envelope(intel_client: TestClient) -> None:
    response = intel_client.post("/v1/intel/match", headers=VIEWER_HEADERS, json={"packages": [{"purl": "not-a-purl"}]})

    assert response.status_code == 422
    body = response.json()
    assert body["error"]["code"] == "VALIDATION_ERROR"
    assert body["error"]["message"] == "purl must start with pkg:"
    assert body["error"]["details"] == "purl must start with pkg:"
    assert body["detail"] == "purl must start with pkg:"
    assert not body["error"]["details"].startswith("{")


@pytest.mark.asyncio
async def test_mcp_intel_tools_return_agent_native_json(intel_db) -> None:  # noqa: ANN001
    lookup = json.loads(await intel_lookup_impl(advisory_id="CVE-2026-12345"))
    assert lookup["found"] is True

    match = json.loads(await intel_match_impl(purl="pkg:pypi/requests@2.31.0"))
    assert match["matched_packages"] == 1

    sources = json.loads(await intel_sources_impl())
    assert sources["schema_version"] == "intel.sources.v1"

    brief = json.loads(await intel_daily_brief_impl(packages=[{"purl": "pkg:pypi/requests@2.31.0"}]))
    assert brief["schema_version"] == "intel.daily_brief.v1"


@pytest.mark.asyncio
async def test_governed_raw_artifact_fetch_records_metadata(monkeypatch, tmp_path) -> None:  # noqa: ANN001
    source = next(source for source in list_intel_sources()["sources"] if source["source_id"] == "cisa_kev")
    from agent_bom.intel_lookup import CANONICAL_INTEL_SOURCES

    canonical = next(item for item in CANONICAL_INTEL_SOURCES if item.source_id == source["source_id"])

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *_args):
            return None

    async def _fake_request(_client, _method, _url, **_kwargs):
        return SimpleNamespace(
            status_code=200,
            headers={"content-type": "application/json", "etag": "abc", "last-modified": "Fri, 22 May 2026 00:00:00 GMT"},
            content=b'{"knownExploitedVulnerabilities":[]}',
        )

    monkeypatch.setattr("agent_bom.intel_fetch.create_client", lambda timeout=15.0: _Client())
    monkeypatch.setattr("agent_bom.intel_fetch.request_with_retry", _fake_request)

    artifact = await fetch_governed_raw_artifact(canonical)
    stored = store_raw_artifact(artifact, tmp_path)

    assert artifact.source_id == "cisa_kev"
    assert artifact.content_hash.startswith("sha256:")
    assert stored["etag"] == "abc"
    assert (tmp_path / "cisa_kev").exists()


def test_governed_raw_artifact_fetch_rejects_manual_only_sources() -> None:
    from agent_bom.intel_fetch import ensure_source_fetch_allowed
    from agent_bom.intel_lookup import CANONICAL_INTEL_SOURCES

    intel = next(source for source in CANONICAL_INTEL_SOURCES if source.source_id == "intel_psirt")

    with pytest.raises(GovernedIntelFetchError):
        ensure_source_fetch_allowed(intel)
