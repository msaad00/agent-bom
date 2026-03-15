"""Tests for CWE enrichment — NVD extraction, DB storage, skip optimization, compliance tagging."""

from __future__ import annotations

import json
import sqlite3
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from agent_bom.db.schema import init_db
from agent_bom.db.sync import sync_nvd
from agent_bom.enrichment import enrich_vulnerabilities
from agent_bom.models import BlastRadius, Package, Severity, Vulnerability

# ── OSV CWE extraction ──────────────────────────────────────────────────────


def test_build_vulnerabilities_extracts_cwe_ids():
    """build_vulnerabilities() should extract CWE IDs from database_specific."""
    from agent_bom.scanners import build_vulnerabilities

    pkg = Package(name="flask", version="2.2.0", ecosystem="pypi")
    vuln_data = [
        {
            "id": "GHSA-xxxx-yyyy-zzzz",
            "summary": "XSS in flask",
            "aliases": ["CVE-2099-1234"],
            "database_specific": {
                "cwe_ids": ["CWE-79", "CWE-80"],
                "severity": "HIGH",
            },
        }
    ]

    vulns = build_vulnerabilities(vuln_data, pkg)
    assert len(vulns) == 1
    assert "CWE-79" in vulns[0].cwe_ids
    assert "CWE-80" in vulns[0].cwe_ids


def test_build_vulnerabilities_no_cwe_ids():
    """build_vulnerabilities() handles missing CWE IDs gracefully."""
    from agent_bom.scanners import build_vulnerabilities

    pkg = Package(name="requests", version="2.0.0", ecosystem="pypi")
    vuln_data = [
        {
            "id": "CVE-2099-0001",
            "summary": "Some vuln",
        }
    ]

    vulns = build_vulnerabilities(vuln_data, pkg)
    assert len(vulns) == 1
    assert vulns[0].cwe_ids == []


def test_build_vulnerabilities_filters_invalid_cwe_ids():
    """build_vulnerabilities() filters out non-CWE strings from cwe_ids."""
    from agent_bom.scanners import build_vulnerabilities

    pkg = Package(name="django", version="3.0", ecosystem="pypi")
    vuln_data = [
        {
            "id": "GHSA-test-test-test",
            "summary": "Test vuln",
            "database_specific": {
                "cwe_ids": ["CWE-89", "not-a-cwe", 42, None, "CWE-79"],
            },
        }
    ]

    vulns = build_vulnerabilities(vuln_data, pkg)
    assert vulns[0].cwe_ids == ["CWE-89", "CWE-79"]


# ── CWE-based compliance tagging (no ecosystem guard) ───────────────────────


def test_vuln_compliance_cwe_tagging_for_pypi():
    """CWE-based compliance tags should apply to PyPI packages (not just SAST)."""
    from agent_bom.vuln_compliance import tag_vulnerability

    vuln = Vulnerability(
        id="CVE-2099-0001",
        summary="SQL injection",
        severity=Severity.HIGH,
        cwe_ids=["CWE-89"],
    )
    pkg = Package(name="sqlalchemy", version="1.0.0", ecosystem="pypi")

    tags = tag_vulnerability(vuln, pkg)

    # CWE-89 should map to owasp_llm tags (via CWE_COMPLIANCE_MAP)
    assert "owasp_llm" in tags
    assert "LLM02" in tags["owasp_llm"]


def test_vuln_compliance_no_cwe_no_extra_tags():
    """Without CWE IDs, only severity/context-based tags appear."""
    from agent_bom.vuln_compliance import tag_vulnerability

    vuln = Vulnerability(
        id="CVE-2099-0002",
        summary="Some vuln",
        severity=Severity.MEDIUM,
        cwe_ids=[],
    )
    pkg = Package(name="requests", version="2.0.0", ecosystem="pypi")

    tags = tag_vulnerability(vuln, pkg)

    # Should still have base tags (nist_csf, cis, iso_27001 etc.) but
    # no CWE-derived extras
    assert "nist_csf" in tags
    # LLM02 is a CWE-derived tag — should NOT appear without CWE data
    for framework_tags in tags.values():
        assert "LLM02" not in framework_tags


def test_blast_radius_cwe_tagging_owasp():
    """BlastRadius-level OWASP tagger should use CWE for non-SAST packages."""
    from agent_bom.models import Agent, AgentType
    from agent_bom.owasp import tag_blast_radius

    agent = Agent(name="test-agent", agent_type=AgentType.CLAUDE_CODE, config_path="test.json")
    vuln = Vulnerability(
        id="CVE-2099-0003",
        summary="Command injection",
        severity=Severity.HIGH,
        cwe_ids=["CWE-78"],
    )
    pkg = Package(name="paramiko", version="2.0.0", ecosystem="pypi")
    br = BlastRadius(
        package=pkg,
        vulnerability=vuln,
        affected_agents=[agent],
        affected_servers=[],
        exposed_credentials=[],
        exposed_tools=[],
    )

    tags = tag_blast_radius(br)
    assert "LLM02" in tags


def test_blast_radius_cwe_tagging_nist_csf():
    """BlastRadius-level NIST CSF tagger should use CWE for non-SAST packages."""
    from agent_bom.models import Agent, AgentType
    from agent_bom.nist_csf import tag_blast_radius

    agent = Agent(name="test-agent", agent_type=AgentType.CLAUDE_CODE, config_path="test.json")
    vuln = Vulnerability(
        id="CVE-2099-0004",
        summary="SQL injection",
        severity=Severity.HIGH,
        cwe_ids=["CWE-89"],
    )
    pkg = Package(name="psycopg2", version="2.9.0", ecosystem="pypi")
    br = BlastRadius(
        package=pkg,
        vulnerability=vuln,
        affected_agents=[agent],
        affected_servers=[],
        exposed_credentials=[],
        exposed_tools=[],
    )

    tags = tag_blast_radius(br)
    # CWE-89 should add nist_csf tags via CWE_COMPLIANCE_MAP
    from agent_bom.constants import CWE_COMPLIANCE_MAP

    expected_nist = CWE_COMPLIANCE_MAP.get("CWE-89", {}).get("nist_csf", [])
    for t in expected_nist:
        assert t in tags


# ── Local DB round-trip ──────────────────────────────────────────────────────


def test_local_db_cwe_round_trip(tmp_path):
    """CWE IDs survive the DB write → read cycle."""
    from agent_bom.db.lookup import lookup_package
    from agent_bom.db.schema import init_db

    db_path = tmp_path / "test_cwe.db"
    conn = init_db(db_path)

    # Insert a vuln with CWE IDs
    conn.execute(
        """
        INSERT INTO vulns (id, summary, severity, cvss_score, fixed_version, cwe_ids, published, modified, source)
        VALUES ('CVE-2099-CWE', 'Test CWE', 'high', 7.5, '1.1.0', 'CWE-79,CWE-89', '2099-01-01', '2099-01-01', 'osv')
        """
    )
    conn.execute(
        """
        INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
        VALUES ('CVE-2099-CWE', 'pypi', 'flask', '0', '1.1.0', '')
        """
    )
    conn.commit()

    results = lookup_package(conn, "PyPI", "flask", "1.0.0")
    assert len(results) == 1
    assert results[0].cwe_ids == ["CWE-79", "CWE-89"]
    conn.close()


def test_local_db_empty_cwe(tmp_path):
    """Empty CWE column returns empty list."""
    from agent_bom.db.lookup import lookup_package
    from agent_bom.db.schema import init_db

    db_path = tmp_path / "test_no_cwe.db"
    conn = init_db(db_path)

    conn.execute(
        """
        INSERT INTO vulns (id, summary, severity, cvss_score, fixed_version, cwe_ids, published, modified, source)
        VALUES ('CVE-2099-NOCWE', 'No CWE', 'medium', 5.0, NULL, '', '2099-01-01', '2099-01-01', 'osv')
        """
    )
    conn.execute(
        """
        INSERT INTO affected (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
        VALUES ('CVE-2099-NOCWE', 'pypi', 'requests', '0', '', '')
        """
    )
    conn.commit()

    results = lookup_package(conn, "PyPI", "requests", "1.0.0")
    assert len(results) == 1
    assert results[0].cwe_ids == []
    conn.close()


# ── DB schema migration ─────────────────────────────────────────────────────


def test_db_migration_v1_to_v2(tmp_path):
    """Schema v1 → v2 migration adds cwe_ids column."""
    db_path = tmp_path / "test_migrate.db"

    # Create a v1 database manually (no cwe_ids column)
    conn = sqlite3.connect(str(db_path))
    conn.executescript("""
        PRAGMA journal_mode = WAL;
        CREATE TABLE IF NOT EXISTS schema_version (version INTEGER NOT NULL);
        INSERT INTO schema_version(version) VALUES (1);

        CREATE TABLE IF NOT EXISTS vulns (
            id TEXT PRIMARY KEY,
            summary TEXT NOT NULL,
            severity TEXT NOT NULL,
            cvss_score REAL,
            cvss_vector TEXT,
            fixed_version TEXT,
            published TEXT,
            modified TEXT,
            source TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS affected (
            vuln_id TEXT NOT NULL,
            ecosystem TEXT NOT NULL,
            package_name TEXT NOT NULL,
            introduced TEXT,
            fixed TEXT,
            last_affected TEXT,
            PRIMARY KEY (vuln_id, ecosystem, package_name, introduced)
        );

        CREATE TABLE IF NOT EXISTS epss_scores (
            cve_id TEXT PRIMARY KEY,
            probability REAL NOT NULL,
            percentile REAL,
            updated_at TEXT NOT NULL
        );

        CREATE TABLE IF NOT EXISTS kev_entries (
            cve_id TEXT PRIMARY KEY,
            date_added TEXT,
            due_date TEXT,
            product TEXT,
            vendor_project TEXT
        );

        CREATE TABLE IF NOT EXISTS sync_meta (
            source TEXT PRIMARY KEY,
            last_synced TEXT,
            record_count INTEGER DEFAULT 0
        );

        INSERT INTO vulns (id, summary, severity, source) VALUES ('CVE-OLD', 'old vuln', 'high', 'osv');
    """)
    conn.commit()
    conn.close()

    # Now open via init_db — should trigger migration
    from agent_bom.db.schema import init_db

    conn = init_db(db_path)

    # Verify schema version bumped (v1 → v2 → v3 via chained migrations)
    from agent_bom.db.schema import _SCHEMA_VERSION

    version = conn.execute("SELECT version FROM schema_version").fetchone()[0]
    assert version == _SCHEMA_VERSION

    # Verify cwe_ids column exists and old data has default
    row = conn.execute("SELECT cwe_ids FROM vulns WHERE id = 'CVE-OLD'").fetchone()
    assert row is not None
    assert row[0] == ""  # default empty string

    # Verify aliases column exists (v2 → v3 migration)
    aliases_row = conn.execute("SELECT aliases FROM vulns WHERE id = 'CVE-OLD'").fetchone()
    assert aliases_row is not None
    assert aliases_row[0] == ""  # default empty string

    conn.close()


# ── sync_nvd CWE extraction ───────────────────────────────────────────────


def _make_conn() -> sqlite3.Connection:
    return init_db(Path(":memory:"))


def _insert_vuln(
    conn: sqlite3.Connection,
    cve_id: str,
    severity: str = "unknown",
    cvss_score: float | None = None,
    cwe_ids: str = "",
) -> None:
    conn.execute(
        """
        INSERT OR REPLACE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, cwe_ids, published, modified, source)
        VALUES (?, ?, ?, ?, NULL, NULL, ?, '', '', 'osv')
        """,
        (cve_id, f"Test {cve_id}", severity, cvss_score, cwe_ids),
    )
    conn.commit()


def _nvd_response_with_cwes(
    cve_id: str,
    score: float = 8.1,
    severity: str = "HIGH",
    cwes: list[str] | None = None,
) -> bytes:
    weaknesses = []
    if cwes:
        weaknesses = [{"source": "nvd@nist.gov", "description": [{"lang": "en", "value": c} for c in cwes]}]
    payload = {
        "vulnerabilities": [
            {
                "cve": {
                    "id": cve_id,
                    "weaknesses": weaknesses,
                    "metrics": {
                        "cvssMetricV31": [
                            {
                                "cvssData": {
                                    "baseScore": score,
                                    "baseSeverity": severity,
                                    "vectorString": "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:N/A:N",
                                }
                            }
                        ]
                    },
                }
            }
        ]
    }
    return json.dumps(payload).encode()


def _mock_urlopen_with_cwes(cwes: list[str], score: float = 8.1, severity: str = "HIGH"):
    def side_effect(req, timeout=30):
        from urllib.parse import parse_qs, urlparse

        url = req.full_url if hasattr(req, "full_url") else str(req)
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        cve_id = qs.get("cveId", ["CVE-UNKNOWN"])[0]
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=cm)
        cm.__exit__ = MagicMock(return_value=False)
        cm.read = MagicMock(return_value=_nvd_response_with_cwes(cve_id, score, severity, cwes))
        return cm

    return side_effect


def test_sync_nvd_stores_cwe_ids() -> None:
    """sync_nvd should extract CWE IDs from NVD response and store in DB."""
    conn = _make_conn()
    _insert_vuln(conn, "CVE-2024-99010", severity="unknown")

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen_with_cwes(["CWE-79", "CWE-89"])):
        with patch("time.sleep"):
            count = sync_nvd(conn, url="https://services.nvd.nist.gov/rest/json/cves/2.0", max_entries=10)

    assert count == 1
    row = conn.execute("SELECT cwe_ids FROM vulns WHERE id = 'CVE-2024-99010'").fetchone()
    cwes = set(row["cwe_ids"].split(","))
    assert cwes == {"CWE-79", "CWE-89"}


def test_sync_nvd_merges_cwe_ids_with_existing() -> None:
    """NVD CWE IDs should be merged with existing ones from OSV/GHSA."""
    conn = _make_conn()
    _insert_vuln(conn, "CVE-2024-99011", severity="unknown", cwe_ids="CWE-79")

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen_with_cwes(["CWE-89"])):
        with patch("time.sleep"):
            sync_nvd(conn, url="https://services.nvd.nist.gov/rest/json/cves/2.0", max_entries=10)

    row = conn.execute("SELECT cwe_ids FROM vulns WHERE id = 'CVE-2024-99011'").fetchone()
    cwes = set(row["cwe_ids"].split(","))
    assert cwes == {"CWE-79", "CWE-89"}


def test_sync_nvd_preserves_existing_cwes_when_nvd_has_none() -> None:
    """When NVD response has no CWE data, existing CWE IDs must not be lost."""
    conn = _make_conn()
    _insert_vuln(conn, "CVE-2024-99014", severity="unknown", cwe_ids="CWE-79")

    with patch("urllib.request.urlopen", side_effect=_mock_urlopen_with_cwes([], score=7.5)):
        with patch("time.sleep"):
            sync_nvd(conn, url="https://services.nvd.nist.gov/rest/json/cves/2.0", max_entries=10)

    row = conn.execute("SELECT cwe_ids FROM vulns WHERE id = 'CVE-2024-99014'").fetchone()
    assert row["cwe_ids"] == "CWE-79"


def test_sync_nvd_cwe_only_no_cvss() -> None:
    """NVD response with CWEs but no CVSS metrics should still store CWEs."""
    conn = _make_conn()
    _insert_vuln(conn, "CVE-2024-99013", severity="unknown")

    def urlopen_cwe_only(req, timeout=30):
        from urllib.parse import parse_qs, urlparse

        url = req.full_url if hasattr(req, "full_url") else str(req)
        parsed = urlparse(url)
        qs = parse_qs(parsed.query)
        cve_id = qs.get("cveId", ["CVE-UNKNOWN"])[0]
        payload = {
            "vulnerabilities": [
                {
                    "cve": {
                        "id": cve_id,
                        "weaknesses": [{"source": "nvd@nist.gov", "description": [{"lang": "en", "value": "CWE-352"}]}],
                        "metrics": {},
                    }
                }
            ]
        }
        cm = MagicMock()
        cm.__enter__ = MagicMock(return_value=cm)
        cm.__exit__ = MagicMock(return_value=False)
        cm.read = MagicMock(return_value=json.dumps(payload).encode())
        return cm

    with patch("urllib.request.urlopen", side_effect=urlopen_cwe_only):
        with patch("time.sleep"):
            count = sync_nvd(conn, url="https://services.nvd.nist.gov/rest/json/cves/2.0", max_entries=10)

    assert count == 1
    row = conn.execute("SELECT cwe_ids FROM vulns WHERE id = 'CVE-2024-99013'").fetchone()
    assert row["cwe_ids"] == "CWE-352"


# ── enrichment.py skip optimization ────────────────────────────────────────


@pytest.mark.asyncio
async def test_enrich_skips_nvd_when_cwe_known() -> None:
    """CVEs with existing CWE data should skip NVD API call (#689)."""
    vuln_with_cwe = Vulnerability(
        id="CVE-2024-1111",
        summary="test",
        severity=Severity.HIGH,
        cwe_ids=["CWE-79"],
    )
    vuln_without_cwe = Vulnerability(
        id="CVE-2024-2222",
        summary="test",
        severity=Severity.MEDIUM,
    )

    fetch_calls: list[str] = []

    async def tracking_fetch(cve_id, client, api_key=None):
        fetch_calls.append(cve_id)
        return {
            "weaknesses": [{"description": [{"value": "CWE-89"}]}],
            "published": "2024-01-01",
            "lastModified": "2024-06-01",
        }

    with (
        patch("agent_bom.enrichment.fetch_nvd_data", side_effect=tracking_fetch),
        patch("agent_bom.enrichment.fetch_epss_scores", return_value={}),
        patch("agent_bom.enrichment.fetch_cisa_kev_catalog", return_value={}),
        patch("agent_bom.enrichment._save_enrichment_cache"),
    ):
        await enrich_vulnerabilities(
            [vuln_with_cwe, vuln_without_cwe],
            enable_nvd=True,
            enable_epss=False,
            enable_kev=False,
        )

    assert "CVE-2024-2222" in fetch_calls
    assert "CVE-2024-1111" not in fetch_calls


@pytest.mark.asyncio
async def test_enrich_skips_nvd_entirely_when_all_have_cwe() -> None:
    """When all CVEs have CWE data, NVD should not be called at all."""
    vulns = [
        Vulnerability(id="CVE-2024-3333", summary="t", severity=Severity.HIGH, cwe_ids=["CWE-79"]),
        Vulnerability(id="CVE-2024-4444", summary="t", severity=Severity.LOW, cwe_ids=["CWE-89"]),
    ]

    fetch_calls: list[str] = []

    async def tracking_fetch(cve_id, client, api_key=None):
        fetch_calls.append(cve_id)
        return None

    with (
        patch("agent_bom.enrichment.fetch_nvd_data", side_effect=tracking_fetch),
        patch("agent_bom.enrichment.fetch_epss_scores", return_value={}),
        patch("agent_bom.enrichment.fetch_cisa_kev_catalog", return_value={}),
        patch("agent_bom.enrichment._save_enrichment_cache"),
    ):
        await enrich_vulnerabilities(
            vulns,
            enable_nvd=True,
            enable_epss=False,
            enable_kev=False,
        )

    assert fetch_calls == []


@pytest.mark.asyncio
async def test_enrich_extracts_cwe_from_nvd_response() -> None:
    """CWE IDs from NVD weaknesses should be added to the vulnerability."""
    vuln = Vulnerability(id="CVE-2024-5555", summary="test", severity=Severity.HIGH)

    async def mock_fetch(cve_id, client, api_key=None):
        return {
            "weaknesses": [
                {"description": [{"value": "CWE-79"}, {"value": "CWE-89"}]},
                {"description": [{"value": "NVD-CWE-noinfo"}]},
            ],
            "published": "2024-01-01",
            "lastModified": "2024-06-01",
        }

    with (
        patch("agent_bom.enrichment.fetch_nvd_data", side_effect=mock_fetch),
        patch("agent_bom.enrichment.fetch_epss_scores", return_value={}),
        patch("agent_bom.enrichment.fetch_cisa_kev_catalog", return_value={}),
        patch("agent_bom.enrichment._save_enrichment_cache"),
    ):
        count = await enrich_vulnerabilities(
            [vuln],
            enable_nvd=True,
            enable_epss=False,
            enable_kev=False,
        )

    assert count == 1
    assert "CWE-79" in vuln.cwe_ids
    assert "CWE-89" in vuln.cwe_ids
    assert "NVD-CWE-noinfo" not in vuln.cwe_ids
