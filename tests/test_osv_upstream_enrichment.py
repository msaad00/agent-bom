"""Bounded regressions for OSV upstream relationships, not advisory equivalence."""

from __future__ import annotations

import json

import pytest

from agent_bom.db.lookup import lookup_package, lookup_packages_batch
from agent_bom.db.schema import init_db
from agent_bom.db.sync import _ingest_osv_file
from agent_bom.enrichment import extract_cve_ids
from agent_bom.models import Package
from agent_bom.scanners import build_vulnerabilities
from agent_bom.scanners.enrichment_apply import apply_intel
from agent_bom.scanners.package_scan import _local_vuln_to_vulnerability

CVE1 = "CVE-2024-10001"
CVE2 = "CVE-2024-10002"
EPSS = {CVE1: {"score": 0.1, "percentile": 50.0}, CVE2: {"score": 0.9, "percentile": 99.0}}
KEV = {CVE1: {"date_added": "2025-02-01", "due_date": "2025-02-22"}, CVE2: {"date_added": "2025-01-01", "due_date": "2025-01-22"}}


def advisory(advisory_id="RHSA-2024:1000", ecosystem="Red Hat", upstream=None):
    return {
        "id": advisory_id,
        "summary": "Distro-specific advisory",
        "upstream": [CVE1, CVE2] if upstream is None else upstream,
        "related": ["CVE-2024-99999"],
        "database_specific": {"severity": "HIGH"},
        "affected": [
            {
                "package": {"name": "openssl", "ecosystem": ecosystem},
                "ranges": [{"type": "ECOSYSTEM", "events": [{"introduced": "0"}, {"fixed": "3.0.9"}]}],
            }
        ],
    }


def live_records(*entries):
    return build_vulnerabilities(list(entries), Package(name="openssl", ecosystem="Red Hat", version="3.0.1"))


def test_live_upstream_enrichment_keeps_identity_and_attribution():
    records = live_records(advisory(), advisory("RHSA-2024:1001"))
    assert len(records) == 2
    for vuln in records:
        assert apply_intel(vuln, EPSS, KEV, {CVE1: {"vulnStatus": "Rejected"}})
        assert vuln.upstream_ids == [CVE1, CVE2]
        assert vuln.aliases == []
        assert vuln.id.startswith("RHSA-")
        assert vuln.fixed_version == "3.0.9"
        assert vuln.nvd_status is None
        assert (vuln.epss_score, vuln.epss_percentile, vuln.epss_cve_id) == (0.9, 99.0, CVE2)
        assert (vuln.is_kev, vuln.kev_due_date, vuln.kev_cve_id) == (True, "2025-01-22", CVE2)
    assert sorted(extract_cve_ids(records)) == [CVE1, CVE2]


@pytest.mark.parametrize("ecosystem,advisory_id", [("Alpine:v3.20", "ALPINE-CVE-2024-10001"), ("Red Hat", "RHSA-2024:1000")])
def test_bulk_lookup_single_batch_and_live_parity(tmp_path, ecosystem, advisory_id):
    conn = init_db(tmp_path / "intel.db")
    entry = advisory(advisory_id, ecosystem)
    _ingest_osv_file(conn, json.dumps(entry).encode(), "advisory.json")
    for cve, epss in EPSS.items():
        conn.execute(
            "INSERT INTO epss_scores(cve_id,probability,percentile,updated_at) VALUES(?,?,?,'2026-10-05')",
            (cve, epss["score"], epss["percentile"]),
        )
    for cve, kev in KEV.items():
        conn.execute("INSERT INTO kev_entries(cve_id,date_added,due_date) VALUES(?,?,?)", (cve, kev["date_added"], kev["due_date"]))
    conn.commit()
    single = lookup_package(conn, ecosystem, "openssl", "3.0.1")
    batch = lookup_packages_batch(conn, [(ecosystem, "openssl", "3.0.1")])[(ecosystem, "openssl", "3.0.1")]
    assert single == batch and len(single) == 1
    vuln = _local_vuln_to_vulnerability(single[0])
    assert (vuln.epss_score, vuln.epss_percentile, vuln.epss_cve_id) == (0.9, 99.0, CVE2)
    assert (vuln.is_kev, vuln.kev_due_date, vuln.kev_cve_id) == (True, "2025-01-22", CVE2)
    assert vuln.upstream_ids == [CVE1, CVE2]
    assert CVE2 not in vuln.aliases
    conn.close()


@pytest.mark.parametrize("upstream", [None, "CVE-2024-10001", [None, 7, {}, "bad,id", "\nCVE-2024-10001"], []])
def test_malformed_upstream_and_related_never_establish_enrichment(upstream):
    entry = advisory()
    entry["upstream"] = upstream
    vuln = live_records(entry)[0]
    assert not apply_intel(vuln, EPSS, KEV, {})
    assert not vuln.is_kev and vuln.epss_score is None


def test_missing_enrichment_remains_unknown():
    vuln = live_records(advisory())[0]
    assert not apply_intel(vuln, {}, {}, {})
    assert vuln.epss_score is None and vuln.epss_cve_id is None
    assert not vuln.is_kev and vuln.kev_cve_id is None


def test_v5_upgrade_preserves_findings_but_requires_osv_metadata_refresh(tmp_path):
    import sqlite3

    from agent_bom.db.schema import _DDL, open_existing_db_readonly

    path = tmp_path / "legacy.db"
    conn = sqlite3.connect(path)
    conn.executescript("\n".join(line for line in _DDL.splitlines() if "upstream_ids" not in line))
    conn.execute("INSERT INTO schema_version VALUES(5)")
    conn.execute("INSERT INTO vulns(id,summary,severity,source) VALUES('RHSA-2024:1000','known','high','osv')")
    conn.execute("INSERT INTO affected(vuln_id,ecosystem,package_name,introduced) VALUES('RHSA-2024:1000','red hat','openssl','0')")
    for source in ("osv", "epss", "kev"):
        conn.execute("INSERT INTO sync_meta(source,last_synced,record_count) VALUES(?, '2026-10-05', 1)", (source,))
    conn.commit()
    conn.close()
    # Old read-only bundles remain readable, but cannot invent missing links.
    readonly = open_existing_db_readonly(path)
    assert lookup_package(readonly, "Red Hat", "openssl", "3.0.1")[0].epss_probability is None
    readonly.close()
    migrated = init_db(path)
    assert migrated.execute("SELECT version FROM schema_version").fetchone()[0] == 6
    assert migrated.execute("SELECT count(*) FROM vulns").fetchone()[0] == 1
    assert {r[0] for r in migrated.execute("SELECT source FROM sync_meta")} == {"epss", "kev"}
    _ingest_osv_file(migrated, json.dumps(advisory()).encode(), "advisory.json")
    migrated.commit()
    migrated.close()
    reopened = init_db(path)
    assert lookup_package(reopened, "Red Hat", "openssl", "3.0.1")[0].upstream_ids == [CVE1, CVE2]
    reopened.close()


def test_failed_migration_rolls_back_ddl_and_receipt(tmp_path, monkeypatch):
    import sqlite3

    import agent_bom.db.schema as schema

    conn = init_db(tmp_path / "failure.db")
    monkeypatch.setattr(schema, "_SCHEMA_VERSION", 7)
    monkeypatch.setattr(schema, "_MIGRATIONS", [(6, 7, "ALTER TABLE vulns ADD COLUMN partial TEXT; SELECT missing FROM nonexistent;")])
    with pytest.raises(sqlite3.OperationalError):
        schema._migrate(conn, 6)
    assert conn.execute("SELECT version FROM schema_version").fetchone()[0] == 6
    assert "partial" not in {row[1] for row in conn.execute("PRAGMA table_info(vulns)")}
    conn.close()


def test_enrichment_exports_and_safe_findings_keep_attribution():
    from agent_bom.finding_scope import safe_finding_response_payload
    from agent_bom.models import Agent, AgentType, AIBOMReport, BlastRadius, MCPServer
    from agent_bom.output.cyclonedx_fmt import to_cyclonedx
    from agent_bom.output.finding_views import cve_findings
    from agent_bom.output.json_sections import _vulnerability_json
    from agent_bom.output.sarif import to_sarif
    from agent_bom.output.spdx_fmt import to_spdx
    from agent_bom.sbom import parse_cyclonedx, parse_spdx

    vuln = live_records(advisory())[0]
    apply_intel(vuln, EPSS, KEV, {})
    package = Package(name="openssl", ecosystem="rpm", version="3.0.1", vulnerabilities=[vuln])
    server = MCPServer(name="tools", packages=[package])
    agent = Agent(name="developer", agent_type=AgentType.CUSTOM, config_path="", mcp_servers=[server])
    radius = BlastRadius(
        vulnerability=vuln, package=package, affected_agents=[agent], affected_servers=[server], exposed_credentials=[], exposed_tools=[]
    )
    report = AIBOMReport(agents=[agent], blast_radii=[radius])
    finding = cve_findings(report)[0]
    for payload in [_vulnerability_json(vuln), finding.to_dict(), safe_finding_response_payload(finding.to_dict())]:
        assert payload["upstream_ids"] == [CVE1, CVE2]
        assert payload["epss_cve_id"] == payload["kev_cve_id"] == CVE2
        assert CVE2 not in payload.get("aliases", [])
    for document, parse in [(to_cyclonedx(report), parse_cyclonedx), (to_spdx(report), parse_spdx)]:
        imported = [v for pkg in parse(document) for v in pkg.vulnerabilities]
        assert len(imported) == 1
        assert imported[0].upstream_ids == [CVE1, CVE2]
        assert imported[0].epss_cve_id == imported[0].kev_cve_id == CVE2
        assert imported[0].epss_score == 0.9 and imported[0].kev_due_date == "2025-01-22"
    props = to_sarif(report)["runs"][0]["results"][0]["properties"]
    assert props["epss_cve_id"] == props["kev_cve_id"] == CVE2


def test_safe_projection_rejects_arbitrary_enrichment_metadata():
    from agent_bom.finding_scope import safe_finding_response_payload

    payload = safe_finding_response_payload(
        {"upstream_ids": ["secret-token", CVE1], "epss_cve_id": "secret-token", "kev_cve_id": "../../secret"}
    )
    assert payload["upstream_ids"] == [CVE1]
    assert "epss_cve_id" not in payload and "kev_cve_id" not in payload


def test_alias_merge_keeps_enrichment_values_paired_with_source():
    from agent_bom.models import Severity, Vulnerability
    from agent_bom.scanners.advisory_merge import merge_advisory_clusters

    first = Vulnerability(id="GHSA-test", aliases=[CVE1], severity=Severity.CRITICAL, summary="authoritative fix", fixed_version="3.0.9")
    second = Vulnerability(id=CVE1, severity=Severity.HIGH, summary="other", upstream_ids=[CVE2])
    apply_intel(first, {CVE1: EPSS[CVE1]}, {CVE1: KEV[CVE1]}, {})
    apply_intel(second, EPSS, KEV, {})
    for records in ([first, second], [second, first]):
        merged = merge_advisory_clusters(records)
        assert len(merged) == 1
        result = merged[0]
        assert result.fixed_version == "3.0.9" and result.severity == Severity.CRITICAL
        assert (result.epss_score, result.epss_percentile, result.epss_cve_id) == (0.9, 99.0, CVE2)
        assert (result.kev_date_added, result.kev_due_date, result.kev_cve_id) == ("2025-01-01", "2025-01-22", CVE2)
        assert CVE2 not in result.aliases and result.upstream_ids == [CVE2]


def test_many_upstream_cves_respect_sqlite_bind_limit(tmp_path):
    import sqlite3

    conn = init_db(tmp_path / "many.db")
    conn.setlimit(sqlite3.SQLITE_LIMIT_VARIABLE_NUMBER, 450)
    cves = [f"CVE-2024-{10000 + index}" for index in range(901)]
    _ingest_osv_file(conn, json.dumps(advisory(upstream=cves)).encode(), "many.json")
    conn.execute("INSERT INTO epss_scores(cve_id,probability,percentile,updated_at) VALUES(?,0.5,99,'2026-10-05')", (cves[-1],))
    local = lookup_package(conn, "Red Hat", "openssl", "3.0.1")
    assert local[0].epss_cve_id == cves[-1]
    assert local[0].epss_probability == 0.5
    conn.close()


@pytest.mark.parametrize("percentile", [float("nan"), float("inf"), -1, 101, True, "invalid"])
def test_invalid_percentile_does_not_invalidate_probability_or_escape_to_exports(percentile):
    vuln = live_records(advisory())[0]
    assert apply_intel(vuln, {CVE1: {"score": 0.4, "percentile": percentile}}, {}, {})
    assert vuln.epss_score == 0.4
    assert vuln.epss_percentile is None
