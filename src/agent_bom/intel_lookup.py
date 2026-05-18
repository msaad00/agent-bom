"""Threat-intel source catalog, advisory lookup, and inventory matching."""

from __future__ import annotations

import os
import re
import sqlite3
from dataclasses import dataclass
from pathlib import Path
from typing import Any
from urllib.parse import unquote

from agent_bom.db.lookup import LocalVuln, lookup_package
from agent_bom.db.schema import DB_PATH, _validated_db_path, init_db
from agent_bom.package_utils import normalize_package_name

_CVE_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_GHSA_RE = re.compile(r"^GHSA-[0-9a-z]{4}-[0-9a-z]{4}-[0-9a-z]{4}$", re.IGNORECASE)
_CWE_RE = re.compile(r"^CWE-\d+$", re.IGNORECASE)


@dataclass(frozen=True)
class IntelSource:
    source_id: str
    display_name: str
    tier: int
    kind: str
    url: str
    license: str
    redistribution: str
    sync_meta_source: str
    description: str


CANONICAL_INTEL_SOURCES: tuple[IntelSource, ...] = (
    IntelSource(
        source_id="osv",
        display_name="OSV",
        tier=1,
        kind="vulnerability",
        url="https://osv.dev/list",
        license="CC-BY-4.0",
        redistribution="structured_records",
        sync_meta_source="osv",
        description="Ecosystem-native vulnerability advisories keyed by purl-like package coordinates.",
    ),
    IntelSource(
        source_id="ghsa",
        display_name="GitHub Security Advisories",
        tier=1,
        kind="vulnerability",
        url="https://github.com/advisories",
        license="GitHub advisory database terms",
        redistribution="structured_records",
        sync_meta_source="ghsa",
        description="GitHub Security Advisory records for package ecosystems supported by the local DB syncer.",
    ),
    IntelSource(
        source_id="nvd",
        display_name="NVD",
        tier=1,
        kind="enrichment",
        url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        license="public_domain_us_government",
        redistribution="structured_enrichment",
        sync_meta_source="nvd",
        description="CVSS, CWE, and CVE enrichment used to explain impact and remediation priority.",
    ),
    IntelSource(
        source_id="epss",
        display_name="FIRST EPSS",
        tier=1,
        kind="exploitability",
        url="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        license="FIRST EPSS terms",
        redistribution="structured_enrichment",
        sync_meta_source="epss",
        description="Exploit Prediction Scoring System probability and percentile enrichment.",
    ),
    IntelSource(
        source_id="cisa_kev",
        display_name="CISA KEV",
        tier=1,
        kind="exploitation",
        url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        license="public_domain_us_government",
        redistribution="structured_enrichment",
        sync_meta_source="kev",
        description="Known-exploited vulnerability signal for prioritizing active exploitation risk.",
    ),
    IntelSource(
        source_id="alpine_secdb",
        display_name="Alpine SecDB",
        tier=1,
        kind="os_package",
        url="https://secdb.alpinelinux.org",
        license="Alpine Linux SecDB terms",
        redistribution="structured_records",
        sync_meta_source="alpine",
        description="Alpine package security database records for container and OS image matching.",
    ),
)


def resolve_intel_db_path() -> Path:
    """Return the local vulnerability DB path for read-only intel surfaces."""

    configured = (os.environ.get("AGENT_BOM_DB_PATH") or "").strip()
    if configured:
        return _validated_db_path(configured)
    return DB_PATH


def _sync_meta(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    rows = conn.execute("SELECT source, last_synced, record_count FROM sync_meta").fetchall()
    return {row["source"]: {"last_synced": row["last_synced"], "record_count": row["record_count"]} for row in rows}


def list_intel_sources(*, db_path: Path | None = None) -> dict[str, Any]:
    """Return canonical source metadata plus local feed-run freshness."""

    conn = init_db(db_path or resolve_intel_db_path())
    try:
        meta = _sync_meta(conn)
    finally:
        conn.close()

    sources: list[dict[str, Any]] = []
    for source in CANONICAL_INTEL_SOURCES:
        run = meta.get(source.sync_meta_source, {})
        sources.append(
            {
                "source_id": source.source_id,
                "display_name": source.display_name,
                "tier": source.tier,
                "kind": source.kind,
                "url": source.url,
                "license": source.license,
                "redistribution": source.redistribution,
                "description": source.description,
                "feed_run": {
                    "sync_meta_source": source.sync_meta_source,
                    "last_synced": run.get("last_synced"),
                    "record_count": run.get("record_count", 0),
                    "status": "freshness_unknown" if not run.get("last_synced") else "synced",
                },
            }
        )
    return {"schema_version": "intel.sources.v1", "sources": sources, "count": len(sources)}


def _canonical_ids(vuln_id: str, aliases: list[str], cwe_ids: list[str]) -> dict[str, list[str]]:
    values = [vuln_id, *aliases]
    cves = sorted({value.upper() for value in values if _CVE_RE.match(value)})
    ghsas = sorted({value.upper() for value in values if _GHSA_RE.match(value)})
    osv = sorted({value for value in values if not _CVE_RE.match(value) and not _GHSA_RE.match(value)})
    cwes = sorted({value.upper() for value in cwe_ids if _CWE_RE.match(value)})
    return {"cves": cves, "ghsas": ghsas, "osv": osv, "cwes": cwes}


def evidence_links(vuln_id: str, aliases: list[str], cwe_ids: list[str], source: str) -> list[dict[str, str]]:
    """Return source links without implying that every link was fetched."""

    links: list[dict[str, str]] = []
    ids = _canonical_ids(vuln_id, aliases, cwe_ids)
    for cve_id in ids["cves"]:
        links.append({"kind": "cve", "id": cve_id, "url": f"https://nvd.nist.gov/vuln/detail/{cve_id}"})
        links.append({"kind": "epss", "id": cve_id, "url": f"https://api.first.org/data/v1/epss?cve={cve_id}"})
    for ghsa_id in ids["ghsas"]:
        links.append({"kind": "ghsa", "id": ghsa_id, "url": f"https://github.com/advisories/{ghsa_id}"})
    for osv_id in ids["osv"]:
        if osv_id:
            links.append({"kind": source or "osv", "id": osv_id, "url": f"https://osv.dev/vulnerability/{osv_id}"})
    for cwe_id in ids["cwes"]:
        cwe_num = cwe_id.removeprefix("CWE-")
        links.append({"kind": "cwe", "id": cwe_id, "url": f"https://cwe.mitre.org/data/definitions/{cwe_num}.html"})
    return links


def _local_vuln_to_advisory(vuln: LocalVuln, *, matched_by: str) -> dict[str, Any]:
    ids = _canonical_ids(vuln.id, vuln.aliases, vuln.cwe_ids)
    return {
        "id": vuln.id,
        "canonical_ids": ids,
        "summary": vuln.summary,
        "severity": vuln.severity,
        "cvss_score": vuln.cvss_score,
        "cvss_vector": vuln.cvss_vector,
        "fixed_version": vuln.fixed_version,
        "source": vuln.source,
        "published_at": vuln.published_at,
        "modified_at": vuln.modified_at,
        "epss_probability": vuln.epss_probability,
        "epss_percentile": vuln.epss_percentile,
        "is_kev": vuln.is_kev,
        "kev_date_added": vuln.kev_date_added,
        "affected": [
            {
                "ecosystem": vuln.ecosystem,
                "package_name": vuln.package_name,
                "introduced": vuln.introduced,
                "fixed": vuln.fixed_version,
            }
        ],
        "matched_by": matched_by,
        "evidence_links": evidence_links(vuln.id, vuln.aliases, vuln.cwe_ids, vuln.source),
    }


def _candidate_ids(value: str) -> tuple[str, str]:
    advisory_id = value.strip()
    return advisory_id, advisory_id.upper()


def _lookup_cve_enrichment(conn: sqlite3.Connection, cve_ids: list[str]) -> tuple[float | None, float | None, str | None]:
    """Return EPSS and KEV enrichment for any CVE mapped to an advisory."""

    unique_cves = list(dict.fromkeys(cve_id.upper() for cve_id in cve_ids if _CVE_RE.match(cve_id)))
    if not unique_cves:
        return None, None, None
    placeholders = ", ".join("?" for _ in unique_cves)
    epss_query = f"""
        SELECT cve_id, probability, percentile
        FROM epss_scores
        WHERE cve_id IN ({placeholders})
        ORDER BY probability DESC
        LIMIT 1
    """  # nosec B608 - placeholders are generated solely from "?" markers
    kev_query = f"""
        SELECT cve_id, date_added
        FROM kev_entries
        WHERE cve_id IN ({placeholders})
        ORDER BY date_added DESC
        LIMIT 1
    """  # nosec B608 - placeholders are generated solely from "?" markers
    epss_row = conn.execute(epss_query, unique_cves).fetchone()
    kev_row = conn.execute(kev_query, unique_cves).fetchone()
    epss_probability = epss_row["probability"] if epss_row else None
    epss_percentile = epss_row["percentile"] if epss_row else None
    kev_date_added = kev_row["date_added"] if kev_row else None
    return epss_probability, epss_percentile, kev_date_added


def lookup_advisory(advisory_id: str, *, db_path: Path | None = None) -> dict[str, Any]:
    """Look up one advisory by ID or alias from the local intel DB."""

    raw_id, upper_id = _candidate_ids(advisory_id)
    if not raw_id:
        raise ValueError("advisory_id is required")
    conn = init_db(db_path or resolve_intel_db_path())
    try:
        rows = conn.execute(
            """
            SELECT
                v.id, v.summary, v.severity, v.cvss_score, v.cvss_vector, v.fixed_version, v.cwe_ids,
                COALESCE(v.aliases, '') AS aliases, v.source, v.published, v.modified,
                a.ecosystem, a.package_name, a.introduced, a.fixed, a.last_affected,
                e.probability AS epss_prob, e.percentile AS epss_pct,
                k.date_added AS kev_date
            FROM vulns v
            LEFT JOIN affected a ON a.vuln_id = v.id
            LEFT JOIN epss_scores e ON e.cve_id = v.id
            LEFT JOIN kev_entries k ON k.cve_id = v.id
            WHERE UPPER(v.id) = ? OR instr(',' || UPPER(COALESCE(v.aliases, '')) || ',', ',' || ? || ',') > 0
            ORDER BY a.ecosystem, a.package_name
            """,
            (upper_id, upper_id),
        ).fetchall()
        if not rows:
            return {"schema_version": "intel.lookup.v1", "found": False, "query": raw_id, "advisory": None}
        first = rows[0]
        aliases = [alias for alias in (first["aliases"] or "").split(",") if alias]
        cwes = [cwe for cwe in (first["cwe_ids"] or "").split(",") if cwe]
        canonical_ids = _canonical_ids(first["id"], aliases, cwes)
        epss_probability, epss_percentile, kev_date_added = _lookup_cve_enrichment(conn, canonical_ids["cves"])
        epss_probability = first["epss_prob"] if first["epss_prob"] is not None else epss_probability
        epss_percentile = first["epss_pct"] if first["epss_pct"] is not None else epss_percentile
        kev_date_added = first["kev_date"] or kev_date_added
        affected = [
            {
                "ecosystem": row["ecosystem"],
                "package_name": row["package_name"],
                "introduced": row["introduced"],
                "fixed": row["fixed"] or row["fixed_version"],
                "last_affected": row["last_affected"],
            }
            for row in rows
            if row["ecosystem"] and row["package_name"]
        ]
        advisory = {
            "id": first["id"],
            "canonical_ids": canonical_ids,
            "summary": first["summary"],
            "severity": first["severity"],
            "cvss_score": first["cvss_score"],
            "cvss_vector": first["cvss_vector"],
            "fixed_version": first["fixed_version"],
            "source": first["source"],
            "published_at": first["published"],
            "modified_at": first["modified"],
            "epss_probability": epss_probability,
            "epss_percentile": epss_percentile,
            "is_kev": kev_date_added is not None,
            "kev_date_added": kev_date_added,
            "affected": affected,
            "matched_by": "id_or_alias",
            "evidence_links": evidence_links(first["id"], aliases, cwes, first["source"]),
        }
        return {"schema_version": "intel.lookup.v1", "found": True, "query": raw_id, "advisory": advisory}
    finally:
        conn.close()


def parse_purl(purl: str) -> dict[str, str]:
    """Parse a package URL subset into ecosystem/name/version fields."""

    if not purl.startswith("pkg:"):
        raise ValueError("purl must start with pkg:")
    body = purl[4:].split("?", 1)[0].split("#", 1)[0]
    ecosystem, _, remainder = body.partition("/")
    if not ecosystem or not remainder:
        raise ValueError("purl must include ecosystem and package name")
    name_part, _, version = remainder.rpartition("@")
    if not name_part:
        name_part = version
        version = ""
    name = unquote(name_part)
    return {"ecosystem": ecosystem.lower(), "name": name, "version": unquote(version)}


def normalize_package_query(package: dict[str, Any]) -> dict[str, str]:
    """Normalize a package match input into ecosystem/name/version/purl."""

    purl = str(package.get("purl") or "").strip()
    parsed = parse_purl(purl) if purl else {}
    ecosystem = str(package.get("ecosystem") or parsed.get("ecosystem") or "").strip().lower()
    name = str(package.get("name") or parsed.get("name") or "").strip()
    version = str(package.get("version") or parsed.get("version") or "").strip()
    if not ecosystem or not name:
        raise ValueError("each package requires purl or ecosystem plus name")
    normalized_name = normalize_package_name(name, ecosystem)
    return {
        "purl": purl,
        "ecosystem": ecosystem,
        "name": name,
        "normalized_name": normalized_name,
        "version": version,
        "inventory_ref": str(package.get("inventory_ref") or package.get("id") or "").strip(),
    }


def match_packages(packages: list[dict[str, Any]], *, db_path: Path | None = None, limit: int = 100) -> dict[str, Any]:
    """Match package coordinates against local advisory intel."""

    if limit < 1 or limit > 500:
        raise ValueError("limit must be between 1 and 500")
    normalized = [normalize_package_query(package) for package in packages[:limit]]
    conn = init_db(db_path or resolve_intel_db_path())
    try:
        matches: list[dict[str, Any]] = []
        for package in normalized:
            vulns = lookup_package(conn, package["ecosystem"], package["normalized_name"], package["version"] or None)
            advisories = [_local_vuln_to_advisory(vuln, matched_by="package") for vuln in vulns]
            matches.append(
                {
                    "package": package,
                    "match_count": len(advisories),
                    "advisories": advisories,
                    "evidence_links": [link for advisory in advisories for link in advisory["evidence_links"]],
                }
            )
    finally:
        conn.close()
    return {
        "schema_version": "intel.match.v1",
        "submitted": len(packages),
        "matched_packages": sum(1 for item in matches if item["match_count"] > 0),
        "match_count": sum(item["match_count"] for item in matches),
        "matches": matches,
    }
