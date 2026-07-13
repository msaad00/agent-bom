"""Threat-intel source catalog, advisory lookup, and inventory matching."""

from __future__ import annotations

import hashlib
import json
import os
import re
import sqlite3
from dataclasses import dataclass
from datetime import UTC, datetime, timedelta
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
    source_tier: int
    kind: str
    source_url: str
    homepage_url: str
    license_or_terms_url: str
    license: str
    robots_policy: str
    crawl_delay_seconds: int | None
    connector_type: str
    enabled: bool
    owner: str
    parser_version: str
    validation_status: str
    support_status: str
    redistribution: str
    sync_meta_source: str
    description: str


CANONICAL_INTEL_SOURCES: tuple[IntelSource, ...] = (
    IntelSource(
        source_id="osv",
        display_name="OSV",
        source_tier=1,
        kind="vulnerability",
        source_url="https://osv.dev/list",
        homepage_url="https://osv.dev/",
        license_or_terms_url="https://github.com/google/osv.dev/blob/master/LICENSE",
        license="CC-BY-4.0",
        robots_policy="structured_api",
        crawl_delay_seconds=None,
        connector_type="structured_api",
        enabled=True,
        owner="agent-bom",
        parser_version="osv-db-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_records",
        sync_meta_source="osv",
        description="Ecosystem-native vulnerability advisories keyed by purl-like package coordinates.",
    ),
    IntelSource(
        source_id="ghsa",
        display_name="GitHub Security Advisories",
        source_tier=1,
        kind="vulnerability",
        source_url="https://github.com/advisories",
        homepage_url="https://github.com/advisories",
        license_or_terms_url="https://docs.github.com/en/site-policy/github-terms/github-terms-of-service",
        license="GitHub advisory database terms",
        robots_policy="api_or_osv_mirror",
        crawl_delay_seconds=None,
        connector_type="structured_api",
        enabled=True,
        owner="agent-bom",
        parser_version="ghsa-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_records",
        sync_meta_source="ghsa",
        description="GitHub Security Advisory records for package ecosystems supported by the local DB syncer.",
    ),
    IntelSource(
        source_id="nvd",
        display_name="NVD",
        source_tier=1,
        kind="enrichment",
        source_url="https://services.nvd.nist.gov/rest/json/cves/2.0",
        homepage_url="https://nvd.nist.gov/",
        license_or_terms_url="https://nvd.nist.gov/general/terms-of-use",
        license="public_domain_us_government",
        robots_policy="structured_api",
        crawl_delay_seconds=None,
        connector_type="structured_api",
        enabled=True,
        owner="agent-bom",
        parser_version="nvd-enrichment.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_enrichment",
        sync_meta_source="nvd",
        description="CVSS, CWE, and CVE enrichment used to explain impact and remediation priority.",
    ),
    IntelSource(
        source_id="epss",
        display_name="FIRST EPSS",
        source_tier=1,
        kind="exploitability",
        source_url="https://epss.empiricalsecurity.com/epss_scores-current.csv.gz",
        homepage_url="https://www.first.org/epss/",
        license_or_terms_url="https://www.first.org/epss/",
        license="FIRST EPSS terms",
        robots_policy="published_bulk_feed",
        crawl_delay_seconds=None,
        connector_type="bulk_file",
        enabled=True,
        owner="agent-bom",
        parser_version="epss-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_enrichment",
        sync_meta_source="epss",
        description="Exploit Prediction Scoring System probability and percentile enrichment.",
    ),
    IntelSource(
        source_id="cisa_kev",
        display_name="CISA KEV",
        source_tier=1,
        kind="exploitation",
        source_url="https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json",
        homepage_url="https://www.cisa.gov/known-exploited-vulnerabilities-catalog",
        license_or_terms_url="https://www.cisa.gov/about/website-policies",
        license="public_domain_us_government",
        robots_policy="published_bulk_feed",
        crawl_delay_seconds=None,
        connector_type="bulk_json",
        enabled=True,
        owner="agent-bom",
        parser_version="kev-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_enrichment",
        sync_meta_source="kev",
        description="Known-exploited vulnerability signal for prioritizing active exploitation risk.",
    ),
    IntelSource(
        source_id="alpine_secdb",
        display_name="Alpine SecDB",
        source_tier=1,
        kind="os_package",
        source_url="https://secdb.alpinelinux.org",
        homepage_url="https://secdb.alpinelinux.org",
        license_or_terms_url="https://gitlab.alpinelinux.org/alpine/security/secdb",
        license="Alpine Linux SecDB terms",
        robots_policy="published_bulk_feed",
        crawl_delay_seconds=None,
        connector_type="bulk_json",
        enabled=True,
        owner="agent-bom",
        parser_version="alpine-secdb-sync.v1",
        validation_status="structured_feed",
        support_status="supported",
        redistribution="structured_records",
        sync_meta_source="alpine",
        description="Alpine package security database records for container and OS image matching.",
    ),
    IntelSource(
        source_id="nvidia_csaf",
        display_name="NVIDIA CSAF",
        source_tier=2,
        kind="vendor_psirt",
        source_url="https://api.github.com/repos/NVIDIA/product-security/contents",
        homepage_url="https://www.nvidia.com/en-us/security/",
        license_or_terms_url="https://github.com/NVIDIA/product-security",
        license="vendor product-security repository terms",
        robots_policy="structured_repository_api",
        crawl_delay_seconds=None,
        connector_type="csaf_json",
        enabled=True,
        owner="agent-bom",
        parser_version="nvidia-csaf.v1",
        validation_status="supported_structured_vendor_feed",
        support_status="supported",
        redistribution="source_links_and_structured_findings",
        sync_meta_source="nvidia_csaf",
        description="Structured CSAF advisory matching for known AI infrastructure package mappings.",
    ),
    IntelSource(
        source_id="amd_psirt",
        display_name="AMD PSIRT",
        source_tier=3,
        kind="vendor_psirt",
        source_url="https://www.amd.com/en/resources/product-security.html",
        homepage_url="https://www.amd.com/en/resources/product-security.html",
        license_or_terms_url="https://www.amd.com/en/legal/copyright.html",
        license="vendor website terms",
        robots_policy="manual_seed_with_guarded_refresh",
        crawl_delay_seconds=None,
        connector_type="vendor_json_seed",
        enabled=True,
        owner="agent-bom",
        parser_version="amd-psirt-seed.v1",
        validation_status="experimental_seed_plus_guarded_refresh",
        support_status="experimental",
        redistribution="source_links_and_structured_findings",
        sync_meta_source="amd_psirt",
        description="ROCm and AMD GPU advisory matching from a curated seed with guarded refresh fallback.",
    ),
    IntelSource(
        source_id="intel_psirt",
        display_name="Intel PSIRT",
        source_tier=3,
        kind="vendor_psirt",
        source_url="https://www.intel.com/content/www/us/en/security-center/default.html",
        homepage_url="https://www.intel.com/content/www/us/en/security-center/default.html",
        license_or_terms_url="https://www.intel.com/content/www/us/en/legal/terms-of-use.html",
        license="vendor website terms",
        robots_policy="manual_seed_only",
        crawl_delay_seconds=None,
        connector_type="curated_seed",
        enabled=True,
        owner="agent-bom",
        parser_version="intel-psirt-seed.v1",
        validation_status="experimental_seed_only",
        support_status="experimental",
        redistribution="source_links_and_structured_findings",
        sync_meta_source="intel_psirt",
        description="GPU and oneAPI advisory matching from curated seed data; no automated webpage scraping is shipped.",
    ),
)

VENDOR_ADVISORY_SOURCE_IDS = {"nvidia_csaf", "amd_psirt", "intel_psirt"}
_MAX_BRIEF_INPUTS = 500

# Display labels for the local-cache sync_meta source ids, keyed by the value
# stored in ``sync_meta.source``. Single source of truth for freshness labels.
SYNC_META_SOURCE_LABELS: dict[str, str] = {
    "osv": "OSV",
    "ghsa": "GHSA",
    "nvd": "NVD",
    "epss": "EPSS",
    "kev": "KEV",
}


def sync_meta_source_label(source_id: str) -> str:
    """Map a ``sync_meta.source`` id to its human display label (OSV/GHSA/…)."""
    return SYNC_META_SOURCE_LABELS.get(source_id.strip().lower(), source_id.upper())


def resolve_intel_db_path() -> Path:
    """Return the local vulnerability DB path for read-only intel surfaces."""

    configured = (os.environ.get("AGENT_BOM_DB_PATH") or "").strip()
    if configured:
        return _validated_db_path(configured)
    return DB_PATH


def _sync_meta(conn: sqlite3.Connection) -> dict[str, dict[str, Any]]:
    rows = conn.execute("SELECT source, last_synced, record_count, metadata_json FROM sync_meta").fetchall()
    meta: dict[str, dict[str, Any]] = {}
    for row in rows:
        metadata: dict[str, Any] = {}
        if row["metadata_json"]:
            try:
                parsed = json.loads(row["metadata_json"])
                if isinstance(parsed, dict):
                    metadata = parsed
            except json.JSONDecodeError:
                metadata = {"validation_status": "metadata_parse_error"}
        meta[row["source"]] = {
            "last_synced": row["last_synced"],
            "record_count": row["record_count"],
            "metadata": metadata,
        }
    return meta


def _string_list(value: Any) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item).strip().lower() for item in value if str(item or "").strip()]


def _tenant_profile(profile: dict[str, Any] | None) -> dict[str, Any]:
    profile = profile or {}
    return {
        "sectors": _string_list(profile.get("sectors")),
        "geos": _string_list(profile.get("geos")),
        "tenant_ref": str(profile.get("tenant_ref") or "").strip() or None,
    }


def _governed_evidence(item: dict[str, Any]) -> dict[str, Any]:
    """Return provenance fields expected on caller-supplied intel items."""

    content_hash = str(item.get("content_hash") or "").strip()
    if not content_hash:
        seed = json.dumps(
            {
                "source_url": item.get("source_url"),
                "indicator": item.get("indicator"),
                "name": item.get("name"),
                "group": item.get("group"),
                "first_seen_at": item.get("first_seen_at"),
            },
            sort_keys=True,
            default=str,
        )
        content_hash = "sha256:" + hashlib.sha256(seed.encode("utf-8")).hexdigest()
    return {
        "source": str(item.get("source") or item.get("source_id") or "caller_supplied").strip(),
        "source_url": str(item.get("source_url") or "").strip(),
        "license": str(item.get("license") or item.get("terms") or "caller_supplied").strip(),
        "fetched_at": str(item.get("fetched_at") or item.get("updated_at") or "").strip(),
        "first_seen_at": str(item.get("first_seen_at") or item.get("discovered_at") or "").strip(),
        "updated_at": str(item.get("updated_at") or "").strip(),
        "content_hash": content_hash,
        "validation_status": str(item.get("validation_status") or "caller_supplied").strip(),
    }


def _match_ioc_telemetry(
    telemetry_indicators: list[dict[str, Any]] | None,
    *,
    limit: int,
) -> list[dict[str, Any]]:
    """Return governed IoC hits when callers provide telemetry observations."""

    matches: list[dict[str, Any]] = []
    for item in (telemetry_indicators or [])[:_MAX_BRIEF_INPUTS]:
        indicator = str(item.get("indicator") or item.get("value") or "").strip()
        if not indicator:
            continue
        telemetry_hits = item.get("hits") or item.get("telemetry_hits") or []
        hit_count = int(item.get("hit_count") or (len(telemetry_hits) if isinstance(telemetry_hits, list) else 0) or 0)
        if hit_count <= 0:
            continue
        matches.append(
            {
                "indicator": indicator,
                "indicator_type": str(item.get("type") or item.get("indicator_type") or "unknown").strip(),
                "hit_count": hit_count,
                "telemetry_refs": telemetry_hits if isinstance(telemetry_hits, list) else [],
                "match_method": "telemetry_indicator_exact",
                "match_confidence": str(item.get("confidence") or "high").strip(),
                "match_reason": "Caller-supplied telemetry contains an exact indicator hit.",
                "evidence": _governed_evidence(item),
            }
        )
        if len(matches) >= limit:
            break
    return matches


def _profile_matches(item: dict[str, Any], profile: dict[str, Any]) -> tuple[bool, list[str]]:
    reasons: list[str] = []
    item_sectors = _string_list(item.get("sectors") or item.get("target_sectors") or item.get("victim_sectors"))
    item_geos = _string_list(item.get("geos") or item.get("target_geos") or item.get("victim_geos"))
    sectors = set(profile.get("sectors") or [])
    geos = set(profile.get("geos") or [])
    if sectors and item_sectors and sectors.intersection(item_sectors):
        reasons.append("sector")
    if geos and item_geos and geos.intersection(item_geos):
        reasons.append("geo")
    return bool(reasons), reasons


def _match_campaign_activity(
    campaign_activity: list[dict[str, Any]] | None,
    *,
    tenant_profile: dict[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in (campaign_activity or [])[:_MAX_BRIEF_INPUTS]:
        matched, reasons = _profile_matches(item, tenant_profile)
        if not matched:
            continue
        matches.append(
            {
                "name": str(item.get("name") or item.get("campaign") or "unnamed_campaign").strip(),
                "activity_type": str(item.get("activity_type") or "campaign").strip(),
                "matched_on": reasons,
                "match_method": "tenant_profile_sector_geo",
                "match_confidence": str(item.get("confidence") or "medium").strip(),
                "match_reason": "Caller-supplied campaign activity overlaps configured tenant sector or geography.",
                "evidence": _governed_evidence(item),
            }
        )
        if len(matches) >= limit:
            break
    return matches


def _match_ransomware_claims(
    ransomware_claims: list[dict[str, Any]] | None,
    *,
    tenant_profile: dict[str, Any],
    limit: int,
) -> list[dict[str, Any]]:
    matches: list[dict[str, Any]] = []
    for item in (ransomware_claims or [])[:_MAX_BRIEF_INPUTS]:
        matched, reasons = _profile_matches(item, tenant_profile)
        if not matched:
            continue
        matches.append(
            {
                "group": str(item.get("group") or item.get("actor") or "unknown_group").strip(),
                "claim": str(item.get("claim") or item.get("victim") or "").strip(),
                "matched_on": reasons,
                "match_method": "tenant_profile_sector_geo",
                "match_confidence": str(item.get("confidence") or "medium").strip(),
                "match_reason": "Caller-supplied ransomware claim overlaps configured tenant sector or geography.",
                "evidence": _governed_evidence(item),
            }
        )
        if len(matches) >= limit:
            break
    return matches


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
        metadata = run.get("metadata") or {}
        validation_status = str(metadata.get("validation_status") or source.validation_status)
        sources.append(
            {
                "source_id": source.source_id,
                "display_name": source.display_name,
                "tier": source.source_tier,
                "source_tier": source.source_tier,
                "kind": source.kind,
                "source_url": source.source_url,
                "homepage_url": source.homepage_url,
                "license_or_terms_url": source.license_or_terms_url,
                "license": source.license,
                "robots_policy": source.robots_policy,
                "crawl_delay_seconds": source.crawl_delay_seconds,
                "connector_type": source.connector_type,
                "enabled": source.enabled,
                "owner": source.owner,
                "parser_version": str(metadata.get("parser_version") or source.parser_version),
                "validation_status": validation_status,
                "support_status": source.support_status,
                "redistribution": source.redistribution,
                "description": source.description,
                "feed_run": {
                    "sync_meta_source": source.sync_meta_source,
                    "last_synced": run.get("last_synced"),
                    "record_count": run.get("record_count", 0),
                    "status": "freshness_unknown" if not run.get("last_synced") else "synced",
                    "last_validated_at": metadata.get("last_validated_at"),
                    "fetched_at": metadata.get("fetched_at") or run.get("last_synced"),
                    "content_hash": metadata.get("content_hash"),
                    "etag": metadata.get("etag"),
                    "last_modified": metadata.get("last_modified"),
                    "parse_errors": int(metadata.get("parse_errors") or 0),
                    "validation_failures": int(metadata.get("validation_failures") or 0),
                    "cap_hit": bool(metadata.get("cap_hit") or False),
                    "validation_status": validation_status,
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
    match_method = "inventory_native_package" if matched_by == "package" else matched_by
    confidence = "high" if match_method in {"inventory_native_package", "id_or_alias"} else "medium"
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
        "match_method": match_method,
        "match_confidence": confidence,
        "match_reason": "Matched by normalized package ecosystem/name/version from tenant inventory.",
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


def _source_registry_by_id() -> dict[str, IntelSource]:
    return {source.source_id: source for source in CANONICAL_INTEL_SOURCES}


def _source_policy(source_id: str | None) -> dict[str, Any]:
    source = _source_registry_by_id().get(source_id or "")
    if not source:
        return {
            "source_id": source_id or "unknown",
            "support_status": "unknown",
            "redistribution": "unknown",
            "license_or_terms_url": None,
            "validation_status": "unknown",
        }
    return {
        "source_id": source.source_id,
        "support_status": source.support_status,
        "redistribution": source.redistribution,
        "license_or_terms_url": source.license_or_terms_url,
        "validation_status": source.validation_status,
    }


def _utc_now() -> datetime:
    return datetime.now(UTC)


def _parse_date_or_datetime(value: str | None) -> datetime | None:
    if not value:
        return None
    normalized = value.strip().replace("Z", "+00:00")
    try:
        parsed = datetime.fromisoformat(normalized)
    except ValueError:
        try:
            parsed = datetime.strptime(normalized, "%Y-%m-%d").replace(tzinfo=UTC)
        except ValueError:
            return None
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=UTC)
    return parsed.astimezone(UTC)


def _row_aliases(row: sqlite3.Row) -> list[str]:
    return [alias for alias in (row["aliases"] or "").split(",") if alias]


def _row_cwes(row: sqlite3.Row) -> list[str]:
    return [cwe for cwe in (row["cwe_ids"] or "").split(",") if cwe]


def _brief_advisory(row: sqlite3.Row, *, section: str, match_reason: str) -> dict[str, Any]:
    aliases = _row_aliases(row)
    cwes = _row_cwes(row)
    source = row["source"]
    return {
        "id": row["id"],
        "canonical_ids": _canonical_ids(row["id"], aliases, cwes),
        "summary": row["summary"],
        "severity": row["severity"],
        "cvss_score": row["cvss_score"],
        "source": source,
        "source_policy": _source_policy(source),
        "published_at": row["published"],
        "modified_at": row["modified"],
        "epss_probability": row["epss_prob"],
        "epss_percentile": row["epss_pct"],
        "is_kev": row["kev_date"] is not None,
        "kev_date_added": row["kev_date"],
        "match_method": "inventory_native_package" if section != "kev_last_24h" else "source_signal",
        "match_confidence": "high",
        "match_reason": match_reason,
        "evidence_links": evidence_links(row["id"], aliases, cwes, source),
    }


def lookup_advisory(advisory_id: str, *, db_path: Path | None = None) -> dict[str, Any]:
    """Look up one advisory by ID or alias from the local intel DB."""

    raw_id, upper_id = _candidate_ids(advisory_id)
    if not raw_id:
        raise ValueError("advisory_id is required")
    conn = init_db(db_path or resolve_intel_db_path())
    # `UPPER(v.id) = ?` defeats the vulns.id PRIMARY KEY index and the `OR
    # instr(aliases)` forces a full scan of vulns (hundreds of thousands of rows)
    # on every advisory lookup — a request/MCP hot path. Serve the common case
    # from the PK index (direct id, raw + upper-cased), and fall back to the
    # non-sargable alias substring scan ONLY when the direct lookup misses.
    _base = """
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
        WHERE {where}
        ORDER BY a.ecosystem, a.package_name
    """
    try:
        # Fast path: index-served direct id match (case-exact + upper-cased variant).
        rows = conn.execute(
            _base.format(where="v.id = ? OR v.id = ?"),
            (raw_id, upper_id),
        ).fetchall()
        if not rows:
            # Rare fallback: the id was actually an alias of a vuln stored under a
            # different id. Substring scan runs only here, not on the hot path.
            rows = conn.execute(
                _base.format(where="instr(',' || UPPER(COALESCE(v.aliases, '')) || ',', ',' || ? || ',') > 0"),
                (upper_id,),
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
            "match_method": "id_or_alias",
            "match_confidence": "high",
            "match_reason": "Matched advisory identifier or alias exactly.",
            "source_policy": _source_policy(first["source"]),
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


def build_daily_brief(
    packages: list[dict[str, Any]] | None = None,
    *,
    telemetry_indicators: list[dict[str, Any]] | None = None,
    campaign_activity: list[dict[str, Any]] | None = None,
    ransomware_claims: list[dict[str, Any]] | None = None,
    tenant_profile: dict[str, Any] | None = None,
    db_path: Path | None = None,
    epss_threshold: float = 0.7,
    kev_window_hours: int = 24,
    limit: int = 100,
    now: datetime | None = None,
) -> dict[str, Any]:
    """Build a local analyst brief from currently shipped intel sources.

    This summarizes local DB evidence only. It does not scrape research sites,
    redistribute vendor pages, or infer telemetry/campaign matches without
    configured input data.
    """

    if epss_threshold < 0 or epss_threshold > 1:
        raise ValueError("epss_threshold must be between 0 and 1")
    if kev_window_hours < 1 or kev_window_hours > 168:
        raise ValueError("kev_window_hours must be between 1 and 168")
    generated_at = now.astimezone(UTC) if now else _utc_now()
    kev_cutoff = generated_at - timedelta(hours=kev_window_hours)
    profile = _tenant_profile(tenant_profile)
    conn = init_db(db_path or resolve_intel_db_path())
    # The KEV↔vuln correlation matches on id OR an alias-substring, which is
    # non-sargable — driving it from `vulns` (hundreds of thousands of rows) scans
    # every KEV entry per vuln (~1e9 instr() calls) and hangs on a populated DB.
    # Only KEV entries inside the brief window matter, so pre-filter KEV first: a
    # `recent_kev` CTE (a handful of rows) drives the join, and the exact
    # window bound is still applied in Python below. `date_added` is a
    # 'YYYY-MM-DD' TEXT column with no index, so use a date-only lower bound one
    # day looser than the cutoff — never tighter than the Python filter.
    kev_lower_bound = (kev_cutoff - timedelta(days=1)).strftime("%Y-%m-%d")
    try:
        source_meta = _sync_meta(conn)
        rows = conn.execute(
            """
            WITH recent_kev AS (
                SELECT cve_id, date_added
                FROM kev_entries
                WHERE date_added >= ?
            )
            SELECT
                v.id, v.summary, v.severity, v.cvss_score, v.cvss_vector, v.fixed_version, v.cwe_ids,
                COALESCE(v.aliases, '') AS aliases, v.source, v.published, v.modified,
                e.probability AS epss_prob, e.percentile AS epss_pct,
                rk.date_added AS kev_date
            FROM recent_kev rk
            JOIN vulns v
                ON v.id = rk.cve_id
                OR instr(',' || UPPER(COALESCE(v.aliases, '')) || ',', ',' || UPPER(rk.cve_id) || ',') > 0
            LEFT JOIN epss_scores e ON e.cve_id = v.id
            ORDER BY rk.date_added DESC, v.id
            LIMIT ?
            """,
            (kev_lower_bound, limit),
        ).fetchall()
    finally:
        conn.close()

    kev_last_24h = [
        _brief_advisory(row, section="kev_last_24h", match_reason=f"CISA KEV date_added is within the last {kev_window_hours} hours.")
        for row in rows
        if (parsed := _parse_date_or_datetime(row["kev_date"])) and parsed >= kev_cutoff
    ]

    package_inputs = packages or []
    inventory_match = match_packages(package_inputs, db_path=db_path, limit=limit) if package_inputs else None
    high_epss_inventory: list[dict[str, Any]] = []
    vendor_advisories: list[dict[str, Any]] = []
    if inventory_match:
        for package_match in inventory_match["matches"]:
            for advisory in package_match["advisories"]:
                item = {
                    "package": package_match["package"],
                    "advisory": advisory,
                    "match_reason": advisory.get("match_reason", "Matched by tenant inventory package coordinates."),
                }
                if advisory.get("epss_probability") is not None and advisory["epss_probability"] >= epss_threshold:
                    high_epss_inventory.append(item)
                if advisory.get("source") in VENDOR_ADVISORY_SOURCE_IDS:
                    vendor_advisories.append(item)
    ioc_hits = _match_ioc_telemetry(telemetry_indicators, limit=limit)
    campaign_matches = _match_campaign_activity(campaign_activity, tenant_profile=profile, limit=limit)
    ransomware_sector_matches = _match_ransomware_claims(ransomware_claims, tenant_profile=profile, limit=limit)

    feed_runs = {
        source.source_id: {
            "last_synced": (source_meta.get(source.sync_meta_source) or {}).get("last_synced"),
            "record_count": (source_meta.get(source.sync_meta_source) or {}).get("record_count", 0),
            "support_status": source.support_status,
            "validation_status": ((source_meta.get(source.sync_meta_source) or {}).get("metadata") or {}).get(
                "validation_status", source.validation_status
            ),
        }
        for source in CANONICAL_INTEL_SOURCES
    }
    return {
        "schema_version": "intel.daily_brief.v1",
        "generated_at": generated_at.isoformat(),
        "inputs": {
            "package_count": len(package_inputs),
            "telemetry_indicator_count": len(telemetry_indicators or []),
            "campaign_activity_count": len(campaign_activity or []),
            "ransomware_claim_count": len(ransomware_claims or []),
            "epss_threshold": epss_threshold,
            "kev_window_hours": kev_window_hours,
            "telemetry_configured": bool(telemetry_indicators),
            "sector_geo_configured": bool(profile["sectors"] or profile["geos"]),
            "tenant_profile": profile,
        },
        "sections": {
            "kev_last_24h": kev_last_24h,
            "high_epss_inventory": high_epss_inventory,
            "vendor_advisories": vendor_advisories,
            "ioc_telemetry_hits": ioc_hits,
            "campaign_matches": campaign_matches,
            "ransomware_sector_matches": ransomware_sector_matches,
        },
        "inventory_match": inventory_match,
        "source_registry": {
            "schema_version": "intel.sources.v1",
            "feed_runs": feed_runs,
        },
        "limitations": [
            (
                "IoC telemetry, campaign, and sector matching run only when the caller supplies governed telemetry, "
                "campaign, ransomware, or tenant-profile inputs."
            ),
            "Vendor webpage scraping is not shipped; vendor entries use structured feeds or curated source-linked seeds only.",
        ],
    }
