"""Sync the local vulnerability database from upstream sources.

Sources:
    osv   — OSV.dev all-ecosystems bulk export (zip of per-ecosystem JSON files)
    epss  — FIRST EPSS CSV bulk export
    kev   — CISA KEV JSON catalog

Usage:
    agent-bom db update            # sync all sources
    agent-bom db update --source osv
    agent-bom db update --source epss
    agent-bom db update --source kev
"""

from __future__ import annotations

import csv
import io
import json
import logging
import sqlite3
import zipfile
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

_logger = logging.getLogger(__name__)


def _validate_sync_url(url: str, param_name: str = "url") -> None:
    """Reject non-HTTPS URLs for sync sources.

    All sync sources must use HTTPS.  Accepting ``file://`` or ``http://``
    custom URLs would allow an attacker who controls the environment to point
    the syncer at a malicious local file or a plaintext server.

    Raises ``ValueError`` with a descriptive message on invalid URLs.
    """
    if not url.startswith("https://"):
        raise ValueError(
            f"{param_name} must use https:// — got {url!r}. Only HTTPS URLs are accepted for vulnerability database sync sources."
        )


# Source URLs — all public, no auth required
_OSV_ALL_ZIP_URL = "https://osv-vulnerabilities.storage.googleapis.com/all.zip"
_EPSS_CSV_URL = "https://epss.cyentia.com/epss_scores-current.csv.gz"
_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"

# Batch insert size for performance
_BATCH_SIZE = 500

# OSV severity mapping (CVSS v3 ranges)
_CVSS_SEVERITY = {
    (9.0, 10.0): "critical",
    (7.0, 8.9): "high",
    (4.0, 6.9): "medium",
    (0.1, 3.9): "low",
}


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    for (lo, hi), sev in _CVSS_SEVERITY.items():
        if lo <= score <= hi:
            return sev
    return "unknown"


def _now_utc() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# OSV ingestion
# ---------------------------------------------------------------------------


def _parse_osv_entry(data: dict) -> Optional[tuple[dict, list[dict]]]:
    """Parse one OSV JSON entry into (vuln_row, affected_rows).

    Returns None if the entry is missing required fields or is a withdrawn advisory.
    """
    vuln_id = data.get("id", "")
    if not vuln_id:
        return None
    if data.get("withdrawn"):
        return None  # skip withdrawn advisories

    summary = data.get("summary") or data.get("details", "")[:200]
    published = data.get("published", "")
    modified = data.get("modified", "")

    # CVSS score
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    for sev in data.get("severity", []):
        if sev.get("type") == "CVSS_V3":
            # Store the vector string; base score is extracted from database_specific below
            cvss_vector = sev.get("score")
        if sev.get("type") == "CVSS_V3" and "score" in sev:
            # Attempt numeric extraction (some entries have "CVSS:3.1/...")
            try:
                # CVSS score may be embedded in database_specific
                pass
            except Exception:
                pass

    # Better: pull score from database_specific NVD block
    db_specific = data.get("database_specific", {})
    if isinstance(db_specific, dict):
        cvss_score = db_specific.get("cvss") or db_specific.get("cvss_score")
        if isinstance(cvss_score, str):
            try:
                cvss_score = float(cvss_score)
            except ValueError:
                cvss_score = None
        elif cvss_score is not None:
            cvss_score = float(cvss_score) if cvss_score else None

    severity = _cvss_to_severity(cvss_score)

    # Fixed version — take first fixed range across all affected entries
    fixed_version: Optional[str] = None
    affected_rows: list[dict] = []

    from agent_bom.models import normalize_package_name

    for aff in data.get("affected", []):
        pkg = aff.get("package", {})
        ecosystem = pkg.get("ecosystem", "")
        pkg_name = pkg.get("name", "")
        if not ecosystem or not pkg_name:
            continue

        norm_name = normalize_package_name(pkg_name, ecosystem)

        for rng in aff.get("ranges", []):
            introduced = None
            fixed = None
            last_affected = None
            for event in rng.get("events", []):
                if "introduced" in event:
                    introduced = event["introduced"]
                if "fixed" in event:
                    fixed = event["fixed"]
                    if fixed_version is None:
                        fixed_version = fixed
                if "last_affected" in event:
                    last_affected = event["last_affected"]
            affected_rows.append(
                {
                    "vuln_id": vuln_id,
                    "ecosystem": ecosystem.lower(),
                    "package_name": norm_name,
                    "introduced": introduced or "",
                    "fixed": fixed or "",
                    "last_affected": last_affected or "",
                }
            )

    vuln_row = {
        "id": vuln_id,
        "summary": summary[:500],
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "fixed_version": fixed_version,
        "published": published,
        "modified": modified,
        "source": "osv",
    }
    return vuln_row, affected_rows


def _ingest_osv_file(conn: sqlite3.Connection, content: bytes, filename: str) -> int:
    """Parse a single OSV JSON file (one advisory per file) and upsert into DB."""
    try:
        data = json.loads(content)
    except json.JSONDecodeError:
        _logger.debug("Skipping invalid JSON: %s", filename)
        return 0

    parsed = _parse_osv_entry(data)
    if parsed is None:
        return 0

    vuln_row, affected_rows = parsed

    conn.execute(
        """
        INSERT OR REPLACE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, published, modified, source)
        VALUES
            (:id, :summary, :severity, :cvss_score, :cvss_vector, :fixed_version, :published, :modified, :source)
        """,
        vuln_row,
    )
    for aff in affected_rows:
        conn.execute(
            """
            INSERT OR REPLACE INTO affected
                (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
            VALUES
                (:vuln_id, :ecosystem, :package_name, :introduced, :fixed, :last_affected)
            """,
            aff,
        )
    return 1


def sync_osv(conn: sqlite3.Connection, url: Optional[str] = None, max_entries: int = 0) -> int:
    """Download and ingest the OSV all-ecosystems bulk export.

    Args:
        conn: open DB connection.
        url: override URL (for testing).
        max_entries: stop after ingesting this many entries (0 = unlimited; for tests).

    Returns the number of advisories ingested.
    """
    import urllib.request

    src = url or _OSV_ALL_ZIP_URL
    _validate_sync_url(src, "osv url")
    _logger.info("Downloading OSV bulk export from %s …", src)

    try:
        with urllib.request.urlopen(src, timeout=60) as resp:  # noqa: S310  # nosec B310 — intentional HTTP fetch to public HTTPS sources
            data = resp.read()
    except Exception as exc:
        _logger.error("Failed to download OSV export: %s", exc)
        raise

    count = 0
    with zipfile.ZipFile(io.BytesIO(data)) as zf:
        names = zf.namelist()
        _logger.info("OSV zip contains %d files", len(names))
        for name in names:
            if max_entries and count >= max_entries:
                break
            if not name.endswith(".json"):
                continue
            content = zf.read(name)
            ingested = _ingest_osv_file(conn, content, name)
            count += ingested
            if count % _BATCH_SIZE == 0 and count > 0:
                conn.commit()
                _logger.debug("Ingested %d OSV advisories …", count)

    conn.commit()
    _update_sync_meta(conn, "osv", count)
    _logger.info("OSV sync complete: %d advisories ingested", count)
    return count


# ---------------------------------------------------------------------------
# EPSS ingestion
# ---------------------------------------------------------------------------


def sync_epss(conn: sqlite3.Connection, url: Optional[str] = None) -> int:
    """Download and ingest the FIRST EPSS scores CSV.

    Returns the number of CVE scores upserted.
    """
    import gzip
    import urllib.request

    src = url or _EPSS_CSV_URL
    _validate_sync_url(src, "epss url")
    _logger.info("Downloading EPSS scores from %s …", src)

    try:
        with urllib.request.urlopen(src, timeout=30) as resp:  # noqa: S310  # nosec B310 — intentional HTTP fetch to public HTTPS sources
            raw = resp.read()
    except Exception as exc:
        _logger.error("Failed to download EPSS data: %s", exc)
        raise

    # EPSS export is gzip-compressed CSV
    try:
        content = gzip.decompress(raw).decode("utf-8")
    except Exception:
        content = raw.decode("utf-8")

    now = _now_utc()
    count = 0
    batch: list[tuple] = []

    reader = csv.DictReader(io.StringIO(content))
    for row in reader:
        cve_id = row.get("cve", "").strip()
        prob_str = row.get("epss", "").strip()
        pct_str = row.get("percentile", "").strip()
        if not cve_id or not prob_str:
            continue
        try:
            prob = float(prob_str)
            pct = float(pct_str) if pct_str else None
        except ValueError:
            continue
        batch.append((cve_id, prob, pct, now))
        if len(batch) >= _BATCH_SIZE:
            conn.executemany(
                "INSERT OR REPLACE INTO epss_scores(cve_id, probability, percentile, updated_at) VALUES (?,?,?,?)",
                batch,
            )
            conn.commit()
            count += len(batch)
            batch = []

    if batch:
        conn.executemany(
            "INSERT OR REPLACE INTO epss_scores(cve_id, probability, percentile, updated_at) VALUES (?,?,?,?)",
            batch,
        )
        conn.commit()
        count += len(batch)

    _update_sync_meta(conn, "epss", count)
    _logger.info("EPSS sync complete: %d scores ingested", count)
    return count


# ---------------------------------------------------------------------------
# KEV ingestion
# ---------------------------------------------------------------------------


def sync_kev(conn: sqlite3.Connection, url: Optional[str] = None) -> int:
    """Download and ingest the CISA KEV catalog JSON.

    Returns the number of KEV entries upserted.
    """
    import urllib.request

    src = url or _KEV_JSON_URL
    _validate_sync_url(src, "kev url")
    _logger.info("Downloading CISA KEV catalog from %s …", src)

    try:
        with urllib.request.urlopen(src, timeout=30) as resp:  # noqa: S310  # nosec B310 — intentional HTTP fetch to public HTTPS sources
            data = json.loads(resp.read())
    except Exception as exc:
        _logger.error("Failed to download KEV catalog: %s", exc)
        raise

    count = 0
    batch: list[tuple] = []
    for entry in data.get("vulnerabilities", []):
        cve_id = entry.get("cveID", "").strip()
        if not cve_id:
            continue
        batch.append(
            (
                cve_id,
                entry.get("dateAdded", ""),
                entry.get("dueDate", ""),
                entry.get("product", ""),
                entry.get("vendorProject", ""),
            )
        )
        if len(batch) >= _BATCH_SIZE:
            conn.executemany(
                "INSERT OR REPLACE INTO kev_entries(cve_id, date_added, due_date, product, vendor_project) VALUES (?,?,?,?,?)",
                batch,
            )
            conn.commit()
            count += len(batch)
            batch = []

    if batch:
        conn.executemany(
            "INSERT OR REPLACE INTO kev_entries(cve_id, date_added, due_date, product, vendor_project) VALUES (?,?,?,?,?)",
            batch,
        )
        conn.commit()
        count += len(batch)

    _update_sync_meta(conn, "kev", count)
    _logger.info("KEV sync complete: %d entries ingested", count)
    return count


# ---------------------------------------------------------------------------
# Sync dispatcher
# ---------------------------------------------------------------------------


def _update_sync_meta(conn: sqlite3.Connection, source: str, count: int) -> None:
    conn.execute(
        "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count) VALUES (?, ?, ?)",
        (source, _now_utc(), count),
    )
    conn.commit()


def sync_db(
    path: Optional[Path] = None,
    sources: Optional[list[str]] = None,
    osv_url: Optional[str] = None,
    epss_url: Optional[str] = None,
    kev_url: Optional[str] = None,
    max_osv_entries: int = 0,
) -> dict:
    """Sync the local vuln DB from all (or selected) upstream sources.

    Args:
        path: DB file path (default: DB_PATH from schema.py).
        sources: list of source names to sync, e.g. ["osv", "kev"]. Default: all.
        osv_url / epss_url / kev_url: URL overrides (for testing).
        max_osv_entries: limit for OSV entries (0 = unlimited; for tests).

    Returns a dict of {source: record_count}.
    """
    from agent_bom.db.schema import DB_PATH, init_db

    db_path = path or DB_PATH
    conn = init_db(db_path)
    enabled = set(sources or ["osv", "epss", "kev"])
    results: dict[str, int] = {}

    try:
        if "osv" in enabled:
            results["osv"] = sync_osv(conn, url=osv_url, max_entries=max_osv_entries)
        if "epss" in enabled:
            results["epss"] = sync_epss(conn, url=epss_url)
        if "kev" in enabled:
            results["kev"] = sync_kev(conn, url=kev_url)
    finally:
        conn.close()

    return results
