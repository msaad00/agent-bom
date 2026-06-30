"""Sync the local vulnerability database from upstream sources.

Sources:
    osv    — OSV.dev all-ecosystems bulk export (zip of per-ecosystem JSON files)
    alpine — Alpine Linux secdb package secfix feeds
    debian — Debian Security Tracker (per-release status + backported fixes,
             incl. end-of-life releases such as buster/Debian 10 via Extended LTS)
    epss   — FIRST EPSS v4 CSV bulk export
    kev    — CISA KEV JSON catalog
    ghsa   — GitHub Security Advisories across all supported ecosystems
    nvd    — NVD incremental CVE enrichment when ``NVD_API_KEY`` is set; otherwise
             backfills missing CVSS/CWE for existing CVE rows only

Usage:
    agent-bom db update            # sync all sources
    agent-bom db update --source osv
    agent-bom db update --source debian
    agent-bom db update --source epss
    agent-bom db update --source kev
    agent-bom db update --source ghsa
    agent-bom db update --source nvd
"""

from __future__ import annotations

import csv
import io
import json
import logging
import re
import sqlite3
import zipfile
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Optional
from urllib.parse import urljoin, urlparse

from agent_bom.package_utils import ALPINE_SECDB_BRANCHES as _ALPINE_SECDB_BRANCHES
from agent_bom.scanners.risk import parse_cvss_vector

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
_EPSS_CSV_URL = "https://epss.empiricalsecurity.com/epss_scores-current.csv.gz"
_EPSS_REDIRECT_HOSTS = {"epss.cyentia.com", "epss.empiricalsecurity.com"}
_KEV_JSON_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
_GHSA_REST_URL = "https://api.github.com/advisories"
_NVD_API_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_ALPINE_SECDB_BASE_URL = "https://secdb.alpinelinux.org"
_ALPINE_SECDB_REPOS = ("main", "community")

# Debian Security Tracker — authoritative per-release vulnerability status with
# backported fix versions. OSV drops releases once they go end-of-life, so its
# bulk export carries no ``debian:10`` (buster) rows and misses the +debNuX
# backports that distro maintainers actually shipped. The tracker is the correct
# source: it records, per source package and per release, whether a CVE is
# resolved (with the exact backported fix), open (no-dsa / won't-fix / EOL), or
# undetermined.
#
# Two feeds, identical JSON shape, parsed by the same ingestor:
#   * the main tracker covers the currently-supported releases (bullseye..forky)
#   * the Extended LTS tracker (run by the Debian LTS maintainers) retains the
#     end-of-life releases — buster (debian:10) and its backported fixes — that
#     the main feed has pruned.
_DEBIAN_TRACKER_JSON_URL = "https://security-tracker.debian.org/tracker/data/json"
_DEBIAN_ELTS_TRACKER_JSON_URL = "https://deb.freexian.com/extended-lts/tracker/data/json"

# Debian release codename -> numeric release for the ``debian:<n>`` ecosystem
# key used by the image/filesystem matchers. Only the releases agent-bom scans
# against (debian:10..debian:14) are ingested; rolling suites (sid/experimental)
# and pre-buster EOL releases are skipped so the DB stays bounded.
_DEBIAN_CODENAME_TO_RELEASE = {
    "buster": "10",
    "bullseye": "11",
    "bookworm": "12",
    "trixie": "13",
    "forky": "14",
}

# AI/ML package names — kept for reference/priority tracking, NOT used as a filter.
# As of v0.71.0, GHSA ingestion fetches ALL advisories across supported ecosystems.
_AI_ML_PACKAGES = frozenset(
    [
        "torch",
        "torchvision",
        "torchaudio",
        "transformers",
        "langchain",
        "langchain-core",
        "openai",
        "anthropic",
        "llama-index",
        "llamaindex",
        "fastapi",
        "uvicorn",
        "numpy",
        "scipy",
        "pandas",
        "scikit-learn",
        "tensorflow",
        "keras",
        "jax",
        "jaxlib",
        "vllm",
        "ray",
        "mlflow",
        "wandb",
        "boto3",
        "azure-ai",
        "google-cloud",
        "huggingface-hub",
        "diffusers",
        "sentence-transformers",
        "pydantic",
        "httpx",
        "requests",
        "aiohttp",
        "cryptography",
        "pillow",
        "opencv-python",
        "mcp",
        "claude-code",
        "crewai",
        "autogen",
        "semantic-kernel",
        "haystack",
        "langflow",
        "flowise",
        "instructor",
        "dspy",
        "pydantic-ai",
        "litellm",
        "agno",
        "smolagents",
        "phidata",
        "agentops",
    ]
)

# Supported GHSA ecosystems — maps to GitHub API ecosystem parameter values
GHSA_ECOSYSTEMS = (
    "pip",
    "npm",
    "go",
    "maven",
    "nuget",
    "rubygems",
    "cargo",
    "composer",
    "swift",
    "pub",
    "erlang",
    "actions",
)

# Batch insert size for performance
_BATCH_SIZE = 500

# OSV severity mapping (CVSS v3 ranges)
_CVSS_SEVERITY = {
    (9.0, 10.0): "critical",
    (7.0, 8.9): "high",
    (4.0, 6.9): "medium",
    (0.1, 3.9): "low",
}
_CVE_ID_RE = re.compile(r"^CVE-\d{4}-\d{4,}$", re.IGNORECASE)
_DEBIAN_CVE_ID_RE = re.compile(r"^DEBIAN-(CVE-\d{4}-\d{4,})$", re.IGNORECASE)


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score == 0.0:
        return "none"
    for (lo, hi), sev in _CVSS_SEVERITY.items():
        if lo <= score <= hi:
            return sev
    return "unknown"


def _nvd_cve_candidates(vuln_id: str, raw_aliases: str = "") -> list[str]:
    """Return canonical CVE IDs that NVD can resolve for a local DB row."""

    candidates: list[str] = []

    def add(value: Any) -> None:
        candidate = str(value or "").strip().upper()
        debian_match = _DEBIAN_CVE_ID_RE.match(candidate)
        if debian_match:
            candidate = debian_match.group(1)
        if _CVE_ID_RE.match(candidate) and candidate not in candidates:
            candidates.append(candidate)

    add(vuln_id)
    for alias in (raw_aliases or "").split(","):
        add(alias)
    return candidates


def _normalize_sync_cvss_score(value: Any) -> Optional[float]:
    """Extract a 0-10 CVSS score from numeric fields or vector strings."""
    if value is None:
        return None
    if isinstance(value, (int, float)):
        score = float(value)
        return score if 0.0 <= score <= 10.0 else None
    if isinstance(value, str):
        try:
            score = float(value)
            return score if 0.0 <= score <= 10.0 else None
        except ValueError:
            return parse_cvss_vector(value)
    if isinstance(value, dict):
        for key in ("score", "baseScore", "base_score", "cvss", "vector", "vectorString"):
            nested_score = _normalize_sync_cvss_score(value.get(key))
            if nested_score is not None:
                return nested_score
    if isinstance(value, list):
        scores = [_normalize_sync_cvss_score(item) for item in value]
        valid_scores = [score for score in scores if score is not None]
        if valid_scores:
            return max(valid_scores)
    return None


def _normalize_sync_severity_label(value: Any) -> Optional[str]:
    """Normalize distro/vendor severity labels to DB severity strings."""
    if value is None:
        return None
    label = str(value).strip().replace("-", "_").replace(" ", "_").upper()
    mapping = {
        "CRITICAL": "critical",
        "HIGH": "high",
        "IMPORTANT": "high",
        "MODERATE": "medium",
        "MEDIUM": "medium",
        "LOW": "low",
        "MINOR": "low",
        "NEGLIGIBLE": "low",
        "UNIMPORTANT": "low",
        "NONE": "none",
    }
    return mapping.get(label)


def _first_sync_cvss_vector(value: Any) -> Optional[str]:
    """Return the first CVSS vector string from common OSV/vendor shapes."""
    if isinstance(value, str) and value.startswith("CVSS:"):
        return value
    if isinstance(value, dict):
        for key in ("score", "baseScore", "base_score", "cvss", "vector", "vectorString"):
            vector = _first_sync_cvss_vector(value.get(key))
            if vector is not None:
                return vector
    if isinstance(value, list):
        for item in value:
            vector = _first_sync_cvss_vector(item)
            if vector is not None:
                return vector
    return None


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

    # CVSS score — extract from severity array and database_specific
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    db_severity: Optional[str] = None

    for sev in data.get("severity", []):
        sev_type = sev.get("type", "")
        sev_score = sev.get("score", "")
        if sev_type in ("CVSS_V3", "CVSS_V3_1", "CVSS_V4") and sev_score:
            cvss_vector = sev_score
            if cvss_score is None:
                cvss_score = _normalize_sync_cvss_score(sev_score)

    # Pull from database_specific (most reliable source for severity + score)
    db_specific = data.get("database_specific", {})
    if isinstance(db_specific, dict):
        # Severity string (CRITICAL, HIGH, etc.)
        db_severity = _normalize_sync_severity_label(db_specific.get("severity"))

        # Numeric CVSS score or CVSS vector, depending on source.
        for key in ("cvss", "cvss_score", "cvss_v3", "severity_vectors"):
            raw_cvss = db_specific.get(key)
            parsed_score = _normalize_sync_cvss_score(raw_cvss)
            if parsed_score is not None:
                cvss_score = parsed_score
                if cvss_vector is None:
                    cvss_vector = _first_sync_cvss_vector(raw_cvss)
                break

    # Debian and other distro OSV advisories often carry their vendor
    # severity/CVSS on affected entries instead of the top-level record.
    for aff in data.get("affected", []):
        if not isinstance(aff, dict):
            continue
        for block_name in ("database_specific", "ecosystem_specific"):
            block = aff.get(block_name)
            if not isinstance(block, dict):
                continue
            if db_severity is None:
                db_severity = _normalize_sync_severity_label(block.get("severity"))
            if cvss_score is None:
                for key in ("cvss", "cvss_score", "cvss_v3", "severity_vectors"):
                    raw_cvss = block.get(key)
                    parsed_score = _normalize_sync_cvss_score(raw_cvss)
                    if parsed_score is not None:
                        cvss_score = parsed_score
                        if cvss_vector is None:
                            cvss_vector = _first_sync_cvss_vector(raw_cvss)
                        break
            if db_severity is not None and cvss_score is not None:
                break
        if db_severity is not None and cvss_score is not None:
            break

    # Determine severity: prefer database_specific string, then derive from CVSS
    if db_severity:
        severity = db_severity
    elif cvss_score is not None:
        severity = _cvss_to_severity(cvss_score)
    else:
        severity = "unknown"

    # Fixed version — take first fixed range across all affected entries
    fixed_version: Optional[str] = None
    affected_rows: list[dict] = []

    from agent_bom.package_utils import normalize_package_name

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

    # Extract CWE IDs from database_specific (GHSA advisories store them here)
    cwe_ids_list: list[str] = []
    if isinstance(db_specific, dict):
        raw_cwes = db_specific.get("cwe_ids", [])
        if isinstance(raw_cwes, list):
            cwe_ids_list = [c for c in raw_cwes if isinstance(c, str) and c.startswith("CWE-")]

    # Store aliases for cross-reference deduplication (PYSEC↔GHSA↔CVE)
    aliases_list = data.get("aliases", [])
    aliases_str = ",".join(a for a in aliases_list if isinstance(a, str))

    vuln_row = {
        "id": vuln_id,
        "summary": summary[:500],
        "severity": severity,
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "fixed_version": fixed_version,
        "cwe_ids": ",".join(cwe_ids_list),
        "aliases": aliases_str,
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
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, cwe_ids, aliases, published, modified, source)
        VALUES
            (:id, :summary, :severity, :cvss_score, :cvss_vector, :fixed_version, :cwe_ids, :aliases, :published, :modified, :source)
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
    from agent_bom.http_client import fetch_bytes

    src = url or _OSV_ALL_ZIP_URL
    _validate_sync_url(src, "osv url")
    _logger.info("Downloading OSV bulk export from %s …", src)

    try:
        data = fetch_bytes(src, timeout=60)
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


def _parse_alpine_secfix_tokens(value: object) -> list[str]:
    """Extract vulnerability identifiers from one Alpine secdb secfix value."""
    if not isinstance(value, str):
        return []
    return re.findall(r"(?:CVE-\d{4}-\d+|ALPINE-\d+|XSA-\d+)", value)


def _iter_alpine_secfix_ids(secfixes: object) -> dict[str, list[str]]:
    """Return {fixed_version: [vuln_ids...]} for one Alpine secdb package."""
    if not isinstance(secfixes, dict):
        return {}

    parsed: dict[str, list[str]] = {}
    for fixed_version, raw_ids in secfixes.items():
        if not isinstance(fixed_version, str):
            continue
        vuln_ids: list[str] = []
        if isinstance(raw_ids, list):
            for item in raw_ids:
                vuln_ids.extend(_parse_alpine_secfix_tokens(item))
        if vuln_ids:
            parsed[fixed_version] = vuln_ids
    return parsed


def _upsert_alpine_vuln_stub(
    conn: sqlite3.Connection,
    vuln_id: str,
    package_name: str,
    fixed_version: str,
) -> None:
    """Insert a minimal vulnerability row unless a richer row already exists."""
    conn.execute(
        """
        INSERT OR IGNORE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, published, modified, source, cwe_ids, aliases)
        VALUES
            (?, ?, 'unknown', NULL, NULL, ?, '', '', 'alpine-secdb', '', '')
        """,
        (
            vuln_id,
            f"Alpine Linux secdb advisory for {package_name}",
            fixed_version,
        ),
    )
    conn.execute(
        """
        UPDATE vulns
        SET fixed_version = CASE
            WHEN fixed_version IS NULL OR fixed_version = '' THEN ?
            ELSE fixed_version
        END
        WHERE id = ?
        """,
        (fixed_version, vuln_id),
    )


def _ingest_alpine_secdb_payload(
    conn: sqlite3.Connection,
    payload: dict,
    *,
    distro_version: str,
    repository: str,
) -> int:
    """Ingest one Alpine secdb JSON document into the local DB.

    Returns the number of affected package/version mappings processed.
    """
    from agent_bom.package_utils import normalize_package_name

    ecosystem = f"alpine:{distro_version}".lower()
    processed = 0

    for package_entry in payload.get("packages", []):
        if not isinstance(package_entry, dict):
            continue
        pkg = package_entry.get("pkg", {})
        if not isinstance(pkg, dict):
            continue
        package_name = pkg.get("name", "")
        if not isinstance(package_name, str) or not package_name:
            continue

        normalized_name = normalize_package_name(package_name, "apk")
        secfixes = _iter_alpine_secfix_ids(pkg.get("secfixes"))
        for fixed_version, vuln_ids in secfixes.items():
            for vuln_id in vuln_ids:
                _upsert_alpine_vuln_stub(conn, vuln_id, normalized_name, fixed_version)
                conn.execute(
                    """
                    INSERT OR REPLACE INTO affected
                        (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
                    VALUES
                        (?, ?, ?, '0', ?, '')
                    """,
                    (vuln_id, ecosystem, normalized_name, fixed_version),
                )
                processed += 1

    _logger.debug(
        "Ingested %d Alpine secdb mappings for %s/%s",
        processed,
        distro_version,
        repository,
    )
    return processed


def sync_alpine_secdb(
    conn: sqlite3.Connection,
    *,
    base_url: Optional[str] = None,
    branches: tuple[str, ...] = _ALPINE_SECDB_BRANCHES,
    repositories: tuple[str, ...] = _ALPINE_SECDB_REPOS,
) -> int:
    """Download and ingest Alpine Linux secdb feeds.

    Alpine secdb carries package-level fix metadata for apk packages and is often
    fresher than OSV for distro-specific Alpine advisories.
    """
    from agent_bom.http_client import fetch_json

    root = (base_url or _ALPINE_SECDB_BASE_URL).rstrip("/")
    _validate_sync_url(root, "alpine secdb base url")

    count = 0
    for branch in branches:
        for repository in repositories:
            url = f"{root}/{branch}/{repository}.json"
            _validate_sync_url(url, "alpine secdb url")
            _logger.info("Downloading Alpine secdb from %s …", url)
            data = fetch_json(url, timeout=30)
            if not isinstance(data, dict):
                raise ValueError(f"Unexpected Alpine secdb payload type for {url}: {type(data)!r}")
            count += _ingest_alpine_secdb_payload(
                conn,
                data,
                distro_version=branch,
                repository=repository,
            )
            conn.commit()

    _update_sync_meta(conn, "alpine", count)
    _logger.info("Alpine secdb sync complete: %d package advisory mappings ingested", count)
    return count


# ---------------------------------------------------------------------------
# Debian Security Tracker ingestion
# ---------------------------------------------------------------------------


def _parse_debian_tracker_release_entry(entry: object) -> Optional[tuple[str, str]]:
    """Map one tracker release block to ``(status, fixed_version)`` or ``None``.

    Returns:
        ``("resolved", "<fix>")`` — the release ships a fix; ``<fix>`` is the
            per-release (backported) version where the CVE is fixed.
        ``("open", "")`` — the release is affected with no fix available. This is
            the tracker's no-dsa / ignored / won't-fix / end-of-life verdict;
            stored with an empty fix so the default OS-advisory suppression hides
            it (and ``AGENT_BOM_INCLUDE_UNFIXED=1`` restores it), exactly like
            other distro sources.
        ``None`` — ``undetermined`` / ``not-affected`` / unknown status carry no
            actionable verdict and are not stored (avoids false positives).
    """
    if not isinstance(entry, dict):
        return None
    status = str(entry.get("status") or "").strip().lower()
    if status == "resolved":
        fixed = str(entry.get("fixed_version") or "").strip()
        # "0" is the tracker sentinel for "this release was never affected".
        if not fixed or fixed == "0":
            return None
        return "resolved", fixed
    if status == "open":
        return "open", ""
    return None


def _upsert_debian_tracker_vuln_stub(
    conn: sqlite3.Connection,
    vuln_id: str,
    cve_id: str,
    summary: str,
    source: str,
) -> None:
    """Insert a minimal vuln row, preserving any richer existing record.

    The tracker shares OSV's ``DEBIAN-CVE-*`` identifier scheme, so when OSV has
    already ingested the same advisory (supported releases) ``INSERT OR IGNORE``
    keeps OSV's severity/CVSS. For EOL releases OSV has nothing, so this seeds a
    stub whose CVE alias lets EPSS/KEV/NVD enrichment fill severity later.
    """
    conn.execute(
        """
        INSERT OR IGNORE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, published, modified, source, cwe_ids, aliases)
        VALUES
            (?, ?, 'unknown', NULL, NULL, NULL, '', '', ?, '', ?)
        """,
        (vuln_id, summary or f"Debian security tracker advisory for {cve_id}", source, cve_id),
    )
    # Backfill alias/summary on a pre-existing stub that lacked them; never
    # overwrite data already present (keeps OSV/NVD enrichment intact).
    conn.execute(
        """
        UPDATE vulns
        SET aliases = CASE WHEN aliases IS NULL OR aliases = '' THEN ? ELSE aliases END,
            summary = CASE WHEN summary IS NULL OR summary = '' THEN ? ELSE summary END
        WHERE id = ?
        """,
        (cve_id, summary or f"Debian security tracker advisory for {cve_id}", vuln_id),
    )


def _ingest_debian_tracker_payload(
    conn: sqlite3.Connection,
    payload: dict,
    *,
    source: str,
) -> int:
    """Ingest one Debian tracker JSON document (``{src_pkg: {cve: {...}}}``).

    Rows are keyed by Debian *source* package name (matching OSV's Debian data
    and how image/filesystem scans resolve binary→source). Returns the number of
    per-release advisory mappings written.
    """
    from agent_bom.package_utils import normalize_package_name

    processed = 0
    pending = 0
    for src_pkg, cves in payload.items():
        if not isinstance(src_pkg, str) or not src_pkg or not isinstance(cves, dict):
            continue
        norm_src = normalize_package_name(src_pkg, "deb")
        for cve_id, info in cves.items():
            if not isinstance(cve_id, str) or not cve_id.upper().startswith("CVE-") or not isinstance(info, dict):
                continue
            releases = info.get("releases")
            if not isinstance(releases, dict):
                continue
            canonical_cve = cve_id.upper()
            vuln_id = f"DEBIAN-{canonical_cve}"
            summary = str(info.get("description") or "")[:500]
            stub_written = False

            for codename, rel_entry in releases.items():
                release = _DEBIAN_CODENAME_TO_RELEASE.get(str(codename).strip().lower())
                if release is None:
                    continue
                parsed = _parse_debian_tracker_release_entry(rel_entry)
                if parsed is None:
                    continue
                status, fixed = parsed

                if not stub_written:
                    _upsert_debian_tracker_vuln_stub(conn, vuln_id, canonical_cve, summary, source)
                    stub_written = True

                ecosystem = f"debian:{release}"
                if status == "resolved":
                    # The tracker's backported fix is authoritative for Debian —
                    # overwrite any sparser OSV row for the same release.
                    conn.execute(
                        """
                        INSERT OR REPLACE INTO affected
                            (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
                        VALUES (?, ?, ?, '0', ?, '')
                        """,
                        (vuln_id, ecosystem, norm_src, fixed),
                    )
                else:  # open — affected, no fix for this release
                    # Never clobber an existing (OSV) fixed row with "no fix".
                    conn.execute(
                        """
                        INSERT OR IGNORE INTO affected
                            (vuln_id, ecosystem, package_name, introduced, fixed, last_affected)
                        VALUES (?, ?, ?, '0', '', '')
                        """,
                        (vuln_id, ecosystem, norm_src),
                    )
                processed += 1
                pending += 1
                if pending >= _BATCH_SIZE:
                    conn.commit()
                    pending = 0

    conn.commit()
    _logger.debug("Ingested %d Debian tracker mappings from %s", processed, source)
    return processed


def sync_debian_tracker(
    conn: sqlite3.Connection,
    *,
    url: Optional[str] = None,
    elts_url: Optional[str] = None,
    include_elts: bool = True,
) -> int:
    """Download and ingest the Debian Security Tracker feed(s).

    Ingests the main tracker (supported releases) and, by default, the Extended
    LTS tracker (end-of-life releases such as buster/Debian 10). The ELTS feed is
    best-effort: a failure there degrades only EOL coverage and never aborts the
    sync. Returns the total number of per-release advisory mappings ingested.
    """
    from agent_bom.http_client import fetch_bytes

    feeds: list[tuple[str, str]] = [(url or _DEBIAN_TRACKER_JSON_URL, "debian-tracker")]
    if include_elts:
        feeds.append((elts_url or _DEBIAN_ELTS_TRACKER_JSON_URL, "debian-elts-tracker"))

    total = 0
    for feed_url, feed_source in feeds:
        _validate_sync_url(feed_url, "debian tracker url")
        best_effort = feed_source == "debian-elts-tracker"
        _logger.info("Downloading Debian security tracker from %s …", feed_url)
        try:
            raw = fetch_bytes(feed_url, timeout=120)
            payload = json.loads(raw)
        except Exception as exc:
            if best_effort:
                _logger.warning("Debian ELTS tracker unavailable (EOL coverage degraded): %s", exc)
                continue
            _logger.error("Failed to download Debian security tracker: %s", exc)
            raise
        if not isinstance(payload, dict):
            if best_effort:
                _logger.warning("Debian ELTS tracker returned unexpected payload type: %s", type(payload).__name__)
                continue
            raise ValueError(f"Unexpected Debian tracker payload type for {feed_url}: {type(payload)!r}")
        total += _ingest_debian_tracker_payload(conn, payload, source=feed_source)

    _update_sync_meta(
        conn,
        "debian",
        total,
        {
            "releases": sorted(set(_DEBIAN_CODENAME_TO_RELEASE.values())),
            "feeds": [name for _u, name in feeds],
            "coverage": "per_release_status_with_backported_fixes",
        },
    )
    _logger.info("Debian security tracker sync complete: %d release advisory mappings ingested", total)
    return total


# ---------------------------------------------------------------------------
# EPSS ingestion
# ---------------------------------------------------------------------------


def _resolve_epss_redirect(current_url: str, location: str) -> str:
    """Resolve an EPSS redirect without allowing arbitrary host pivots."""
    next_url = urljoin(current_url, location)
    _validate_sync_url(next_url, "epss redirect url")
    current_host = (urlparse(current_url).hostname or "").lower()
    next_host = (urlparse(next_url).hostname or "").lower()
    allowed_hosts = set(_EPSS_REDIRECT_HOSTS)
    if current_host:
        allowed_hosts.add(current_host)
    if next_host not in allowed_hosts:
        raise ValueError(f"epss redirect url host is not allowed: {next_host!r}")
    return next_url


def _fetch_epss_csv_bytes(src: str) -> bytes:
    """Fetch EPSS CSV bytes, following only expected HTTPS EPSS redirects."""
    from agent_bom.http_client import create_sync_client, sync_request_with_retry

    current_url = src
    with create_sync_client(timeout=30) as client:
        for _ in range(4):
            response = sync_request_with_retry(client, "GET", current_url)
            if response is None:
                raise ConnectionError(f"Failed to fetch EPSS data from {current_url!r} after retries")
            if response.status_code in {301, 302, 303, 307, 308}:
                location = response.headers.get("location")
                if not location:
                    response.raise_for_status()
                current_url = _resolve_epss_redirect(current_url, location)
                continue
            response.raise_for_status()
            return response.content
    raise RuntimeError("EPSS download exceeded redirect limit")


def sync_epss(conn: sqlite3.Connection, url: Optional[str] = None) -> int:
    """Download and ingest the FIRST EPSS scores CSV.

    Returns the number of CVE scores upserted.
    """
    import gzip

    src = url or _EPSS_CSV_URL
    _validate_sync_url(src, "epss url")
    _logger.info("Downloading EPSS scores from %s …", src)

    try:
        raw = _fetch_epss_csv_bytes(src)
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

    # EPSS CSV may have comment lines (starting with #) before the header.
    # Strip them so csv.DictReader sees "cve,epss,percentile" as the header.
    lines = content.splitlines(keepends=True)
    clean_content = "".join(line for line in lines if not line.startswith("#"))
    reader = csv.DictReader(io.StringIO(clean_content))
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
    from agent_bom.http_client import fetch_json

    src = url or _KEV_JSON_URL
    _validate_sync_url(src, "kev url")
    _logger.info("Downloading CISA KEV catalog from %s …", src)

    try:
        data = fetch_json(src, timeout=30)
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
# GHSA ingestion
# ---------------------------------------------------------------------------


def _parse_ghsa_version_range(version_range: Optional[str]) -> tuple[str, str]:
    """Parse a GHSA version range string into (introduced, fixed).

    GHSA uses strings like ``">= 1.0, < 2.0"`` or ``"< 3.5"`` or ``">= 0"``.
    Returns ``("", "")`` when the range cannot be parsed.
    """
    if not version_range:
        return "", ""
    introduced = ""
    fixed = ""
    for part in version_range.split(","):
        part = part.strip()
        if part.startswith(">="):
            introduced = part[2:].strip()
        elif part.startswith("<"):
            fixed = part[1:].strip()
    return introduced, fixed


def _ingest_ghsa_advisory(
    conn: sqlite3.Connection,
    advisory: dict,
    normalize_package_name: object,
) -> bool:
    """Ingest a single GHSA advisory into the DB. Returns True if ingested."""
    ghsa_id = advisory.get("ghsa_id", "")
    cve_id = advisory.get("cve_id") or ""
    # Use CVE ID if available (allows dedup with OSV entries), else GHSA ID
    vuln_id = cve_id if cve_id else ghsa_id
    if not vuln_id:
        return False

    summary = (advisory.get("summary") or "")[:500]
    severity_raw = (advisory.get("severity") or "unknown").lower()
    severity = severity_raw if severity_raw in ("critical", "high", "medium", "low") else "unknown"

    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cvss_obj = advisory.get("cvss") or {}
    if cvss_obj:
        cvss_vector = cvss_obj.get("vector_string")
        cvss_score = _normalize_sync_cvss_score(cvss_obj.get("score"))
        if cvss_score is None:
            cvss_score = _normalize_sync_cvss_score(cvss_vector)

    # If CVSS score present but severity not, derive it
    if severity == "unknown" and cvss_score is not None:
        severity = _cvss_to_severity(cvss_score)

    published = advisory.get("published_at") or ""
    modified = advisory.get("updated_at") or ""

    # Collect affected package rows
    vulnerabilities = advisory.get("vulnerabilities") or []
    fixed_version: Optional[str] = None
    affected_rows: list[dict] = []

    for vuln in vulnerabilities:
        pkg = vuln.get("package") or {}
        ecosystem = pkg.get("ecosystem", "")
        pkg_name = pkg.get("name", "")
        if not ecosystem or not pkg_name:
            continue

        norm_name = normalize_package_name(pkg_name, ecosystem)  # type: ignore[operator]
        version_range = vuln.get("vulnerable_version_range") or ""
        patched = vuln.get("first_patched_version") or ""
        introduced, fixed = _parse_ghsa_version_range(version_range)

        # Prefer explicit patched version over parsed fixed
        if patched and not fixed:
            fixed = patched
        if fixed and fixed_version is None:
            fixed_version = fixed

        affected_rows.append(
            {
                "vuln_id": vuln_id,
                "ecosystem": ecosystem.lower(),
                "package_name": norm_name,
                "introduced": introduced,
                "fixed": fixed,
                "last_affected": "",
            }
        )

    # Extract CWE IDs from GHSA advisory
    ghsa_cwes: list[str] = []
    for cwe_entry in advisory.get("cwes", []):
        cwe_val = cwe_entry.get("cwe_id", "") if isinstance(cwe_entry, dict) else ""
        if cwe_val.startswith("CWE-"):
            ghsa_cwes.append(cwe_val)

    conn.execute(
        """
        INSERT OR REPLACE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, cwe_ids, aliases, published, modified, source)
        VALUES
            (:id, :summary, :severity, :cvss_score, :cvss_vector, :fixed_version, :cwe_ids, :aliases, :published, :modified, :source)
        """,
        {
            "id": vuln_id,
            "summary": summary,
            "severity": severity,
            "cvss_score": cvss_score,
            "cvss_vector": cvss_vector,
            "fixed_version": fixed_version,
            "cwe_ids": ",".join(ghsa_cwes),
            "aliases": ",".join(filter(None, [ghsa_id if vuln_id != ghsa_id else "", cve_id if vuln_id != cve_id else ""])),
            "published": published,
            "modified": modified,
            "source": "ghsa",
        },
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
    return True


def sync_ghsa(
    conn: sqlite3.Connection,
    url: Optional[str] = None,
    github_token: Optional[str] = None,
    max_entries: int = 5000,
    ecosystems: Optional[list[str]] = None,
) -> int:
    """Fetch GitHub Security Advisories across all supported ecosystems and store in DB.

    Iterates over each ecosystem (pip, npm, go, maven, nuget, rubygems, cargo)
    and paginates through ALL reviewed advisories.  No package-name filtering is
    applied — every advisory for the requested ecosystems is ingested.

    Uses the GHSA REST API (``GET /advisories``).  If *github_token* is provided
    (or ``GITHUB_TOKEN`` env var is set), higher rate limits apply (5000/hr vs 60/hr).

    Args:
        conn: open DB connection.
        url: base URL override (for testing — must be HTTPS).
        github_token: GitHub personal access token or Actions token.
        max_entries: maximum total advisories to ingest across all ecosystems (default 5000).
        ecosystems: list of GHSA ecosystem names to sync (default: all from GHSA_ECOSYSTEMS).

    Returns the number of advisories ingested.
    """
    import os
    import time

    from agent_bom.http_client import fetch_json

    base_url = url or _GHSA_REST_URL
    _validate_sync_url(base_url, "ghsa url")

    token = github_token or os.environ.get("GITHUB_TOKEN")
    target_ecosystems = [ecosystem.lower() for ecosystem in (ecosystems or list(GHSA_ECOSYSTEMS))]
    unsupported = sorted(set(target_ecosystems) - set(GHSA_ECOSYSTEMS))
    if unsupported:
        supported = ", ".join(GHSA_ECOSYSTEMS)
        raise ValueError(f"Unsupported GHSA ecosystem(s): {', '.join(unsupported)}. Supported ecosystems: {supported}")

    _logger.info(
        "Fetching GHSA advisories from %s for ecosystems: %s",
        base_url,
        ", ".join(target_ecosystems),
    )

    count = 0
    per_page = 100
    eco_counts: dict[str, int] = {}

    from agent_bom.package_utils import normalize_package_name

    cap_hit = False
    for ecosystem in target_ecosystems:
        if count >= max_entries:
            cap_hit = True
            break

        eco_count = 0
        page = 1

        while count < max_entries:
            fetch_url = f"{base_url}?type=reviewed&ecosystem={ecosystem}&per_page={per_page}&page={page}"
            hdrs: dict[str, str] = {
                "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28",
            }
            if token:
                hdrs["Authorization"] = f"Bearer {token}"

            try:
                advisories = fetch_json(fetch_url, timeout=30, headers=hdrs)
            except Exception as exc:
                _logger.error("Failed to fetch GHSA page %d for %s: %s", page, ecosystem, exc)
                break

            if not advisories:
                break  # No more pages for this ecosystem

            for advisory in advisories:
                if count >= max_entries:
                    cap_hit = True
                    break

                if _ingest_ghsa_advisory(conn, advisory, normalize_package_name):
                    count += 1
                    eco_count += 1

                    if count % _BATCH_SIZE == 0:
                        conn.commit()
                        _logger.debug("Ingested %d GHSA advisories …", count)

            page += 1

            # Respect GitHub unauthenticated rate limit — brief pause between pages
            if not token:
                time.sleep(1)

        eco_counts[ecosystem] = eco_count

    conn.commit()
    _update_sync_meta(
        conn,
        "ghsa",
        count,
        {
            "ecosystems_requested": target_ecosystems,
            "ecosystem_counts": eco_counts,
            "max_entries": max_entries,
            "cap_hit": cap_hit,
            "coverage": "truncated" if cap_hit else "complete_for_requested_pages",
        },
    )
    if cap_hit:
        _logger.warning(
            "GHSA sync hit max_entries=%d; coverage is truncated. Increase --max-ghsa-entries for fuller coverage.",
            max_entries,
        )
    eco_summary = ", ".join(f"{e}={c}" for e, c in eco_counts.items() if c > 0)
    _logger.info(
        "GHSA sync complete: ingested %d advisories across %d ecosystems (%s)",
        count,
        len([c for c in eco_counts.values() if c > 0]),
        eco_summary or "none",
    )
    return count


# ---------------------------------------------------------------------------
# NVD CVSS enrichment
# ---------------------------------------------------------------------------


def _read_sync_metadata(conn: sqlite3.Connection, source: str) -> dict[str, Any]:
    """Return parsed sync metadata for one source, or an empty dict."""
    if not _sync_meta_has_metadata_column(conn):
        return {}
    row = conn.execute("SELECT metadata_json FROM sync_meta WHERE source = ?", (source,)).fetchone()
    if not row or not row[0]:
        return {}
    try:
        payload = json.loads(row[0])
    except json.JSONDecodeError:
        return {}
    return payload if isinstance(payload, dict) else {}


def _nvd_api_timestamp(value: datetime) -> str:
    return value.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S.000")


def _extract_nvd_cve_fields(cve_data: dict[str, Any]) -> dict[str, Any]:
    """Extract CVSS/CWE/summary fields from one NVD CVE object."""
    metrics = cve_data.get("metrics") or {}
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    severity: Optional[str] = None

    for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        metric_list = metrics.get(metric_key) or []
        if not metric_list:
            continue
        cvss_data = metric_list[0].get("cvssData") or {}
        raw_score = cvss_data.get("baseScore")
        if raw_score is not None:
            try:
                cvss_score = float(raw_score)
            except (TypeError, ValueError):
                cvss_score = None
        cvss_vector = cvss_data.get("vectorString")
        raw_sev = (cvss_data.get("baseSeverity") or "").lower()
        if raw_sev in ("critical", "high", "medium", "low"):
            severity = raw_sev
        break

    nvd_cwes: list[str] = []
    for weakness in cve_data.get("weaknesses", []):
        for desc in weakness.get("description", []):
            cwe_val = desc.get("value", "")
            if cwe_val.startswith("CWE-") and cwe_val not in nvd_cwes:
                nvd_cwes.append(cwe_val)

    if not severity and cvss_score is not None:
        severity = _cvss_to_severity(cvss_score)

    descriptions = cve_data.get("descriptions") or []
    summary = ""
    for desc in descriptions:
        if desc.get("lang") == "en" and desc.get("value"):
            summary = str(desc["value"])[:500]
            break

    return {
        "cvss_score": cvss_score,
        "cvss_vector": cvss_vector,
        "severity": severity,
        "cwe_ids": nvd_cwes,
        "summary": summary,
    }


def _upsert_nvd_enrichment_row(conn: sqlite3.Connection, cve_id: str, fields: dict[str, Any]) -> bool:
    """Insert or update one CVE row from parsed NVD fields."""
    if not fields.get("cvss_score") and not fields.get("cwe_ids"):
        return False

    summary = fields.get("summary") or f"NVD entry for {cve_id}"
    conn.execute(
        """
        INSERT OR IGNORE INTO vulns
            (id, summary, severity, cvss_score, cvss_vector, fixed_version, published, modified, source, cwe_ids, aliases)
        VALUES (?, ?, 'unknown', NULL, NULL, NULL, '', '', 'nvd', '', '')
        """,
        (cve_id, summary),
    )

    merged_cwes = ",".join(sorted(fields.get("cwe_ids") or [])) or None
    if fields.get("cvss_score") is not None:
        if merged_cwes:
            conn.execute(
                "UPDATE vulns SET cvss_score=?, cvss_vector=?, severity=?, summary=?, cwe_ids=? WHERE id=?",
                (fields["cvss_score"], fields.get("cvss_vector"), fields.get("severity"), summary, merged_cwes, cve_id),
            )
        else:
            conn.execute(
                "UPDATE vulns SET cvss_score=?, cvss_vector=?, severity=?, summary=? WHERE id=?",
                (fields["cvss_score"], fields.get("cvss_vector"), fields.get("severity"), summary, cve_id),
            )
    elif merged_cwes:
        conn.execute("UPDATE vulns SET summary=?, cwe_ids=? WHERE id=?", (summary, merged_cwes, cve_id))
    return True


def sync_nvd_incremental(
    conn: sqlite3.Connection,
    nvd_api_key: Optional[str] = None,
    url: Optional[str] = None,
    max_results: int = 2000,
    lookback_days: int = 120,
) -> int:
    """Fetch recently modified CVEs from NVD and upsert enrichment into the local DB.

  Requires ``NVD_API_KEY`` for practical rate limits. Uses ``lastModStartDate`` /
  ``lastModEndDate`` windows and stores the end timestamp in sync metadata for
  the next incremental run.
    """
    import os
    import time
    import urllib.parse

    from agent_bom.http_client import fetch_json

    base_url = url or _NVD_API_URL
    _validate_sync_url(base_url, "nvd url")

    api_key = nvd_api_key or os.environ.get("NVD_API_KEY")
    sleep_seconds = 0.6 if api_key else 6.0

    now = datetime.now(timezone.utc)
    end_ts = _nvd_api_timestamp(now)
    metadata = _read_sync_metadata(conn, "nvd")
    checkpoint = metadata.get("last_modified_end")
    if isinstance(checkpoint, str) and checkpoint.strip():
        try:
            start_dt = datetime.fromisoformat(checkpoint.replace("Z", "+00:00"))
            if start_dt.tzinfo is None:
                start_dt = start_dt.replace(tzinfo=timezone.utc)
        except ValueError:
            start_dt = now - timedelta(days=lookback_days)
    else:
        start_dt = now - timedelta(days=lookback_days)

    if now - start_dt > timedelta(days=lookback_days):
        start_dt = now - timedelta(days=lookback_days)
    start_ts = _nvd_api_timestamp(start_dt)

    enriched = 0
    start_index = 0
    page_size = min(2000, max_results)

    sync_failed = False

    while enriched < max_results:
        params: dict[str, str | int] = {
            "lastModStartDate": start_ts,
            "lastModEndDate": end_ts,
            "resultsPerPage": page_size,
            "startIndex": start_index,
        }
        # NVD API 2.0 only honors the key in the `apiKey` request header; a
        # query-string key is ignored and the call is throttled as anonymous
        # (5 req/30s), so the key must travel in the headers.
        request_headers = {"Accept": "application/json"}
        if api_key:
            request_headers["apiKey"] = api_key
        fetch_url = f"{base_url}?{urllib.parse.urlencode(params)}"

        try:
            data = fetch_json(fetch_url, timeout=60, headers=request_headers)
        except Exception as exc:
            _logger.warning("NVD incremental sync failed at startIndex=%s: %s", start_index, exc)
            sync_failed = True
            break

        items = data.get("vulnerabilities") or []
        if not items:
            break

        for item in items:
            cve_data = item.get("cve") or {}
            cve_id = str(cve_data.get("id") or "")
            if not cve_id.startswith("CVE-"):
                continue
            fields = _extract_nvd_cve_fields(cve_data)
            if _upsert_nvd_enrichment_row(conn, cve_id, fields):
                enriched += 1
                if enriched >= max_results:
                    break

        if enriched % _BATCH_SIZE == 0:
            conn.commit()

        total_results = int(data.get("totalResults") or 0)
        start_index += len(items)
        if start_index >= total_results:
            break
        time.sleep(sleep_seconds)

    conn.commit()
    _update_sync_meta(
        conn,
        "nvd",
        enriched,
        {
            "mode": "incremental",
            "last_modified_start": start_ts,
            # Only advance the synced-through cursor when the whole window
            # fetched cleanly; on failure keep the window start so the next run
            # retries it instead of permanently skipping the unsynced CVEs.
            "last_modified_end": start_ts if sync_failed else end_ts,
            "max_results": max_results,
            "api_key_used": bool(api_key),
            "sync_failed": sync_failed,
        },
    )
    _logger.info("NVD incremental sync complete: %d CVE rows upserted", enriched)
    return enriched


def sync_nvd(
    conn: sqlite3.Connection,
    nvd_api_key: Optional[str] = None,
    url: Optional[str] = None,
    max_entries: int = 1000,
) -> int:
    """Enrich local DB entries missing CVSS data using the NVD API.

    Queries the DB for CVE-backed rows with unknown severity, then fetches
    CVSS v3.1 data from NVD and updates the ``vulns`` table in-place. Distro
    advisory rows such as ``DEBIAN-CVE-*`` are resolved through their embedded
    or aliased canonical CVE ID so native image scans do not stay unknown.

    Rate limiting:
        - Without key: 5 requests / 30s (sleep 6s between requests)
        - With ``NVD_API_KEY``: 50 requests / 30s (sleep 1s between requests)

    Args:
        conn: open DB connection.
        nvd_api_key: NVD API key (or set ``NVD_API_KEY`` env var).
        url: base URL override for the NVD API (must be HTTPS).
        max_entries: maximum number of CVEs to enrich (default 1000).

    Returns the number of CVEs successfully enriched.
    """
    import os
    import time
    import urllib.parse

    from agent_bom.http_client import fetch_json

    base_url = url or _NVD_API_URL
    _validate_sync_url(base_url, "nvd url")

    api_key = nvd_api_key or os.environ.get("NVD_API_KEY")
    # Rate limit: 5 req/30s without key → 6s between; 50 req/30s with key → 0.6s between
    sleep_seconds = 0.6 if api_key else 6.0

    # Find CVE-backed rows in our DB that are missing CVSS data. Some OSV
    # distro advisories use IDs such as DEBIAN-CVE-2014-6271 but still map to
    # the canonical CVE in aliases or in the ID suffix.
    total_candidates = conn.execute(
        """
        SELECT COUNT(*) FROM vulns
        WHERE (severity = 'unknown' OR cvss_score IS NULL)
          AND (id LIKE '%CVE-%' OR aliases LIKE '%CVE-%')
        """
    ).fetchone()[0]
    rows = conn.execute(
        """
        SELECT id, COALESCE(aliases, '') AS aliases FROM vulns
        WHERE (severity = 'unknown' OR cvss_score IS NULL)
          AND (id LIKE '%CVE-%' OR aliases LIKE '%CVE-%')
        LIMIT :max_entries
        """,
        {"max_entries": max_entries},
    ).fetchall()

    row_targets: list[tuple[str, str]] = []
    for row in rows:
        candidates = _nvd_cve_candidates(row["id"], row["aliases"])
        if candidates:
            row_targets.append((row["id"], candidates[0]))

    if not row_targets:
        _logger.info("NVD enrichment: no CVEs missing CVSS data — nothing to do")
        _update_sync_meta(
            conn,
            "nvd",
            0,
            {
                "mode": "enrichment_only",
                "candidate_rows": total_candidates,
                "selected_rows": 0,
                "max_entries": max_entries,
                "cap_hit": total_candidates > max_entries,
            },
        )
        return 0

    _logger.info("NVD enrichment: fetching CVSS data for %d CVE-backed rows …", len(row_targets))

    enriched = 0

    for row_id, cve_id in row_targets:
        params = {"cveId": cve_id}
        if api_key:
            params["apiKey"] = api_key
        fetch_url = f"{base_url}?{urllib.parse.urlencode(params)}"

        try:
            data = fetch_json(fetch_url, timeout=30, headers={"Accept": "application/json"})
        except Exception as exc:
            _logger.debug("NVD API error for %s: %s", cve_id, exc)
            time.sleep(sleep_seconds)
            continue

        # Extract CVSS v3.1 metrics
        cve_items = data.get("vulnerabilities") or []
        if not cve_items:
            time.sleep(sleep_seconds)
            continue

        cve_data = cve_items[0].get("cve") or {}
        metrics = cve_data.get("metrics") or {}
        cvss_score: Optional[float] = None
        cvss_vector: Optional[str] = None
        severity: Optional[str] = None

        # Prefer CVSSv31, fall back to CVSSv30, then CVSSv2
        for metric_key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            metric_list = metrics.get(metric_key) or []
            if not metric_list:
                continue
            cvss_data = metric_list[0].get("cvssData") or {}
            raw_score = cvss_data.get("baseScore")
            if raw_score is not None:
                try:
                    cvss_score = float(raw_score)
                except (TypeError, ValueError):
                    pass
            cvss_vector = cvss_data.get("vectorString")
            raw_sev = (cvss_data.get("baseSeverity") or "").lower()
            if raw_sev in ("critical", "high", "medium", "low"):
                severity = raw_sev
            break

        # Extract CWE IDs from NVD weaknesses
        nvd_cwes: list[str] = []
        for weakness in cve_data.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val.startswith("CWE-") and cwe_val not in nvd_cwes:
                    nvd_cwes.append(cwe_val)

        if cvss_score is None and not nvd_cwes:
            time.sleep(sleep_seconds)
            continue

        if not severity and cvss_score is not None:
            severity = _cvss_to_severity(cvss_score)

        # Merge NVD CWE IDs with any existing ones (from OSV/GHSA)
        if nvd_cwes:
            existing_cwes_raw = conn.execute("SELECT cwe_ids FROM vulns WHERE id=?", (row_id,)).fetchone()
            existing_cwes = set((existing_cwes_raw[0] or "").split(",")) if existing_cwes_raw and existing_cwes_raw[0] else set()
            existing_cwes.discard("")
            merged = list(existing_cwes | set(nvd_cwes))
            merged_str = ",".join(sorted(merged))
        else:
            merged_str = None  # no update needed

        if cvss_score is not None:
            if merged_str is not None:
                conn.execute(
                    "UPDATE vulns SET cvss_score=?, cvss_vector=?, severity=?, cwe_ids=? WHERE id=?",
                    (cvss_score, cvss_vector, severity, merged_str, row_id),
                )
            else:
                conn.execute(
                    "UPDATE vulns SET cvss_score=?, cvss_vector=?, severity=? WHERE id=?",
                    (cvss_score, cvss_vector, severity, row_id),
                )
        elif merged_str is not None:
            conn.execute(
                "UPDATE vulns SET cwe_ids=? WHERE id=?",
                (merged_str, row_id),
            )
        enriched += 1

        if enriched % _BATCH_SIZE == 0:
            conn.commit()
            _logger.debug("NVD enriched %d CVEs …", enriched)

        time.sleep(sleep_seconds)

    conn.commit()
    _update_sync_meta(
        conn,
        "nvd",
        enriched,
        {
            "mode": "enrichment_only",
            "candidate_rows": total_candidates,
            "selected_rows": len(row_targets),
            "max_entries": max_entries,
            "cap_hit": total_candidates > max_entries,
        },
    )
    _logger.info("NVD enrichment complete: %d CVEs updated", enriched)
    return enriched


# ---------------------------------------------------------------------------
# Sync dispatcher
# ---------------------------------------------------------------------------


def _sync_meta_has_metadata_column(conn: sqlite3.Connection) -> bool:
    return any(row[1] == "metadata_json" for row in conn.execute("PRAGMA table_info(sync_meta)").fetchall())


def _update_sync_meta(conn: sqlite3.Connection, source: str, count: int, metadata: dict[str, Any] | None = None) -> None:
    metadata_json = json.dumps(metadata or {}, sort_keys=True, separators=(",", ":"))
    if _sync_meta_has_metadata_column(conn):
        conn.execute(
            "INSERT OR REPLACE INTO sync_meta(source, last_synced, record_count, metadata_json) VALUES (?, ?, ?, ?)",
            (source, _now_utc(), count, metadata_json),
        )
    else:
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
    ghsa_url: Optional[str] = None,
    nvd_url: Optional[str] = None,
    debian_url: Optional[str] = None,
    debian_elts_url: Optional[str] = None,
    max_osv_entries: int = 0,
    max_ghsa_entries: int = 5000,
    max_nvd_entries: int = 1000,
    github_token: Optional[str] = None,
    nvd_api_key: Optional[str] = None,
    ghsa_ecosystems: Optional[list[str]] = None,
) -> dict:
    """Sync the local vuln DB from all (or selected) upstream sources.

    Args:
        path: DB file path (default: DB_PATH from schema.py).
        sources: list of source names to sync, e.g. ["osv", "kev"]. Default: ["osv","alpine","debian","epss","kev"].
                 Note: "nvd" is NOT in the default set — it is slow without an API key.
        osv_url / epss_url / kev_url / ghsa_url / nvd_url: URL overrides (for testing).
        max_osv_entries: limit for OSV entries (0 = unlimited; for tests).
        max_ghsa_entries: limit for GHSA entries (default 5000).
        max_nvd_entries: limit for NVD enrichment (default 1000).
        github_token: override GITHUB_TOKEN env var for GHSA fetches.
        nvd_api_key: override NVD_API_KEY env var for NVD fetches.
        ghsa_ecosystems: list of GHSA ecosystem names to sync (default: all supported).

    Returns a dict of {source: record_count}.
    """
    import os

    from agent_bom.db.schema import DB_PATH, init_db

    db_path = path or DB_PATH
    conn = init_db(db_path)
    enabled = set(sources or ["osv", "alpine", "debian", "epss", "kev"])
    results: dict[str, int] = {}

    try:
        if "osv" in enabled:
            results["osv"] = sync_osv(conn, url=osv_url, max_entries=max_osv_entries)
        if "alpine" in enabled:
            results["alpine"] = sync_alpine_secdb(conn)
        # Debian tracker runs after OSV so its authoritative per-release backports
        # override OSV's sparser/absent distro rows (and preserve OSV severity via
        # INSERT OR IGNORE on the shared DEBIAN-CVE-* id).
        if "debian" in enabled:
            results["debian"] = sync_debian_tracker(conn, url=debian_url, elts_url=debian_elts_url)
        if "epss" in enabled:
            results["epss"] = sync_epss(conn, url=epss_url)
        if "kev" in enabled:
            results["kev"] = sync_kev(conn, url=kev_url)
        if "ghsa" in enabled:
            token = github_token or os.environ.get("GITHUB_TOKEN")
            results["ghsa"] = sync_ghsa(
                conn,
                url=ghsa_url,
                github_token=token,
                max_entries=max_ghsa_entries,
                ecosystems=ghsa_ecosystems,
            )
        if "nvd" in enabled:
            key = nvd_api_key or os.environ.get("NVD_API_KEY")
            if key:
                results["nvd"] = sync_nvd_incremental(
                    conn,
                    nvd_api_key=key,
                    url=nvd_url,
                    max_results=max_nvd_entries,
                )
            else:
                results["nvd"] = sync_nvd(
                    conn,
                    nvd_api_key=key,
                    url=nvd_url,
                    max_entries=max_nvd_entries,
                )
    finally:
        conn.close()

    return results
