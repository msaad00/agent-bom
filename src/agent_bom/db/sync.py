"""Sync the local vulnerability database from upstream sources.

Sources:
    osv   — OSV.dev all-ecosystems bulk export (zip of per-ecosystem JSON files)
    epss  — FIRST EPSS v4 CSV bulk export
    kev   — CISA KEV JSON catalog
    ghsa  — GitHub Security Advisories across all supported ecosystems
    nvd   — NVD CVSS enrichment for CVEs missing severity data

Usage:
    agent-bom db update            # sync all sources
    agent-bom db update --source osv
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
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional
from urllib.parse import urljoin, urlparse

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
_ALPINE_SECDB_BRANCHES = ("v3.18", "v3.19", "v3.20", "v3.21", "v3.22", "v3.23")
_ALPINE_SECDB_REPOS = ("main", "community")

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


def _cvss_to_severity(score: Optional[float]) -> str:
    if score is None:
        return "unknown"
    if score == 0.0:
        return "none"
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

    # CVSS score — extract from severity array and database_specific
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    db_severity: Optional[str] = None

    for sev in data.get("severity", []):
        sev_type = sev.get("type", "")
        sev_score = sev.get("score", "")
        if sev_type in ("CVSS_V3", "CVSS_V4") and sev_score:
            cvss_vector = sev_score
            # Extract base score from CVSS vector string (e.g. "CVSS:3.1/AV:N/AC:L/...")
            if cvss_score is None:
                import re

                m = re.search(r"/AV:[NALP]/AC:[LH]", sev_score)
                if m and sev_score.startswith("CVSS:"):
                    # Parse base score from vector using cvss lib or approximate
                    _parts = sev_score.split("/")
                    # Simple heuristic: count High-impact metrics
                    _high = sum(1 for p in _parts if p.endswith(":H") or p.endswith(":N") and "UI" in p)
                    # For accuracy, prefer database_specific score below

    # Pull from database_specific (most reliable source for severity + score)
    db_specific = data.get("database_specific", {})
    if isinstance(db_specific, dict):
        # Severity string (CRITICAL, HIGH, etc.)
        raw_sev = db_specific.get("severity", "")
        if isinstance(raw_sev, str) and raw_sev.upper() in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
            db_severity = raw_sev.upper()

        # Numeric CVSS score
        raw_cvss = db_specific.get("cvss") or db_specific.get("cvss_score")
        if raw_cvss is not None:
            try:
                cvss_score = float(raw_cvss)
            except (ValueError, TypeError):
                pass

    # Determine severity: prefer database_specific string, then derive from CVSS
    if db_severity:
        severity = db_severity.lower()
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
        raw_score = cvss_obj.get("score")
        if raw_score is not None:
            try:
                cvss_score = float(raw_score)
            except (TypeError, ValueError):
                pass
        cvss_vector = cvss_obj.get("vector_string")

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
    target_ecosystems = ecosystems or list(GHSA_ECOSYSTEMS)

    _logger.info(
        "Fetching GHSA advisories from %s for ecosystems: %s",
        base_url,
        ", ".join(target_ecosystems),
    )

    count = 0
    per_page = 100
    eco_counts: dict[str, int] = {}

    from agent_bom.package_utils import normalize_package_name

    for ecosystem in target_ecosystems:
        if count >= max_entries:
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
    _update_sync_meta(conn, "ghsa", count)
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


def sync_nvd(
    conn: sqlite3.Connection,
    nvd_api_key: Optional[str] = None,
    url: Optional[str] = None,
    max_entries: int = 1000,
) -> int:
    """Enrich local DB entries missing CVSS data using the NVD API.

    Queries the DB for CVEs with unknown severity, then fetches CVSS v3.1
    data from NVD and updates the ``vulns`` table in-place.

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

    # Find CVEs in our DB that are missing CVSS data
    rows = conn.execute(
        """
        SELECT id FROM vulns
        WHERE (severity = 'unknown' OR cvss_score IS NULL)
          AND id LIKE 'CVE-%'
        LIMIT :max_entries
        """,
        {"max_entries": max_entries},
    ).fetchall()

    if not rows:
        _logger.info("NVD enrichment: no CVEs missing CVSS data — nothing to do")
        _update_sync_meta(conn, "nvd", 0)
        return 0

    cve_ids = [row[0] for row in rows]
    _logger.info("NVD enrichment: fetching CVSS data for %d CVEs …", len(cve_ids))

    enriched = 0

    for cve_id in cve_ids:
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
            existing_cwes_raw = conn.execute("SELECT cwe_ids FROM vulns WHERE id=?", (cve_id,)).fetchone()
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
                    (cvss_score, cvss_vector, severity, merged_str, cve_id),
                )
            else:
                conn.execute(
                    "UPDATE vulns SET cvss_score=?, cvss_vector=?, severity=? WHERE id=?",
                    (cvss_score, cvss_vector, severity, cve_id),
                )
        elif merged_str is not None:
            conn.execute(
                "UPDATE vulns SET cwe_ids=? WHERE id=?",
                (merged_str, cve_id),
            )
        enriched += 1

        if enriched % _BATCH_SIZE == 0:
            conn.commit()
            _logger.debug("NVD enriched %d CVEs …", enriched)

        time.sleep(sleep_seconds)

    conn.commit()
    _update_sync_meta(conn, "nvd", enriched)
    _logger.info("NVD enrichment complete: %d CVEs updated", enriched)
    return enriched


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
    ghsa_url: Optional[str] = None,
    nvd_url: Optional[str] = None,
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
        sources: list of source names to sync, e.g. ["osv", "kev"]. Default: ["osv","alpine","epss","kev"].
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
    enabled = set(sources or ["osv", "alpine", "epss", "kev"])
    results: dict[str, int] = {}

    try:
        if "osv" in enabled:
            results["osv"] = sync_osv(conn, url=osv_url, max_entries=max_osv_entries)
        if "alpine" in enabled:
            results["alpine"] = sync_alpine_secdb(conn)
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
            results["nvd"] = sync_nvd(
                conn,
                nvd_api_key=key,
                url=nvd_url,
                max_entries=max_nvd_entries,
            )
    finally:
        conn.close()

    return results
