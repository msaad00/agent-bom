"""Fast local vulnerability lookup against the SQLite DB.

The primary query pattern is:
    vulns = lookup_package(conn, ecosystem="PyPI", name="requests", version="2.0.0")

Version range matching uses the shared ecosystem-aware comparator from
``agent_bom.version_utils`` so Debian, Alpine, and RPM advisories use the
same semantics as CLI, image, and OSV scans.
"""

from __future__ import annotations

import logging
import sqlite3
from collections import defaultdict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_logger = logging.getLogger(__name__)


@dataclass
class LocalVuln:
    """A vulnerability record from the local DB."""

    id: str  # CVE-* / GHSA-* / OSV-*
    summary: str
    severity: str
    cvss_score: Optional[float]
    fixed_version: Optional[str]
    epss_probability: Optional[float] = None
    epss_percentile: Optional[float] = None
    is_kev: bool = False
    kev_date_added: Optional[str] = None
    published_at: Optional[str] = None
    modified_at: Optional[str] = None
    source: str = "osv"
    ecosystem: str = ""
    package_name: str = ""
    introduced: Optional[str] = None
    aliases: list[str] = field(default_factory=list)
    cwe_ids: list[str] = field(default_factory=list)


def lookup_package(
    conn: sqlite3.Connection,
    ecosystem: str,
    name: str,
    version: Optional[str] = None,
) -> list[LocalVuln]:
    """Return all vulns affecting the given package/ecosystem from the local DB.

    If ``version`` is provided, only returns vulns where the version falls in the
    affected range.  Version matching is a simple lexicographic check — for exact
    semver semantics use ``lookup_package_strict()``.
    """
    from agent_bom.models import normalize_package_name

    norm_name = normalize_package_name(name, ecosystem)
    eco_lower = ecosystem.lower()

    rows = conn.execute(
        """
        SELECT
            v.id, v.summary, v.severity, v.cvss_score, v.fixed_version, v.cwe_ids, COALESCE(v.aliases, '') AS aliases, v.source,
            v.published, v.modified,
            a.ecosystem, a.package_name, a.introduced, a.fixed, a.last_affected,
            e.probability AS epss_prob, e.percentile AS epss_pct,
            k.date_added AS kev_date
        FROM affected a
        JOIN vulns v ON v.id = a.vuln_id
        LEFT JOIN epss_scores e ON e.cve_id = v.id
        LEFT JOIN kev_entries k ON k.cve_id = v.id
        WHERE a.ecosystem = ? AND a.package_name = ?
        ORDER BY v.cvss_score DESC NULLS LAST
        """,
        (eco_lower, norm_name),
    ).fetchall()

    results: list[LocalVuln] = []
    for row in _select_vulnerability_rows(rows, version):
        # Parse comma-separated CWE IDs from DB column
        raw_cwes = row["cwe_ids"] or ""
        cwe_list = [c for c in raw_cwes.split(",") if c] if raw_cwes else []
        raw_aliases = row["aliases"] or ""
        alias_list = [a for a in raw_aliases.split(",") if a] if raw_aliases else []

        results.append(
            LocalVuln(
                id=row["id"],
                summary=row["summary"],
                severity=row["severity"],
                cvss_score=row["cvss_score"],
                fixed_version=row["fixed_version"] or row["fixed"],
                epss_probability=row["epss_prob"],
                epss_percentile=row["epss_pct"],
                is_kev=row["kev_date"] is not None,
                kev_date_added=row["kev_date"],
                published_at=row["published"],
                modified_at=row["modified"],
                source=row["source"],
                ecosystem=row["ecosystem"],
                package_name=row["package_name"],
                introduced=row["introduced"],
                aliases=alias_list,
                cwe_ids=cwe_list,
            )
        )
    return results


def _version_affected(
    version: str,
    introduced: Optional[str],
    fixed: Optional[str],
    last_affected: Optional[str],
    ecosystem: str = "",
) -> bool:
    """Ecosystem-aware version-in-range check."""
    from agent_bom.version_utils import version_in_range

    return version_in_range(version, introduced, fixed, last_affected, ecosystem)


def _version_match_state(
    version: str,
    introduced: Optional[str],
    fixed: Optional[str],
    last_affected: Optional[str],
    ecosystem: str = "",
) -> str:
    """Return ``affected``, ``unaffected``, or ``unknown`` for one affected-range row."""
    from agent_bom.version_utils import _looks_like_commit_sha, compare_version_order

    intro = introduced or None
    fix = fixed or None
    last = last_affected or None
    unknown = False

    if intro:
        intro_cmp = compare_version_order(version, intro, ecosystem)
        if intro_cmp is not None and intro_cmp < 0:
            return "unaffected"
        if intro_cmp is None:
            unknown = True

    if fix:
        if _looks_like_commit_sha(fix):
            unknown = True
        else:
            fix_cmp = compare_version_order(version, fix, ecosystem)
            if fix_cmp is not None and fix_cmp >= 0:
                return "unaffected"
            if fix_cmp is None:
                unknown = True

    if last:
        last_cmp = compare_version_order(version, last, ecosystem)
        if last_cmp is not None and last_cmp > 0:
            return "unaffected"
        if last_cmp is None:
            unknown = True

    return "unknown" if unknown else "affected"


def _select_vulnerability_rows(rows: list[sqlite3.Row], version: Optional[str]) -> list[sqlite3.Row]:
    """Choose at most one authoritative affected row per vulnerability.

    If any row for a vulnerability definitively matches the requested version,
    include the vulnerability. If no rows match but at least one row
    definitively excludes the version, suppress the vulnerability even if
    sibling rows are ambiguous (for example, duplicate PYSEC rows with git-SHA
    fix bounds). If all rows are ambiguous, include the first one
    conservatively.
    """
    if not version:
        grouped_rows: dict[str, list[sqlite3.Row]] = defaultdict(list)
        for row in rows:
            grouped_rows[row["id"]].append(row)
        return [group[0] for group in grouped_rows.values()]

    grouped: dict[str, list[sqlite3.Row]] = defaultdict(list)
    for row in rows:
        grouped[row["id"]].append(row)

    selected: list[sqlite3.Row] = []
    for vuln_rows in grouped.values():
        affected_row: sqlite3.Row | None = None
        unknown_row: sqlite3.Row | None = None
        saw_unaffected = False

        for row in vuln_rows:
            state = _version_match_state(version, row["introduced"], row["fixed"], row["last_affected"], row["ecosystem"])
            if state == "affected":
                affected_row = row
                break
            if state == "unknown" and unknown_row is None:
                unknown_row = row
            if state == "unaffected":
                saw_unaffected = True

        if affected_row is not None:
            selected.append(affected_row)
        elif not saw_unaffected and unknown_row is not None:
            selected.append(unknown_row)

    return selected


def lookup_packages_batch(
    conn: sqlite3.Connection,
    packages: list[tuple[str, str, str]],
) -> dict[tuple[str, str, str], list[LocalVuln]]:
    """Batch lookup vulnerabilities for multiple packages in a single query.

    *packages* is a list of ``(ecosystem, normalized_name, version)`` tuples.

    Returns a dict mapping each input tuple to its list of matching
    :class:`LocalVuln` records.  Version range matching uses the same logic
    as :func:`lookup_package`.

    The query fetches all rows for the unique ``(ecosystem, package_name)``
    pairs, then filters by version in-memory.  SQLite's variable limit
    (default 999) is respected by chunking into groups of 400 pairs.
    """
    if not packages:
        return {}

    chunk_size = 400  # 400 pairs = 800 params, well under SQLite's 999

    # Deduplicate (ecosystem, name) pairs for the SQL query; keep version
    # info for in-memory filtering afterwards.
    pair_set: set[tuple[str, str]] = set()
    for eco, name, _ver in packages:
        pair_set.add((eco.lower(), name))

    pairs = list(pair_set)

    # Fetch all rows in chunks
    all_rows: list[sqlite3.Row] = []
    for start in range(0, len(pairs), chunk_size):
        chunk = pairs[start : start + chunk_size]
        placeholders = ", ".join(["(?, ?)"] * len(chunk))
        params: list[str] = []
        for eco, nm in chunk:
            params.extend([eco, nm])

        # placeholders is only "(?, ?)" repeated — no user data in the SQL string.
        query = f"""
            SELECT
                v.id, v.summary, v.severity, v.cvss_score, v.fixed_version, v.cwe_ids, COALESCE(v.aliases, '') AS aliases, v.source,
                v.published, v.modified,
                a.ecosystem, a.package_name, a.introduced, a.fixed, a.last_affected,
                e.probability AS epss_prob, e.percentile AS epss_pct,
                k.date_added AS kev_date
            FROM affected a
            JOIN vulns v ON v.id = a.vuln_id
            LEFT JOIN epss_scores e ON e.cve_id = v.id
            LEFT JOIN kev_entries k ON k.cve_id = v.id
            WHERE (a.ecosystem, a.package_name) IN (VALUES {placeholders})
            ORDER BY v.cvss_score DESC NULLS LAST
        """  # nosec B608
        all_rows.extend(conn.execute(query, params).fetchall())

    # Group rows by (lower_ecosystem, package_name)
    grouped: dict[tuple[str, str], list[sqlite3.Row]] = defaultdict(list)
    for row in all_rows:
        grouped[(row["ecosystem"].lower(), row["package_name"])].append(row)

    # Build results per input package (with version filtering)
    results: dict[tuple[str, str, str], list[LocalVuln]] = {}
    for eco, name, version in packages:
        key = (eco, name, version)
        eco_lower = eco.lower()
        rows = grouped.get((eco_lower, name), [])

        vulns: list[LocalVuln] = []
        for row in _select_vulnerability_rows(rows, version):
            raw_cwes = row["cwe_ids"] or ""
            cwe_list = [c for c in raw_cwes.split(",") if c] if raw_cwes else []
            raw_aliases = row["aliases"] or ""
            alias_list = [a for a in raw_aliases.split(",") if a] if raw_aliases else []

            vulns.append(
                LocalVuln(
                    id=row["id"],
                    summary=row["summary"],
                    severity=row["severity"],
                    cvss_score=row["cvss_score"],
                    fixed_version=row["fixed_version"] or row["fixed"],
                    epss_probability=row["epss_prob"],
                    epss_percentile=row["epss_pct"],
                    is_kev=row["kev_date"] is not None,
                    kev_date_added=row["kev_date"],
                    published_at=row["published"],
                    modified_at=row["modified"],
                    source=row["source"],
                    ecosystem=row["ecosystem"],
                    package_name=row["package_name"],
                    introduced=row["introduced"],
                    aliases=alias_list,
                    cwe_ids=cwe_list,
                )
            )
        results[key] = vulns

    return results


def package_in_db(conn: sqlite3.Connection, ecosystem: str, name: str) -> bool:
    """Return True if *any* affected record exists for this package in the DB.

    Used to decide whether the DB is authoritative for a package (and OSV fallback
    can be skipped) vs. the package simply not being indexed yet.
    """
    from agent_bom.models import normalize_package_name

    norm_name = normalize_package_name(name, ecosystem)
    row = conn.execute(
        "SELECT 1 FROM affected WHERE ecosystem = ? AND package_name = ? LIMIT 1",
        (ecosystem.lower(), norm_name),
    ).fetchone()
    return row is not None


class VulnDB:
    """Context-manager wrapper for the local vuln DB connection."""

    def __init__(self, path: Optional[Path] = None) -> None:
        self._path = path
        self._conn: Optional[sqlite3.Connection] = None

    def __enter__(self) -> "VulnDB":
        from agent_bom.db.schema import DB_PATH, init_db

        self._conn = init_db(self._path or DB_PATH)
        return self

    def __exit__(self, *_) -> None:
        if self._conn:
            self._conn.close()
            self._conn = None

    def lookup(self, ecosystem: str, name: str, version: Optional[str] = None) -> list[LocalVuln]:
        """Look up vulns for a package."""
        if not self._conn:
            raise RuntimeError("VulnDB not opened — use as context manager")
        return lookup_package(self._conn, ecosystem, name, version)

    def stats(self) -> dict:
        """Return DB stats."""
        if not self._conn:
            raise RuntimeError("VulnDB not opened — use as context manager")
        from agent_bom.db.schema import db_stats

        return db_stats(self._conn)
