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
from contextlib import nullcontext
from dataclasses import dataclass, field
from functools import lru_cache
from pathlib import Path
from typing import Optional

from agent_bom.api.tracing import get_tracer
from agent_bom.os_advisory import OS_DISTRO_COMPARATOR_FAMILIES

_logger = logging.getLogger(__name__)
_LOOKUP_TRACER = get_tracer("agent_bom.db.lookup")


@dataclass
class LocalVuln:
    """A vulnerability record from the local DB."""

    id: str  # CVE-* / GHSA-* / OSV-*
    summary: str
    severity: str
    cvss_score: Optional[float]
    fixed_version: Optional[str]
    cvss_vector: Optional[str] = None
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
    # Set only by the CPE matcher so the finding surfaces as nvd_cpe_candidate;
    # left None for OSV/distro rows, which compute their tier downstream.
    match_confidence_tier: Optional[str] = None


def _cve_candidates(vuln_id: str, raw_aliases: str) -> list[str]:
    """Return unique CVE identifiers associated with one vulnerability row."""
    candidates: list[str] = []
    if vuln_id.startswith("CVE-"):
        candidates.append(vuln_id)
    for alias in (raw_aliases or "").split(","):
        alias = alias.strip()
        if alias.startswith("CVE-") and alias not in candidates:
            candidates.append(alias)
    return candidates


def _load_cve_enrichment(
    conn: sqlite3.Connection,
    rows: list[sqlite3.Row],
) -> tuple[dict[str, tuple[Optional[float], Optional[float]]], dict[str, str]]:
    """Load EPSS and KEV data for any CVE aliases referenced by *rows*."""
    cve_ids: list[str] = []
    seen: set[str] = set()
    for row in rows:
        for cve_id in _cve_candidates(row["id"], row["aliases"] or ""):
            if cve_id not in seen:
                seen.add(cve_id)
                cve_ids.append(cve_id)

    if not cve_ids:
        return {}, {}

    placeholders = ", ".join("?" for _ in cve_ids)
    epss_query = f"""
        SELECT cve_id, probability, percentile
        FROM epss_scores
        WHERE cve_id IN ({placeholders})
    """  # nosec B608 - placeholders are generated solely from "?" markers
    kev_query = f"""
        SELECT cve_id, date_added
        FROM kev_entries
        WHERE cve_id IN ({placeholders})
    """  # nosec B608 - placeholders are generated solely from "?" markers
    epss_rows = conn.execute(epss_query, cve_ids).fetchall()
    kev_rows = conn.execute(kev_query, cve_ids).fetchall()

    epss_map = {row["cve_id"]: (row["probability"], row["percentile"]) for row in epss_rows}
    kev_map = {row["cve_id"]: row["date_added"] for row in kev_rows}
    return epss_map, kev_map


def _resolve_row_enrichment(
    row: sqlite3.Row,
    epss_map: dict[str, tuple[Optional[float], Optional[float]]],
    kev_map: dict[str, str],
) -> tuple[Optional[float], Optional[float], Optional[str]]:
    """Return EPSS probability/percentile and KEV date, falling back to CVE aliases."""
    epss_prob = row["epss_prob"]
    epss_pct = row["epss_pct"]
    kev_date = row["kev_date"]
    if epss_prob is not None and kev_date is not None:
        return epss_prob, epss_pct, kev_date

    for cve_id in _cve_candidates(row["id"], row["aliases"] or ""):
        if epss_prob is None and cve_id in epss_map:
            epss_prob, epss_pct = epss_map[cve_id]
        if kev_date is None and cve_id in kev_map:
            kev_date = kev_map[cve_id]
        if epss_prob is not None and kev_date is not None:
            break
    return epss_prob, epss_pct, kev_date


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
    from agent_bom.package_utils import normalize_package_name

    norm_name = normalize_package_name(name, ecosystem)
    eco_lower = ecosystem.lower()

    span_cm = _LOOKUP_TRACER.start_as_current_span("db.lookup_package") if _LOOKUP_TRACER else nullcontext()
    with span_cm as span:
        rows = conn.execute(
            """
            SELECT
                v.id, v.summary, v.severity, v.cvss_score, v.cvss_vector, v.fixed_version, v.cwe_ids,
                COALESCE(v.aliases, '') AS aliases, v.source,
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

        epss_map, kev_map = _load_cve_enrichment(conn, rows)
        results: list[LocalVuln] = []
        for row in _select_vulnerability_rows(rows, version):
            # Parse comma-separated CWE IDs from DB column
            raw_cwes = row["cwe_ids"] or ""
            cwe_list = [c for c in raw_cwes.split(",") if c] if raw_cwes else []
            raw_aliases = row["aliases"] or ""
            alias_list = [a for a in raw_aliases.split(",") if a] if raw_aliases else []
            epss_prob, epss_pct, kev_date = _resolve_row_enrichment(row, epss_map, kev_map)

            results.append(
                LocalVuln(
                    id=row["id"],
                    summary=row["summary"],
                    severity=row["severity"],
                    cvss_score=row["cvss_score"],
                    cvss_vector=row["cvss_vector"],
                    fixed_version=_resolve_fixed_version(row),
                    epss_probability=epss_prob,
                    epss_percentile=epss_pct,
                    is_kev=kev_date is not None,
                    kev_date_added=kev_date,
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

        if span is not None:
            span.set_attribute("agent_bom.lookup.ecosystem", eco_lower)
            span.set_attribute("agent_bom.lookup.package_name", norm_name)
            span.set_attribute("agent_bom.lookup.row_count", len(rows))
            span.set_attribute("agent_bom.lookup.match_count", len(results))
        return results


def cpe_lookup_package(
    conn: sqlite3.Connection, name: str, version: str, *, vendor: Optional[str] = None, limit: int = 500
) -> list[LocalVuln]:
    """Long-tail CPE-candidate matches for a component, hydrated from ``vulns``.

    Maps the component to NVD CPE applicability ranges (see
    :func:`agent_bom.cpe_match.match_component_cpe`) and hydrates each matched CVE
    from the local ``vulns`` table so it carries real severity/CVSS/CWE. CVEs not
    yet synced into ``vulns`` are skipped (no severity to report). Every result is
    tagged ``nvd_cpe_candidate`` — a review-grade tier, never confirmed.
    """
    from agent_bom.cpe_match import MATCH_CONFIDENCE_NVD_CPE_CANDIDATE, match_component_cpe

    matches = match_component_cpe(conn, name, version, vendor=vendor, limit=limit)
    if not matches:
        return []
    cve_ids = [m["cve_id"] for m in matches]
    placeholders = ", ".join("?" for _ in cve_ids)
    rows = {
        row["id"]: row
        for row in conn.execute(
            "SELECT id, summary, severity, cvss_score, cvss_vector, fixed_version, "
            f"cwe_ids, aliases, published, modified FROM vulns WHERE id IN ({placeholders})",  # nosec B608 - placeholders are generated solely from "?" markers
            cve_ids,
        ).fetchall()
    }
    out: list[LocalVuln] = []
    for cve_id in cve_ids:
        row = rows.get(cve_id)
        if row is None:
            continue
        out.append(
            LocalVuln(
                id=row["id"],
                summary=row["summary"],
                severity=row["severity"],
                cvss_score=row["cvss_score"],
                fixed_version=row["fixed_version"],
                cvss_vector=row["cvss_vector"],
                source="nvd",
                package_name=name,
                cwe_ids=[c for c in (row["cwe_ids"] or "").split(",") if c],
                aliases=[a for a in (row["aliases"] or "").split(",") if a],
                published_at=row["published"],
                modified_at=row["modified"],
                match_confidence_tier=MATCH_CONFIDENCE_NVD_CPE_CANDIDATE,
            )
        )
    return out


def _version_affected(
    version: str,
    introduced: Optional[str],
    fixed: Optional[str],
    last_affected: Optional[str],
    ecosystem: str = "",
) -> bool:
    """Ecosystem-aware version-in-range check."""
    from agent_bom.version_utils import version_in_range

    return version_in_range(version, introduced, fixed, last_affected, _comparator_ecosystem(ecosystem))


# Map a (possibly release-suffixed) DB ecosystem to a base family the version
# comparator understands. The RPM/apk distro families (Red Hat, Rocky, AlmaLinux,
# openSUSE/SUSE, Wolfi, Chainguard) are contributed by ``os_advisory`` so the
# routing and comparator maps never drift apart.
_ECO_FAMILY_TO_COMPARATOR = {
    "debian": "deb",
    "ubuntu": "deb",
    "deb": "deb",
    "alpine": "apk",
    "apk": "apk",
    "rpm": "rpm",
    "linux": "rpm",
    **OS_DISTRO_COMPARATOR_FAMILIES,
}


def _is_distro_release_ecosystem(ecosystem: str) -> bool:
    """True for release-scoped OS ecosystems (``debian:10``, ``alpine:v3.18``, …).

    For these the authoritative fixed version is the *per-release* ``affected.fixed``
    column, not the cross-release ``vulns.fixed_version`` rollup. Debian/distro
    advisories assign a different (backported) fix — or no fix at all — per release,
    so reusing the global rollup both displays a wrong-release version and, worse,
    makes a no-fix-for-this-release entry look fixed, defeating the default
    unfixed-advisory suppression.
    """
    return _comparator_ecosystem(ecosystem) in ("deb", "apk", "rpm")


def _resolve_fixed_version(row: sqlite3.Row) -> Optional[str]:
    """Pick the fixed version to report for a matched affected row.

    Distro releases use the per-release ``affected.fixed`` (empty means *no fix for
    this release*); application ecosystems keep the existing rollup-then-range
    preference so a missing range fix can fall back to the advisory-level fix.
    """
    if _is_distro_release_ecosystem(row["ecosystem"]):
        return (row["fixed"] or "").strip() or None
    return row["fixed_version"] or row["fixed"]


def _comparator_ecosystem(ecosystem: str) -> str:
    """Normalise a DB ecosystem to a key the version comparator can order.

    DB ``affected`` rows store distro ecosystems with a release suffix
    (``debian:10``, ``alpine:v3.18``, ``ubuntu:22.04``). The ecosystem-aware
    version comparator only recognises the base families (``deb``/``apk``/
    ``rpm``); handed the suffixed form it cannot pick a distro comparator and
    returns "unknown" for every range. That silently flips already-fixed distro
    advisories into conservative false positives (e.g. ``bash 5.0-4`` reported
    against a fix of ``4.3-9.1``). Normalising to the base family restores
    correct version ordering.
    """
    base = (ecosystem or "").split(":", 1)[0].strip().lower()
    return _ECO_FAMILY_TO_COMPARATOR.get(base, base)


@lru_cache(maxsize=131072)
def _cached_version_match_state(
    version: str,
    introduced: Optional[str],
    fixed: Optional[str],
    last_affected: Optional[str],
    ecosystem: str = "",
) -> str:
    from agent_bom.version_utils import _looks_like_commit_sha, compare_version_order

    intro = introduced or None
    fix = fixed or None
    last = last_affected or None
    # ``ambiguous``: a genuine version-vs-version comparison yielded no ordering
    # (unusual/unparseable version string) — worth a conservative include.
    # ``uncomparable``: a bound is a git-commit SHA or other non-version token
    # that can never establish semver range membership — NOT grounds for
    # inclusion. Mirrors ``version_utils.version_in_range`` returning False for
    # SHA bounds so this offline path stops emitting OSS-Fuzz/OSV-2022 false
    # positives against concrete semver versions.
    ambiguous = False
    uncomparable = False

    if intro:
        if _looks_like_commit_sha(intro):
            uncomparable = True
        else:
            intro_cmp = compare_version_order(version, intro, ecosystem)
            if intro_cmp is not None and intro_cmp < 0:
                return "unaffected"
            if intro_cmp is None:
                ambiguous = True

    if fix:
        if _looks_like_commit_sha(fix):
            uncomparable = True
        else:
            fix_cmp = compare_version_order(version, fix, ecosystem)
            if fix_cmp is not None and fix_cmp >= 0:
                return "unaffected"
            if fix_cmp is None:
                ambiguous = True

    if last:
        if _looks_like_commit_sha(last):
            uncomparable = True
        else:
            last_cmp = compare_version_order(version, last, ecosystem)
            if last_cmp is not None and last_cmp > 0:
                return "unaffected"
            if last_cmp is None:
                ambiguous = True

    if ambiguous:
        return "unknown"
    if uncomparable:
        return "uncomparable"
    return "affected"


def _version_match_state(
    version: str,
    introduced: Optional[str],
    fixed: Optional[str],
    last_affected: Optional[str],
    ecosystem: str = "",
) -> str:
    """Classify one affected-range row for a version.

    Returns ``affected`` / ``unaffected`` for a definitive semver comparison,
    ``unknown`` for a genuine version-vs-version ambiguity (conservatively
    included), or ``uncomparable`` when a bound is a git SHA / non-version token
    that can never match a concrete semver (never a reason to include).
    """
    return _cached_version_match_state(version, introduced, fixed, last_affected, _comparator_ecosystem(ecosystem))


def _select_vulnerability_rows(rows: list[sqlite3.Row], version: Optional[str]) -> list[sqlite3.Row]:
    """Choose at most one authoritative affected row per vulnerability.

    If any row for a vulnerability definitively matches the requested version,
    include the vulnerability. If no rows match but at least one row
    definitively excludes the version, suppress the vulnerability even if
    sibling rows are ambiguous (for example, duplicate PYSEC rows with git-SHA
    fix bounds). If all rows are genuinely ambiguous, include the first one
    conservatively. Rows whose only signal is ``uncomparable`` (git-SHA /
    non-version bounds — e.g. OSV-2022 OSS-Fuzz advisories) are never grounds
    for inclusion, so a concrete semver version does not draw a false positive.
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

    span_cm = _LOOKUP_TRACER.start_as_current_span("db.lookup_packages_batch") if _LOOKUP_TRACER else nullcontext()
    with span_cm as span:
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
                    v.id, v.summary, v.severity, v.cvss_score, v.cvss_vector, v.fixed_version, v.cwe_ids,
                    COALESCE(v.aliases, '') AS aliases, v.source,
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

        epss_map, kev_map = _load_cve_enrichment(conn, all_rows)

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
                epss_prob, epss_pct, kev_date = _resolve_row_enrichment(row, epss_map, kev_map)

                vulns.append(
                    LocalVuln(
                        id=row["id"],
                        summary=row["summary"],
                        severity=row["severity"],
                        cvss_score=row["cvss_score"],
                        cvss_vector=row["cvss_vector"],
                        fixed_version=_resolve_fixed_version(row),
                        epss_probability=epss_prob,
                        epss_percentile=epss_pct,
                        is_kev=kev_date is not None,
                        kev_date_added=kev_date,
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

        if span is not None:
            span.set_attribute("agent_bom.lookup.package_count", len(packages))
            span.set_attribute("agent_bom.lookup.unique_pairs", len(pairs))
            span.set_attribute("agent_bom.lookup.row_count", len(all_rows))
        return results


def package_in_db(conn: sqlite3.Connection, ecosystem: str, name: str) -> bool:
    """Return True if *any* affected record exists for this package in the DB.

    Used to decide whether the DB is authoritative for a package (and OSV fallback
    can be skipped) vs. the package simply not being indexed yet.
    """
    from agent_bom.package_utils import normalize_package_name

    norm_name = normalize_package_name(name, ecosystem)
    row = conn.execute(
        "SELECT 1 FROM affected WHERE ecosystem = ? AND package_name = ? LIMIT 1",
        (ecosystem.lower(), norm_name),
    ).fetchone()
    return row is not None


def package_in_db_batch(
    conn: sqlite3.Connection,
    packages: list[tuple[str, str]],
) -> set[tuple[str, str]]:
    """Return the subset of ``(ecosystem, package_name)`` pairs present in affected."""
    if not packages:
        return set()

    normalized = {(ecosystem.lower(), name) for ecosystem, name in packages}
    pairs = list(normalized)
    chunk_size = 400
    present: set[tuple[str, str]] = set()

    for start in range(0, len(pairs), chunk_size):
        chunk = pairs[start : start + chunk_size]
        placeholders = ", ".join(["(?, ?)"] * len(chunk))
        params: list[str] = []
        for eco, name in chunk:
            params.extend([eco, name])
        query = f"""
            SELECT DISTINCT ecosystem, package_name
            FROM affected
            WHERE (ecosystem, package_name) IN (VALUES {placeholders})
        """  # nosec B608
        present.update((row["ecosystem"], row["package_name"]) for row in conn.execute(query, params).fetchall())

    return present


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
