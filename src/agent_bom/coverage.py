"""Detect OS releases whose vulnerability data the local DB does not carry.

Advisory feeds drop end-of-life distro releases. When a release is dropped, the
local DB holds (near-)zero advisory rows for it even though the image is full of
packages from that release — so a scan can report a deceptively low or zero
vulnerability count for a release that is, in reality, riddled with known CVEs.

This module flags that situation so the result is never mistaken for a clean
bill of health. It is a *warning-only* signal: it does not change version
matching, suppression, or which advisories are reported. The per-release
matching is correct; the data is simply absent.

The check is data-source-agnostic and threshold-based — it fires for any
``ecosystem:release`` that has many packages present in the image but
(near-)zero advisory rows in the local DB, *while the feed clearly carries the
distro family at other releases*. That last gate keeps it quiet when the local
DB is empty (e.g. a default online scan that resolves against the remote API),
where every release legitimately has zero local rows.
"""

from __future__ import annotations

import logging
import sqlite3
from dataclasses import asdict, dataclass
from typing import TYPE_CHECKING, Optional, Sequence

if TYPE_CHECKING:
    from agent_bom.models import Package

_logger = logging.getLogger(__name__)

# An image must carry at least this many packages of a release before a missing
# advisory set is treated as a coverage gap (vs. a single stray package).
_MIN_PACKAGES_FOR_RELEASE = 5
# A release with this few advisory rows (while the family has many) counts as
# uncovered. Kept above zero so a handful of stray rows can't mask an EOL gap.
_MAX_ROWS_FOR_UNCOVERED = 5
# The feed must carry at least this many advisory rows for the distro family
# (across all releases) before we conclude "carried generally, just not this
# release". This gates out the empty/absent-DB case where every release has zero
# local rows and the remote API is the live source.
_MIN_FAMILY_ROWS = 50


@dataclass(frozen=True)
class CoverageWarning:
    """A structured warning that a release's advisory coverage is incomplete."""

    ecosystem: str  # distro family, e.g. "debian"
    release: str  # release identifier as stored in the DB, e.g. "debian:10"
    reason: str  # short machine-readable reason code
    detail: str  # human-readable explanation
    package_count: int  # OS packages of this release found in the scan target
    advisory_rows: int  # advisory rows the local DB holds for this release

    def to_dict(self) -> dict:
        return asdict(self)


def _release_key(pkg: "Package") -> Optional[tuple[str, str]]:
    """Return ``(family, db_release_key)`` for an OS package with a known release.

    The DB stores distro advisories with a release-suffixed, lowercased
    ecosystem (``debian:10``, ``ubuntu:22.04``, ``alpine:v3.18``). This mirrors
    that key so coverage can be counted per release. Returns ``None`` for
    packages without a concrete release (no per-release coverage claim possible).
    """
    eco = (pkg.ecosystem or "").lower()
    distro_name = (getattr(pkg, "distro_name", None) or "").lower()
    distro_version = (getattr(pkg, "distro_version", None) or "").strip()
    if not distro_version:
        return None
    if eco == "deb":
        if distro_name == "debian":
            return ("debian", f"debian:{distro_version.split('.', 1)[0]}")
        if distro_name == "ubuntu":
            return ("ubuntu", f"ubuntu:{distro_version}")
        return None
    if eco == "apk":
        normalized = distro_version if distro_version.startswith("v") else f"v{distro_version}"
        return ("alpine", f"alpine:{normalized}")
    return None


def _open_readonly_db() -> Optional[sqlite3.Connection]:
    try:
        from agent_bom.db.schema import DB_PATH, open_existing_db_readonly

        if not DB_PATH.exists():
            return None
        return open_existing_db_readonly(DB_PATH)
    except Exception as exc:  # noqa: BLE001
        _logger.debug("coverage check could not open local DB: %s", exc)
        return None


def _count_family_rows(conn: sqlite3.Connection, family: str) -> int:
    row = conn.execute(
        "SELECT COUNT(*) FROM affected WHERE ecosystem LIKE ?",
        (f"{family}:%",),
    ).fetchone()
    return int(row[0]) if row else 0


def _count_release_rows(conn: sqlite3.Connection, release_key: str) -> int:
    # Some releases carry sub-suffixed variants (e.g. ``ubuntu:22.04:lts``).
    row = conn.execute(
        "SELECT COUNT(*) FROM affected WHERE ecosystem = ? OR ecosystem LIKE ?",
        (release_key, f"{release_key}:%"),
    ).fetchone()
    return int(row[0]) if row else 0


def detect_release_coverage_gaps(
    packages: Sequence["Package"],
    *,
    conn: Optional[sqlite3.Connection] = None,
) -> list[dict]:
    """Return coverage warnings for OS releases the local DB does not carry.

    Args:
        packages: scanned packages (OS packages must carry ``distro_name`` /
            ``distro_version`` for a per-release coverage claim).
        conn: optional read-only DB connection; opened (and closed) internally
            when not supplied.

    Returns:
        A list of :class:`CoverageWarning` dicts — empty when coverage looks
        complete or the local DB has no data for the relevant distro families.
    """
    groups: dict[tuple[str, str], int] = {}
    for pkg in packages:
        key = _release_key(pkg)
        if key is None:
            continue
        groups[key] = groups.get(key, 0) + 1

    candidates = {key: count for key, count in groups.items() if count >= _MIN_PACKAGES_FOR_RELEASE}
    if not candidates:
        return []

    owns_conn = False
    if conn is None:
        conn = _open_readonly_db()
        owns_conn = conn is not None
    if conn is None:
        return []

    try:
        warnings: list[dict] = []
        for (family, release_key), pkg_count in sorted(candidates.items()):
            try:
                family_rows = _count_family_rows(conn, family)
            except sqlite3.Error as exc:
                _logger.debug("coverage check family count failed for %s: %s", family, exc)
                continue
            if family_rows < _MIN_FAMILY_ROWS:
                # Feed doesn't carry this distro family at all (or DB empty) — not
                # a per-release gap; the remote/online path covers it instead.
                continue
            release_rows = _count_release_rows(conn, release_key)
            if release_rows > _MAX_ROWS_FOR_UNCOVERED:
                continue
            warnings.append(
                CoverageWarning(
                    ecosystem=family,
                    release=release_key,
                    reason="release_advisories_absent",
                    detail=(
                        f"Vulnerability coverage for {release_key} is incomplete. The local "
                        f"advisory data carries {family_rows} advisories for {family} overall but "
                        f"only {release_rows} for {release_key}, while this scan target has "
                        f"{pkg_count} {family} package(s) from that release. This release is "
                        f"likely end-of-life and no longer carried by the data source — results "
                        f"UNDER-report and a low or zero vulnerability count is NOT a clean bill "
                        f"of health. Re-scan against a source that tracks end-of-life releases."
                    ),
                    package_count=pkg_count,
                    advisory_rows=release_rows,
                ).to_dict()
            )
        return warnings
    finally:
        if owns_conn:
            try:
                conn.close()
            except Exception:  # noqa: BLE001
                pass
