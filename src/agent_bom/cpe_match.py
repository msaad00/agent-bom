"""CPE-based vulnerability matching against the local NVD CPE applicability cache.

This is the long-tail matcher for components that the OSV and distro advisory
feeds do not cover — system software, vendored binaries, and other non-ecosystem
products. It maps a discovered component to candidate CPE product names, then
checks the component's version against NVD's stored ``cpe:2.3`` applicability
ranges (see :func:`agent_bom.db.sync._extract_nvd_cpe_matches`).

Matches are emitted at the lower-confidence ``nvd_cpe_candidate`` tier: CPE
vendor/product names do not always equal package names, so these are candidates
for review rather than confirmed hits. The matcher is opt-in via
``AGENT_BOM_ENABLE_CPE_MATCH`` so it never silently adds noise to a scan.
"""

from __future__ import annotations

import re
import sqlite3
from typing import Any, Optional

from agent_bom.advisory_ids import MATCH_CONFIDENCE_NVD_CPE_CANDIDATE
from agent_bom.version_utils import version_in_range

# CPE versions are bare dotted strings with no ecosystem; use the generic
# comparator path in version_in_range.
_CPE_ECOSYSTEM = "generic"


def normalize_cpe_product(name: str) -> str:
    """Lowercase + underscore form NVD uses for CPE vendor/product fields."""
    return re.sub(r"[\s\-]+", "_", name.strip().lower())


def candidate_cpe_products(name: str) -> list[str]:
    """Candidate CPE ``product`` strings for a discovered component name.

    CPE products are normalized (lowercase, underscores). We also try the
    hyphenated and raw-lowercase forms because real-world naming varies.
    """
    base = normalize_cpe_product(name)
    out: list[str] = []
    for candidate in (base, base.replace("_", "-"), name.strip().lower()):
        if candidate and candidate not in out:
            out.append(candidate)
    return out


def _cpe_range_applies(version: str, row: sqlite3.Row) -> bool:
    """Whether ``version`` falls inside one stored CPE applicability row."""
    exact = row["version"]
    if exact:
        # The criteria pins a specific version (e.g. cpe:2.3:a:acme:gadget:3.1).
        return str(version).strip() == str(exact).strip()

    introduced = row["version_start"]  # start bound (incl/excl) -> inclusive lower
    fixed = row["version_end"] if row["version_end_op"] == "excluding" else None
    last_affected = row["version_end"] if row["version_end_op"] == "including" else None

    if not (introduced or fixed or last_affected):
        # Product matches with no version bounds -> every version is affected.
        return True
    return version_in_range(version, introduced, fixed, last_affected, _CPE_ECOSYSTEM)


def match_component_cpe(
    conn: sqlite3.Connection,
    name: str,
    version: str,
    *,
    vendor: Optional[str] = None,
    limit: int = 500,
) -> list[dict[str, Any]]:
    """Return ``nvd_cpe_candidate`` CVE matches for a component (name, version).

    When ``vendor`` is supplied (e.g. inferred from a purl namespace or
    Maven groupId) the candidate set is constrained to that CPE vendor, which is
    the main false-positive control: it disambiguates same-named products from
    different vendors. Empty when the component has no name/version, no candidate
    CPE product is in the cache, or no version range applies.
    """
    if not name or not version:
        return []
    products = candidate_cpe_products(name)
    if not products:
        return []

    placeholders = ",".join("?" * len(products))
    query = (
        "SELECT cve_id, criteria, version, version_start, version_start_op, "
        "version_end, version_end_op "
        f"FROM cpe_matches WHERE product IN ({placeholders})"  # nosec B608 - placeholders are generated solely from "?" markers
    )
    params: list[Any] = [*products]
    if vendor:
        query += " AND vendor = ?"
        params.append(normalize_cpe_product(vendor))
    query += " LIMIT ?"
    params.append(limit)
    rows = conn.execute(query, params).fetchall()

    matched: dict[str, str] = {}
    for row in rows:
        cve_id = row["cve_id"]
        if cve_id in matched:
            continue
        try:
            applies = _cpe_range_applies(version, row)
        except Exception:  # noqa: BLE001 - a malformed range must not abort the scan
            applies = False
        if applies:
            matched[cve_id] = row["criteria"]

    return [
        {
            "cve_id": cve_id,
            "cpe": criteria,
            "match_confidence_tier": MATCH_CONFIDENCE_NVD_CPE_CANDIDATE,
        }
        for cve_id, criteria in matched.items()
    ]
