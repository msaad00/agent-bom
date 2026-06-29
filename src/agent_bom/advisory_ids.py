"""Canonical vulnerability identifier helpers for cross-tool parity."""

from __future__ import annotations

import re
from collections.abc import Iterable

_ALPINE_CVE_RE = re.compile(r"^ALPINE-CVE-(\d{4}-\d+)$", re.IGNORECASE)
_DEBIAN_CVE_RE = re.compile(r"^DEBIAN-CVE-(\d{4}-\d+)$", re.IGNORECASE)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

# Ordered tiers surfaced on findings for SCA transparency (distro-first strategy).
MATCH_CONFIDENCE_DISTRO_CONFIRMED = "distro_confirmed"
MATCH_CONFIDENCE_OSV_RANGE = "osv_range"
MATCH_CONFIDENCE_OSV_ECOSYSTEM = "osv_ecosystem"
MATCH_CONFIDENCE_UNFIXED_DISTRO = "unfixed_distro"
MATCH_CONFIDENCE_NVD_CPE_CANDIDATE = "nvd_cpe_candidate"


def derive_cve_from_advisory_id(advisory_id: str) -> str | None:
    """Map distro-scoped advisory IDs to canonical CVE-* when the pattern allows."""
    if not advisory_id:
        return None
    normalized = advisory_id.strip().upper()
    if _CVE_RE.match(normalized):
        return normalized
    alpine = _ALPINE_CVE_RE.match(normalized)
    if alpine:
        return f"CVE-{alpine.group(1)}"
    debian = _DEBIAN_CVE_RE.match(normalized)
    if debian:
        return f"CVE-{debian.group(1)}"
    return None


def canonical_vulnerability_id(advisory_id: str, aliases: Iterable[str] = ()) -> tuple[str, list[str]]:
    """Return canonical vulnerability id plus remaining aliases (stable order)."""
    raw_id = (advisory_id or "").strip()
    if not raw_id:
        return raw_id, []

    alias_list = [alias.strip() for alias in aliases if isinstance(alias, str) and alias.strip()]
    cve_from_alias = next((alias for alias in alias_list if alias.upper().startswith("CVE-")), None)
    derived = derive_cve_from_advisory_id(raw_id)
    canonical = cve_from_alias or derived or raw_id

    remaining: list[str] = []
    seen = {canonical}
    if raw_id not in seen:
        remaining.append(raw_id)
        seen.add(raw_id)
    for alias in alias_list:
        if alias == canonical or alias in seen:
            continue
        remaining.append(alias)
        seen.add(alias)
    return canonical, remaining


def match_confidence_tier(
    *,
    advisory_source: str | None,
    db_ecosystem: str | None,
    package_ecosystem: str | None,
    fixed_version: str | None,
) -> str:
    """Classify how a vulnerability match was derived for SCA transparency."""
    source = (advisory_source or "").lower()
    if source in {"alpine-secdb", "debian-tracker", "debian-elts"}:
        return MATCH_CONFIDENCE_DISTRO_CONFIRMED
    eco = (db_ecosystem or package_ecosystem or "").lower()
    if eco.startswith(("alpine:", "debian:", "ubuntu:")):
        return MATCH_CONFIDENCE_DISTRO_CONFIRMED
    if eco in {"apk", "deb", "rpm"} and not fixed_version:
        return MATCH_CONFIDENCE_UNFIXED_DISTRO
    if fixed_version:
        return MATCH_CONFIDENCE_OSV_RANGE
    return MATCH_CONFIDENCE_OSV_ECOSYSTEM


def all_cve_identifiers(advisory_id: str, aliases: Iterable[str] = ()) -> list[str]:
    """Return unique CVE-* identifiers associated with one advisory."""
    canonical, remaining = canonical_vulnerability_id(advisory_id, aliases)
    cves: list[str] = []
    seen: set[str] = set()

    def _add(value: str | None) -> None:
        if not value:
            return
        upper = value.upper()
        if not upper.startswith("CVE-") or upper in seen:
            return
        seen.add(upper)
        cves.append(upper)

    _add(derive_cve_from_advisory_id(canonical) or (canonical if canonical.upper().startswith("CVE-") else None))
    for alias in remaining:
        _add(derive_cve_from_advisory_id(alias) or (alias if alias.upper().startswith("CVE-") else None))
    return cves
