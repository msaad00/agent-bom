"""Canonical vulnerability identifier helpers for cross-tool parity."""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

_ALPINE_CVE_RE = re.compile(r"^ALPINE-CVE-(\d{4}-\d+)$", re.IGNORECASE)
_DEBIAN_CVE_RE = re.compile(r"^DEBIAN-CVE-(\d{4}-\d+)$", re.IGNORECASE)
_CVE_RE = re.compile(r"^CVE-\d{4}-\d+$", re.IGNORECASE)

# Ordered tiers surfaced on findings for SCA transparency (distro-first strategy).
MATCH_CONFIDENCE_DISTRO_CONFIRMED = "distro_confirmed"
MATCH_CONFIDENCE_OSV_RANGE = "osv_range"
MATCH_CONFIDENCE_OSV_ECOSYSTEM = "osv_ecosystem"
MATCH_CONFIDENCE_UNFIXED_DISTRO = "unfixed_distro"
MATCH_CONFIDENCE_NVD_CPE_CANDIDATE = "nvd_cpe_candidate"
# A distro package with no release metadata, matched against every supported
# release branch at once. The advisory is real for *some* release; whether it is
# real for the scanned one is unknown, and so is which branch's fix applies.
MATCH_CONFIDENCE_AMBIGUOUS_DISTRO_RELEASE = "ambiguous_distro_release"


def upstream_advisory_ids(value: object) -> list[str]:
    """Keep explicit OSV upstream relationships separate from identity aliases."""
    if not isinstance(value, list):
        return []
    return sorted({item for item in value if isinstance(item, str) and re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._:+-]{0,255}", item)})


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


def cve_alias_metadata(values: object) -> dict[str, list[str]]:
    """Retain bounded, validated public CVE aliases without arbitrary metadata."""
    if not isinstance(values, list):
        return {}
    aliases = list(
        dict.fromkeys(
            cve
            for value in values[:100]
            if isinstance(value, str) and len(value) <= 64 and value.isascii() and (cve := derive_cve_from_advisory_id(value)) is not None
        )
    )
    return {"aliases": aliases} if aliases else {}


def upstream_enrichment_metadata(value: Any) -> dict[str, Any]:
    """Serialize directional links and the CVEs supplying scalar enrichment."""

    def read(key: str, default: Any = None) -> Any:
        return value.get(key, default) if isinstance(value, Mapping) else getattr(value, key, default)

    return {"upstream_ids": read("upstream_ids", []) or [], "epss_cve_id": read("epss_cve_id"), "kev_cve_id": read("kev_cve_id")}


def vulnerability_enrichment_metadata(value: Any) -> dict[str, Any]:
    """Keep score, dates and attribution together in machine evidence."""
    return {
        **upstream_enrichment_metadata(value),
        **{key: getattr(value, key, None) for key in ("epss_score", "epss_percentile", "is_kev", "kev_date_added", "kev_due_date")},
    }


def safe_upstream_enrichment_metadata(row: Mapping[str, Any]) -> dict[str, Any]:
    """Public finding projection retains only validated structural CVE links."""
    raw_evidence = row.get("evidence")
    evidence = raw_evidence if isinstance(raw_evidence, Mapping) else {}
    result: dict[str, Any] = {}
    upstream = cve_alias_metadata(row.get("upstream_ids", evidence.get("upstream_ids"))).get("aliases", [])
    if upstream:
        result["upstream_ids"] = upstream
    for key in ("epss_cve_id", "kev_cve_id"):
        ids = cve_alias_metadata([row.get(key, evidence.get(key))]).get("aliases", [])
        if ids:
            result[key] = ids[0]
    return result


def finding_advisory_metadata(evidence: Mapping[str, Any]) -> dict[str, Any]:
    """Keep equivalence aliases and directional links visibly distinct."""
    return {"advisory_aliases": evidence.get("advisory_aliases") or [], **upstream_enrichment_metadata(evidence)}
