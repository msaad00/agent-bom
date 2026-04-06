"""Helpers for advisory source attribution and coverage summaries."""

from __future__ import annotations

from collections import Counter
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from agent_bom.models import Package, Vulnerability

PRIMARY_ADVISORY_SOURCES: tuple[str, ...] = ("osv", "ghsa", "nvidia_csaf")
ENRICHMENT_ADVISORY_SOURCES: tuple[str, ...] = ("nvd", "epss", "cisa_kev")
_PREFERRED_SOURCE_ORDER: tuple[str, ...] = PRIMARY_ADVISORY_SOURCES + ENRICHMENT_ADVISORY_SOURCES


def normalize_advisory_source(source: str | None) -> str | None:
    """Normalize advisory source names to stable public contract values."""
    if not source:
        return None
    value = source.strip().lower().replace("-", "_")
    aliases = {
        "github": "ghsa",
        "github_advisory": "ghsa",
        "github_security_advisory": "ghsa",
        "kev": "cisa_kev",
        "cisa": "cisa_kev",
        "cisa_kev_catalog": "cisa_kev",
        "nvidia": "nvidia_csaf",
        "nvidia_advisory": "nvidia_csaf",
        "nvidia_csaf_advisory": "nvidia_csaf",
    }
    return aliases.get(value, value)


def merge_advisory_sources(*sources: str | None) -> list[str]:
    """Deduplicate and order advisory sources using stable preference rules."""
    seen: set[str] = set()
    merged: list[str] = []
    for source in sources:
        normalized = normalize_advisory_source(source)
        if not normalized or normalized in seen:
            continue
        seen.add(normalized)
        merged.append(normalized)
    preferred = [source for source in _PREFERRED_SOURCE_ORDER if source in seen]
    unknown = sorted(source for source in merged if source not in _PREFERRED_SOURCE_ORDER)
    return preferred + unknown


def primary_advisory_source(vuln: "Vulnerability") -> str:
    """Return the highest-signal advisory source label for a vulnerability."""
    sources = getattr(vuln, "all_advisory_sources", []) or []
    for preferred in PRIMARY_ADVISORY_SOURCES:
        if preferred in sources:
            return preferred
    return sources[0] if sources else "unknown"


def summarize_advisory_coverage(packages: list["Package"]) -> dict:
    """Aggregate advisory-source and enrichment depth across package findings."""
    primary_counts: Counter[str] = Counter()
    enrichment_counts: Counter[str] = Counter()
    total_records = 0
    with_enrichment = 0
    multi_source = 0
    primary_only = 0

    for pkg in packages:
        for vuln in pkg.vulnerabilities:
            total_records += 1
            sources = getattr(vuln, "all_advisory_sources", []) or []
            primary = [source for source in sources if source in PRIMARY_ADVISORY_SOURCES]
            enrichment = [source for source in sources if source in ENRICHMENT_ADVISORY_SOURCES]
            primary_counts.update(primary)
            enrichment_counts.update(enrichment)
            if enrichment:
                with_enrichment += 1
            else:
                primary_only += 1
            if len(sources) > 1:
                multi_source += 1

    return {
        "finding_records": total_records,
        "primary_sources": {source: primary_counts.get(source, 0) for source in PRIMARY_ADVISORY_SOURCES},
        "enrichment_sources": {source: enrichment_counts.get(source, 0) for source in ENRICHMENT_ADVISORY_SOURCES},
        "records_with_enrichment": with_enrichment,
        "records_primary_only": primary_only,
        "records_with_multiple_sources": multi_source,
    }
