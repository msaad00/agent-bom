"""Apply fetched EPSS, CISA KEV and NVD intel onto vulnerability records (pure, no I/O)."""

from __future__ import annotations

import math
from typing import Optional

from agent_bom.advisory_ids import upstream_advisory_ids
from agent_bom.models import Vulnerability


def calculate_exploitability(epss_score: Optional[float]) -> Optional[str]:
    """Calculate exploitability level from EPSS score.

    Thresholds configurable via ``AGENT_BOM_EPSS_CRITICAL_THRESHOLD``
    and ``AGENT_BOM_EPSS_HIGH_THRESHOLD``.
    """
    if epss_score is None:
        return None

    from agent_bom.config import EPSS_CRITICAL_THRESHOLD, EPSS_HIGH_LIKELY_THRESHOLD

    if epss_score >= EPSS_CRITICAL_THRESHOLD:
        return "HIGH"
    if epss_score >= EPSS_HIGH_LIKELY_THRESHOLD:
        return "MEDIUM"
    return "LOW"


def vuln_cve_ids(vuln: Vulnerability, *, include_upstream: bool = True) -> list[str]:
    ids = [vuln.id] if vuln.id.startswith("CVE-") else []
    ids.extend(alias for alias in vuln.aliases if alias.startswith("CVE-"))
    if include_upstream:
        ids.extend(item for item in upstream_advisory_ids(vuln.upstream_ids) if item.startswith("CVE-"))
    return sorted(set(ids))


def select_kev_cve(cve_ids: list[str], kev_data: dict) -> str | None:
    """Select the earliest remediation deadline, retaining that entry's dates."""
    matches = [cve for cve in cve_ids if cve in kev_data]
    return min(matches, key=lambda cve: (kev_data[cve].get("due_date") or "9999", cve)) if matches else None


def select_epss_cve(cve_ids: list[str], epss_data: dict) -> str | None:
    """Select maximum probability; the CVE breaks ties deterministically."""
    matches = [
        cve
        for cve in cve_ids
        if cve in epss_data
        and isinstance(epss_data[cve].get("score"), (int, float))
        and not isinstance(epss_data[cve]["score"], bool)
        and math.isfinite(epss_data[cve]["score"])
        and 0 <= epss_data[cve]["score"] <= 1
    ]
    return min(matches, key=lambda cve: (-epss_data[cve]["score"], cve)) if matches else None


def apply_kev_entry(vuln: Vulnerability, cve_ids: list[str], kev_data: dict) -> bool:
    cve = select_kev_cve(cve_ids, kev_data)
    if cve is None:
        return False
    kev = kev_data[cve]
    vuln.is_kev = True
    vuln.kev_cve_id = cve
    vuln.kev_date_added = kev.get("date_added")
    vuln.kev_due_date = kev.get("due_date")
    return True


def epss_percentile(value: object) -> float | None:
    """Missing or malformed percentile must not become invalid JSON numeric data."""
    if isinstance(value, (int, float)) and not isinstance(value, bool) and math.isfinite(value) and 0 <= value <= 100:
        return float(value)
    return None


def apply_epss_entry(vuln: Vulnerability, cve_ids: list[str], epss_data: dict[str, dict]) -> bool:
    """Apply maximum matching probability with its own percentile and CVE."""
    cve = select_epss_cve(cve_ids, epss_data)
    if cve is None:
        return False
    epss = epss_data[cve]
    vuln.epss_cve_id = cve
    vuln.epss_score = epss["score"]
    vuln.epss_percentile = epss_percentile(epss.get("percentile"))
    vuln.exploitability = calculate_exploitability(epss["score"])
    return True


def apply_nvd_entry(vuln: Vulnerability, cve_ids: list[str], nvd_data: dict[str, dict]) -> bool:
    """Merge the first matching CVE's NVD CWEs, dates, status and references."""
    for cve in cve_ids:
        if cve not in nvd_data:
            continue
        nvd = nvd_data[cve]
        existing_cwes = set(vuln.cwe_ids)
        for weakness in nvd.get("weaknesses", []):
            for desc in weakness.get("description", []):
                cwe_val = desc.get("value", "")
                if cwe_val.startswith("CWE-") and cwe_val not in existing_cwes:
                    vuln.cwe_ids.append(cwe_val)
                    existing_cwes.add(cwe_val)
        vuln.nvd_published = nvd.get("published")
        vuln.nvd_modified = nvd.get("lastModified")
        vuln.nvd_status = nvd.get("vulnStatus")
        # Merge NVD references with existing OSV references (deduplicated)
        existing_urls = set(vuln.references)
        for ref in nvd.get("references", []):
            url = ref.get("url")
            if url and url not in existing_urls:
                vuln.references.append(url)
                existing_urls.add(url)
        # Always include canonical NVD link as first reference
        canonical = f"https://nvd.nist.gov/vuln/detail/{cve}"
        if canonical not in existing_urls:
            vuln.references.insert(0, canonical)
        return True
    return False


def apply_intel(vuln: Vulnerability, epss_data: dict[str, dict], kev_data: dict, nvd_data: dict[str, dict]) -> bool:
    """Apply every source to one vulnerability; True when any source matched."""
    cve_ids = vuln_cve_ids(vuln)
    if not cve_ids:
        return False
    epss_hit = apply_epss_entry(vuln, cve_ids, epss_data)
    kev_hit = apply_kev_entry(vuln, cve_ids, kev_data)
    nvd_hit = apply_nvd_entry(vuln, vuln_cve_ids(vuln, include_upstream=False), nvd_data)
    return epss_hit or kev_hit or nvd_hit
