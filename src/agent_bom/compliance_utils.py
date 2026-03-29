"""Helpers for consistent compliance tag handling across scan outputs.

Blast radius findings can carry two layers of framework tags:

- vulnerability-intrinsic tags derived from CVE/package properties
- context-aware tags derived from agent/server/credential/tool exposure

These helpers merge both sources so JSON, posture scoring, and reports stay
truthful even when a caller only populated one layer.
"""

from __future__ import annotations

from collections.abc import Iterable

from agent_bom.models import BlastRadius

_FIELD_TO_VULN_KEY: dict[str, str] = {
    "owasp_tags": "owasp_llm",
    "atlas_tags": "atlas",
    "nist_ai_rmf_tags": "nist_ai_rmf",
    "owasp_mcp_tags": "owasp_mcp",
    "owasp_agentic_tags": "owasp_agentic",
    "eu_ai_act_tags": "eu_ai_act",
    "nist_csf_tags": "nist_csf",
    "iso_27001_tags": "iso_27001",
    "soc2_tags": "soc2",
    "cis_tags": "cis",
    "cmmc_tags": "cmmc",
    "nist_800_53_tags": "nist_800_53",
    "fedramp_tags": "fedramp",
}


def _merged_tags(*groups: Iterable[str]) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for group in groups:
        for tag in group:
            if tag and tag not in seen:
                seen.add(tag)
                result.append(tag)
    return sorted(result)


def effective_blast_radius_tags(br: BlastRadius) -> dict[str, list[str]]:
    """Return merged framework tags for a blast radius entry."""
    vuln_tags = getattr(br.vulnerability, "compliance_tags", {}) or {}
    result: dict[str, list[str]] = {}
    for field, vuln_key in _FIELD_TO_VULN_KEY.items():
        result[field] = _merged_tags(
            getattr(br, field, []) or [],
            vuln_tags.get(vuln_key, []) or [],
        )
    result["attack_tags"] = _merged_tags(getattr(br, "attack_tags", []) or [])
    return result


def apply_effective_blast_radius_tags(br: BlastRadius) -> BlastRadius:
    """Mutate ``br`` so all framework fields reflect merged effective tags."""
    for field, tags in effective_blast_radius_tags(br).items():
        setattr(br, field, tags)
    return br
