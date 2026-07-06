"""Helpers for consistent compliance tag handling across scan outputs.

Blast radius findings can carry two layers of framework tags:

- vulnerability-intrinsic tags derived from CVE/package properties
- context-aware tags derived from agent/server/credential/tool exposure

These helpers merge both sources so JSON, posture scoring, and reports stay
truthful even when a caller only populated one layer.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from typing import Any

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
    "pci_dss_tags": "pci_dss",
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


def framework_qualified_blast_radius_tags(br: BlastRadius) -> list[str]:
    """Return merged tags as stable framework:control strings."""
    tags: list[str] = []
    for field, values in effective_blast_radius_tags(br).items():
        framework = _FIELD_TO_VULN_KEY.get(field, field.removesuffix("_tags"))
        tags.extend(f"{framework}:{value}" for value in values)
    return tags


def framework_qualified_finding_tags(finding: object) -> list[str]:
    """Return unified Finding tags as stable framework:control strings."""
    tags: list[str] = []
    seen: set[str] = set()

    def add(framework: object, control: object) -> None:
        framework_text = str(framework or "").strip()
        control_text = str(control or "").strip()
        if not control_text:
            return
        value = control_text if ":" in control_text else f"{framework_text or 'generic'}:{control_text}"
        if value not in seen:
            seen.add(value)
            tags.append(value)

    for control in getattr(finding, "normalized_controls", lambda: [])():
        add(getattr(control, "framework", "generic"), getattr(control, "control", ""))

    for value in getattr(finding, "compliance_tags", []) or []:
        add("generic", value)

    evidence = getattr(finding, "evidence", {}) or {}
    raw_vuln_tags = evidence.get("vulnerability_compliance_tags", {}) if isinstance(evidence, dict) else {}
    if isinstance(raw_vuln_tags, dict):
        for framework, values in sorted(raw_vuln_tags.items()):
            if isinstance(values, str):
                values = [values]
            for value in values or []:
                add(framework, value)

    return sorted(tags)


COMPLIANCE_TAGS_EXPORT_SEPARATOR = ";"


def compliance_tags_export_cell(finding: object, *, separator: str = COMPLIANCE_TAGS_EXPORT_SEPARATOR) -> str:
    """Canonical semicolon-joined compliance tags for CSV, Parquet, and lake sinks."""
    return separator.join(framework_qualified_finding_tags(finding))


_ROW_TAG_FIELDS: dict[str, str] = {}


def _row_tag_fields() -> dict[str, str]:
    if not _ROW_TAG_FIELDS:
        from agent_bom.finding import LEGACY_CONTROL_FIELDS

        _ROW_TAG_FIELDS.update(dict(LEGACY_CONTROL_FIELDS))
    return _ROW_TAG_FIELDS


def framework_qualified_tags_from_row(row: Mapping[str, Any]) -> list[str]:
    """Flatten framework control tags from API/scan finding rows."""
    tags: list[str] = []
    seen: set[str] = set()

    def add(framework: str, control: object) -> None:
        control_text = str(control or "").strip()
        if not control_text:
            return
        value = control_text if ":" in control_text else f"{framework}:{control_text}"
        if value not in seen:
            seen.add(value)
            tags.append(value)

    raw = row.get("compliance_tags")
    if isinstance(raw, dict):
        for framework, values in sorted(raw.items()):
            if isinstance(values, str):
                values = [values]
            if isinstance(values, list):
                for value in values:
                    add(str(framework), value)
    elif isinstance(raw, list):
        for value in raw:
            add("generic", value)

    for tag_field, framework in _row_tag_fields().items():
        values = row.get(tag_field)
        if isinstance(values, list):
            for value in values:
                add(framework, value)

    controls = row.get("controls")
    if isinstance(controls, list):
        for control in controls:
            if isinstance(control, dict):
                add(str(control.get("framework") or "generic"), control.get("control") or control.get("id"))

    return sorted(tags)
