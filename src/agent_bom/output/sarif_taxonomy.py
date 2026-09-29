"""SARIF framework and CWE taxonomies: run catalogs, result references and index compaction."""

from __future__ import annotations

import re
import uuid
from typing import Any

_FRAMEWORK_TAXONOMY_META: dict[str, tuple[str, str, str]] = {
    "owasp_tags": (
        "owasp-llm-top10",
        "OWASP Top 10 for Large Language Model Applications",
        "https://owasp.org/www-project-top-10-for-large-language-model-applications/",
    ),
    "atlas_tags": ("mitre-atlas", "MITRE ATLAS", "https://atlas.mitre.org/"),
    "attack_tags": ("mitre-attack", "MITRE ATT&CK", "https://attack.mitre.org/"),
    "nist_ai_rmf_tags": ("nist-ai-rmf", "NIST AI Risk Management Framework", "https://www.nist.gov/itl/ai-risk-management-framework"),
    "owasp_mcp_tags": ("owasp-mcp", "OWASP MCP Security", "https://owasp.org/"),
    "owasp_agentic_tags": ("owasp-agentic", "OWASP Agentic AI Security", "https://owasp.org/"),
    "eu_ai_act_tags": ("eu-ai-act", "EU AI Act", "https://artificialintelligenceact.eu/"),
    "nist_csf_tags": ("nist-csf", "NIST Cybersecurity Framework", "https://www.nist.gov/cyberframework"),
    "iso_27001_tags": ("iso-27001", "ISO/IEC 27001", "https://www.iso.org/standard/27001"),
    "soc2_tags": (
        "soc2",
        "SOC 2 Trust Services Criteria",
        "https://www.aicpa-cima.com/resources/landing/system-and-organization-controls-soc-suite-of-services",
    ),
    "cis_tags": ("cis-controls", "CIS Controls", "https://www.cisecurity.org/controls"),
    "cmmc_tags": ("cmmc", "Cybersecurity Maturity Model Certification", "https://dodcio.defense.gov/CMMC/"),
    "nist_800_53_tags": ("nist-800-53", "NIST SP 800-53", "https://csrc.nist.gov/publications/detail/sp/800-53/rev-5/final"),
    "fedramp_tags": ("fedramp", "FedRAMP", "https://www.fedramp.gov/"),
    "pci_dss_tags": ("pci-dss", "PCI DSS", "https://www.pcisecuritystandards.org/"),
}


def _framework_taxa_references(properties: dict[str, Any]) -> list[dict]:
    """Build result-level SARIF taxa references for declared framework taxonomies."""
    refs: list[dict] = []
    seen: set[tuple[str, str]] = set()
    for property_name, (taxonomy_name, _full_name, _uri) in _FRAMEWORK_TAXONOMY_META.items():
        raw_tags = properties.get(property_name) or []
        if isinstance(raw_tags, str):
            raw_tags = [raw_tags]
        if not isinstance(raw_tags, list):
            continue
        for raw_tag in raw_tags:
            tag = str(raw_tag).strip()
            if not tag:
                continue
            key = (taxonomy_name, tag)
            if key in seen:
                continue
            seen.add(key)
            refs.append({"id": tag, "toolComponent": {"name": taxonomy_name}})
    return refs


def _build_run_taxonomies(results: list[dict]) -> list[dict]:
    """Build SARIF run-level taxonomies from per-result framework tags."""
    tags_by_property: dict[str, set[str]] = {key: set() for key in _FRAMEWORK_TAXONOMY_META}
    for result in results:
        properties = result.get("properties") or {}
        if not isinstance(properties, dict):
            continue
        for property_name in tags_by_property:
            raw_tags = properties.get(property_name) or []
            if isinstance(raw_tags, str):
                raw_tags = [raw_tags]
            if isinstance(raw_tags, list):
                tags_by_property[property_name].update(str(tag) for tag in raw_tags if str(tag).strip())

    taxonomies: list[dict] = []
    for property_name, tags in tags_by_property.items():
        if not tags:
            continue
        name, full_name, uri = _FRAMEWORK_TAXONOMY_META[property_name]
        taxonomies.append(
            {
                "name": name,
                "fullName": full_name,
                "informationUri": uri,
                # Honesty: agent-bom's finding→control mappings are its own
                # asserted judgment of which control a finding evidences, not an
                # authority-published crosswalk. Label the provenance so SARIF
                # consumers never read these as official. taxa carry control IDs
                # only (name == id) — no copyrighted control-title text.
                "properties": {
                    "agent-bom:mappingProvenance": "vendor-asserted",
                    "agent-bom:mappingProvenanceNote": (
                        "Finding-to-control mappings are agent-bom's own asserted judgment of which "
                        "control a finding evidences, not an authority-published crosswalk."
                    ),
                },
                "taxa": [{"id": tag, "name": tag} for tag in sorted(tags)],
            }
        )
    return taxonomies


def _attach_cwe_taxonomy(results: list[dict], rules: list[dict]) -> dict | None:
    """Link structured finding CWEs to SARIF's standard CWE taxonomy.

    GUIDs resolve taxonomy descriptors per SARIF 2.1.0 sections 3.52-3.54;
    names are display labels only. Rule mappings are relevant associations:
    a shared rule must not assign every observed CWE to all of its results.
    """
    taxonomy_guid = str(uuid.uuid5(uuid.NAMESPACE_URL, "https://cwe.mitre.org/"))

    def taxon_guid(value: str) -> str:
        return str(uuid.uuid5(uuid.NAMESPACE_URL, f"https://cwe.mitre.org/data/definitions/{value}.html"))

    def reference(value: str) -> dict:
        return {"id": value, "guid": taxon_guid(value), "toolComponent": {"name": "CWE", "guid": taxonomy_guid}}

    by_rule: dict[str, set[str]] = {}
    all_ids: set[str] = set()
    for result in results:
        cwes = sorted(
            {
                value[4:]
                for value in result.get("properties", {}).get("cwe_ids", [])
                if isinstance(value, str) and re.fullmatch(r"CWE-[1-9][0-9]{0,8}", value)
            },
            key=int,
        )
        if not cwes:
            continue
        all_ids.update(cwes)
        by_rule.setdefault(result["ruleId"], set()).update(cwes)
        result.setdefault("taxa", []).extend(reference(value) for value in cwes)
    if not all_ids:
        return None
    for rule in rules:
        rule_cwes = by_rule.get(rule["id"], set())
        if rule_cwes:
            rule.setdefault("relationships", []).extend(
                {"target": reference(value), "kinds": ["relevant"]} for value in sorted(rule_cwes, key=int)
            )
    return {
        "name": "CWE",
        "guid": taxonomy_guid,
        "fullName": "Common Weakness Enumeration",
        "informationUri": "https://cwe.mitre.org/",
        "organization": "MITRE",
        "isComprehensive": False,
        "taxa": [
            {
                "id": value,
                "guid": taxon_guid(value),
                "name": f"CWE-{value}",
                "helpUri": f"https://cwe.mitre.org/data/definitions/{value}.html",
            }
            for value in sorted(all_ids, key=int)
        ],
    }


def _taxonomies_as_tool_extensions(taxonomies: list[dict]) -> list[dict]:
    """Expose framework catalogs as SARIF tool extensions for catalog readers."""
    extensions: list[dict] = []
    for taxonomy in taxonomies:
        extension_taxa: list[dict] = []
        for taxon in taxonomy.get("taxa", []):
            compact_taxon = dict(taxon)
            if compact_taxon.get("name") == compact_taxon.get("id"):
                compact_taxon.pop("name", None)
            extension_taxa.append(compact_taxon)
        extension = {
            "name": taxonomy["name"],
            "fullName": taxonomy.get("fullName", taxonomy["name"]),
            "informationUri": taxonomy.get("informationUri", ""),
            "taxa": extension_taxa,
        }
        extensions.append(extension)
    return extensions


def _compact_taxa_references(results: list[dict], taxonomies: list[dict]) -> None:
    """Replace repeated taxonomy names and IDs with SARIF index references."""
    taxonomy_indexes = {taxonomy.get("name"): index for index, taxonomy in enumerate(taxonomies)}
    taxon_indexes = {
        (taxonomy.get("name"), taxon.get("id")): index for taxonomy in taxonomies for index, taxon in enumerate(taxonomy.get("taxa") or [])
    }
    for result in results:
        references = result.get("taxa")
        if not isinstance(references, list):
            continue
        compact: list[dict] = []
        for reference in references:
            if not isinstance(reference, dict):
                compact.append(reference)
                continue
            component = reference.get("toolComponent")
            taxonomy_name = component.get("name") if isinstance(component, dict) else None
            taxon_id = reference.get("id")
            taxonomy_index = taxonomy_indexes.get(taxonomy_name)
            taxon_index = taxon_indexes.get((taxonomy_name, taxon_id))
            if taxonomy_index is None or taxon_index is None:
                compact.append(reference)
                continue
            compact.append({"index": taxon_index, "toolComponent": {"index": taxonomy_index}})
        result["taxa"] = compact
