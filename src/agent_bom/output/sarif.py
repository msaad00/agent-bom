"""SARIF 2.1.0 output for GitHub Security tab integration."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any, Optional

from agent_bom.asset_provenance import (
    agent_discovery_provenance,
    sanitize_discovery_provenance,
)
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.exploitability import exploitability_tags, parse_cvss_vector_signals
from agent_bom.finding import Finding, FindingType
from agent_bom.models import AIBOMReport, BlastRadius, Severity
from agent_bom.output.exposure_path import (
    exposure_path_blast_summary,
    exposure_path_chain,
    exposure_path_for_report_finding,
)
from agent_bom.output.finding_views import (
    cve_findings,
    evidence,
    exploit_likelihood_value,
    finding_severity,
    package_ecosystem,
    package_name,
    package_version,
)
from agent_bom.security import sanitize_sensitive_payload

_SARIF_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.NONE: "none",
    Severity.UNKNOWN: "note",
}


def _sarif_fingerprint_fields(
    *,
    stable_input: str,
    artifact_uri: str,
    start_line: int = 1,
) -> dict[str, dict[str, str]]:
    """Return SARIF fingerprints and GitHub partialFingerprints for dedup."""
    return {
        "fingerprints": {
            "agent-bom/v1": hashlib.sha256(stable_input.encode()).hexdigest(),
        },
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha256(f"{artifact_uri}:{start_line}".encode()).hexdigest(),
        },
    }


# GitHub Security tab uses security-severity (0.0–10.0) for granular sorting.
# Ranges per docs.github.com: >9.0=critical, 7.0–8.9=high, 4.0–6.9=medium, 0.1–3.9=low
_SECURITY_SEVERITY_SCORE = {
    Severity.CRITICAL: "9.5",
    Severity.HIGH: "7.5",
    Severity.MEDIUM: "5.5",
    Severity.LOW: "2.5",
    Severity.NONE: "0.0",
    Severity.UNKNOWN: "0.0",
}

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


# Per-ecosystem manifest candidates, checked in order. Lets a SARIF result for
# a maven/go/cargo finding point at pom.xml/go.mod/Cargo.toml instead of all
# findings collapsing onto the first manifest in the directory.
_ECOSYSTEM_MANIFESTS: dict[str, tuple[str, ...]] = {
    "pypi": ("requirements.txt", "pyproject.toml", "setup.py", "Pipfile"),
    "npm": ("package.json",),
    "maven": ("pom.xml", "build.gradle", "build.gradle.kts"),
    "gradle": ("build.gradle", "build.gradle.kts", "pom.xml"),
    "go": ("go.mod",),
    "cargo": ("Cargo.toml", "Cargo.lock"),
    "rubygems": ("Gemfile", "Gemfile.lock"),
    "composer": ("composer.json",),
    "nuget": ("packages.config",),
    "hex": ("mix.exs",),
    "pub": ("pubspec.yaml",),
    "conda": ("environment.yml", "environment.yaml"),
}


def _ecosystem_from_purl(identifier: Optional[str]) -> Optional[str]:
    """Extract the ecosystem from a purl identifier (``pkg:pypi/...`` → ``pypi``)."""
    if identifier and identifier.startswith("pkg:"):
        rest = identifier[4:]
        return rest.split("/", 1)[0].split("@", 1)[0].lower() or None
    return None


def _to_relative_path(path: str, ecosystem: Optional[str] = None) -> str:
    """Convert an absolute path to a relative path suitable for SARIF.

    GitHub Code Scanning requires relative paths from the repo root.
    Absolute paths cause "No summary of scanned files" in the Security tab.
    For dependency findings on a directory, points to the manifest of the
    finding's own ecosystem (so maven/go/cargo findings don't all collapse onto
    the first manifest), falling back to any present manifest.
    """

    p = Path(path)
    # If it's a directory (e.g., project root from --self-scan), point to manifest
    if p.is_dir():
        if ecosystem:
            for manifest in _ECOSYSTEM_MANIFESTS.get(ecosystem.lower(), ()):
                if (p / manifest).exists():
                    return manifest
        for manifest in ("pyproject.toml", "package.json", "go.mod", "Cargo.toml", "requirements.txt", "pom.xml"):
            if (p / manifest).exists():
                return manifest
        return "pyproject.toml"  # default fallback for Python projects

    # If it's an absolute path, try to make it relative to cwd
    if p.is_absolute():
        try:
            return str(p.relative_to(Path.cwd()))
        except ValueError:
            # Can't make relative — extract just the filename
            return p.name

    return path


def _sanitize_sarif_property(value: Any) -> Any:
    """Apply final defensive redaction before data leaves via SARIF."""
    sanitized = sanitize_sensitive_payload(value, max_str_len=1000)
    if isinstance(sanitized, str):
        return None
    return redact_for_persistence({"details": sanitized}, EvidenceTier.SAFE_TO_STORE).get("details")


def _sanitize_sarif_text(field_name: str, value: Any, *, fallback: str = "") -> str:
    """Redact free-text SARIF fields using the two-bucket persistence policy."""
    sanitized = sanitize_sensitive_payload(str(value or ""), key=field_name, max_str_len=1000)
    redacted = redact_for_persistence({field_name: sanitized}, EvidenceTier.SAFE_TO_STORE).get(field_name)
    if redacted is None:
        return fallback
    return str(redacted)


def _exposure_related_locations(exposure_path: dict[str, Any]) -> list[dict]:
    """Project an ExposurePath spine into SARIF relatedLocations.

    Each hop becomes a logicalLocation so SARIF viewers can render the
    agent → server → package → CVE → tool trust chain alongside the result.
    """

    hops = [hop for hop in (exposure_path.get("hops") or []) if isinstance(hop, str) and hop]
    related: list[dict] = []
    for index, hop in enumerate(hops):
        kind, _, name = hop.partition(":")
        related.append(
            {
                "id": index,
                "logicalLocations": [
                    {
                        "fullyQualifiedName": _sanitize_sarif_text("title", hop, fallback=hop),
                        "kind": _sanitize_sarif_text("title", kind or "node", fallback="node"),
                    }
                ],
                "message": {"text": _sanitize_sarif_text("title", name or hop, fallback=hop)},
            }
        )
    return related


def _trust_assessment_sarif_property(data: dict[str, Any]) -> dict[str, str]:
    """Project safe dual-axis trust fields into SARIF run properties."""
    allowed_fields = (
        "verdict",
        "content_verdict",
        "provenance_verdict",
        "review_verdict",
        "overall_recommendation",
        "confidence",
    )
    return {field: str(data[field]) for field in allowed_fields if data.get(field) is not None}


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
                "taxa": [{"id": tag, "name": tag} for tag in sorted(tags)],
            }
        )
    return taxonomies


def _taxonomies_as_tool_extensions(taxonomies: list[dict]) -> list[dict]:
    """Expose framework catalogs as SARIF tool extensions for catalog readers."""
    extensions: list[dict] = []
    for taxonomy in taxonomies:
        extension = {
            "name": taxonomy["name"],
            "fullName": taxonomy.get("fullName", taxonomy["name"]),
            "informationUri": taxonomy.get("informationUri", ""),
            "taxa": taxonomy.get("taxa", []),
        }
        extensions.append(extension)
    return extensions


_GUID_RE = re.compile(r"^[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[1-5][0-9a-fA-F]{3}-[89abAB][0-9a-fA-F]{3}-[0-9a-fA-F]{12}$")

# Map agent-bom suppression states onto the SARIF 2.1.0 suppression.status enum.
_SARIF_SUPPRESSION_STATUS = {
    "accepted": "accepted",
    "acknowledged": "accepted",
    "resolved": "accepted",
    "approved": "accepted",
    "risk_accepted": "accepted",
    "under_review": "underReview",
    "pending": "underReview",
    "open": "underReview",
    "rejected": "rejected",
    "denied": "rejected",
}


def _suppression_entries(source: object) -> list[dict]:
    """Build a SARIF 2.1.0 ``suppressions[]`` array from a suppressed finding/BlastRadius.

    Emitting ``result.suppressions`` is the standard signal SARIF consumers
    (GitHub Code Scanning, IDEs) use to hide a result. Suppressions persisted
    in an external tenant store are ``kind: "external"``. The agent-bom-specific
    ``suppression_id`` / ``suppression_state`` / ``suppression_reason`` ride in
    the suppression ``properties`` bag (a free-form propertyBag in the schema)
    so no information is lost while staying schema-valid.
    """
    if not getattr(source, "suppressed", False):
        return []
    suppression_id = getattr(source, "suppression_id", None)
    suppression_state = getattr(source, "suppression_state", None)
    suppression_reason = getattr(source, "suppression_reason", None)
    unsuppressed_risk_score = getattr(source, "unsuppressed_risk_score", None)

    entry: dict[str, Any] = {"kind": "external"}
    if isinstance(suppression_id, str) and _GUID_RE.match(suppression_id):
        entry["guid"] = suppression_id
    status = _SARIF_SUPPRESSION_STATUS.get(str(suppression_state or "").lower())
    if status:
        entry["status"] = status
    if suppression_reason:
        # A tenant-authored suppression justification is structural metadata, not
        # free-text scanner output — keep it (with secret/PII scrubbing) rather
        # than dropping it through the replay-only persistence tier.
        justification = sanitize_sensitive_payload(str(suppression_reason), key="justification", max_str_len=1000)
        if isinstance(justification, str) and justification:
            entry["justification"] = justification
    properties: dict[str, Any] = {}
    if suppression_id is not None:
        properties["suppression_id"] = sanitize_sensitive_payload(str(suppression_id), key="suppression_id", max_str_len=200)
    if suppression_state is not None:
        properties["suppression_state"] = sanitize_sensitive_payload(str(suppression_state), key="suppression_state", max_str_len=200)
    if unsuppressed_risk_score is not None:
        properties["unsuppressed_risk_score"] = unsuppressed_risk_score
    if properties:
        entry["properties"] = properties
    return [entry]


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


# Cloud providers whose CIS benchmark failures are emitted by the dedicated CIS
# loop in to_sarif() with per-check rule IDs + structured remediation. The
# unified non-CVE loop skips these so each failed check yields exactly one SARIF
# result (no duplicate ruleId+location) in the GitHub Security tab. databricks
# CIS and snowflake governance findings have no dedicated loop, so they keep
# flowing through the unified path.
_DEDICATED_CIS_BENCHMARKS: tuple[tuple[str, str], ...] = (
    ("aws", "cis_benchmark_data"),
    ("azure", "azure_cis_benchmark_data"),
    ("gcp", "gcp_cis_benchmark_data"),
    ("snowflake", "snowflake_cis_benchmark_data"),
)
_DEDICATED_CIS_PROVIDERS = frozenset(provider for provider, _ in _DEDICATED_CIS_BENCHMARKS)

_FRAMEWORK_TAG_FIELDS: tuple[str, ...] = (
    "owasp_tags",
    "atlas_tags",
    "attack_tags",
    "nist_ai_rmf_tags",
    "owasp_mcp_tags",
    "owasp_agentic_tags",
    "eu_ai_act_tags",
    "nist_csf_tags",
    "iso_27001_tags",
    "soc2_tags",
    "cis_tags",
    "cmmc_tags",
    "nist_800_53_tags",
    "fedramp_tags",
    "pci_dss_tags",
)


def _finding_artifact_uri(report: AIBOMReport, finding: Finding) -> str:
    """Resolve a SARIF artifact URI from unified finding + report agent inventory."""
    ecosystem = package_ecosystem(finding) or None
    if finding.affected_agents:
        agents_by_name = {agent.name: agent for agent in report.agents}
        first_agent = finding.affected_agents[0]
        agent = agents_by_name.get(str(first_agent))
        config_path = getattr(agent, "config_path", None) if agent else None
        if config_path:
            return _to_relative_path(str(config_path), ecosystem=ecosystem)
    if finding.asset.location:
        return _to_relative_path(str(finding.asset.location), ecosystem=ecosystem)
    return _to_relative_path("unknown", ecosystem=ecosystem)


def _agent_discovery_provenance_from_report(report: AIBOMReport, agent_names: list[str]) -> list[Any]:
    agents_by_name = {agent.name: agent for agent in report.agents}
    out: list[Any] = []
    for name in agent_names[:10]:
        agent = agents_by_name.get(str(name))
        if not agent:
            continue
        provenance = agent_discovery_provenance(agent)
        if provenance:
            out.append(provenance)
    return out


def _server_discovery_provenance_from_report(report: AIBOMReport, server_names: list[str]) -> list[Any]:
    servers_by_name: dict[str, Any] = {}
    for agent in report.agents:
        for server in agent.mcp_servers:
            servers_by_name[server.name] = server
    out: list[Any] = []
    for name in server_names[:10]:
        matched_server: Any = servers_by_name.get(str(name))
        if not matched_server:
            continue
        provenance = sanitize_discovery_provenance(getattr(matched_server, "discovery_provenance", None))
        if provenance:
            out.append(provenance)
    return out


def _framework_tag_properties(finding: Finding) -> dict[str, list[str]]:
    props: dict[str, list[str]] = {}
    for field in _FRAMEWORK_TAG_FIELDS:
        value = getattr(finding, field, [])
        if value:
            props[field] = list(value)
    return props


def _cve_ids_for_finding(finding: Finding) -> list[str]:
    candidates: list[Any] = [finding.cve_id]
    aliases = evidence(finding, "advisory_aliases", [])
    if isinstance(aliases, list):
        candidates.extend(aliases)
    cve_evidence = evidence(finding, "cve_ids", [])
    if isinstance(cve_evidence, list):
        candidates.extend(cve_evidence)
    return sorted({cid for cid in candidates if isinstance(cid, str) and cid.upper().startswith("CVE-")})


def _ensure_cve_sarif_rule(
    finding: Finding,
    *,
    rule_id: str,
    level: str,
    pkg_name: str,
    pkg_version: str,
    seen_rule_ids: set[str],
    rules: list[dict],
) -> None:
    if rule_id in seen_rule_ids:
        return
    seen_rule_ids.add(rule_id)
    sev = finding_severity(finding)
    sec_sev = str(finding.cvss_score) if finding.cvss_score is not None else _SECURITY_SEVERITY_SCORE.get(sev, "0.0")
    rule_props: dict[str, Any] = {"security-severity": sec_sev}
    if finding.epss_score is not None:
        rule_props["epss-score"] = round(finding.epss_score, 5)
    if finding.is_kev:
        rule_props["kev"] = True
    if finding.cvss_vector:
        rule_props["cvss_vector"] = finding.cvss_vector
    rule_props["attack_vector"] = finding.attack_vector
    rule_props["attack_complexity"] = finding.attack_complexity
    rule_props["privileges_required"] = finding.privileges_required
    rule_props["user_interaction"] = finding.user_interaction
    rule_props["network_exploitable"] = bool(finding.network_exploitable)
    rule_props["exploit_likelihood"] = exploit_likelihood_value(finding)
    # Order-preserving de-dup keeps properties.tags byte-stable across runs.
    tags = list(dict.fromkeys([*finding.cwe_ids, *exploitability_tags(parse_cvss_vector_signals(finding.cvss_vector))]))
    if tags:
        rule_props["tags"] = tags
    rules.append(
        {
            "id": rule_id,
            "shortDescription": {
                "text": _sanitize_sarif_text(
                    "title",
                    f"{sev.value.upper()}: {rule_id} in {pkg_name}@{pkg_version}",
                    fallback=f"{rule_id} package vulnerability",
                )
            },
            "fullDescription": {"text": _sanitize_sarif_text("description", finding.description, fallback=f"Vulnerability {rule_id}")},
            "helpUri": f"https://osv.dev/vulnerability/{rule_id}",
            "defaultConfiguration": {"level": level},
            "properties": rule_props,
        }
    )


def _ai_assessment_result_properties(assessment: Any) -> dict[str, Any]:
    """Advisory AI-triage fields for a SARIF result, namespaced under agent-bom.

    The triage assessment is advisory only (it never changes severity or
    suppression); it is joined onto the finding it describes by ``finding_id``
    so a SARIF consumer sees the classification inline instead of only in the
    JSON side-block.
    """
    props: dict[str, Any] = {
        "agent-bom:ai_classification": assessment.classification,
        "agent-bom:ai_confidence": assessment.confidence,
        "agent-bom:ai_false_positive_likelihood": assessment.false_positive_likelihood,
    }
    rationale = (assessment.rationale or "").strip()
    if rationale:
        props["agent-bom:ai_rationale"] = _sanitize_sarif_text("description", rationale, fallback="")
    if assessment.suggested_controls:
        props["agent-bom:ai_suggested_controls"] = list(assessment.suggested_controls)
    return props


def _cve_sarif_result(
    report: AIBOMReport,
    finding: Finding,
    *,
    rank: int,
    rule_id: str,
    level: str,
    pkg_name: str,
    pkg_version: str,
    ai_assessment: Any = None,
) -> dict:
    exposure_path = exposure_path_for_report_finding(finding, rank=rank)
    affected = ", ".join(str(name) for name in finding.affected_agents)
    sev = finding_severity(finding)
    message_text = f"{rule_id} ({sev.value}) in {pkg_name}@{pkg_version}. Affects agents: {affected}."
    if finding.fixed_version:
        message_text += f" Fix: upgrade to {finding.fixed_version}."
    exposure_chain = exposure_path_chain(exposure_path)
    if exposure_chain:
        message_text += f" Exposure path: {exposure_chain}. Blast radius: {exposure_path_blast_summary(exposure_path)}."

    config_path = _finding_artifact_uri(report, finding)
    fp_input = f"{rule_id}:{pkg_name}:{pkg_version}:{config_path}"
    kind = "informational" if sev == Severity.NONE else "fail"
    result: dict = {
        "ruleId": rule_id,
        "level": level,
        "kind": kind,
        "message": {"text": _sanitize_sarif_text("title", message_text, fallback=f"{rule_id} package vulnerability")},
        **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=config_path, start_line=1),
        "locations": [
            {
                "physicalLocation": {
                    "artifactLocation": {"uri": config_path, "uriBaseId": "%SRCROOT%"},
                    "region": {"startLine": 1, "startColumn": 1},
                },
            }
        ],
    }
    related_locations = _exposure_related_locations(exposure_path)
    if related_locations:
        result["relatedLocations"] = related_locations
    result_properties: dict[str, Any] = {
        "blast_score": finding.risk_score,
        "match_confidence_tier": evidence(finding, "match_confidence_tier"),
        "cve_ids": _cve_ids_for_finding(finding),
        "exposure_path": exposure_path,
        "exposure_chain": exposure_chain or None,
        "epss_score": finding.epss_score,
        "is_kev": finding.is_kev,
        "cvss_vector": finding.cvss_vector,
        "attack_vector": finding.attack_vector,
        "attack_complexity": finding.attack_complexity,
        "privileges_required": finding.privileges_required,
        "user_interaction": finding.user_interaction,
        "network_exploitable": bool(finding.network_exploitable),
        "exploit_likelihood": exploit_likelihood_value(finding),
        "exposed_credentials": list(finding.exposed_credentials),
        "impact_category": finding.impact_category or "code-execution",
        "attack_vector_summary": finding.attack_vector_summary,
        "reachability": finding.reachability,
        "symbol_reachability": evidence(finding, "symbol_reachability"),
        "reachable_affected_symbols": evidence(finding, "reachable_affected_symbols", []),
        "affected_servers": list(finding.affected_servers),
        "affected_agents": list(finding.affected_agents),
        "exposed_tools": list(finding.exposed_tools),
        "ai_risk_context": finding.ai_risk_context,
        "ai_summary": finding.ai_summary,
        "suppressed": bool(finding.suppressed),
        "is_malicious": finding.is_malicious,
        "malicious_reason": (_sanitize_sarif_text("title", finding.malicious_reason) or None) if finding.malicious_reason else None,
    }
    if finding.fixed_version:
        result_properties["fixed_version"] = finding.fixed_version
    vex_status = evidence(finding, "vex_status")
    if vex_status:
        result_properties["vex_status"] = vex_status
    vex_justification = evidence(finding, "vex_justification")
    if vex_justification:
        result_properties["vex_justification"] = vex_justification
    package_provenance = evidence(finding, "package_discovery_provenance")
    if package_provenance:
        result_properties["package_discovery_provenance"] = _sanitize_sarif_property(package_provenance)
    version_provenance = evidence(finding, "package_version_provenance")
    if version_provenance is not None:
        result_properties["package_version_provenance"] = _sanitize_sarif_property(version_provenance)
    agent_provenance = _agent_discovery_provenance_from_report(report, list(finding.affected_agents))
    if agent_provenance:
        result_properties["agent_discovery_provenance"] = _sanitize_sarif_property(agent_provenance)
    server_provenance = _server_discovery_provenance_from_report(report, list(finding.affected_servers))
    if server_provenance:
        result_properties["server_discovery_provenance"] = _sanitize_sarif_property(server_provenance)
    framework_props = _framework_tag_properties(finding)
    if framework_props:
        result_properties.update(framework_props)
    if ai_assessment is not None:
        result_properties.update(_ai_assessment_result_properties(ai_assessment))
    result["properties"] = result_properties
    suppressions = _suppression_entries(finding)
    if suppressions:
        result["suppressions"] = suppressions
    taxa_refs = _framework_taxa_references(result_properties)
    if taxa_refs:
        result["taxa"] = taxa_refs
    return result


def to_sarif(
    report: AIBOMReport,
    *,
    exclude_unfixable: bool = False,
    blast_radii: list[BlastRadius] | None = None,
) -> dict:
    """Convert report to SARIF 2.1.0 dict for GitHub Security tab.

    Args:
        exclude_unfixable: If True, skip findings where no fix is available
            (fixed_version is None/empty). Reduces noise in GitHub Security tab
            from CVEs that can't be acted on.
    """
    rules: list[dict[str, Any]] = []
    results: list[dict[str, Any]] = []
    seen_rule_ids: set[str] = set()
    # Advisory AI-triage assessments keyed by the finding_id they describe, so
    # each is joined onto its finding's result instead of only the JSON block.
    ai_assessments_by_finding: dict[str, Any] = {
        assessment.finding_id: assessment for assessment in getattr(report, "ai_finding_assessments", []) or []
    }

    # Stable-sort the CVE stream so exposure_path.rank never flips on score ties:
    # primary key is descending unified risk, tie-broken by finding id. This keeps
    # rank (and therefore SARIF/JSON bytes) deterministic across identical runs.
    ordered_cve_findings = sorted(
        cve_findings(report, blast_radii),
        key=lambda finding: (-float(finding.risk_score or 0.0), finding.cve_id or finding.id or ""),
    )
    for rank, finding in enumerate(ordered_cve_findings, 1):
        rule_id = finding.cve_id or finding.id
        if not rule_id:
            continue

        if exclude_unfixable and not finding.fixed_version:
            continue

        cve_severity = finding_severity(finding)
        level = _SARIF_SEVERITY_MAP.get(cve_severity, "warning")
        pkg_name = package_name(finding)
        pkg_version = package_version(finding)

        _ensure_cve_sarif_rule(
            finding,
            rule_id=rule_id,
            level=level,
            pkg_name=pkg_name,
            pkg_version=pkg_version,
            seen_rule_ids=seen_rule_ids,
            rules=rules,
        )
        results.append(
            _cve_sarif_result(
                report,
                finding,
                rank=rank,
                rule_id=rule_id,
                level=level,
                pkg_name=pkg_name,
                pkg_version=pkg_version,
                ai_assessment=ai_assessments_by_finding.get(finding.id),
            )
        )

    # Unified non-CVE findings, including MCP intelligence/blocklist matches.
    finding_sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
    finding_sev_score = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0", "info": "0.0"}
    for finding in report.to_findings():
        if finding.finding_type == FindingType.CVE:
            continue
        # Cloud CIS benchmark failures for the dedicated-loop providers are
        # emitted once below with richer per-check rule IDs + structured
        # remediation. Skip them here so a failed check is not double-counted in
        # the GitHub Security tab. databricks CIS + snowflake governance have no
        # dedicated loop, so they still flow through this unified path.
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        if (
            finding.finding_type == FindingType.CIS_FAIL
            and evidence.get("benchmark") == "CIS"
            and evidence.get("provider") in _DEDICATED_CIS_PROVIDERS
        ):
            continue
        finding_severity_name = str(finding.severity or "medium").lower()
        rule_id = f"finding/{finding.finding_type.value}"
        level = finding_sev_map.get(finding_severity_name, "warning")
        if rule_id not in seen_rule_ids:
            seen_rule_ids.add(rule_id)
            rules.append(
                {
                    "id": rule_id,
                    "shortDescription": {"text": _sanitize_sarif_text("title", finding.finding_type.value.replace("_", " ").title())},
                    "fullDescription": {
                        "text": _sanitize_sarif_text(
                            "description",
                            finding.description,
                            fallback=_sanitize_sarif_text("title", finding.title or finding.finding_type.value),
                        )
                    },
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "security-severity": finding_sev_score.get(finding_severity_name, "4.0"),
                        "source": finding.source.value,
                        "finding_type": finding.finding_type.value,
                    },
                }
            )

        file_path = _to_relative_path(
            finding.asset.location or "agent-bom-report.json",
            _ecosystem_from_purl(finding.asset.identifier),
        )
        fp_input = f"{finding.id}:{file_path}:{finding.asset.stable_id}"
        finding_result: dict = {
            "ruleId": rule_id,
            "level": level,
            "kind": "fail" if level in {"error", "warning"} else "informational",
            "message": {
                "text": _sanitize_sarif_text(
                    "title",
                    finding.title,
                    fallback=_sanitize_sarif_text("description", finding.description, fallback=finding.finding_type.value),
                )
            },
            **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=file_path, start_line=1),
            "locations": [
                {
                    "physicalLocation": {
                        "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                        "region": {"startLine": 1, "startColumn": 1},
                    },
                }
            ],
            "properties": {
                "risk_score": finding.risk_score,
                "asset_type": finding.asset.asset_type,
                "asset_name": _sanitize_sarif_text("title", finding.asset.name, fallback=finding.asset.asset_type),
                "evidence": _sanitize_sarif_property(finding.evidence),
                "remediation_guidance": _sanitize_sarif_property(finding.remediation_guidance),
                "is_malicious": finding.is_malicious,
                "malicious_reason": (_sanitize_sarif_text("title", finding.malicious_reason) or None) if finding.malicious_reason else None,
                # Structured reach lists + AI-native context (unified Finding parity).
                "affected_servers": list(finding.affected_servers),
                "affected_agents": list(finding.affected_agents),
                "exposed_credentials": list(finding.exposed_credentials),
                "exposed_tools": list(finding.exposed_tools),
                "ai_risk_context": finding.ai_risk_context,
                "ai_summary": finding.ai_summary,
                "attack_vector_summary": finding.attack_vector_summary,
                "suppressed": finding.suppressed,
            },
        }
        suppressions = _suppression_entries(finding)
        if suppressions:
            finding_result["suppressions"] = suppressions
        results.append(finding_result)

    # IaC misconfiguration findings (Dockerfile, K8s, Terraform, CloudFormation)
    iac_data = getattr(report, "iac_findings_data", None)
    if iac_data:
        iac_sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
        iac_sev_score = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0", "info": "0.0"}
        for iac_finding in iac_data.get("findings", []):
            sev = iac_finding.get("severity", "medium").lower()
            rule_id = f"iac/{iac_finding.get('rule_id', 'unknown')}"
            level = iac_sev_map.get(sev, "warning")
            file_path = _to_relative_path(iac_finding.get("file_path", "unknown") or "unknown")
            line_num = iac_finding.get("line_number") or 1

            if rule_id not in seen_rule_ids:
                seen_rule_ids.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "shortDescription": {"text": _sanitize_sarif_text("title", iac_finding.get("title", rule_id), fallback=rule_id)},
                        "fullDescription": {
                            "text": _sanitize_sarif_text(
                                "description",
                                iac_finding.get("message"),
                                fallback=_sanitize_sarif_text("title", iac_finding.get("title", rule_id), fallback=rule_id),
                            )
                        },
                        "defaultConfiguration": {"level": level},
                        "properties": {
                            "security-severity": iac_sev_score.get(sev, "4.0"),
                            "category": iac_finding.get("category", "iac"),
                            "compliance": iac_finding.get("compliance", []),
                        },
                    }
                )

            fp_input = f"{rule_id}:{file_path}:{line_num}"
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "kind": "fail",
                    "message": {
                        "text": _sanitize_sarif_text(
                            "description",
                            iac_finding.get("message"),
                            fallback=_sanitize_sarif_text("title", iac_finding.get("title", "IaC misconfiguration")),
                        )
                    },
                    **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=file_path, start_line=line_num),
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": line_num, "startColumn": 1},
                            },
                        }
                    ],
                }
            )

    # AI inventory findings (shadow AI, deprecated models, API keys, invisible Unicode)
    ai_inv = getattr(report, "ai_inventory_data", None)
    if ai_inv:
        ai_sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
        ai_sev_score = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0", "info": "0.0"}
        for comp in ai_inv.get("components", []):
            sev = comp.get("severity", "info")
            if sev not in ("critical", "high", "medium"):
                continue  # only actionable findings in SARIF
            comp_type = comp.get("type", "unknown")
            # Redact credential fragments — never embed key material in SARIF
            raw_name = comp.get("name", "")
            name = "[REDACTED]" if comp_type == "api_key" else raw_name
            rule_id = f"ai-inventory/{comp_type}/{name}"
            level = ai_sev_map.get(sev, "warning")

            if rule_id not in seen_rule_ids:
                seen_rule_ids.add(rule_id)
                rules.append(
                    {
                        "id": rule_id,
                        "shortDescription": {
                            "text": _sanitize_sarif_text("title", f"{sev.upper()}: {comp_type.replace('_', ' ')} - {name}")
                        },
                        "fullDescription": {
                            "text": _sanitize_sarif_text(
                                "description",
                                comp.get("description", ""),
                                fallback=f"AI component finding: {name}",
                            )
                        },
                        "defaultConfiguration": {"level": level},
                        "properties": {"security-severity": ai_sev_score.get(sev, "0.0")},
                    }
                )

            file_path = _to_relative_path(comp.get("file", "unknown") or "unknown")
            line_num = int(comp.get("line", 1) or 1)
            fp_input = f"{rule_id}:{file_path}:{line_num}"
            desc = _sanitize_sarif_text("description", comp.get("description", ""), fallback=f"{comp_type.replace('_', ' ')}: {name}")
            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "kind": "fail",
                    "message": {"text": desc},
                    **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=file_path, start_line=line_num),
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": file_path, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": comp.get("line", 1), "startColumn": 1},
                            },
                        }
                    ],
                }
            )

    # CIS benchmark findings (AWS / Azure / GCP / Snowflake). Each failed
    # check emits a SARIF result with the structured remediation dict
    # (issue #665) in ``properties.remediation`` so GitHub Code Scanning
    # and downstream SARIF consumers can surface fix guidance per finding.
    cis_sev_map = {"critical": "error", "high": "error", "medium": "warning", "low": "note", "info": "none"}
    cis_sev_score = {"critical": "9.0", "high": "7.0", "medium": "4.0", "low": "1.0", "info": "0.0"}
    for cloud_key, data_attr in _DEDICATED_CIS_BENCHMARKS:
        bundle = getattr(report, data_attr, None)
        if not bundle:
            continue
        for check in bundle.get("checks", []):
            if check.get("status") != "fail":
                continue
            cis_severity = str(check.get("severity") or "medium").lower()
            check_id = check.get("check_id") or "unknown"
            rule_id = f"cis/{cloud_key}/{check_id}"
            level = cis_sev_map.get(cis_severity, "warning")
            remediation = check.get("remediation") or {}
            title = check.get("title") or rule_id
            help_uri = remediation.get("docs") or ""

            if rule_id not in seen_rule_ids:
                seen_rule_ids.add(rule_id)
                cis_rule: dict = {
                    "id": rule_id,
                    "shortDescription": {
                        "text": _sanitize_sarif_text(
                            "title",
                            f"{cis_severity.upper()}: CIS {cloud_key.upper()} {check_id} - {title}",
                            fallback=rule_id,
                        )
                    },
                    "fullDescription": {
                        "text": _sanitize_sarif_text(
                            "recommendation",
                            check.get("recommendation"),
                            fallback=_sanitize_sarif_text("title", title, fallback=rule_id),
                        )
                    },
                    "defaultConfiguration": {"level": level},
                    "properties": {
                        "security-severity": cis_sev_score.get(cis_severity, "4.0"),
                        "tags": ["cis", cloud_key, "compliance"],
                        "cis_section": check.get("cis_section") or "",
                    },
                }
                if help_uri:
                    cis_rule["helpUri"] = help_uri
                rules.append(cis_rule)

            # Synthetic fingerprint so repeat runs produce stable IDs.
            fp_input = f"{rule_id}:{','.join(check.get('resource_ids') or [])}"
            artifact_uri = f"cis-{cloud_key}-benchmark"

            # CIS findings are cloud-control-level, not file-level. Point
            # at a conventional manifest so GitHub renders the result;
            # the rich context lives in ``properties``.
            result_props: dict = {
                "remediation": remediation,
                "cis_section": check.get("cis_section") or "",
                "evidence": _sanitize_sarif_property(check.get("evidence") or ""),
                "resource_ids": _sanitize_sarif_property(check.get("resource_ids") or []),
            }
            # Surface the remediation knobs flat for consumers that
            # can't (or don't want to) read nested dicts.
            if remediation:
                result_props["fix_cli"] = remediation.get("fix_cli")
                result_props["fix_console"] = remediation.get("fix_console") or ""
                result_props["effort"] = remediation.get("effort") or "manual"
                result_props["priority"] = remediation.get("priority") or 3
                result_props["guardrails"] = remediation.get("guardrails") or []
                result_props["requires_human_review"] = bool(remediation.get("requires_human_review"))

            results.append(
                {
                    "ruleId": rule_id,
                    "level": level,
                    "kind": "fail",
                    "message": {
                        "text": _sanitize_sarif_text(
                            "title",
                            f"CIS {cloud_key.upper()} {check_id} failed: {title}",
                            fallback=rule_id,
                        )
                    },
                    **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=artifact_uri, start_line=1),
                    "locations": [
                        {
                            "physicalLocation": {
                                "artifactLocation": {"uri": artifact_uri, "uriBaseId": "%SRCROOT%"},
                                "region": {"startLine": 1, "startColumn": 1},
                            },
                        }
                    ],
                    "properties": result_props,
                }
            )

    taxonomies = _build_run_taxonomies(results)
    run: dict = {
        "tool": {
            "driver": {
                "name": "agent-bom",
                "version": report.tool_version,
                "informationUri": "https://github.com/msaad00/agent-bom",
                "rules": rules,
            }
        },
        "results": results,
        **({"automationDetails": {"id": f"agent-bom/{report.scan_id}"}} if report.scan_id else {}),
    }
    trust_assessment = getattr(report, "trust_assessment_data", None)
    if isinstance(trust_assessment, dict) and trust_assessment:
        run["properties"] = {
            "trust_assessment": _trust_assessment_sarif_property(trust_assessment),
        }
    if taxonomies:
        run["taxonomies"] = taxonomies
        run["tool"]["extensions"] = _taxonomies_as_tool_extensions(taxonomies)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [run],
    }


def export_sarif(
    report: AIBOMReport,
    output_path: str,
    *,
    exclude_unfixable: bool = False,
) -> None:
    """Export report as SARIF 2.1.0 JSON file."""
    data = to_sarif(report, exclude_unfixable=exclude_unfixable)
    Path(output_path).write_text(json.dumps(data, indent=2))
