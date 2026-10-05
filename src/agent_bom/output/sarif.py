"""SARIF 2.1.0 output for GitHub Security tab integration."""

from __future__ import annotations

import dataclasses
import hashlib
import json
import re
from pathlib import Path
from typing import Any, Optional

from agent_bom.asset_provenance import (
    agent_discovery_provenance,
    sanitize_discovery_provenance,
)
from agent_bom.compliance_coverage import COMPLIANCE_TAG_FIELDS
from agent_bom.evidence import EvidenceTier, redact_for_persistence
from agent_bom.evidence.scan_run import ScanOutcome, ScanRun, effective_scan_run
from agent_bom.exploitability import exploitability_tags, parse_cvss_vector_signals
from agent_bom.finding import Finding, FindingType
from agent_bom.models import AIBOMReport, BlastRadius, Severity
from agent_bom.output.advisory_text import advisory_help, sanitize_advisory_text
from agent_bom.output.exposure_path import (
    exposure_path_blast_summary,
    exposure_path_chain,
    exposure_path_for_report_finding,
)
from agent_bom.output.finding_views import (
    apply_workload_runtime_evidence_for_export,
    cve_findings,
    evidence,
    exploit_likelihood_value,
    finding_severity,
    package_name,
    package_version,
)
from agent_bom.output.sarif_taxonomy import (
    _FRAMEWORK_TAXONOMY_META,  # noqa: F401
    _attach_cwe_taxonomy,
    _build_run_taxonomies,
    _compact_taxa_references,
    _framework_taxa_references,
    _taxonomies_as_tool_extensions,
)
from agent_bom.output.source_locations import SourceIndex, finding_package_location, package_source_index
from agent_bom.security import sanitize_sensitive_payload, sanitize_text, sanitize_url

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
    start_line: int | None = 1,
) -> dict[str, dict[str, str]]:
    """Return SARIF fingerprints and GitHub partialFingerprints for dedup."""
    fields = {
        "fingerprints": {
            "agent-bom/v1": hashlib.sha256(stable_input.encode()).hexdigest(),
        },
        "partialFingerprints": {
            "primaryLocationLineHash": hashlib.sha256(f"{artifact_uri}:{start_line}".encode()).hexdigest(),
        },
    }
    if start_line is None or artifact_uri.startswith(("self-scan://", "pkg:", "package:")):
        fields.pop("partialFingerprints")
    return fields


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

# ``info`` is the unified findings stream's spelling for "reported, not a
# problem" — the same thing SARIF calls level ``none``. Every other label is
# read the way ``graph.severity.normalize_severity`` reads it, which is what
# ``Finding.__post_init__`` has already applied to anything in that stream.
_SARIF_INFO_LABELS = frozenset({"info", "informational"})
_UNIFIED_RULE_HELP_URI = "https://github.com/msaad00/agent-bom#readme"
_SARIF_RULE_TOKEN_RE = re.compile(r"[^A-Za-z0-9._-]+")


def _sarif_severity(label: object) -> tuple[str, str]:
    """Return ``(level, security-severity)`` for a finding severity label.

    Every result stream in a document resolves severity here. The unified
    finding, IaC, AI and CIS streams each used to carry an inline copy of these
    tables keyed by severity string; none of the copies had a ``none`` or
    ``unknown`` key and they fell back to ``warning`` / ``4.0``, so a finding
    rated ``none`` — or one the scanner could not rate — reached GitHub code
    scanning as Medium while the CVE stream in the same document reported it as
    ``note`` / ``0.0``. An unrecognised label resolves to ``unknown``: unrated
    is never silently promoted to a rating.
    """
    name = str(label or "").strip().lower()
    if name in _SARIF_INFO_LABELS:
        return _SARIF_SEVERITY_MAP[Severity.NONE], _SECURITY_SEVERITY_SCORE[Severity.NONE]
    try:
        severity = Severity(name)
    except ValueError:
        severity = Severity.UNKNOWN
    return _SARIF_SEVERITY_MAP[severity], _SECURITY_SEVERITY_SCORE[severity]


def _unified_finding_rule_id(finding: Finding) -> str:
    """Return a stable SARIF rule ID for a unified non-CVE finding.

    A broad finding family is not a scanner rule. Reusing ``finding/SAST``
    for every static-analysis detector made GitHub attach the first result's
    description to every later SAST alert. Prefer the producer's rule/category
    identity and fall back to a title-derived token for legacy producers.
    """
    family_rule_id = f"finding/{finding.finding_type.value}"
    raw_token = next(
        (
            finding.evidence.get(key)
            for key in ("rule_id", "check_id", "detector_id", "category")
            if isinstance(finding.evidence, dict) and finding.evidence.get(key)
        ),
        None,
    )
    # Legacy producers do not expose a detector identity. Keep their stable
    # family rule rather than turning a finding title (which can contain an
    # asset name) into a new SARIF rule on every occurrence.
    if raw_token is None:
        return family_rule_id
    token = _SARIF_RULE_TOKEN_RE.sub("-", str(raw_token).strip()).strip("-._")
    if not token:
        token = hashlib.sha256(finding.id.encode()).hexdigest()[:16]
    if len(token) > 96:
        digest = hashlib.sha256(token.encode()).hexdigest()[:12]
        token = f"{token[:80]}-{digest}"
    return f"{family_rule_id}/{token}"


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
    """Apply final defensive redaction before data leaves via SARIF.

    Property bags carry arbitrary nested evidence — scanner payloads, runtime
    capture, provenance — so they keep the conservative tier-A allowlist.
    """
    sanitized = sanitize_sensitive_payload(value, max_str_len=1000)
    if isinstance(sanitized, str):
        return None
    return redact_for_persistence({"details": sanitized}, EvidenceTier.SAFE_TO_STORE).get("details")


def _sanitize_scanner_text(field_name: str, value: Any, *, fallback: str = "") -> str:
    """Redact scanner free text that may quote the scanned workspace.

    Descriptions on the unified finding path (SAST, secret, credential
    exposure) and model-authored triage rationale can echo source lines out of
    the repository being scanned, so they stay behind the conservative tier-A
    allowlist: the field name is not on it, the text is dropped, and the caller
    falls back to the structural title. Published advisory prose is a different
    provenance and uses :func:`sanitize_advisory_text` instead.
    """
    sanitized = sanitize_sensitive_payload(str(value or ""), key=field_name, max_str_len=1000)
    redacted = redact_for_persistence({field_name: sanitized}, EvidenceTier.SAFE_TO_STORE).get(field_name)
    if redacted is None:
        return fallback
    return str(redacted)


def _cis_remediation_text(remediation: Any) -> str:
    """Flatten a CIS remediation dict into one sanitized guidance line."""
    if not isinstance(remediation, dict):
        return ""
    parts = [sanitize_advisory_text("recommendation", remediation.get(key)) for key in ("fix_cli", "fix_console")]
    return " ".join(part for part in parts if part)


def _exposure_related_locations(exposure_path: dict[str, Any]) -> list[dict]:
    """Project an ExposurePath spine into SARIF relatedLocations.

    Each hop becomes a logicalLocation so SARIF viewers can render the
    agent → server → package → CVE → tool trust chain alongside the result.
    """

    hops = [hop for hop in (exposure_path.get("hops") or []) if isinstance(hop, str) and hop]
    # Side nodes (tools and credential references) remain outside the primary
    # topology spine, but SARIF logical locations must retain the full bounded
    # exposure context for viewers and downstream automation.
    nodes = [node for node in (exposure_path.get("nodeIds") or []) if isinstance(node, str) and node]
    locations = list(dict.fromkeys([*hops, *nodes]))
    related: list[dict] = []
    for index, hop in enumerate(locations):
        kind, _, name = hop.partition(":")
        related.append(
            {
                "id": index,
                "logicalLocations": [
                    {
                        "fullyQualifiedName": sanitize_advisory_text("title", hop, fallback=hop),
                        "kind": sanitize_advisory_text("title", kind or "node", fallback="node"),
                    }
                ],
                "message": {"text": sanitize_advisory_text("title", name or hop, fallback=hop)},
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


# Cloud providers whose CIS benchmark failures are emitted by the dedicated CIS
# loop (_add_cis_benchmark_results) with per-check rule IDs + structured remediation. The
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
    for field in COMPLIANCE_TAG_FIELDS:
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


def _kev_date_properties(finding: Finding) -> dict[str, str]:
    """CISA KEV catalog dates for a finding, omitted entirely when absent.

    ``kev_due_date`` is the BOD 22-01 remediation deadline and ``kev_date_added``
    the catalog entry date; both are already carried by CSV/JSON/CycloneDX/SPDX,
    so SARIF emitting only the boolean was a per-format enrichment drop.
    """
    props: dict[str, str] = {}
    for key in ("kev_date_added", "kev_due_date"):
        value = evidence(finding, key, "")
        if isinstance(value, str) and value.strip():
            props[key] = value.strip()
    return props


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
        # BOD 22-01 binds federal agencies to a dated remediation deadline. A
        # bare ``kev: true`` in the GitHub Code Scanning payload strips the only
        # part of the KEV record that carries an obligation.
        rule_props.update(_kev_date_properties(finding))
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
    advisory_uri = f"https://osv.dev/vulnerability/{rule_id}"
    description = sanitize_advisory_text("description", finding.description, fallback=f"Vulnerability {rule_id}")
    rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {
            "text": sanitize_advisory_text(
                "title",
                f"{sev.value.upper()}: {rule_id} in {pkg_name}@{pkg_version}",
                fallback=f"{rule_id} package vulnerability",
            )
        },
        "fullDescription": {"text": description},
        "helpUri": advisory_uri,
        "defaultConfiguration": {"level": level},
        "properties": rule_props,
    }
    help_body = advisory_help(
        description,
        remediation=sanitize_advisory_text("recommendation", finding.remediation_guidance),
        reference_uri=advisory_uri,
    )
    if help_body:
        rule["help"] = help_body
    rules.append(rule)


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
        props["agent-bom:ai_rationale"] = _sanitize_scanner_text("description", rationale, fallback="")
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
    source_index: SourceIndex | None = None,
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

    config_path, start_line = finding_package_location(finding, source_index or {})
    fp_input = f"{rule_id}:{pkg_name}:{pkg_version}:{config_path}"
    kind = "informational" if sev == Severity.NONE else "fail"
    result: dict = {
        "ruleId": rule_id,
        "level": level,
        "kind": kind,
        "message": {"text": sanitize_advisory_text("title", message_text, fallback=f"{rule_id} package vulnerability")},
        **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=config_path, start_line=start_line),
        "locations": [_sarif_location(config_path, start_line)],
    }
    related_locations = _exposure_related_locations(exposure_path)
    if related_locations:
        result["relatedLocations"] = related_locations
    # Ownership + remediation SLA (single source of truth in agent_bom.graph.sla). The
    # scan-completion time anchors the deadline when the finding carries no
    # first-seen history, matching the JSON report spine.
    from agent_bom.graph.sla import finding_owner, finding_sla_fields

    finding_sla = finding_sla_fields(
        {
            **finding.to_dict(),
            "first_seen": finding.first_seen or report.generated_at.isoformat(),
        }
    )
    result_properties: dict[str, Any] = {
        "advisory_id": rule_id,
        "asset_canonical_id": finding.asset.stable_id,
        "occurrence_id": finding.id,
        "canonical_id": finding.id,
        "owner": finding_owner(finding.owner),
        "sla_due_at": finding_sla["sla_due_at"],
        "sla_due_at_source": finding_sla["sla_due_at_source"],
        "blast_score": finding.risk_score,
        "match_confidence_tier": evidence(finding, "match_confidence_tier"),
        "cve_ids": _cve_ids_for_finding(finding),
        "cwe_ids": list(finding.cwe_ids),
        "exposure_path": exposure_path,
        "exposure_chain": exposure_chain or None,
        "epss_score": finding.epss_score,
        "is_kev": finding.is_kev,
        **({} if not finding.is_kev else _kev_date_properties(finding)),
        "cvss_vector": finding.cvss_vector,
        "attack_vector": finding.attack_vector,
        "attack_complexity": finding.attack_complexity,
        "privileges_required": finding.privileges_required,
        "user_interaction": finding.user_interaction,
        "network_exploitable": bool(finding.network_exploitable),
        "exploit_likelihood": exploit_likelihood_value(finding),
        "exposed_credentials": list(finding.exposed_credentials),
        "impact_category": finding.impact_category,
        "attack_vector_summary": finding.attack_vector_summary,
        "reachability": finding.reachability,
        "symbol_reachability": evidence(finding, "symbol_reachability"),
        "reachable_affected_symbols": evidence(finding, "reachable_affected_symbols", []),
        "symbol_reachability_reason": evidence(finding, "symbol_reachability_reason"),
        "runtime_dependency_chain": evidence(finding, "runtime_dependency_chain", []),
        "affected_servers": list(finding.affected_servers),
        "affected_agents": list(finding.affected_agents),
        "exposed_tools": list(finding.exposed_tools),
        "ai_risk_context": finding.ai_risk_context,
        "ai_summary": finding.ai_summary,
        "suppressed": bool(finding.suppressed),
        "is_malicious": finding.is_malicious,
        "malicious_reason": (sanitize_advisory_text("title", finding.malicious_reason) or None) if finding.malicious_reason else None,
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
    for verdict_key in (
        "package_integrity_verified",
        "package_provenance_attested",
        "package_provenance_source",
        "package_provenance_status",
    ):
        # --verify-integrity verdict. Omitted when the check never ran, so a
        # missing key never reads as "verification failed".
        verdict_value = evidence(finding, verdict_key, None)
        if verdict_value is not None:
            result_properties[verdict_key] = verdict_value
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
    workload_runtime = getattr(finding, "workload_runtime_evidence", None)
    if isinstance(workload_runtime, dict) and workload_runtime:
        result_properties["workload_runtime_evidence"] = _sanitize_sarif_property(workload_runtime)
    result["properties"] = result_properties
    suppressions = _suppression_entries(finding)
    if suppressions:
        result["suppressions"] = suppressions
    taxa_refs = _framework_taxa_references(result_properties)
    if taxa_refs:
        result["taxa"] = taxa_refs
    return result


@dataclasses.dataclass
class _SarifCatalog:
    """Rules and results accumulated across finding families for one SARIF run."""

    rules: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    results: list[dict[str, Any]] = dataclasses.field(default_factory=list)
    seen_rule_ids: set[str] = dataclasses.field(default_factory=set)

    def claim_rule(self, rule_id: str) -> bool:
        """Return True the first time a rule ID is seen, so its rule is emitted once."""
        if rule_id in self.seen_rule_ids:
            return False
        self.seen_rule_ids.add(rule_id)
        return True


def _sarif_location(uri: str, start_line: Any) -> dict[str, Any]:
    # Installed distributions have an inventory identity, not a checkout file.
    if uri.startswith(("self-scan://", "pkg:", "package:")):
        return {"logicalLocations": [{"fullyQualifiedName": uri}]}
    location: dict[str, Any] = {"artifactLocation": {"uri": uri, "uriBaseId": "%SRCROOT%"}}
    if type(start_line) is int and start_line > 0:
        location["region"] = {"startLine": start_line, "startColumn": 1}
    return {"physicalLocation": location}


def _add_cve_results(
    catalog: _SarifCatalog,
    report: AIBOMReport,
    blast_radii: list[BlastRadius] | None,
    exclude_unfixable: bool,
) -> None:
    # Advisory AI-triage assessments keyed by the finding_id they describe, so
    # each is joined onto its finding's result instead of only the JSON block.
    ai_assessments_by_finding: dict[str, Any] = {
        assessment.finding_id: assessment for assessment in getattr(report, "ai_finding_assessments", []) or []
    }

    # Stable-sort the CVE stream so exposure_path.rank never flips on score ties:
    # primary key is descending unified risk, tie-broken by finding id. This keeps
    # rank (and therefore SARIF/JSON bytes) deterministic across identical runs.
    ordered_cve_findings = sorted(
        apply_workload_runtime_evidence_for_export(cve_findings(report, blast_radii)),
        key=lambda finding: (-float(finding.risk_score or 0.0), finding.cve_id or finding.id or ""),
    )
    source_index = package_source_index(report)
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
            seen_rule_ids=catalog.seen_rule_ids,
            rules=catalog.rules,
        )
        catalog.results.append(
            _cve_sarif_result(
                report,
                finding,
                rank=rank,
                source_index=source_index,
                rule_id=rule_id,
                level=level,
                pkg_name=pkg_name,
                pkg_version=pkg_version,
                ai_assessment=ai_assessments_by_finding.get(finding.id),
            )
        )


def _emitted_by_dedicated_loop(finding: Finding, evidence: dict[str, Any]) -> bool:
    """True when a unified finding is emitted by a richer family-specific loop instead."""
    # Package CVEs are emitted by the blast-radius loop above; an imported
    # advisory with no resolvable package has no blast radius, so it flows here.
    if finding.finding_type == FindingType.CVE and evidence.get("package_resolution") != "unresolved":
        return True
    # Cloud CIS benchmark failures for the dedicated-loop providers are
    # emitted once below with richer per-check rule IDs + structured
    # remediation. Skip them here so a failed check is not double-counted in
    # the GitHub Security tab. databricks CIS + snowflake governance have no
    # dedicated loop, so they still flow through this unified path.
    if (
        finding.finding_type == FindingType.CIS_FAIL
        and evidence.get("benchmark") == "CIS"
        and evidence.get("provider") in _DEDICATED_CIS_PROVIDERS
    ):
        return True
    # IaC misconfigurations are emitted once below by the dedicated IaC loop
    # with richer per-rule rule IDs + line numbers. They now also flow through
    # report.to_findings() (for exec totals + the severity gate), carrying an
    # ``iac`` evidence marker; skip them here to keep each IaC finding to
    # exactly one SARIF result.
    return bool(finding.finding_type == FindingType.CIS_FAIL and evidence.get("iac"))


def _unified_finding_rule(finding: Finding, rule_id: str, level: str, security_severity: str) -> dict[str, Any]:
    description = _sanitize_scanner_text(
        "description",
        finding.description,
        fallback=sanitize_advisory_text("title", finding.title or finding.finding_type.value),
    )
    finding_rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {
            "text": sanitize_advisory_text(
                "title",
                finding.title,
                fallback=finding.finding_type.value.replace("_", " ").title(),
            )
        },
        "fullDescription": {"text": description},
        "helpUri": _UNIFIED_RULE_HELP_URI,
        "defaultConfiguration": {"level": level},
        "properties": {
            "security-severity": security_severity,
            "source": finding.source.value,
            "finding_type": finding.finding_type.value,
        },
    }
    help_body = advisory_help(
        description,
        remediation=_sanitize_scanner_text("recommendation", finding.remediation_guidance),
    )
    if help_body:
        finding_rule["help"] = help_body
    return finding_rule


def _sast_result_properties(finding: Finding, evidence: dict[str, Any]) -> dict[str, Any]:
    if finding.finding_type != FindingType.SAST:
        return {}
    return {
        **{key: sanitize_text(value, max_len=500) for key in ("category", "entrypoint", "sink", "source") if (value := evidence.get(key))},
        **{
            key: [sanitize_text(item, max_len=500) for item in value]
            for key in ("call_path", "detector_categories")
            if isinstance((value := evidence.get(key)), list)
        },
    }


def _unified_finding_properties(finding: Finding, rule_id: str, evidence: dict[str, Any]) -> dict[str, Any]:
    return {
        "advisory_id": rule_id,
        "cwe_ids": list(finding.cwe_ids),
        "asset_canonical_id": finding.asset.stable_id,
        "occurrence_id": finding.id,
        "canonical_id": finding.id,
        "risk_score": finding.risk_score,
        "asset_type": finding.asset.asset_type,
        "asset_name": sanitize_advisory_text("title", finding.asset.name, fallback=finding.asset.asset_type),
        "evidence": _sanitize_sarif_property(finding.evidence),
        "remediation_guidance": _sanitize_sarif_property(finding.remediation_guidance),
        "is_malicious": finding.is_malicious,
        "malicious_reason": (sanitize_advisory_text("title", finding.malicious_reason) or None) if finding.malicious_reason else None,
        # Structured reach lists + AI-native context (unified Finding parity).
        "affected_servers": list(finding.affected_servers),
        "affected_agents": list(finding.affected_agents),
        "exposed_credentials": list(finding.exposed_credentials),
        "exposed_tools": list(finding.exposed_tools),
        "ai_risk_context": finding.ai_risk_context,
        "ai_summary": finding.ai_summary,
        "attack_vector_summary": finding.attack_vector_summary,
        "suppressed": finding.suppressed,
        **_sast_result_properties(finding, evidence),
        **(
            {
                "workload_runtime_evidence": _sanitize_sarif_property(finding.workload_runtime_evidence),
            }
            if isinstance(getattr(finding, "workload_runtime_evidence", None), dict) and finding.workload_runtime_evidence
            else {}
        ),
    }


def _unified_finding_result(finding: Finding, rule_id: str, level: str, evidence: dict[str, Any]) -> dict[str, Any]:
    file_path = (
        _to_relative_path(
            finding.asset.location,
            _ecosystem_from_purl(finding.asset.identifier),
        )
        if finding.asset.location
        else None
    )
    raw_start_line = finding.evidence.get("line_number") or finding.evidence.get("line")
    start_line = raw_start_line if isinstance(raw_start_line, int) and raw_start_line > 0 else 1
    fingerprint_uri = file_path or f"{finding.asset.asset_type}:{finding.asset.stable_id}"
    fp_input = f"{finding.id}:{fingerprint_uri}:{finding.asset.stable_id}"
    fingerprint_fields = _sarif_fingerprint_fields(
        stable_input=fp_input,
        artifact_uri=fingerprint_uri,
        start_line=start_line,
    )
    if file_path is None:
        fingerprint_fields.pop("partialFingerprints", None)
    finding_result: dict = {
        "ruleId": rule_id,
        "level": level,
        "kind": "fail" if level in {"error", "warning"} else "informational",
        "message": {
            "text": sanitize_advisory_text(
                "title",
                finding.title,
                fallback=_sanitize_scanner_text("description", finding.description, fallback=finding.finding_type.value),
            )
        },
        **fingerprint_fields,
        "properties": _unified_finding_properties(finding, rule_id, evidence),
    }
    if file_path is not None:
        finding_result["locations"] = [_sarif_location(file_path, start_line)]
    else:
        asset_name = sanitize_advisory_text("title", finding.asset.name, fallback=finding.asset.asset_type)
        finding_result["locations"] = [{"logicalLocations": [{"name": asset_name, "kind": finding.asset.asset_type}]}]
    suppressions = _suppression_entries(finding)
    if suppressions:
        finding_result["suppressions"] = suppressions
    return finding_result


def _add_unified_finding_results(catalog: _SarifCatalog, report: AIBOMReport) -> None:
    """Unified non-CVE findings, including MCP intelligence/blocklist matches."""
    for finding in apply_workload_runtime_evidence_for_export(list(report.to_findings())):
        evidence = finding.evidence if isinstance(finding.evidence, dict) else {}
        if _emitted_by_dedicated_loop(finding, evidence):
            continue
        rule_id = _unified_finding_rule_id(finding)
        level, security_severity = _sarif_severity(finding.severity or "medium")
        if catalog.claim_rule(rule_id):
            catalog.rules.append(_unified_finding_rule(finding, rule_id, level, security_severity))
        catalog.results.append(_unified_finding_result(finding, rule_id, level, evidence))


def _iac_rule(iac_finding: dict[str, Any], rule_id: str, level: str, security_severity: str) -> dict[str, Any]:
    description = sanitize_advisory_text(
        "description",
        iac_finding.get("message"),
        fallback=sanitize_advisory_text("title", iac_finding.get("title", rule_id), fallback=rule_id),
    )
    iac_rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": sanitize_advisory_text("title", iac_finding.get("title", rule_id), fallback=rule_id)},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": level},
        "properties": {
            "security-severity": security_severity,
            "category": iac_finding.get("category", "iac"),
            "compliance": iac_finding.get("compliance", []),
        },
    }
    help_body = advisory_help(
        description,
        remediation=sanitize_advisory_text("recommendation", iac_finding.get("remediation")),
    )
    if help_body:
        iac_rule["help"] = help_body
    return iac_rule


def _add_iac_results(catalog: _SarifCatalog, report: AIBOMReport) -> None:
    """IaC misconfiguration findings (Dockerfile, K8s, Terraform, CloudFormation)."""
    iac_data = getattr(report, "iac_findings_data", None)
    if not iac_data:
        return
    for iac_finding in iac_data.get("findings", []):
        sev = iac_finding.get("severity", "medium").lower()
        rule_id = f"iac/{iac_finding.get('rule_id', 'unknown')}"
        level, security_severity = _sarif_severity(sev)
        file_path = _to_relative_path(iac_finding.get("file_path", "unknown") or "unknown")
        line_num = iac_finding.get("line_number") or 1
        if catalog.claim_rule(rule_id):
            catalog.rules.append(_iac_rule(iac_finding, rule_id, level, security_severity))

        fp_input = f"{rule_id}:{file_path}:{line_num}"
        catalog.results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "kind": "fail",
                "message": {
                    "text": sanitize_advisory_text(
                        "description",
                        iac_finding.get("message"),
                        fallback=sanitize_advisory_text("title", iac_finding.get("title", "IaC misconfiguration")),
                    )
                },
                **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=file_path, start_line=line_num),
                "locations": [_sarif_location(file_path, line_num)],
            }
        )


def _ai_inventory_rule(comp: dict[str, Any], rule_id: str, name: str, level: str, security_severity: str) -> dict[str, Any]:
    sev = comp.get("severity", "info")
    comp_type = comp.get("type", "unknown")
    description = sanitize_advisory_text(
        "description",
        comp.get("description", ""),
        fallback=f"AI component finding: {name}",
    )
    ai_rule: dict[str, Any] = {
        "id": rule_id,
        "shortDescription": {"text": sanitize_advisory_text("title", f"{sev.upper()}: {comp_type.replace('_', ' ')} - {name}")},
        "fullDescription": {"text": description},
        "defaultConfiguration": {"level": level},
        "properties": {"security-severity": security_severity},
    }
    help_body = advisory_help(
        description,
        remediation=sanitize_advisory_text("recommendation", comp.get("recommendation")),
    )
    if help_body:
        ai_rule["help"] = help_body
    return ai_rule


def _add_ai_inventory_results(catalog: _SarifCatalog, report: AIBOMReport) -> None:
    """AI inventory findings (shadow AI, deprecated models, API keys, invisible Unicode)."""
    ai_inv = getattr(report, "ai_inventory_data", None)
    if not ai_inv:
        return
    for comp in ai_inv.get("components", []):
        sev = comp.get("severity", "info")
        if sev not in ("critical", "high", "medium"):
            continue  # only actionable findings in SARIF
        comp_type = comp.get("type", "unknown")
        # Redact credential fragments — never embed key material in SARIF
        raw_name = comp.get("name", "")
        name = "[REDACTED]" if comp_type == "api_key" else raw_name
        rule_id = f"ai-inventory/{comp_type}/{name}"
        level, security_severity = _sarif_severity(sev)
        if catalog.claim_rule(rule_id):
            catalog.rules.append(_ai_inventory_rule(comp, rule_id, name, level, security_severity))

        file_path = _to_relative_path(comp.get("file", "unknown") or "unknown")
        line_num = int(comp.get("line", 1) or 1)
        fp_input = f"{rule_id}:{file_path}:{line_num}"
        desc = sanitize_advisory_text("description", comp.get("description", ""), fallback=f"{comp_type.replace('_', ' ')}: {name}")
        catalog.results.append(
            {
                "ruleId": rule_id,
                "level": level,
                "kind": "fail",
                "message": {"text": desc},
                **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=file_path, start_line=line_num),
                "locations": [_sarif_location(file_path, comp.get("line", 1))],
            }
        )


def _cis_rule(check: dict[str, Any], cloud_key: str, rule_id: str, level: str, security_severity: str) -> dict[str, Any]:
    cis_severity = str(check.get("severity") or "unknown").lower()
    check_id = check.get("check_id") or "unknown"
    remediation = check.get("remediation") or {}
    title = check.get("title") or rule_id
    help_uri = sanitize_url(str(remediation.get("docs") or "")) or ""
    recommendation = sanitize_advisory_text(
        "recommendation",
        check.get("recommendation"),
        fallback=sanitize_advisory_text("title", title, fallback=rule_id),
    )
    cis_rule: dict = {
        "id": rule_id,
        "shortDescription": {
            "text": sanitize_advisory_text(
                "title",
                f"{cis_severity.upper()}: CIS {cloud_key.upper()} {check_id} - {title}",
                fallback=rule_id,
            )
        },
        "fullDescription": {"text": recommendation},
        "defaultConfiguration": {"level": level},
        "properties": {
            "security-severity": security_severity,
            "tags": ["cis", cloud_key, "compliance"],
            "cis_section": check.get("cis_section") or "",
        },
    }
    if help_uri:
        cis_rule["helpUri"] = help_uri
    help_body = advisory_help(
        recommendation,
        remediation=_cis_remediation_text(remediation),
        reference_uri=help_uri,
    )
    if help_body:
        cis_rule["help"] = help_body
    return cis_rule


def _cis_result_properties(check: dict[str, Any]) -> dict[str, Any]:
    remediation = check.get("remediation") or {}
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
    return result_props


def _cis_result(check: dict[str, Any], cloud_key: str, rule_id: str, level: str) -> dict[str, Any]:
    check_id = check.get("check_id") or "unknown"
    title = check.get("title") or rule_id
    # Synthetic fingerprint so repeat runs produce stable IDs.
    fp_input = f"{rule_id}:{','.join(check.get('resource_ids') or [])}"
    # CIS findings are cloud-control-level, not file-level. Point
    # at a conventional manifest so GitHub renders the result;
    # the rich context lives in ``properties``.
    artifact_uri = f"cis-{cloud_key}-benchmark"
    return {
        "ruleId": rule_id,
        "level": level,
        "kind": "fail",
        "message": {
            "text": sanitize_advisory_text(
                "title",
                f"CIS {cloud_key.upper()} {check_id} failed: {title}",
                fallback=rule_id,
            )
        },
        **_sarif_fingerprint_fields(stable_input=fp_input, artifact_uri=artifact_uri, start_line=1),
        "locations": [_sarif_location(artifact_uri, 1)],
        "properties": _cis_result_properties(check),
    }


def _add_cis_benchmark_results(catalog: _SarifCatalog, report: AIBOMReport) -> None:
    """CIS benchmark findings (AWS / Azure / GCP / Snowflake).

    Each failed check emits a SARIF result with the structured remediation dict
    (issue #665) in ``properties.remediation`` so GitHub Code Scanning and
    downstream SARIF consumers can surface fix guidance per finding.
    """
    from agent_bom.cloud.cis_remediation import fail_closed_cis_bundle

    for cloud_key, data_attr in _DEDICATED_CIS_BENCHMARKS:
        bundle = getattr(report, data_attr, None)
        if not bundle:
            continue
        bundle = fail_closed_cis_bundle(bundle, cloud=cloud_key)
        for check in bundle.get("checks", []):
            if check.get("status") != "fail":
                continue
            # Matches `cis_check_to_finding`: a control that reports no severity
            # is unrated, not medium. Defaulting to a rated band here published
            # the check to GitHub as Medium while every summary built from the
            # unified stream called the same check unrated.
            cis_severity = str(check.get("severity") or "unknown").lower()
            rule_id = f"cis/{cloud_key}/{check.get('check_id') or 'unknown'}"
            level, security_severity = _sarif_severity(cis_severity)
            if catalog.claim_rule(rule_id):
                catalog.rules.append(_cis_rule(check, cloud_key, rule_id, level, security_severity))
            catalog.results.append(_cis_result(check, cloud_key, rule_id, level))


def _sarif_invocation(scan_run: ScanRun) -> dict[str, Any]:
    return {
        "executionSuccessful": scan_run.outcome is not ScanOutcome.FAILED,
        "toolExecutionNotifications": [
            {
                "descriptor": {"id": issue.code},
                "level": issue.severity,
                "message": {"text": sanitize_text(issue.message) or "Scan execution issue"},
                "properties": {
                    "stage": issue.stage,
                    "source": issue.source,
                    "affectsCoverage": issue.affects_coverage,
                },
            }
            for issue in scan_run.issues
        ],
    }


def _build_sarif_run(report: AIBOMReport, catalog: _SarifCatalog, scan_run: ScanRun) -> dict[str, Any]:
    taxonomies = _build_run_taxonomies(catalog.results)
    _compact_taxa_references(catalog.results, taxonomies)
    cwe_taxonomy = _attach_cwe_taxonomy(catalog.results, catalog.rules)
    run: dict = {
        "tool": {
            "driver": {
                "name": "agent-bom",
                "version": report.tool_version,
                "informationUri": "https://github.com/msaad00/agent-bom",
                "rules": catalog.rules,
            }
        },
        "results": catalog.results,
        "properties": {"scan_outcome": scan_run.outcome.value},
        "invocations": [_sarif_invocation(scan_run)],
        **({"automationDetails": {"id": f"agent-bom/{report.scan_id}"}} if report.scan_id else {}),
    }
    trust_assessment = getattr(report, "trust_assessment_data", None)
    if isinstance(trust_assessment, dict) and trust_assessment:
        run["properties"]["trust_assessment"] = _trust_assessment_sarif_property(trust_assessment)
    if taxonomies:
        run["taxonomies"] = taxonomies
        run["tool"]["extensions"] = _taxonomies_as_tool_extensions(taxonomies)

    if cwe_taxonomy:
        run.setdefault("taxonomies", []).append(cwe_taxonomy)
        run["tool"]["driver"]["supportedTaxonomies"] = [{"name": "CWE", "guid": cwe_taxonomy["guid"]}]
    return run


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
    scan_run = effective_scan_run(report)
    catalog = _SarifCatalog()
    _add_cve_results(catalog, report, blast_radii, exclude_unfixable)
    _add_unified_finding_results(catalog, report)
    _add_iac_results(catalog, report)
    _add_ai_inventory_results(catalog, report)
    _add_cis_benchmark_results(catalog, report)
    document = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [_build_sarif_run(report, catalog, scan_run)],
    }
    from agent_bom.output.interop_security import sanitize_linked_document

    return sanitize_linked_document(document)


def export_sarif(
    report: AIBOMReport,
    output_path: str,
    *,
    exclude_unfixable: bool = False,
) -> None:
    """Export report as SARIF 2.1.0 JSON file."""
    data = to_sarif(report, exclude_unfixable=exclude_unfixable)
    Path(output_path).write_text(json.dumps(data, separators=(",", ":")), encoding="utf-8")
