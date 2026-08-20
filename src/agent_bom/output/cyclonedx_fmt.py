"""CycloneDX 1.7 SBOM output format with ML BOM extensions.

Supports native CycloneDX 1.7 machine learning extensions:
- ``modelCard`` — model provenance, training parameters, performance metrics
- ``data`` — dataset provenance, governance, classification
- Component type ``machine-learning-model`` for ML model artifacts
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any
from uuid import uuid4

from agent_bom import __version__
from agent_bom.asset_provenance import (
    agent_discovery_provenance,
    package_discovery_provenance,
    package_version_provenance,
    sanitize_discovery_provenance,
)
from agent_bom.canonical_ids import CANONICAL_ID_SCHEMA_VERSION
from agent_bom.checksums import cyclonedx_hashes, integrity_verdict, strongest_checksum
from agent_bom.evidence.scan_run import ScanOutcome, effective_scan_run
from agent_bom.models import AIBOMReport, Vulnerability
from agent_bom.package_utils import synthesize_purl
from agent_bom.security import sanitize_launch_command, sanitize_path_label
from agent_bom.vex import vex_justification_to_cdx


def _sanitize_bom_ref(raw: str) -> str:
    """Sanitize a CycloneDX bom-ref to contain only valid characters.

    CycloneDX 1.7 bom-ref should match ``^[a-zA-Z0-9._-]+$``.
    Replace invalid characters (``@``, ``/``, spaces, etc.) with ``-``.
    """
    return re.sub(r"[^a-zA-Z0-9._-]", "-", raw)


def _merge_properties(current: list[dict], incoming: list[dict]) -> list[dict]:
    """Merge component properties without dropping later security evidence."""
    merged = [dict(prop) for prop in current]
    positions = {str(prop.get("name")): index for index, prop in enumerate(merged)}
    seen = {(str(prop.get("name")), str(prop.get("value"))) for prop in merged}
    for prop in incoming:
        name = str(prop.get("name") or "")
        value = str(prop.get("value") or "")
        if (name, value) in seen:
            continue
        if name == "agent-bom:tool-count" and name in positions:
            index = positions[name]
            try:
                current_count = int(str(merged[index].get("value") or "0"))
                incoming_count = int(value)
            except ValueError:
                pass
            else:
                if incoming_count > current_count:
                    seen.discard((name, str(merged[index].get("value") or "")))
                    merged[index] = dict(prop)
                    seen.add((name, value))
                continue
        merged.append(dict(prop))
        seen.add((name, value))
        positions.setdefault(name, len(merged) - 1)
    return merged


def _merge_bom_ref_items(items: list[dict]) -> list[dict]:
    """Return one item per ``bom-ref`` while merging later evidence.

    The same agent, server, tool service, model, or dataset can be discovered
    through multiple configuration surfaces. CycloneDX requires those arrays
    to be unique, but first-observation deduplication must not discard security
    properties learned from an enriched observation.
    """
    unique: list[dict] = []
    by_ref: dict[str, dict] = {}
    for item in items:
        ref = str(item.get("bom-ref") or "")
        existing = by_ref.get(ref) if ref else None
        if existing is not None:
            existing["properties"] = _merge_properties(
                list(existing.get("properties", [])),
                list(item.get("properties", [])),
            )
            for key, value in item.items():
                if key not in existing or existing[key] in (None, "", []):
                    existing[key] = value
            continue
        if ref:
            copied = dict(item)
            if "properties" in copied:
                copied["properties"] = [dict(prop) for prop in copied["properties"]]
            by_ref[ref] = copied
            unique.append(copied)
        else:
            unique.append(item)
    return unique


def _merge_dependencies(dependencies: list[dict]) -> list[dict]:
    """Merge repeated graph entries into a stable ref/dependsOn adjacency."""
    by_ref: dict[str, set[str]] = {}
    for dependency in dependencies:
        ref = str(dependency.get("ref") or "")
        if not ref:
            continue
        targets = by_ref.setdefault(ref, set())
        targets.update(str(target) for target in dependency.get("dependsOn", []) if target)
    return [{"ref": ref, "dependsOn": sorted(by_ref[ref])} for ref in sorted(by_ref)]


def _cwe_ids_to_integers(cwe_ids: list[str]) -> list[int]:
    """Map ``["CWE-94", "CWE-502"]`` to the CycloneDX-native integer form.

    CDX 1.7 ``cwes`` is an array of integer CWE IDs (``>= 1``). Non-numeric or
    malformed entries are dropped rather than invented.
    """
    ints: list[int] = []
    for raw in cwe_ids:
        match = re.search(r"(\d+)", str(raw))
        if not match:
            continue
        value = int(match.group(1))
        if value >= 1 and value not in ints:
            ints.append(value)
    return ints


def _cdx_score_method(cvss_vector: str | None) -> str:
    """Map a CVSS vector string onto the CDX 1.7 ``scoreMethod`` enum.

    The enum separates CVSSv3 (3.0) from CVSSv31 (3.1), so a hardcoded
    ``CVSSv3`` mislabels every 3.1 and 4.0 score the scanner produces. Falls
    back to CVSSv3 when no vector is available, matching the prior default.
    """
    vector = (cvss_vector or "").strip().upper()
    if vector.startswith("CVSS:4"):
        return "CVSSv4"
    if vector.startswith("CVSS:3.1"):
        return "CVSSv31"
    if vector.startswith("CVSS:3"):
        return "CVSSv3"
    if vector and not vector.startswith("CVSS:"):
        # CVSS v2 vectors carry no version prefix (``AV:N/AC:L/Au:N/...``).
        return "CVSSv2"
    return "CVSSv3"


def _cyclonedx_vulnerability(
    vuln: Vulnerability,
    pkg_ref: str,
    *,
    observed_at: str | None = None,
    workflow: dict[str, str] | None = None,
) -> dict:
    """Build one package-scoped CycloneDX vulnerability observation.

    Carries the enrichment other exporters already surface: CWE weaknesses via
    the native ``cwes`` array, EPSS as an ``other``-method rating, and CISA KEV
    plus EPSS detail as namespaced ``agent-bom:`` properties (KEV/EPSS have no
    first-class CDX 1.7 vulnerability slot). ``observed_at`` anchors the
    severity-derived remediation SLA (``agent-bom:sla_due_at``); omitted when no
    deadline is derivable so a missing property never reads as "no SLA".
    """
    ratings: list[dict[str, object]] = []
    if vuln.cvss_score:
        cvss_rating: dict[str, object] = {
            "score": vuln.cvss_score,
            "severity": vuln.severity.value,
            "method": _cdx_score_method(vuln.cvss_vector),
        }
        if vuln.cvss_vector:
            # CDX 1.7 `ratings[].vector` is the canonical slot for the metric
            # string. Emitting a bare score forces every consumer to re-derive
            # AV/AC/PR/UI — which they cannot, so the detail was simply lost.
            cvss_rating["vector"] = vuln.cvss_vector
        ratings.append(cvss_rating)
    else:
        ratings.append({"severity": vuln.severity.value})
    if vuln.epss_score is not None:
        # EPSS is a probability (0.0–1.0), not a CVSS-style severity — surface it
        # as an `other`-method rating attributed to the EPSS source.
        ratings.append(
            {
                "source": {"name": "EPSS", "url": "https://www.first.org/epss/"},
                "score": vuln.epss_score,
                "method": "other",
            }
        )
    entry: dict = {
        "id": vuln.id,
        "description": vuln.summary or f"See {vuln.id} for details",
        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln.id}"},
        "ratings": ratings,
        "affects": [{"ref": pkg_ref}],
    }
    cwes = _cwe_ids_to_integers(vuln.cwe_ids)
    if cwes:
        entry["cwes"] = cwes
    vuln_properties: list[dict[str, str]] = []
    if vuln.is_kev:
        vuln_properties.append({"name": "agent-bom:kev", "value": "true"})
        if vuln.kev_date_added:
            vuln_properties.append({"name": "agent-bom:kev_date_added", "value": vuln.kev_date_added})
        if vuln.kev_due_date:
            vuln_properties.append({"name": "agent-bom:kev_due_date", "value": vuln.kev_due_date})
    # Severity-derived remediation SLA (KEV override) — one source of truth in
    # agent_bom.graph.sla. Only emitted when an anchor + policy make a deadline real.
    from agent_bom.graph.sla import sla_due_at as _compute_sla_due_at

    workflow_data = workflow or {}
    sla_due = _compute_sla_due_at(
        vuln.severity.value,
        observed_at,
        kev_due_date=vuln.kev_due_date,
    )
    if sla_due is not None:
        vuln_properties.append({"name": "agent-bom:sla_due_at", "value": sla_due})
    if vuln.epss_score is not None:
        vuln_properties.append({"name": "agent-bom:epss_score", "value": str(vuln.epss_score)})
    if vuln.epss_percentile is not None:
        vuln_properties.append({"name": "agent-bom:epss_percentile", "value": str(vuln.epss_percentile)})
    if workflow_data:
        # A CycloneDX vulnerability can affect more than one component. Owner,
        # explicit SLA, and workflow state belong to the package observation,
        # not the globally merged CVE, so retain the affected bom-ref in one
        # deterministic structured property. The generic sla_due_at above stays
        # the single severity-policy deadline shared by the vulnerability.
        scoped_workflow = {"affects_ref": pkg_ref, **workflow_data}
        vuln_properties.append(
            {
                "name": "agent-bom:workflow",
                "value": json.dumps(scoped_workflow, sort_keys=True, separators=(",", ":")),
            }
        )
    if vuln.is_kev or vuln.epss_score is not None:
        vuln_properties.append({"name": "agent-bom:exploit_likelihood", "value": vuln.exploit_likelihood})
    # Framework control attribution (CDX 1.7 has no first-class vulnerability
    # slot for compliance mappings) as namespaced properties: framework:control
    # IDs only — no copyrighted control-title text — labeled vendor-asserted so
    # consumers never read agent-bom's own mapping judgment as an official
    # crosswalk.
    compliance_tags = getattr(vuln, "compliance_tags", None) or {}
    emitted_compliance = False
    if isinstance(compliance_tags, dict):
        for framework, controls in sorted(compliance_tags.items()):
            control_list = [controls] if isinstance(controls, str) else list(controls or [])
            for control in control_list:
                vuln_properties.append({"name": "agent-bom:compliance-tag", "value": f"{framework}:{control}"})
                emitted_compliance = True
    if emitted_compliance:
        vuln_properties.append({"name": "agent-bom:compliance-tag-provenance", "value": "vendor-asserted"})
    if vuln_properties:
        entry["properties"] = vuln_properties
    if vuln.fixed_version:
        entry["recommendation"] = f"Upgrade to {vuln.fixed_version}"
    if vuln.vex_status:
        state_map = {
            "affected": "exploitable",
            "not_affected": "not_affected",
            "fixed": "resolved",
            "under_investigation": "in_triage",
        }
        analysis: dict[str, str] = {"state": state_map.get(vuln.vex_status, "in_triage")}
        if vuln.vex_justification:
            justification = vex_justification_to_cdx(vuln.vex_justification)
            if justification:
                analysis["justification"] = justification
        entry["analysis"] = analysis
    return entry


def _merge_vulnerability_observation(by_id: dict[str, dict], observation: dict) -> None:
    """Merge a vulnerability ID into one entry with all affected components."""
    vuln_id = str(observation["id"])
    existing = by_id.get(vuln_id)
    if existing is None:
        by_id[vuln_id] = observation
        return
    affected_refs = {
        str(affected.get("ref")) for affected in [*existing.get("affects", []), *observation.get("affects", [])] if affected.get("ref")
    }
    existing["affects"] = [{"ref": ref} for ref in sorted(affected_refs)]
    incoming_properties = observation.get("properties")
    if isinstance(incoming_properties, list):
        existing["properties"] = _merge_properties(existing.get("properties", []), incoming_properties)


def _append_discovery_provenance_properties(properties: list[dict], provenance: dict | None) -> None:
    """Append sanitized discovery provenance as CycloneDX component properties."""
    if not provenance:
        return
    for key, value in sorted(provenance.items()):
        if isinstance(value, (dict, list)):
            prop_value = json.dumps(value, sort_keys=True, separators=(",", ":"))
        elif isinstance(value, bool):
            prop_value = str(value).lower()
        else:
            prop_value = str(value)
        properties.append(
            {
                "name": f"agent-bom:discovery-provenance:{key.replace('_', '-')}",
                "value": prop_value,
            }
        )


# ── ML BOM extension builders ────────────────────────────────────────────────


def _integrity_identity_evidence(pkg: Any, verdict: dict[str, Any], purl: str | None) -> list[dict[str, Any]]:
    """Render the verification verdict as CycloneDX 1.7 identity evidence.

    CycloneDX models this natively: ``component.evidence.identity[]`` carries
    ``methods[].technique``, whose enum includes ``hash-comparison`` (the
    registry-digest check) and ``attestation`` (the SLSA / PEP 740 /
    sum.golang.org lookup). ``confidence`` is 1.0 for a pass and 0.0 for a
    documented failure — absent entirely when the check never ran, and equally
    absent when the registry was asked but did not answer, because a 0.0 here
    asserts a failure the lookup never established. That third state is carried
    by the ``agent-bom:provenance-status`` property instead.
    """
    identities: list[dict[str, Any]] = []
    verified = verdict.get("integrity_verified")
    if verified is not None:
        confidence = 1.0 if verified else 0.0
        method: dict[str, Any] = {"technique": "hash-comparison", "confidence": confidence}
        digest = strongest_checksum(getattr(pkg, "checksums", {}) or {})
        entry: dict[str, Any] = {"field": "hash", "confidence": confidence}
        if digest is not None:
            alg, value = digest
            method["value"] = f"{alg}:{value}"
            entry["concludedValue"] = f"{alg}:{value}"
        entry["methods"] = [method]
        identities.append(entry)
    attested = verdict.get("provenance_attested")
    if attested is not None:
        confidence = 1.0 if attested else 0.0
        method = {"technique": "attestation", "confidence": confidence}
        source = verdict.get("provenance_source")
        if source:
            method["value"] = str(source)
        entry = {"field": "purl", "confidence": confidence, "methods": [method]}
        if purl:
            entry["concludedValue"] = purl
        identities.append(entry)
    return identities


def _build_model_card(provenance: dict) -> dict:
    """Build a CycloneDX 1.7 modelCard from a model provenance dict.

    Maps HuggingFace/Ollama provenance metadata to the CycloneDX modelCard
    schema: bom-ref, modelParameters, quantitativeAnalysis, considerations.
    """
    card: dict = {}

    # modelParameters — architecture, format, inputs/outputs
    params: dict = {}
    if provenance.get("format"):
        params["approach"] = {"type": provenance["format"]}
    model_id = provenance.get("model_id", "")
    if model_id:
        params["modelArchitecture"] = model_id
    if provenance.get("metadata"):
        meta = provenance["metadata"]
        if meta.get("pipeline_tag"):
            params["task"] = meta["pipeline_tag"]
        if meta.get("tags"):
            params["datasets"] = [{"ref": t} for t in meta["tags"] if t.startswith("dataset:")][:10]
    if params:
        card["modelParameters"] = params

    # considerations — safety, security, ethical
    considerations: dict = {}
    risk_flags = provenance.get("risk_flags", [])
    if risk_flags:
        considerations["technicalLimitations"] = [f"Risk flag: {flag}" for flag in risk_flags]
    safe_format = provenance.get("is_safe_format", True)
    if not safe_format:
        considerations.setdefault("technicalLimitations", []).append(
            "Model uses unsafe serialization format (pickle/pt) — arbitrary code execution on load"
        )
    if considerations:
        card["considerations"] = considerations

    return card


def _build_model_component(provenance: dict, comp_id: int) -> tuple[dict, str]:
    """Build a CycloneDX 1.7 component of type machine-learning-model.

    Returns (component_dict, bom_ref).
    """
    model_id = provenance.get("model_id", f"model-{comp_id}")
    ref = _sanitize_bom_ref(f"ml-model-{model_id}-{comp_id}")

    component: dict = {
        "type": "machine-learning-model",
        "bom-ref": ref,
        "name": model_id,
        "description": f"ML model ({provenance.get('source', 'unknown')})",
        "properties": [
            {"name": "agent-bom:model-source", "value": provenance.get("source", "unknown")},
            {"name": "agent-bom:serialization-format", "value": provenance.get("format", "unknown")},
            {"name": "agent-bom:safe-format", "value": str(provenance.get("is_safe_format", False)).lower()},
            {"name": "agent-bom:risk-level", "value": provenance.get("risk_level", "unknown")},
        ],
    }

    # Digest for integrity verification
    digest = provenance.get("digest", "")
    if digest:
        component["hashes"] = [{"alg": "SHA-256", "content": digest}]

    # Model card (CycloneDX 1.7 native)
    model_card = _build_model_card(provenance)
    if model_card:
        component["modelCard"] = model_card

    # Security flags as properties
    for flag in provenance.get("risk_flags", []):
        component["properties"].append({"name": "agent-bom:risk-flag", "value": flag})

    return component, ref


def _build_model_file_component(model_file: dict, comp_id: int) -> tuple[dict, str]:
    """Build a CycloneDX 1.7 component from a local model file scan result."""
    filename = model_file.get("filename", f"model-file-{comp_id}")
    ref = _sanitize_bom_ref(f"ml-file-{filename}-{comp_id}")

    component: dict = {
        "type": "machine-learning-model",
        "bom-ref": ref,
        "name": filename,
        "version": model_file.get("size_human", ""),
        "description": f"ML model file ({model_file.get('format', 'unknown')} — {model_file.get('ecosystem', '')})",
        "properties": [
            {"name": "agent-bom:format", "value": model_file.get("format", "unknown")},
            {"name": "agent-bom:ecosystem", "value": model_file.get("ecosystem", "unknown")},
            {"name": "agent-bom:size-bytes", "value": str(model_file.get("size_bytes", 0))},
        ],
    }

    # Security flags (e.g., PICKLE_DESERIALIZATION)
    for flag in model_file.get("security_flags", []):
        component["properties"].append(
            {"name": f"agent-bom:security-{flag.get('type', 'unknown').lower()}", "value": flag.get("severity", "UNKNOWN")}
        )
        # Also add to considerations in modelCard
        component.setdefault("modelCard", {}).setdefault("considerations", {}).setdefault("technicalLimitations", []).append(
            str(flag.get("description", ""))
        )

    return component, ref


def _build_dataset_component(dataset: dict, comp_id: int) -> tuple[dict, str]:
    """Build a CycloneDX 1.7 component with data classification for datasets.

    Uses the CycloneDX 1.7 ``data`` extension for dataset governance:
    type, name, classification, contents, governance.
    """
    ds_name = dataset.get("name", f"dataset-{comp_id}")
    ref = _sanitize_bom_ref(f"dataset-{ds_name}-{comp_id}")

    component: dict = {
        "type": "data",
        "bom-ref": ref,
        "name": ds_name,
        "description": dataset.get("description", "")[:300],
        "properties": [
            {"name": "agent-bom:type", "value": "dataset"},
            {"name": "agent-bom:source-file", "value": dataset.get("source_file", "")},
        ],
    }

    # License
    lic = dataset.get("license", "")
    if lic:
        if any(op in lic for op in (" AND ", " OR ", " WITH ")):
            component["licenses"] = [{"expression": lic}]
        else:
            component["licenses"] = [{"license": {"id": lic}}]

    # CycloneDX 1.7 data extension — governance and classification
    data_ext: dict = {"type": "dataset", "name": ds_name}

    # Contents description
    contents: dict = {}
    if dataset.get("features"):
        contents["properties"] = [{"name": "feature", "value": f} for f in dataset["features"][:20]]
    if dataset.get("splits"):
        contents["properties"] = contents.get("properties", []) + [
            {"name": f"split:{k}", "value": str(v)} for k, v in dataset["splits"].items()
        ]
    if contents:
        data_ext["contents"] = contents

    # Governance
    governance: dict = {}
    if dataset.get("task_categories"):
        governance["custodians"] = [{"organization": {"name": cat}} for cat in dataset["task_categories"][:5]]
    if dataset.get("languages"):
        data_ext["classification"] = ", ".join(dataset["languages"])
    if governance:
        data_ext["governance"] = governance

    component["data"] = [data_ext]

    # Security flags
    for flag in dataset.get("security_flags", []):
        component["properties"].append(
            {"name": f"agent-bom:flag-{flag.get('type', 'unknown').lower()}", "value": flag.get("severity", "UNKNOWN")}
        )

    return component, ref


def _build_mcp_prompt_component(prompt: Any) -> tuple[dict, str]:
    """Build native CycloneDX data evidence for one MCP prompt template."""
    ref = _sanitize_bom_ref(f"mcp-prompt-{prompt.stable_id}")
    properties = [
        {"name": "agent-bom:type", "value": "mcp-prompt"},
        {"name": "agent-bom:canonical-id", "value": prompt.canonical_id},
        {"name": "agent-bom:argument-count", "value": str(len(prompt.arguments))},
    ]
    properties.extend({"name": "agent-bom:content-finding", "value": finding} for finding in prompt.content_findings)
    component: dict[str, Any] = {
        "type": "data",
        "bom-ref": ref,
        "name": prompt.name,
        "properties": properties,
        "data": [{"type": "definition", "name": prompt.name}],
    }
    if prompt.description:
        component["description"] = prompt.description[:300]
    return component, ref


def _build_mcp_resource_component(resource: Any) -> tuple[dict, str]:
    """Build native CycloneDX data evidence for one MCP resource descriptor."""
    ref = _sanitize_bom_ref(f"mcp-resource-{resource.stable_id}")
    properties = [
        {"name": "agent-bom:type", "value": "mcp-resource"},
        {"name": "agent-bom:canonical-id", "value": resource.canonical_id},
        {"name": "agent-bom:uri", "value": resource.uri},
    ]
    if resource.mime_type:
        properties.append({"name": "agent-bom:mime-type", "value": resource.mime_type})
    properties.extend({"name": "agent-bom:content-finding", "value": finding} for finding in resource.content_findings)
    component: dict[str, Any] = {
        "type": "data",
        "bom-ref": ref,
        "name": resource.name,
        "properties": properties,
        "data": [{"type": "other", "name": resource.name}],
    }
    if resource.description:
        component["description"] = resource.description[:300]
    return component, ref


def _build_training_component(run: dict, comp_id: int) -> tuple[dict, str]:
    """Build a CycloneDX 1.7 component for a training pipeline run.

    Uses modelCard.quantitativeAnalysis for metrics and
    modelCard.modelParameters for hyperparameters.
    """
    run_name = run.get("name", f"training-run-{comp_id}")
    ref = _sanitize_bom_ref(f"training-{run_name}-{comp_id}")

    component: dict = {
        "type": "machine-learning-model",
        "bom-ref": ref,
        "name": run_name,
        "description": f"Training run ({run.get('framework', 'unknown')})",
        "properties": [
            {"name": "agent-bom:type", "value": "training-run"},
            {"name": "agent-bom:framework", "value": run.get("framework", "unknown")},
            {"name": "agent-bom:source-file", "value": run.get("source_file", "")},
        ],
    }

    if run.get("run_id"):
        component["properties"].append({"name": "agent-bom:run-id", "value": run["run_id"]})
    if run.get("model_flavor"):
        component["properties"].append({"name": "agent-bom:model-flavor", "value": run["model_flavor"]})
    if run.get("git_sha"):
        component["properties"].append({"name": "agent-bom:git-sha", "value": run["git_sha"]})

    # Build modelCard with training metadata
    model_card: dict = {}

    # modelParameters — hyperparameters
    params = run.get("parameters", {})
    if params:
        model_card["modelParameters"] = {
            "approach": {"type": run.get("model_flavor", run.get("framework", "unknown"))},
        }

    # quantitativeAnalysis — metrics
    metrics = run.get("metrics", {})
    if metrics:
        model_card["quantitativeAnalysis"] = {"performanceMetrics": [{"type": k, "value": str(v)} for k, v in metrics.items()]}

    # considerations — security flags
    for flag in run.get("security_flags", []):
        model_card.setdefault("considerations", {}).setdefault("technicalLimitations", []).append(str(flag.get("description", "")))

    if model_card:
        component["modelCard"] = model_card

    return component, ref


# ── Main export ──────────────────────────────────────────────────────────────


def to_cyclonedx(report: AIBOMReport) -> dict:
    """Build CycloneDX 1.7 dict from report with ML BOM extensions.

    Emits native CycloneDX 1.7 ``machine-learning-model`` components with
    ``modelCard`` for model provenance, ``data`` components for datasets,
    and training run metadata via ``quantitativeAnalysis``.
    """
    components = []
    scan_run = effective_scan_run(report)
    services: list[dict] = []
    vulnerabilities_by_id: dict[str, dict] = {}
    from agent_bom.output.finding_views import cve_findings, package_ecosystem, package_name, package_version, workflow_status

    workflow_by_vulnerability: dict[tuple[str, str, str | None, str], dict[str, str]] = {}
    for finding in cve_findings(report):
        workflow: dict[str, str] = {}
        if finding.owner:
            workflow["owner"] = finding.owner
        sla_due = finding.to_dict().get("sla_due_at")
        if sla_due:
            workflow["sla_due_at"] = str(sla_due)
        status = workflow_status(finding)
        if status:
            workflow["workflow_status"] = status
        if workflow:
            workflow_by_vulnerability[
                (package_ecosystem(finding), package_name(finding), package_version(finding), finding.cve_id or finding.id)
            ] = workflow
    dependencies = []

    comp_id = 0
    bom_ref_map = {}
    ml_component_refs: list[str] = []  # Track ML components for top-level deps
    # Bom-refs must be unique across the document. A package reachable via
    # multiple servers is otherwise emitted as duplicate components sharing one
    # bom-ref (invalid CycloneDX), so emit each component once and keep only the
    # dependency edges from every referencing server.
    seen_component_refs: set[str] = set()

    for agent in report.agents:
        agent_ref = _sanitize_bom_ref(f"agent-{agent.stable_id}")
        agent_deps = []
        agent_provenance = agent_discovery_provenance(agent)
        agent_properties = [
            {"name": "agent-bom:type", "value": "ai-agent"},
            {"name": "agent-bom:canonical-id-schema-version", "value": CANONICAL_ID_SCHEMA_VERSION},
            {"name": "agent-bom:config-path", "value": sanitize_path_label(agent.config_path) if agent.config_path else ""},
            {"name": "agent-bom:status", "value": agent.status.value},
        ]
        agent_properties.extend(
            {"name": "agent-bom:previous-canonical-id", "value": legacy_id} for legacy_id in agent.previous_canonical_ids
        )
        _append_discovery_provenance_properties(agent_properties, agent_provenance)

        components.append(
            {
                "type": "application",
                "bom-ref": agent_ref,
                "name": agent.name,
                "version": agent.version or "unknown",
                "description": f"AI Agent ({agent.agent_type.value})",
                "properties": agent_properties,
            }
        )

        for server in agent.mcp_servers:
            server_ref = _sanitize_bom_ref(f"mcp-server-{server.stable_id}")
            server_deps = []
            server_provenance = sanitize_discovery_provenance(getattr(server, "discovery_provenance", None), defaults=agent_provenance)

            server_props = [
                {"name": "agent-bom:type", "value": "mcp-server"},
                {"name": "agent-bom:command", "value": sanitize_launch_command(server.command, server.args)},
                {"name": "agent-bom:transport", "value": server.transport.value},
            ]
            _append_discovery_provenance_properties(server_props, server_provenance)
            if server.has_credentials:
                server_props.append({"name": "agent-bom:has-credentials", "value": "true"})
            if server.tools:
                server_props.append({"name": "agent-bom:tool-count", "value": str(len(server.tools))})
                # Export each tool as a property for SBOM consumers
                for tool in server.tools:
                    tool_val = tool.name
                    if tool.description:
                        tool_val = f"{tool.name}: {tool.description[:120]}"
                    server_props.append({"name": "agent-bom:mcp-tool", "value": tool_val})

            server_component: dict = {
                "type": "application",
                "bom-ref": server_ref,
                "name": server.name,
                "description": f"MCP Server ({server.transport.value})",
                "properties": server_props,
            }
            components.append(server_component)
            # MCP tool capabilities belong in the top-level CycloneDX 1.7
            # ``services`` array — ``services`` is not a valid property of a
            # component, so nesting it here fails strict 1.7 validation.
            for tool in server.tools:
                service_entry: dict = {
                    "bom-ref": _sanitize_bom_ref(f"service-{server_ref}-{tool.name}"),
                    "name": tool.name,
                }
                if tool.description:
                    service_entry["description"] = tool.description
                services.append(service_entry)
            for prompt in server.prompts:
                prompt_component, prompt_ref = _build_mcp_prompt_component(prompt)
                components.append(prompt_component)
                server_deps.append(prompt_ref)
            for resource in server.resources:
                resource_component, resource_ref = _build_mcp_resource_component(resource)
                components.append(resource_component)
                server_deps.append(resource_ref)
            agent_deps.append(server_ref)

            for pkg in server.packages:
                pkg_ref = _sanitize_bom_ref(f"pkg-{pkg.stable_id}")
                # Always record the edge from this server, even if the component
                # (and its vulnerabilities) were already emitted via another server.
                server_deps.append(pkg_ref)
                bom_ref_map[f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"] = pkg_ref
                for vuln in pkg.vulnerabilities:
                    _merge_vulnerability_observation(
                        vulnerabilities_by_id,
                        _cyclonedx_vulnerability(
                            vuln,
                            pkg_ref,
                            observed_at=report.generated_at.isoformat(),
                            workflow=workflow_by_vulnerability.get((pkg.ecosystem, pkg.name, pkg.version, vuln.id)),
                        ),
                    )
                if pkg_ref in seen_component_refs:
                    continue
                seen_component_refs.add(pkg_ref)
                package_provenance = package_discovery_provenance(pkg, inherited=server_provenance)
                version_provenance = package_version_provenance(pkg, inherited=server_provenance)

                pkg_properties = [
                    {"name": "agent-bom:ecosystem", "value": pkg.ecosystem},
                    {"name": "agent-bom:is-direct", "value": str(pkg.is_direct).lower()},
                    {"name": "agent-bom:dependency-depth", "value": str(pkg.dependency_depth)},
                    {"name": "agent-bom:dependency-scope", "value": pkg.dependency_scope},
                    {"name": "agent-bom:reachability-evidence", "value": pkg.reachability_evidence},
                    {"name": "agent-bom:resolved-from-registry", "value": str(pkg.resolved_from_registry).lower()},
                    {"name": "agent-bom:version-source", "value": pkg.version_source},
                    {"name": "agent-bom:version-provenance-source", "value": version_provenance.get("version_source", "unknown")},
                    {"name": "agent-bom:version-provenance-confidence", "value": version_provenance.get("confidence", "unknown")},
                    {"name": "agent-bom:floating-reference", "value": str(pkg.floating_reference).lower()},
                ]
                _append_discovery_provenance_properties(pkg_properties, package_provenance)
                if pkg.floating_reference_reason:
                    pkg_properties.append({"name": "agent-bom:floating-reference-reason", "value": pkg.floating_reference_reason})
                if pkg.parent_package:
                    pkg_properties.append({"name": "agent-bom:parent-package", "value": pkg.parent_package})
                if pkg.scorecard_score is not None:
                    pkg_properties.append({"name": "agent-bom:scorecard-score", "value": str(pkg.scorecard_score)})
                if pkg.is_malicious:
                    # Surface the malicious flag so a MAL- package is
                    # distinguishable from an ordinary library component.
                    pkg_properties.append({"name": "agent-bom:is-malicious", "value": "true"})
                    if pkg.malicious_reason:
                        pkg_properties.append({"name": "agent-bom:malicious-reason", "value": pkg.malicious_reason})
                # --verify-integrity verdict. The namespaced properties give a
                # consumer an unambiguous boolean; the identity evidence below
                # says the same thing in the spec's own vocabulary.
                verdict = integrity_verdict(pkg)
                if verdict is not None:
                    if "integrity_verified" in verdict:
                        pkg_properties.append({"name": "agent-bom:integrity-verified", "value": str(verdict["integrity_verified"]).lower()})
                    if "provenance_attested" in verdict:
                        pkg_properties.append(
                            {"name": "agent-bom:provenance-attested", "value": str(verdict["provenance_attested"]).lower()}
                        )
                    if verdict.get("provenance_source"):
                        pkg_properties.append({"name": "agent-bom:provenance-source", "value": str(verdict["provenance_source"])})
                    if verdict.get("provenance_status"):
                        pkg_properties.append({"name": "agent-bom:provenance-status", "value": str(verdict["provenance_status"])})

                pkg_component: dict = {
                    "type": "library",
                    "bom-ref": pkg_ref,
                    "name": pkg.name,
                    "version": pkg.version,
                    "properties": pkg_properties,
                }
                # purl is the join key for downstream SBOM consumers: pass the
                # resolved purl through, else synthesize one from the known
                # ecosystem+name+version.
                purl = pkg.purl or synthesize_purl(pkg.name, pkg.version, pkg.ecosystem)
                if purl:
                    pkg_component["purl"] = purl
                if verdict is not None:
                    identities = _integrity_identity_evidence(pkg, verdict, purl)
                    if identities:
                        pkg_component["evidence"] = {"identity": identities}
                if pkg.license_expression or pkg.license:
                    lic_val = pkg.license_expression or pkg.license or ""
                    # CycloneDX 1.7: compound expressions (AND/OR/WITH) use
                    # "expression" at the licenses array level, not "license.id".
                    # Single SPDX IDs use "license.id".
                    if any(op in lic_val for op in (" AND ", " OR ", " WITH ")):
                        pkg_component["licenses"] = [{"expression": lic_val}]
                    else:
                        pkg_component["licenses"] = [{"license": {"id": lic_val}}]
                hashes = cyclonedx_hashes(pkg.checksums)
                if hashes:
                    pkg_component["hashes"] = hashes
                if pkg.supplier:
                    pkg_component["supplier"] = {"name": pkg.supplier}
                if pkg.author:
                    pkg_component["author"] = pkg.author
                if pkg.description:
                    pkg_component["description"] = pkg.description
                if pkg.copyright_text:
                    pkg_component["copyright"] = pkg.copyright_text
                ext_refs = []
                if pkg.homepage:
                    ext_refs.append({"type": "website", "url": pkg.homepage})
                if pkg.repository_url:
                    ext_refs.append({"type": "vcs", "url": pkg.repository_url})
                if pkg.download_url:
                    ext_refs.append({"type": "distribution", "url": pkg.download_url})
                if ext_refs:
                    pkg_component["externalReferences"] = ext_refs
                components.append(pkg_component)

            dependencies.append({"ref": server_ref, "dependsOn": server_deps})
        dependencies.append({"ref": agent_ref, "dependsOn": agent_deps})

    # ── ML BOM extensions: model provenance ──────────────────────────────
    for prov in report.model_provenance:
        comp, ref = _build_model_component(prov, comp_id)
        comp_id += 1
        components.append(comp)
        ml_component_refs.append(ref)

    # ── ML BOM extensions: model files ───────────────────────────────────
    for mf in report.model_files:
        comp, ref = _build_model_file_component(mf, comp_id)
        comp_id += 1
        components.append(comp)
        ml_component_refs.append(ref)

    # ── ML BOM extensions: dataset cards ─────────────────────────────────
    if report.dataset_cards and isinstance(report.dataset_cards, dict):
        for ds in report.dataset_cards.get("datasets", []):
            comp, ref = _build_dataset_component(ds, comp_id)
            comp_id += 1
            components.append(comp)
            ml_component_refs.append(ref)

    # ── ML BOM extensions: training pipelines ────────────────────────────
    if report.training_pipelines and isinstance(report.training_pipelines, dict):
        for run in report.training_pipelines.get("runs", []):
            comp, ref = _build_training_component(run, comp_id)
            comp_id += 1
            components.append(comp)
            ml_component_refs.append(ref)

    # Discovery paths overlap by design. Normalize the document-level arrays
    # once after all builders have contributed so uniqueness applies globally,
    # not only to package components.
    components = _merge_bom_ref_items(components)
    services = _merge_bom_ref_items(services)
    dependencies = _merge_dependencies(dependencies)
    vulnerabilities_cdx = [vulnerabilities_by_id[vuln_id] for vuln_id in sorted(vulnerabilities_by_id)]

    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.7",
        "serialNumber": f"urn:uuid:{report.scan_id}" if report.scan_id else f"urn:uuid:{uuid4()}",
        "version": 1,
        "metadata": {
            "timestamp": report.generated_at.isoformat(),
            "tools": {
                "components": [
                    {
                        "type": "application",
                        "name": "agent-bom",
                        "version": report.tool_version,
                        "description": "Security scanner for AI infrastructure — from agent to runtime",
                    }
                ]
            },
            "properties": [
                {"name": "agent-bom:total-agents", "value": str(report.total_agents)},
                {"name": "agent-bom:canonical-id-schema-version", "value": CANONICAL_ID_SCHEMA_VERSION},
                {"name": "agent-bom:total-mcp-servers", "value": str(report.total_servers)},
                {"name": "agent-bom:total-vulnerabilities", "value": str(report.total_vulnerabilities)},
                {"name": "agent-bom:ml-models", "value": str(len(report.model_provenance) + len(report.model_files))},
                {"name": "agent-bom:scan-outcome", "value": scan_run.outcome.value},
                {"name": "agent-bom:scan-issue-count", "value": str(len(scan_run.issues))},
            ],
        },
        "components": components,
        "dependencies": dependencies,
        # CDX 1.7 defines `formulation` as a top-level BOM array, not a metadata
        # field — placing it under metadata fails strict 1.7 schema validation.
        "formulation": [
            {
                "components": [
                    {
                        "type": "application",
                        "name": "agent-bom",
                        "version": __version__,
                    }
                ]
            }
        ],
    }

    if services:
        cdx["services"] = services

    if vulnerabilities_cdx:
        cdx["vulnerabilities"] = vulnerabilities_cdx

    # Compositions — declare assembly completeness for SBOM consumers
    if components:
        has_registry_resolved = any(
            isinstance(c, dict)
            and c.get("type") == "library"
            and any(
                isinstance(p, dict) and p.get("name") == "agent-bom:resolved-from-registry" and p.get("value") == "true"
                for p in c.get("properties", [])
            )
            for c in components
        )
        cdx["compositions"] = [
            {
                "aggregate": "incomplete" if has_registry_resolved or scan_run.outcome is not ScanOutcome.COMPLETE else "complete",
                "assemblies": [c["bom-ref"] for c in components if isinstance(c, dict) and "bom-ref" in c],
            }
        ]

    return cdx


def export_cyclonedx(report: AIBOMReport, output_path: str) -> None:
    """Export report as CycloneDX 1.7 JSON file."""
    cdx = to_cyclonedx(report)
    Path(output_path).write_text(json.dumps(cdx, indent=2))
