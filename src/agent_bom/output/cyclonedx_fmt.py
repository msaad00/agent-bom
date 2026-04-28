"""CycloneDX 1.6 SBOM output format with ML BOM extensions.

Supports native CycloneDX 1.6 machine learning extensions:
- ``modelCard`` — model provenance, training parameters, performance metrics
- ``data`` — dataset provenance, governance, classification
- Component type ``machine-learning-model`` for ML model artifacts
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from uuid import uuid4

from agent_bom import __version__
from agent_bom.models import AIBOMReport
from agent_bom.security import sanitize_launch_command


def _sanitize_bom_ref(raw: str) -> str:
    """Sanitize a CycloneDX bom-ref to contain only valid characters.

    CycloneDX 1.6 bom-ref should match ``^[a-zA-Z0-9._-]+$``.
    Replace invalid characters (``@``, ``/``, spaces, etc.) with ``-``.
    """
    return re.sub(r"[^a-zA-Z0-9._-]", "-", raw)


# ── ML BOM extension builders ────────────────────────────────────────────────


def _build_model_card(provenance: dict) -> dict:
    """Build a CycloneDX 1.6 modelCard from a model provenance dict.

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
        considerations["technicalLimitations"] = [{"description": f"Risk flag: {flag}"} for flag in risk_flags]
    safe_format = provenance.get("is_safe_format", True)
    if not safe_format:
        considerations.setdefault("technicalLimitations", []).append(
            {"description": "Model uses unsafe serialization format (pickle/pt) — arbitrary code execution on load"}
        )
    if considerations:
        card["considerations"] = considerations

    return card


def _build_model_component(provenance: dict, comp_id: int) -> tuple[dict, str]:
    """Build a CycloneDX 1.6 component of type machine-learning-model.

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

    # Model card (CycloneDX 1.6 native)
    model_card = _build_model_card(provenance)
    if model_card:
        component["modelCard"] = model_card

    # Security flags as properties
    for flag in provenance.get("risk_flags", []):
        component["properties"].append({"name": "agent-bom:risk-flag", "value": flag})

    return component, ref


def _build_model_file_component(model_file: dict, comp_id: int) -> tuple[dict, str]:
    """Build a CycloneDX 1.6 component from a local model file scan result."""
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
            {"description": flag.get("description", "")}
        )

    return component, ref


def _build_dataset_component(dataset: dict, comp_id: int) -> tuple[dict, str]:
    """Build a CycloneDX 1.6 component with data classification for datasets.

    Uses the CycloneDX 1.6 ``data`` extension for dataset governance:
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

    # CycloneDX 1.6 data extension — governance and classification
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


def _build_training_component(run: dict, comp_id: int) -> tuple[dict, str]:
    """Build a CycloneDX 1.6 component for a training pipeline run.

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
        model_card.setdefault("considerations", {}).setdefault("technicalLimitations", []).append(
            {"description": flag.get("description", "")}
        )

    if model_card:
        component["modelCard"] = model_card

    return component, ref


# ── Main export ──────────────────────────────────────────────────────────────


def to_cyclonedx(report: AIBOMReport) -> dict:
    """Build CycloneDX 1.6 dict from report with ML BOM extensions.

    Emits native CycloneDX 1.6 ``machine-learning-model`` components with
    ``modelCard`` for model provenance, ``data`` components for datasets,
    and training run metadata via ``quantitativeAnalysis``.
    """
    components = []
    vulnerabilities_cdx = []
    dependencies = []

    comp_id = 0
    bom_ref_map = {}
    ml_component_refs: list[str] = []  # Track ML components for top-level deps

    for agent in report.agents:
        agent_ref = _sanitize_bom_ref(f"agent-{agent.stable_id}")
        agent_deps = []

        components.append(
            {
                "type": "application",
                "bom-ref": agent_ref,
                "name": agent.name,
                "version": agent.version or "unknown",
                "description": f"AI Agent ({agent.agent_type.value})",
                "properties": [
                    {"name": "agent-bom:type", "value": "ai-agent"},
                    {"name": "agent-bom:config-path", "value": agent.config_path},
                    {"name": "agent-bom:status", "value": agent.status.value},
                ],
            }
        )

        for server in agent.mcp_servers:
            server_ref = _sanitize_bom_ref(f"mcp-server-{server.stable_id}")
            server_deps = []

            server_props = [
                {"name": "agent-bom:type", "value": "mcp-server"},
                {"name": "agent-bom:command", "value": sanitize_launch_command(server.command, server.args)},
                {"name": "agent-bom:transport", "value": server.transport.value},
            ]
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
            # Add MCP tool capabilities as services (CycloneDX 1.6 services array)
            if server.tools:
                server_component["services"] = [
                    {
                        "name": tool.name,
                        "description": tool.description or "",
                    }
                    for tool in server.tools
                ]
            components.append(server_component)
            agent_deps.append(server_ref)

            for pkg in server.packages:
                pkg_ref = _sanitize_bom_ref(f"pkg-{pkg.stable_id}")

                pkg_properties = [
                    {"name": "agent-bom:ecosystem", "value": pkg.ecosystem},
                    {"name": "agent-bom:is-direct", "value": str(pkg.is_direct).lower()},
                    {"name": "agent-bom:dependency-depth", "value": str(pkg.dependency_depth)},
                    {"name": "agent-bom:dependency-scope", "value": pkg.dependency_scope},
                    {"name": "agent-bom:reachability-evidence", "value": pkg.reachability_evidence},
                    {"name": "agent-bom:resolved-from-registry", "value": str(pkg.resolved_from_registry).lower()},
                    {"name": "agent-bom:version-source", "value": pkg.version_source},
                    {"name": "agent-bom:floating-reference", "value": str(pkg.floating_reference).lower()},
                ]
                if pkg.floating_reference_reason:
                    pkg_properties.append({"name": "agent-bom:floating-reference-reason", "value": pkg.floating_reference_reason})
                if pkg.parent_package:
                    pkg_properties.append({"name": "agent-bom:parent-package", "value": pkg.parent_package})
                if pkg.scorecard_score is not None:
                    pkg_properties.append({"name": "agent-bom:scorecard-score", "value": str(pkg.scorecard_score)})

                pkg_component: dict = {
                    "type": "library",
                    "bom-ref": pkg_ref,
                    "name": pkg.name,
                    "version": pkg.version,
                    "purl": pkg.purl,
                    "properties": pkg_properties,
                }
                if pkg.license_expression or pkg.license:
                    lic_val = pkg.license_expression or pkg.license or ""
                    # CycloneDX 1.6: compound expressions (AND/OR/WITH) use
                    # "expression" at the licenses array level, not "license.id".
                    # Single SPDX IDs use "license.id".
                    if any(op in lic_val for op in (" AND ", " OR ", " WITH ")):
                        pkg_component["licenses"] = [{"expression": lic_val}]
                    else:
                        pkg_component["licenses"] = [{"license": {"id": lic_val}}]
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
                server_deps.append(pkg_ref)
                bom_ref_map[f"{pkg.ecosystem}:{pkg.name}@{pkg.version}"] = pkg_ref

                for vuln in pkg.vulnerabilities:
                    ratings: list[dict[str, object]] = []
                    if vuln.cvss_score:
                        ratings.append(
                            {
                                "score": vuln.cvss_score,
                                "severity": vuln.severity.value,
                                "method": "CVSSv3",
                            }
                        )
                    else:
                        ratings.append(
                            {
                                "severity": vuln.severity.value,
                            }
                        )
                    vuln_entry: dict[str, object] = {
                        "id": vuln.id,
                        "description": vuln.summary or f"See {vuln.id} for details",
                        "source": {"name": "OSV", "url": f"https://osv.dev/vulnerability/{vuln.id}"},
                        "ratings": ratings,
                        "affects": [{"ref": pkg_ref}],
                    }
                    if vuln.fixed_version:
                        vuln_entry["recommendation"] = f"Upgrade to {vuln.fixed_version}"
                    if vuln.vex_status:
                        _cdx_state_map = {
                            "affected": "exploitable",
                            "not_affected": "not_affected",
                            "fixed": "resolved",
                            "under_investigation": "in_triage",
                        }
                        analysis_dict: dict[str, str] = {
                            "state": _cdx_state_map.get(vuln.vex_status, "in_triage"),
                        }
                        if vuln.vex_justification:
                            analysis_dict["justification"] = vuln.vex_justification
                        vuln_entry["analysis"] = analysis_dict
                    vulnerabilities_cdx.append(vuln_entry)

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

    cdx = {
        "bomFormat": "CycloneDX",
        "specVersion": "1.6",
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
                {"name": "agent-bom:total-mcp-servers", "value": str(report.total_servers)},
                {"name": "agent-bom:total-vulnerabilities", "value": str(report.total_vulnerabilities)},
                {"name": "agent-bom:ml-models", "value": str(len(report.model_provenance) + len(report.model_files))},
            ],
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
        },
        "components": components,
        "dependencies": dependencies,
    }

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
                "aggregate": "incomplete" if has_registry_resolved else "complete",
                "assemblies": [c["bom-ref"] for c in components if isinstance(c, dict) and "bom-ref" in c],
            }
        ]

    return cdx


def export_cyclonedx(report: AIBOMReport, output_path: str) -> None:
    """Export report as CycloneDX 1.6 JSON file."""
    cdx = to_cyclonedx(report)
    Path(output_path).write_text(json.dumps(cdx, indent=2))
