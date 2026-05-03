"""Specialized scan tools — dataset_card_scan, training_pipeline_scan,
browser_extension_scan, model_provenance_scan, prompt_scan, model_file_scan implementations.
"""

from __future__ import annotations

import json
import logging

from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


async def dataset_card_scan_impl(
    *,
    directory: str,
    scan_pii: bool = False,
    _truncate_response,
) -> str:
    """Implementation of the dataset_card_scan tool."""
    try:
        from agent_bom.security import validate_path

        path = validate_path(directory, must_exist=True, restrict_to_home=True)
        from agent_bom.parsers.dataset_cards import scan_dataset_directory

        result = scan_dataset_directory(path)
        output = result.to_dict()

        if scan_pii:
            from agent_bom.parsers.dataset_pii_scanner import scan_directory_for_pii

            pii_result = scan_directory_for_pii(path)
            output["pii_scan"] = pii_result.to_dict()

        return _truncate_response(json.dumps(output, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def training_pipeline_scan_impl(
    *,
    directory: str,
    _truncate_response,
) -> str:
    """Implementation of the training_pipeline_scan tool."""
    try:
        from agent_bom.security import validate_path

        path = validate_path(directory, must_exist=True, restrict_to_home=True)
        from agent_bom.parsers.training_pipeline import scan_training_directory

        result = scan_training_directory(path)
        return _truncate_response(json.dumps(result.to_dict(), indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def browser_extension_scan_impl(
    *,
    include_low_risk: bool = False,
    _truncate_response,
) -> str:
    """Implementation of the browser_extension_scan tool."""
    try:
        from agent_bom.parsers.browser_extensions import discover_browser_extensions

        exts = discover_browser_extensions(include_low_risk=include_low_risk)
        return _truncate_response(
            json.dumps(
                {
                    "extensions": [e.to_dict() for e in exts],
                    "total": len(exts),
                    "critical_count": sum(1 for e in exts if e.risk_level == "critical"),
                    "high_count": sum(1 for e in exts if e.risk_level == "high"),
                },
                indent=2,
                default=str,
            )
        )
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def model_provenance_scan_impl(
    *,
    model_id: str,
    source: str = "huggingface",
    _truncate_response,
) -> str:
    """Implementation of the model_provenance_scan tool."""
    try:
        if source.lower() == "ollama":
            from agent_bom.cloud.model_provenance import check_ollama_model

            result = check_ollama_model(model_id)
        else:
            from agent_bom.cloud.model_provenance import check_hf_model

            result = check_hf_model(model_id)
        return _truncate_response(json.dumps(result.to_dict(), indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def prompt_scan_impl(
    *,
    directory: str,
    _truncate_response,
) -> str:
    """Implementation of the prompt_scan tool."""
    try:
        from agent_bom.security import validate_path

        path = validate_path(directory, must_exist=True, restrict_to_home=True)
        from agent_bom.parsers.prompt_scanner import scan_prompt_files

        result = scan_prompt_files(root=path)
        return _truncate_response(
            json.dumps(
                {
                    "files_scanned": result.files_scanned,
                    "total_prompt_files": len(result.prompt_files),
                    "prompt_files": result.prompt_files[:50],
                    "passed": result.passed,
                    "total_findings": len(result.findings),
                    "findings_shown": min(len(result.findings), 100),
                    "findings": [
                        {
                            "file": f.source_file,
                            "line": f.line_number,
                            "severity": f.severity,
                            "rule": f.category,
                            "message": f.detail,
                        }
                        for f in result.findings[:100]
                    ],
                },
                indent=2,
                default=str,
            )
        )
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def model_file_scan_impl(
    *,
    directory: str,
    _truncate_response,
) -> str:
    """Implementation of the model_file_scan tool."""
    try:
        from agent_bom.security import validate_path

        path = validate_path(directory, must_exist=True, restrict_to_home=True)
        from agent_bom.model_files import scan_model_files, scan_model_manifests

        model_files, warnings = scan_model_files(str(path))
        model_manifests, manifest_warnings = scan_model_manifests(str(path))
        return _truncate_response(
            json.dumps(
                {
                    "model_files": model_files,
                    "model_manifests": model_manifests,
                    "total": len(model_files),
                    "manifest_total": len(model_manifests),
                    "unsafe_count": sum(
                        1 for r in model_files if any(f.get("severity") in ("HIGH", "CRITICAL") for f in r.get("security_flags", []))
                    ),
                    "warnings": warnings + manifest_warnings,
                },
                indent=2,
                default=str,
            )
        )
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


async def ai_inventory_scan_impl(
    *,
    directory: str,
    _truncate_response,
) -> str:
    """Implementation of the ai_inventory_scan tool."""
    try:
        from agent_bom.security import validate_path

        path = validate_path(directory, must_exist=True, restrict_to_home=True)
        from agent_bom.ai_components import scan_source

        report = scan_source(str(path))
        return _truncate_response(
            json.dumps(
                {
                    "total_components": report.total,
                    "files_scanned": report.files_scanned,
                    "shadow_ai_count": len(report.shadow_ai),
                    "deprecated_models_count": len(report.deprecated_models),
                    "api_keys_count": len(report.api_keys),
                    "unique_sdks": sorted(report.unique_sdks),
                    "unique_models": sorted(report.unique_models),
                    "components": [
                        {
                            "type": c.component_type.value,
                            "name": c.name,
                            "language": c.language,
                            "file": c.file_path,
                            "line": c.line_number,
                            "severity": c.severity.value,
                            "is_shadow": c.is_shadow,
                            "description": c.description,
                        }
                        for c in report.components
                    ],
                    "warnings": report.warnings,
                },
                indent=2,
                default=str,
            )
        )
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})
