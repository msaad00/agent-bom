"""Specialized MCP tool registrations for agent-bom."""

from __future__ import annotations

from typing import Annotated, Any, Awaitable, Callable

from pydantic import Field

from agent_bom.security import sanitize_error


def register_specialized_ai_tools(
    mcp: Any,
    *,
    read_only: Any,
    execute_tool_async: Callable[..., Awaitable[Any]],
    safe_path: Callable[[str], Any],
    truncate_response: Callable[[str], str],
) -> None:
    """Register specialized AI, model, and external-ingest MCP tools."""
    from agent_bom.mcp_tools.cloud import gpu_infra_scan_impl, vector_db_scan_impl
    from agent_bom.mcp_tools.compliance import aisvs_benchmark_impl, license_compliance_scan_impl
    from agent_bom.mcp_tools.specialized import (
        ai_inventory_scan_impl,
        browser_extension_scan_impl,
        dataset_card_scan_impl,
        model_file_scan_impl,
        model_provenance_scan_impl,
        prompt_scan_impl,
        training_pipeline_scan_impl,
    )

    @mcp.tool(annotations=read_only, title="Vector DB Scan")
    async def vector_db_scan(
        hosts: Annotated[
            str | None,
            Field(description="Comma-separated hosts to probe (default: 127.0.0.1). Example: '127.0.0.1,10.0.0.5'."),
        ] = None,
    ) -> str:
        """Scan for running vector databases and assess their security posture."""
        return await execute_tool_async(
            "vector_db_scan",
            vector_db_scan_impl,
            hosts=hosts,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="AISVS Benchmark")
    async def aisvs_benchmark(
        checks: Annotated[
            str | None,
            Field(description=("Comma-separated AISVS check IDs to run (e.g. 'AI-4.1,AI-6.1'). Omit to run all 9 checks.")),
        ] = None,
    ) -> str:
        """Run AISVS v1.0 (AI Security Verification Standard) compliance checks."""
        return await execute_tool_async(
            "aisvs_benchmark",
            aisvs_benchmark_impl,
            checks=checks,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="GPU Infrastructure Scan")
    async def gpu_infra_scan(
        k8s_context: Annotated[
            str | None,
            Field(description="kubectl context to use for K8s GPU node discovery. Omit for current context."),
        ] = None,
        probe_dcgm: Annotated[
            bool,
            Field(description="Whether to probe DCGM exporter endpoints on port 9400 (unauthenticated metrics leak detection)."),
        ] = True,
    ) -> str:
        """Discover GPU/AI compute infrastructure: containers, K8s nodes, and DCGM endpoints."""
        return await execute_tool_async(
            "gpu_infra_scan",
            gpu_infra_scan_impl,
            k8s_context=k8s_context,
            probe_dcgm=probe_dcgm,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Dataset Card Scan")
    async def dataset_card_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for dataset cards (dataset_info.json, README.md frontmatter, .dvc files)."),
        ],
    ) -> str:
        """Scan a directory for ML dataset card metadata and provenance."""
        return await execute_tool_async(
            "dataset_card_scan",
            dataset_card_scan_impl,
            directory=str(safe_path(directory)),
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Training Pipeline Scan")
    async def training_pipeline_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for training pipeline artifacts (MLflow, Kubeflow, W&B)."),
        ],
    ) -> str:
        """Scan a directory for ML training pipeline lineage and provenance."""
        return await execute_tool_async(
            "training_pipeline_scan",
            training_pipeline_scan_impl,
            directory=str(safe_path(directory)),
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Browser Extension Scan")
    async def browser_extension_scan(
        include_low_risk: Annotated[
            bool,
            Field(description="Include low-risk extensions in results (default: only medium+ risk)."),
        ] = False,
    ) -> str:
        """Scan installed browser extensions for dangerous permissions."""
        return await execute_tool_async(
            "browser_extension_scan",
            browser_extension_scan_impl,
            include_low_risk=include_low_risk,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Model Provenance Scan")
    async def model_provenance_scan(
        model_id: Annotated[
            str,
            Field(description="HuggingFace model ID (e.g. 'meta-llama/Llama-3-8B') or Ollama model name (e.g. 'llama3')."),
        ],
        source: Annotated[
            str,
            Field(description="Model source: 'huggingface' or 'ollama' (default: huggingface)."),
        ] = "huggingface",
    ) -> str:
        """Check ML model provenance and supply chain metadata."""
        return await execute_tool_async(
            "model_provenance_scan",
            model_provenance_scan_impl,
            model_id=model_id,
            source=source,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Prompt Template Scan")
    async def prompt_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for prompt template files (.prompt, system_prompt.*, prompts/ directories)."),
        ],
    ) -> str:
        """Scan prompt template files for injection risks and security issues."""
        return await execute_tool_async(
            "prompt_scan",
            prompt_scan_impl,
            directory=str(safe_path(directory)),
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Model File Scan")
    async def model_file_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for ML model files (.gguf, .safetensors, .onnx, .pt, .pkl, .h5, etc.)."),
        ],
    ) -> str:
        """Scan a directory for ML model files and assess serialization risks."""
        return await execute_tool_async(
            "model_file_scan",
            model_file_scan_impl,
            directory=str(safe_path(directory)),
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="AI Inventory Scan")
    async def ai_inventory_scan(
        directory: Annotated[
            str,
            Field(description="Directory to scan for AI SDK imports, model refs, API keys, shadow AI (Python/JS/TS/Java/Go/Rust/Ruby)."),
        ],
    ) -> str:
        """Scan source code for AI component usage patterns."""
        return await execute_tool_async(
            "ai_inventory_scan",
            ai_inventory_scan_impl,
            directory=str(safe_path(directory)),
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="License Compliance Scan")
    async def license_compliance_scan(
        scan_json: Annotated[
            str,
            Field(
                description=(
                    "JSON string of a previous scan result (from the 'scan' tool) "
                    "containing agents with packages. Or a JSON array of "
                    '{"name": "pkg", "version": "1.0", "ecosystem": "npm", "license": "MIT"} objects.'
                ),
            ),
        ],
        policy_json: Annotated[
            str,
            Field(
                default="",
                description=(
                    'Optional JSON policy: {"license_block": ["GPL-*"], "license_warn": ["LGPL-*"]}. '
                    "Uses default policy (block GPL/AGPL/SSPL/BUSL/EUPL/OSL, warn LGPL/MPL/EPL/CDDL) if empty."
                ),
            ),
        ] = "",
    ) -> str:
        """Evaluate package licenses against compliance policy."""
        return await execute_tool_async(
            "license_compliance_scan",
            license_compliance_scan_impl,
            scan_json=scan_json,
            policy_json=policy_json,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Ingest External Scanner Report")
    async def ingest_external_scan(
        scan_json: Annotated[
            str,
            Field(
                description="JSON string from Trivy, Grype, or Syft scan output",
            ),
        ],
    ) -> str:
        """Ingest Trivy, Grype, or Syft JSON scan output and return packages with blast radius analysis."""

        async def _impl() -> str:
            import json as _json

            from agent_bom.parsers.external_scanners import detect_and_parse

            try:
                data = _json.loads(scan_json)
                packages = detect_and_parse(data)
                return _json.dumps(
                    {
                        "packages": len(packages),
                        "ingested": [
                            {
                                "name": p.name,
                                "version": p.version,
                                "ecosystem": p.ecosystem,
                                "vulnerabilities": len(p.vulnerabilities),
                            }
                            for p in packages[:50]
                        ],
                    }
                )
            except Exception as exc:  # noqa: BLE001
                return truncate_response(_json.dumps({"error": sanitize_error(exc)}))

        return await execute_tool_async("ingest_external_scan", _impl)
