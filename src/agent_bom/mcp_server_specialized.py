"""Specialized MCP tool registrations for agent-bom."""

from __future__ import annotations

from typing import Annotated, Any, Awaitable, Callable

from pydantic import Field

from agent_bom.mcp_errors import CODE_INTERNAL_UNEXPECTED, mcp_error_json
from agent_bom.security import sanitize_error  # noqa: F401 — kept for downstream importers


def register_specialized_ai_tools(
    mcp: Any,
    *,
    read_only: Any,
    write_action: Any,
    execute_tool_async: Callable[..., Awaitable[Any]],
    safe_path: Callable[[str], Any],
    truncate_response: Callable[[str], str],
) -> None:
    """Register specialized AI, model, and external-ingest MCP tools."""
    from agent_bom.mcp_tools.cloud import gpu_infra_scan_impl, registry_sweep_scan_impl, vector_db_scan_impl
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

    @mcp.tool(annotations=read_only, title="Registry Image Sweep")
    async def registry_sweep_scan(
        provider: Annotated[
            str,
            Field(description="Container registry to sweep: 'ecr' (AWS), 'acr' (Azure), or 'gar' (GCP Artifact Registry)."),
        ],
        region: Annotated[str | None, Field(description="AWS region (ecr only).")] = None,
        profile: Annotated[str | None, Field(description="AWS credential profile (ecr only).")] = None,
        registry: Annotated[str | None, Field(description="ACR login server, e.g. 'myacr.azurecr.io' (acr only).")] = None,
        project: Annotated[str | None, Field(description="GCP project id (gar only).")] = None,
        location: Annotated[str | None, Field(description="GAR location/multi-region, e.g. 'us' (gar only).")] = None,
        max_images: Annotated[
            int | None,
            Field(description="Cap on images scanned (default: AGENT_BOM_REGISTRY_MAX_IMAGES or 50)."),
        ] = None,
    ) -> str:
        """Sweep an entire cloud container registry: enumerate every repo+tag, dedupe by digest, cap, and scan each (read-only)."""
        return await execute_tool_async(
            "registry_sweep_scan",
            registry_sweep_scan_impl,
            provider=provider,
            region=region,
            profile=profile,
            registry=registry,
            project=project,
            location=location,
            max_images=max_images,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=read_only, title="Dataset Card Scan")
    async def dataset_card_scan(
        directory: Annotated[
            str,
            Field(description="Directory path to scan for dataset cards (dataset_info.json, README.md frontmatter, .dvc files)."),
        ],
        scan_pii: Annotated[
            bool,
            Field(
                description=(
                    "Also scan CSV/JSON/JSONL file contents for PII/PHI (emails, SSNs, credit cards, medical data). Default false."
                )
            ),
        ] = False,
    ) -> str:
        """Scan a directory for ML dataset card metadata, provenance, and optionally PII/PHI content."""
        return await execute_tool_async(
            "dataset_card_scan",
            dataset_card_scan_impl,
            directory=str(safe_path(directory)),
            scan_pii=scan_pii,
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
        """Scan prompt template files for prompt-injection and unsafe-interpolation risks.

        Walks the given directory for prompt assets (``.prompt`` files,
        ``system_prompt.*``, and ``prompts/`` directories), then statically
        inspects each template for injection-prone patterns and unsafe variable
        interpolation (untrusted input concatenated into instructions, missing
        delimiters, tool/role-confusion phrasing).

        Args:
            directory: Directory path to scan for prompt template files.

        Returns:
            JSON with the scanned files, per-file findings (rule id, severity,
            line, message), and a summary count by severity.

        Use this before shipping or registering agent prompts to catch
        injection exposure that package and CVE scans do not cover.
        """
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
        """Evaluate package licenses against an SPDX compliance policy.

        Takes packages (either a prior ``scan`` result JSON or an explicit array
        of ``{name, version, ecosystem, license}`` objects) and classifies each
        license as allowed, warn, or blocked. Normalizes 2,500+ SPDX IDs
        (including deprecated identifiers) and flags network-copyleft licenses
        (AGPL/SSPL/BUSL and similar).

        Args:
            scan_json: JSON of a previous scan result, or a JSON array of
                package objects with license metadata.
            policy_json: Optional JSON policy with ``license_block`` /
                ``license_warn`` glob lists. Falls back to the built-in policy
                (block strong/network copyleft, warn weak copyleft) when empty.

        Returns:
            JSON with per-package license verdicts, the matched policy rule,
            and counts of blocked / warned / allowed packages.

        Call this in release or procurement gates to enforce license policy on
        an agent's dependency set without running a full scan.
        """
        return await execute_tool_async(
            "license_compliance_scan",
            license_compliance_scan_impl,
            scan_json=scan_json,
            policy_json=policy_json,
            _truncate_response=truncate_response,
        )

    @mcp.tool(annotations=write_action, title="Ingest External Scanner Report")
    async def ingest_external_scan(
        scan_json: Annotated[
            str,
            Field(
                description="JSON string from Trivy, Grype, or Syft scan output",
            ),
        ],
        parse_only: Annotated[
            bool,
            Field(
                description=(
                    "When true, parse locally only. When false, bulk-ingest to the control plane "
                    "when AGENT_BOM_API_URL and credentials are configured."
                ),
            ),
        ] = False,
        source: Annotated[str, Field(description="Source label stored on ingested findings.")] = "external_scan",
        reconcile_absent: Annotated[
            bool,
            Field(description="When pushing, mark findings absent from this batch as resolved."),
        ] = False,
    ) -> str:
        """Ingest Trivy, Grype, or Syft JSON scan output and optionally push findings to the control plane.

        This tool mutates the control plane when ``parse_only`` is false: it bulk-ingests
        findings and, with ``reconcile_absent``, resolves open findings absent from the batch.
        That write path is gated as a destructive action requiring the ``findings:write`` scope.
        ``parse_only`` requests parse locally only and stay a read.
        """

        async def _impl(**_operator_context: object) -> str:
            import json as _json
            import os

            from agent_bom.client import AgentBomClient
            from agent_bom.findings_push import packages_to_bulk_findings
            from agent_bom.parsers.external_scanners import detect_and_parse

            try:
                data = _json.loads(scan_json)
                packages = detect_and_parse(data)
                findings = packages_to_bulk_findings(packages, source=source)
                result: dict[str, object] = {
                    "packages": len(packages),
                    "findings": len(findings),
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
                if not parse_only:
                    base_url = os.getenv("AGENT_BOM_API_URL")
                    api_key = os.getenv("AGENT_BOM_API_KEY")
                    bearer_token = os.getenv("AGENT_BOM_API_TOKEN")
                    if base_url and (api_key or bearer_token):
                        client = AgentBomClient(
                            base_url=base_url,
                            api_key=api_key,
                            bearer_token=bearer_token,
                            tenant_id=os.getenv("AGENT_BOM_TENANT_ID"),
                        )
                        try:
                            result["control_plane"] = client.ingest_findings(
                                findings,
                                source=source,
                                reconcile_absent=reconcile_absent,
                            )
                        finally:
                            client.close()
                    elif findings:
                        result["control_plane"] = {
                            "skipped": True,
                            "reason": "Set AGENT_BOM_API_URL and AGENT_BOM_API_KEY or AGENT_BOM_API_TOKEN to bulk-ingest findings",
                        }
                return _json.dumps(result)
            except Exception as exc:  # noqa: BLE001
                return truncate_response(mcp_error_json(CODE_INTERNAL_UNEXPECTED, exc))

        return await execute_tool_async(
            "ingest_external_scan",
            _impl,
            destructive=not parse_only,
            required_scope="findings:write",
        )
