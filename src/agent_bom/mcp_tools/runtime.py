"""Runtime tools — runtime_correlate, verify, where, inventory, skill_trust implementations."""

from __future__ import annotations

import json
import logging
from pathlib import Path

from agent_bom.config import MCP_MAX_FILE_SIZE as _MAX_FILE_SIZE
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


async def runtime_correlate_impl(
    *,
    config_path: str = "auto",
    audit_log: str = "",
    otel_trace: str = "",
    _safe_path,
    _run_scan_pipeline,
    _truncate_response,
) -> str:
    """Implementation of the runtime_correlate tool."""
    try:
        # Normalize "auto" -> None so _run_scan_pipeline uses default discovery
        effective_config = None if config_path == "auto" else config_path
        agents, blast_radii, _warnings, _srcs = await _run_scan_pipeline(effective_config)
        result: dict = {
            "scan_summary": {
                "agents": len(agents) if agents else 0,
                "servers": sum(len(a.mcp_servers) for a in agents) if agents else 0,
                "vulnerabilities": len(blast_radii),
            },
        }

        if audit_log:
            # Validate audit_log path to prevent directory traversal
            safe_audit = _safe_path(audit_log)
            from agent_bom.runtime_correlation import correlate as _correlate

            corr = _correlate(blast_radii, audit_log_path=str(safe_audit))
            result["correlation"] = corr.to_dict()
        else:
            result["correlation"] = {
                "note": "No audit log provided. Run 'agent-bom proxy --log audit.jsonl' to capture tool calls, then pass the log path.",
                "vulnerable_tools": len({t.name for br in blast_radii for t in br.exposed_tools}) if blast_radii else 0,
            }

        # ML API provenance via OTel trace
        if otel_trace:
            import json as _json

            from agent_bom.otel_ingest import flag_deprecated_models, parse_ml_api_spans

            safe_trace = _safe_path(otel_trace)
            try:
                from agent_bom.otel_ingest import _MAX_TRACE_FILE_BYTES

                file_size = safe_trace.stat().st_size
                if file_size > _MAX_TRACE_FILE_BYTES:
                    result["ml_api_calls"] = []
                    result["ml_api_error"] = (
                        f"OTel trace file too large ({file_size / 1024 / 1024:.1f} MB, max {_MAX_TRACE_FILE_BYTES // 1024 // 1024} MB)"
                    )
                    return _truncate_response(json.dumps(result, indent=2, default=str))
                trace_data = _json.loads(safe_trace.read_text())
                ml_calls = parse_ml_api_spans(trace_data)
                flagged = flag_deprecated_models(ml_calls)
                result["ml_api_calls"] = [
                    {
                        "provider": c.provider,
                        "model": c.model_name,
                        "model_version": c.model_version,
                        "endpoint": c.endpoint,
                        "input_tokens": c.input_tokens,
                        "output_tokens": c.output_tokens,
                        "duration_ms": c.duration_ms,
                        "status": c.status,
                        "trace_id": c.trace_id,
                    }
                    for c in ml_calls
                ]
                result["ml_api_flagged"] = [
                    {
                        "model": f.call.model_name,
                        "provider": f.call.provider,
                        "severity": f.severity,
                        "reason": f.reason,
                        "advisory": f.advisory,
                    }
                    for f in flagged
                ]
                result["ml_api_summary"] = {
                    "total_calls": len(ml_calls),
                    "flagged": len(flagged),
                    "providers": list({c.provider for c in ml_calls}),
                    "models": list({c.model_name for c in ml_calls if c.model_name}),
                    "total_input_tokens": sum(c.input_tokens for c in ml_calls),
                    "total_output_tokens": sum(c.output_tokens for c in ml_calls),
                }
            except Exception as trace_exc:
                result["ml_api_calls"] = []
                result["ml_api_error"] = f"Failed to parse OTel trace: {sanitize_error(trace_exc)}"
        else:
            result["ml_api_calls"] = []
            result["ml_api_note"] = "Pass otel_trace path to extract ML API provenance from OTel spans."

        return _truncate_response(json.dumps(result, indent=2, default=str))
    except Exception as exc:
        logger.exception("Runtime correlation failed")
        return json.dumps({"error": f"Correlation failed: {sanitize_error(exc)}"})


async def verify_impl(
    *,
    package: str,
    ecosystem: str = "npm",
    _validate_ecosystem,
    _truncate_response,
) -> str:
    """Implementation of the verify tool."""
    try:
        from agent_bom.http_client import create_client
        from agent_bom.integrity import (
            check_package_provenance,
            verify_package_integrity,
        )
        from agent_bom.models import Package as Pkg

        spec = package.strip()
        try:
            eco = _validate_ecosystem(ecosystem)
        except ValueError as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

        # Parse name@version or name==version
        if eco == "pypi" and "==" in spec:
            name, version = spec.split("==", 1)
        elif "@" in spec and not spec.startswith("@"):
            name, version = spec.rsplit("@", 1)
        elif spec.startswith("@") and spec.count("@") > 1:
            last_at = spec.rindex("@")
            name, version = spec[:last_at], spec[last_at + 1 :]
        else:
            name, version = spec, "latest"

        pkg = Pkg(name=name, version=version, ecosystem=eco)

        async with create_client(timeout=15.0) as client:
            integrity = await verify_package_integrity(pkg, client)
            provenance = await check_package_provenance(pkg, client)

        result = {
            "package": name,
            "version": version,
            "ecosystem": eco,
            "integrity": integrity.to_dict() if integrity and hasattr(integrity, "to_dict") else integrity,
            "provenance": provenance.to_dict() if provenance and hasattr(provenance, "to_dict") else provenance,
        }
        return _truncate_response(json.dumps(result, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


def where_impl(
    *,
    _truncate_response,
) -> str:
    """Implementation of the where tool."""
    try:
        import platform

        from agent_bom.discovery import CONFIG_LOCATIONS

        current_os = platform.system()
        clients = []
        for agent_type, platforms in CONFIG_LOCATIONS.items():
            paths = platforms.get(current_os, [])
            entries = []
            for p in paths:
                try:
                    expanded = Path(p).expanduser()
                    entries.append(
                        {
                            "path": str(expanded),
                            "exists": expanded.exists(),
                        }
                    )
                except Exception:
                    entries.append({"path": p, "exists": False, "error": "path expansion failed"})
            clients.append(
                {
                    "client": agent_type.value,
                    "platform": current_os,
                    "config_paths": entries,
                }
            )

        return _truncate_response(json.dumps({"clients": clients, "platform": current_os}, indent=2))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


def inventory_impl(
    *,
    config_path: str | None = None,
    _truncate_response,
) -> str:
    """Implementation of the inventory tool."""
    try:
        from agent_bom.discovery import discover_all
        from agent_bom.parsers import extract_packages

        agents = discover_all(project_dir=config_path)
        if not agents:
            return json.dumps({"status": "no_agents_found", "agents": []})

        for agent in agents:
            for server in agent.mcp_servers:
                if not server.packages:
                    server.packages = extract_packages(server)

        result = []
        for agent in agents:
            servers = []
            for s in agent.mcp_servers:
                servers.append(
                    {
                        "name": s.name,
                        "command": s.command,
                        "transport": s.transport.value,
                        "packages": [{"name": p.name, "version": p.version, "ecosystem": p.ecosystem} for p in s.packages],
                    }
                )
            result.append(
                {
                    "name": agent.name,
                    "agent_type": agent.agent_type.value,
                    "config_path": agent.config_path,
                    "servers": servers,
                }
            )
        return _truncate_response(json.dumps({"agents": result, "total_agents": len(result)}, indent=2))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


def skill_trust_impl(
    *,
    skill_path: str,
    _safe_path,
    _truncate_response,
) -> str:
    """Implementation of the skill_trust tool."""
    try:
        from agent_bom.parsers.skill_audit import audit_skill_result
        from agent_bom.parsers.skills import parse_skill_file
        from agent_bom.parsers.trust_assessment import assess_trust

        try:
            p = _safe_path(skill_path)
        except ValueError as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})
        if not p.is_file():
            return json.dumps({"error": f"File not found: {skill_path}"})
        if p.stat().st_size > _MAX_FILE_SIZE:
            return json.dumps({"error": f"File too large ({p.stat().st_size} bytes, max {_MAX_FILE_SIZE})"})

        scan = parse_skill_file(p)
        audit = audit_skill_result(scan)
        trust = assess_trust(scan, audit)

        result = trust.to_dict()

        # Instruction file provenance check (Sigstore)
        try:
            from agent_bom.integrity import verify_instruction_file

            provenance = verify_instruction_file(p)
            if provenance.verified:
                result["provenance"] = {
                    "status": "verified",
                    "signer": provenance.signer_identity,
                    "rekor_index": provenance.rekor_log_index,
                    "sha256": provenance.sha256,
                }
            elif provenance.has_sigstore_bundle:
                result["provenance"] = {
                    "status": "bundle_found_but_invalid",
                    "reason": provenance.reason,
                    "sha256": provenance.sha256,
                }
            else:
                result["provenance"] = {
                    "status": "unsigned",
                    "sha256": provenance.sha256,
                }
        except Exception:
            result["provenance"] = {"status": "check_failed"}

        return _truncate_response(json.dumps(result, indent=2))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})
