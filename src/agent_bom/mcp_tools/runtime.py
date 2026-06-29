"""Runtime tools — runtime correlation, verification, inventory, and skill scanning."""

from __future__ import annotations

import json
import logging
from pathlib import Path
from types import SimpleNamespace
from typing import Any, cast

from agent_bom.config import MCP_MAX_FILE_SIZE as _MAX_FILE_SIZE
from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


def _request_for_tenant(tenant_id: str | None = None) -> SimpleNamespace:
    return SimpleNamespace(state=SimpleNamespace(tenant_id=resolve_mcp_tool_tenant_id(tenant_id)))


def _csv_set(value: str) -> set[str]:
    return {part.strip() for part in value.split(",") if part.strip()}


def _has_shield_write_scope(operator_scopes: str) -> bool:
    scopes = _csv_set(operator_scopes)
    return bool(scopes & {"*", "shield:*", "shield:write"})


def _authorize_shield_write(
    *,
    action: str,
    operator_role: str,
    operator_scopes: str,
    reason: str,
    tenant_id: str,
    session_id: str,
) -> tuple[bool, dict[str, Any]]:
    normalized_role = (operator_role or "").strip().lower()
    clean_reason = (reason or "").strip()
    if normalized_role != "admin":
        return (
            False,
            {
                "error": "shield write action requires admin role",
                "action": action,
                "required_role": "admin",
                "provided_role": normalized_role or "unset",
                "status": "blocked",
            },
        )
    if not _has_shield_write_scope(operator_scopes):
        return (
            False,
            {
                "error": "shield write action requires shield:write scope",
                "action": action,
                "required_role": "admin",
                "required_scope": "shield:write",
                "status": "blocked",
            },
        )
    if len(clean_reason) < 8:
        return (
            False,
            {
                "error": "shield write action requires an audit reason of at least 8 characters",
                "action": action,
                "required_role": "admin",
                "status": "blocked",
            },
        )
    return (
        True,
        {
            "action": action,
            "actor": normalized_role,
            "tenant_id": tenant_id or "default",
            "resource": f"shield/{session_id or 'default'}",
            "reason": clean_reason,
        },
    )


def _record_shield_write_audit(context: dict[str, Any], *, result: dict[str, Any]) -> None:
    try:
        from agent_bom.api.audit_log import log_action

        log_action(
            context["action"],
            actor=context["actor"],
            resource=context["resource"],
            tenant_id=context["tenant_id"],
            reason=context["reason"],
            result_status=result.get("status", "unknown"),
        )
    except Exception:  # noqa: BLE001
        logger.exception("MCP shield write audit logging failed")


async def runtime_production_index_impl(
    *,
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the runtime_production_index tool."""
    try:
        from agent_bom.api.routes.proxy import runtime_production_index

        payload = await runtime_production_index(cast(Any, _request_for_tenant(tenant_id)))
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP runtime production index error")
        return json.dumps({"error": sanitize_error(exc)})


async def runtime_blueprints_impl(
    *,
    blueprint_id: str = "",
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the runtime_blueprints tool."""
    try:
        from fastapi import HTTPException

        from agent_bom.api.routes.runtime_blueprints import get_runtime_blueprint, list_runtime_blueprints

        request = _request_for_tenant(tenant_id)
        if blueprint_id.strip():
            try:
                payload = await get_runtime_blueprint(cast(Any, request), blueprint_id.strip())
            except HTTPException as exc:
                return json.dumps({"error": sanitize_error(exc.detail)})
        else:
            payload = await list_runtime_blueprints(cast(Any, request))
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP runtime blueprints error")
        return json.dumps({"error": sanitize_error(exc)})


async def runtime_blueprint_drift_impl(
    *,
    blueprint_id: str,
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the runtime_blueprint_drift tool."""
    try:
        from fastapi import HTTPException

        from agent_bom.api.routes.runtime_blueprints import get_runtime_blueprint_drift

        try:
            payload = await get_runtime_blueprint_drift(cast(Any, _request_for_tenant(tenant_id)), blueprint_id.strip())
        except HTTPException as exc:
            return json.dumps({"error": sanitize_error(exc.detail)})
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP runtime blueprint drift error")
        return json.dumps({"error": sanitize_error(exc)})


async def drift_incidents_impl(
    *,
    include_resolved: bool = False,
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the drift_incidents tool: open blueprint-drift incidents."""
    try:
        from agent_bom.api.routes.runtime_blueprints import list_drift_incidents

        payload = await list_drift_incidents(cast(Any, _request_for_tenant(tenant_id)), include_resolved=include_resolved)
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP drift incidents error")
        return json.dumps({"error": sanitize_error(exc)})


async def anomaly_scan_impl(
    *,
    z_threshold: float = 3.0,
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the anomaly_scan tool: cost + behavior anomalies."""
    try:
        from agent_bom.api.routes.observability import get_anomalies

        payload = await get_anomalies(cast(Any, _request_for_tenant(tenant_id)), z_threshold=z_threshold)
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP anomaly scan error")
        return json.dumps({"error": sanitize_error(exc)})


async def cost_report_impl(
    *,
    agent: str = "",
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the cost_report tool: tenant LLM spend + budget posture."""
    try:
        from agent_bom.api.routes.observability import get_llm_costs

        payload = await get_llm_costs(cast(Any, _request_for_tenant(tenant_id)), agent=agent.strip() or None)
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP cost report error")
        return json.dumps({"error": sanitize_error(exc)})


async def proxy_status_impl(
    *,
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the proxy_status tool."""
    try:
        from agent_bom.api.routes.proxy import proxy_status

        payload = await proxy_status(cast(Any, _request_for_tenant(tenant_id)))
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP proxy status error")
        return json.dumps({"error": sanitize_error(exc)})


async def proxy_alerts_impl(
    *,
    tenant_id: str = "default",
    severity: str = "",
    detector: str = "",
    limit: int = 100,
    _truncate_response,
) -> str:
    """Implementation of the proxy_alerts tool."""
    try:
        from agent_bom.api.routes.proxy import proxy_alerts

        bounded_limit = max(1, min(int(limit), 1000))
        payload = await proxy_alerts(
            cast(Any, _request_for_tenant(tenant_id)),
            severity=severity.strip() or None,
            detector=detector.strip() or None,
            limit=bounded_limit,
        )
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP proxy alerts error")
        return json.dumps({"error": sanitize_error(exc)})


async def shield_status_impl(
    *,
    session_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the shield_status tool."""
    try:
        from agent_bom.api.routes.proxy import shield_status

        payload = await shield_status(cast(Any, _request_for_tenant(None)), session_id=session_id or "default")
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP shield status error")
        return json.dumps({"error": sanitize_error(exc)})


async def shield_start_impl(
    *,
    session_id: str = "default",
    correlation_window: float = 30.0,
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the shield_start write tool."""
    authorized, context = _authorize_shield_write(
        action="shield_start",
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        tenant_id=tenant_id,
        session_id=session_id,
    )
    if not authorized:
        return json.dumps(context)
    try:
        from agent_bom.api.routes.proxy import shield_start

        bounded_window = max(1.0, min(float(correlation_window), 3600.0))
        payload = await shield_start(
            cast(Any, _request_for_tenant(context["tenant_id"])),
            session_id=session_id or "default",
            correlation_window=bounded_window,
        )
        payload["mcp_write_policy"] = {
            "required_role": "admin",
            "required_scope": "shield:write",
            "actor_role": context["actor"],
            "audit_logged": True,
            "tenant_id": context["tenant_id"],
        }
        _record_shield_write_audit(context, result=payload)
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP shield start error")
        return json.dumps({"error": sanitize_error(exc)})


async def shield_unblock_impl(
    *,
    session_id: str = "default",
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the shield_unblock write tool."""
    authorized, context = _authorize_shield_write(
        action="shield_unblock",
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        tenant_id=tenant_id,
        session_id=session_id,
    )
    if not authorized:
        return json.dumps(context)
    try:
        from agent_bom.api.routes.proxy import shield_unblock

        payload = await shield_unblock(cast(Any, _request_for_tenant(context["tenant_id"])), session_id=session_id or "default")
        payload["mcp_write_policy"] = {
            "required_role": "admin",
            "required_scope": "shield:write",
            "actor_role": context["actor"],
            "audit_logged": True,
            "tenant_id": context["tenant_id"],
        }
        _record_shield_write_audit(context, result=payload)
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP shield unblock error")
        return json.dumps({"error": sanitize_error(exc)})


async def shield_break_glass_impl(
    *,
    session_id: str = "default",
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the shield_break_glass write tool."""
    authorized, context = _authorize_shield_write(
        action="shield_break_glass",
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        tenant_id=tenant_id,
        session_id=session_id,
    )
    if not authorized:
        return json.dumps(context)
    try:
        from agent_bom.api.routes.proxy import break_glass

        request = _request_for_tenant(context["tenant_id"])
        request.state.api_key_role = context["actor"]
        payload = await break_glass(cast(Any, request), session_id=session_id or "default", reason=context["reason"])
        payload["mcp_write_policy"] = {
            "required_role": "admin",
            "required_scope": "shield:write",
            "actor_role": context["actor"],
            "audit_logged": True,
            "tenant_id": context["tenant_id"],
        }
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP shield break-glass error")
        return json.dumps({"error": sanitize_error(exc)})


async def gateway_status_impl(
    *,
    tenant_id: str = "default",
    _truncate_response,
) -> str:
    """Implementation of the gateway_status tool."""
    try:
        from agent_bom.api.routes.gateway import gateway_stats

        payload = await gateway_stats(cast(Any, _request_for_tenant(tenant_id)))
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP gateway status error")
        return json.dumps({"error": sanitize_error(exc)})


async def audit_query_impl(
    *,
    tenant_id: str = "default",
    action: str = "",
    resource: str = "",
    since: str = "",
    limit: int = 100,
    offset: int = 0,
    _truncate_response,
) -> str:
    """Implementation of the audit_query tool."""
    try:
        from agent_bom.api.routes.enterprise import list_audit_entries

        bounded_limit = max(1, min(int(limit), 1000))
        bounded_offset = max(0, int(offset))
        payload = await list_audit_entries(
            cast(Any, _request_for_tenant(tenant_id)),
            action=action.strip() or None,
            resource=resource.strip() or None,
            since=since.strip() or None,
            limit=bounded_limit,
            offset=bounded_offset,
        )
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP audit query error")
        return json.dumps({"error": sanitize_error(exc)})


async def audit_integrity_impl(
    *,
    tenant_id: str = "default",
    limit: int = 1000,
    include_runtime: bool = True,
    _truncate_response,
) -> str:
    """Implementation of the audit_integrity tool."""
    try:
        from agent_bom.api.routes.enterprise import audit_integrity

        bounded_limit = max(1, min(int(limit), 10_000))
        payload = await audit_integrity(
            cast(Any, _request_for_tenant(tenant_id)),
            limit=bounded_limit,
            include_runtime=include_runtime,
        )
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP audit integrity error")
        return json.dumps({"error": sanitize_error(exc)})


def firewall_check_impl(
    *,
    source_agent: str,
    target_agent: str,
    source_roles: str = "",
    target_roles: str = "",
    _truncate_response,
) -> str:
    """Implementation of the read-only firewall_check tool."""
    try:
        from agent_bom.api.routes.gateway import _firewall_rule_payload, _load_control_plane_firewall_policy
        from agent_bom.firewall import evaluate

        source = source_agent.strip()
        target = target_agent.strip()
        if not source or not target:
            return json.dumps({"error": "source_agent and target_agent are required"})
        policy, policy_meta = _load_control_plane_firewall_policy()
        result = evaluate(
            policy,
            source_agent=source,
            target_agent=target,
            source_roles=_csv_set(source_roles),
            target_roles=_csv_set(target_roles),
        )
        payload = {
            "source_agent": source,
            "target_agent": target,
            "source_roles": sorted(_csv_set(source_roles)),
            "target_roles": sorted(_csv_set(target_roles)),
            "decision": result.decision.value,
            "effective_decision": result.effective_decision.value,
            "matched_rule": _firewall_rule_payload(result.matched_rule),
            "policy": policy_meta,
            "recorded": False,
            "note": "Read-only MCP evaluation; use /v1/firewall/check to record control-plane decisions.",
        }
        return _truncate_response(json.dumps(payload, indent=2, default=str))
    except Exception as exc:
        logger.exception("MCP firewall check error")
        return json.dumps({"error": sanitize_error(exc)})


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


def tool_risk_assessment_impl(
    *,
    config_path: str | None = None,
    timeout: float = 10.0,
    _truncate_response,
) -> str:
    """Implementation of the tool_risk_assessment tool."""
    try:
        from agent_bom.discovery import discover_all
        from agent_bom.mcp_introspect import introspect_servers_sync

        agents = discover_all(project_dir=config_path)
        servers = [s for a in agents for s in a.mcp_servers]
        if not servers:
            return json.dumps({"status": "no_servers_found", "servers": []})

        report = introspect_servers_sync(servers, timeout=timeout)
        results = [r.to_dict(include_runtime_objects=True) for r in report.results]
        summary = {
            "total_servers": report.total_servers,
            "successful": report.successful,
            "failed": report.failed,
            "critical_or_high": sum(1 for r in report.results if r.capability_risk_level in ("critical", "high")),
            "max_capability_risk_score": max((r.capability_risk_score for r in report.results), default=0.0),
        }
        return _truncate_response(json.dumps({"summary": summary, "servers": results}, indent=2))
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
        from agent_bom.skills_service import scan_skill_targets

        try:
            p = _safe_path(skill_path)
        except ValueError as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})
        if not p.is_file():
            return json.dumps({"error": f"File not found: {skill_path}"})
        if p.stat().st_size > _MAX_FILE_SIZE:
            return json.dumps({"error": f"File too large ({p.stat().st_size} bytes, max {_MAX_FILE_SIZE})"})

        file_report = scan_skill_targets([p]).files[0]
        result = file_report.trust.to_dict()
        result["provenance"] = file_report.provenance
        result["audit"] = {
            "passed": file_report.audit.passed,
            "findings": len(file_report.audit.findings),
        }

        return _truncate_response(json.dumps(result, indent=2))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


def skill_scan_impl(
    *,
    path: str,
    _safe_path,
    _truncate_response,
) -> str:
    """Implementation of the skill_scan tool."""
    try:
        from agent_bom.skills_service import scan_skill_targets

        try:
            target = _safe_path(path)
        except ValueError as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

        report = scan_skill_targets([target]).to_dict()
        if report["summary"]["files_scanned"] == 0:
            return json.dumps({"status": "no_skill_files_found", "path": str(target)})
        return _truncate_response(json.dumps(report, indent=2))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})


def skill_verify_impl(
    *,
    path: str,
    _safe_path,
    _truncate_response,
) -> str:
    """Implementation of the skill_verify tool."""
    try:
        from agent_bom.skills_service import verify_skill_targets

        try:
            target = _safe_path(path)
        except ValueError as exc:
            logger.exception("MCP tool error")
            return json.dumps({"error": sanitize_error(exc)})

        results = verify_skill_targets([target])
        if not results:
            return json.dumps({"status": "no_skill_files_found", "path": str(target)})
        return _truncate_response(json.dumps({"files": results}, indent=2))
    except Exception as exc:
        logger.exception("MCP tool error")
        return json.dumps({"error": sanitize_error(exc)})
