"""MCP tool: ingest CWPP runtime/EDR workload signals (#4158 stage 4)."""

from __future__ import annotations

import json
import logging
from typing import Any

from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


def _write_denial(
    *,
    operator_role: str,
    operator_scopes: str,
    reason: str,
    authenticated_actor: str,
) -> dict[str, Any] | None:
    """Validate the auditable context carried by an authorized MCP write."""
    role = (operator_role or "").strip().lower()
    scopes = {part.strip().lower() for part in (operator_scopes or "").split(",") if part.strip()}
    if role != "admin":
        return {
            "error": "runtime evidence write action requires admin role",
            "status": "blocked",
            "required_role": "admin",
            "provided_role": role or "unset",
        }
    if not scopes & {"*", "findings:*", "findings:write"}:
        return {
            "error": "runtime evidence write action requires findings:write scope",
            "status": "blocked",
            "required_role": "admin",
            "required_scope": "findings:write",
        }
    if len((reason or "").strip()) < 8:
        return {
            "error": "runtime evidence write action requires an audit reason of at least 8 characters",
            "status": "blocked",
            "required_role": "admin",
        }
    if not (authenticated_actor or "").strip():
        return {
            "error": "runtime evidence write action requires authenticated operator actor",
            "status": "blocked",
            "required_role": "admin",
            "required_scope": "findings:write",
        }
    return None


async def runtime_evidence_ingest_impl(
    *,
    source_id: str,
    secret: str,
    signals_json: str,
    operator_role: str = "viewer",
    operator_scopes: str = "",
    reason: str = "",
    _authenticated_actor: str = "",
    _truncate_response: Any,
) -> str:
    """Authenticate a registered source and ingest a JSON array of signals."""
    denial = _write_denial(
        operator_role=operator_role,
        operator_scopes=operator_scopes,
        reason=reason,
        authenticated_actor=_authenticated_actor,
    )
    if denial is not None:
        return json.dumps(denial)
    try:
        from agent_bom.cloud.runtime_workload_evidence import (
            SourceAuthenticationError,
            get_runtime_source_registry,
            ingest_runtime_signals_payload,
        )
        from agent_bom.mcp_tenant import resolve_mcp_tool_tenant_id

        registry = get_runtime_source_registry()
        source = registry.authenticate(source_id, secret)
        if source.tenant_id != resolve_mcp_tool_tenant_id():
            return json.dumps({"error": "runtime evidence source authentication failed"})
        payload = json.loads(signals_json)
        result = ingest_runtime_signals_payload(
            source_id=source_id,
            secret=secret,
            payload=payload,
            persist=True,
            registry=registry,
        )
        payload = result.to_dict()
        try:
            from agent_bom.api.audit_log import log_action

            log_action(
                "runtime_evidence.ingest",
                actor=_authenticated_actor.strip(),
                resource=f"runtime-evidence/source/{result.source_id}",
                tenant_id=result.tenant_id,
                reason=reason.strip(),
                accepted=payload["accepted"],
                persisted=payload["persisted"],
                rejected_stale=payload["rejected_stale"],
                rejected_incomplete=payload["rejected_incomplete"],
            )
            payload["status"] = "ok"
            payload["audit_status"] = "recorded"
        except Exception as exc:  # noqa: BLE001 - evidence ingest succeeds independently of audit sink availability
            logger.warning("MCP runtime evidence audit logging failed: %s", sanitize_error(exc, generic=True))
            payload["status"] = "partial"
            payload["audit_status"] = "unavailable"
            payload["audit_error"] = "Runtime evidence was persisted, but its audit event is unavailable."
        return _truncate_response(json.dumps(payload, indent=2, sort_keys=True))
    except SourceAuthenticationError:
        return json.dumps({"error": "runtime evidence source authentication failed"})
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        return json.dumps({"error": sanitize_error(exc)})
    except Exception as exc:  # noqa: BLE001
        safe_error = sanitize_error(exc, generic=True)
        logger.warning("MCP runtime_evidence_ingest error: %s", safe_error)
        return json.dumps({"error": safe_error})


__all__ = ["runtime_evidence_ingest_impl"]
