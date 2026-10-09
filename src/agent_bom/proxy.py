"""MCP runtime proxy — intercept JSON-RPC between client and server.

A stdio proxy that sits between an MCP client (Claude Desktop, Cursor, etc.)
and an MCP server. It intercepts all JSON-RPC messages, logs tool call
invocations, compares actual usage against declared capabilities, and
optionally enforces security policy in real-time.

Usage:
    agent-bom proxy --no-isolate [--policy policy.json] [--log audit.jsonl] -- npx @mcp/server-filesystem /tmp
    agent-bom proxy --sandbox-image ghcr.io/acme/mcp-runtime@sha256:<digest> -- npx @mcp/server-filesystem /tmp
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import signal
import sys
import tempfile
import time
import uuid
from contextlib import nullcontext
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Any, Mapping, Optional

from agent_bom import proxy_audit as _proxy_audit
from agent_bom import proxy_policy as _proxy_policy
from agent_bom.agent_identity import check_identity
from agent_bom.api.tracing import (
    build_traceparent,
    get_tracer,
    inject_current_trace_headers,
    inject_trace_headers,
    parse_baggage,
    parse_traceparent,
    parse_tracestate,
)
from agent_bom.async_stdin import create_async_stdin_reader, read_async_stdin_line
from agent_bom.langfuse_otel import set_langfuse_runtime_attributes
from agent_bom.proxy_sandbox import SandboxConfig, build_sandboxed_command
from agent_bom.proxy_scanner import ScanConfig, load_scan_config, scan_jsonrpc_response, scan_tool_call
from agent_bom.runtime import proxy_relay as _proxy_relay
from agent_bom.runtime import proxy_session as _proxy_session
from agent_bom.runtime.trace_metadata import inject_jsonrpc_trace_meta as _inject_jsonrpc_trace_meta
from agent_bom.security import (
    redact_secret_url,
    require_recognized_launcher,
    sanitize_sensitive_payload,
    sanitize_text,
    validate_arguments,
)
from agent_bom.storage import state_home

logger = logging.getLogger(__name__)

if TYPE_CHECKING:
    from agent_bom.api.policy_store import GatewayPolicy

# Re-export stable helper names for tests and existing callers while keeping the
# implementation split across dedicated proxy helper modules.
ProxyMetrics = _proxy_audit.ProxyMetrics
ProxyMetricsServer = _proxy_audit.ProxyMetricsServer
ReplayDetector = _proxy_audit.ReplayDetector
RotatingAuditLog = _proxy_audit.RotatingAuditLog
AuditDeliveryController = _proxy_audit.AuditDeliveryController
AuditDeliveryPaths = _proxy_audit.AuditDeliveryPaths
AuditDeliveryState = _proxy_audit.AuditDeliveryState
AuditSpilloverStore = _proxy_audit.AuditSpilloverStore
audit_delivery_paths = _proxy_audit.audit_delivery_paths
_truncate_args = _proxy_audit._truncate_args
compute_payload_hash = _proxy_audit.compute_payload_hash
compute_response_hmac = _proxy_audit.compute_response_hmac
log_tool_call = _proxy_audit.log_tool_call
summarize_runtime_alerts = _proxy_audit.summarize_runtime_alerts
write_audit_record = _proxy_audit.write_audit_record

_safe_compile = _proxy_policy._safe_compile
_safe_regex_match = _proxy_policy._safe_regex_match
_safe_regex_search = _proxy_policy._safe_regex_search
check_policy = _proxy_policy.check_policy
resolve_rate_limit_threshold = _proxy_policy.resolve_rate_limit_threshold

# Maximum JSON-RPC message size accepted from client or server (2 MiB).
# Guards against DoS via oversized payloads in the stdio relay loop.
_MAX_MESSAGE_BYTES = 2 * 1024 * 1024
_PROXY_TRACER = get_tracer("agent_bom.proxy")
_PROXY_POLICY_CACHE_SIGNING_ENV_VAR = "AGENT_BOM_PROXY_POLICY_CACHE_ED25519_PRIVATE_KEY_PEM"


def _proxy_policy_cache_signing_pem() -> str:
    """Resolve the cache-signing PEM file-first without retaining it in process env."""
    from agent_bom.api.secret_source import resolve_secret

    return resolve_secret(_PROXY_POLICY_CACHE_SIGNING_ENV_VAR).strip()


async def _read_bounded_line(reader: asyncio.StreamReader, *, max_bytes: int = _MAX_MESSAGE_BYTES) -> bytes | None:
    """Read one newline-delimited message without accepting an oversized line."""
    try:
        line = await reader.readuntil(b"\n")
    except asyncio.IncompleteReadError as exc:
        return exc.partial or b""
    except asyncio.LimitOverrunError as exc:
        if exc.consumed:
            await reader.readexactly(exc.consumed)
        try:
            await reader.readuntil(b"\n")
        except (asyncio.IncompleteReadError, asyncio.LimitOverrunError, ValueError):
            pass
        return None
    except ValueError:
        while True:
            chunk = await reader.read(1)
            if not chunk or b"\n" in chunk:
                break
        return None

    if len(line) > max_bytes:
        return None
    return line


# ─── JSON-RPC parsing ────────────────────────────────────────────────────────


def parse_jsonrpc(line: str) -> Optional[dict]:
    """Parse a JSON-RPC message from a single line.

    Returns the parsed dict or None if the line is not valid JSON-RPC.
    """
    line = line.strip()
    if not line:
        return None
    try:
        msg = json.loads(line)
        if isinstance(msg, dict) and ("jsonrpc" in msg or "method" in msg or "result" in msg):
            return msg
        return None
    except (json.JSONDecodeError, TypeError):
        return None


def is_tools_call(msg: dict) -> bool:
    """Check if a JSON-RPC message is a tools/call request."""
    return msg.get("method") == "tools/call"


_POLICY_GATED_METHODS = {
    "prompts/get",
    "resources/read",
    "sampling/createMessage",
}


def policy_subject_from_message(msg: dict) -> tuple[str, dict] | None:
    """Return the policy subject and arguments for gated JSON-RPC methods."""
    if is_tools_call(msg):
        return extract_tool_name(msg) or "unknown", extract_tool_arguments(msg)

    method = msg.get("method")
    if not isinstance(method, str):
        return None
    if method not in _POLICY_GATED_METHODS and not method.startswith("mcp_extension/"):
        return None

    params = msg.get("params", {})
    if isinstance(params, dict):
        return method, params
    return method, {"params": params}


def is_tools_list_response(msg: dict, request_id: Optional[int | str] = None) -> bool:
    """Check if a JSON-RPC message is a tools/list response."""
    if "result" not in msg:
        return False
    result = msg.get("result", {})
    if isinstance(result, dict) and "tools" in result:
        return True
    return False


def extract_tool_name(msg: dict) -> Optional[str]:
    """Extract the tool name from a tools/call request.

    A caller controls these types. A non-dict ``params`` or a non-string
    ``name`` used to raise ``AttributeError`` out of the relay: a 500 with no
    policy decision, no audit event, and no ledger record. Ill-typed is not
    unnameable — it resolves to no name, and the caller is still governed.
    """
    params = msg.get("params", {})
    if not isinstance(params, dict):
        return None
    name = params.get("name")
    return name if isinstance(name, str) else None


def extract_tool_arguments(msg: dict) -> dict:
    """Extract tool arguments from a tools/call request.

    Coerces a caller-supplied non-dict to an empty mapping for the same reason
    as :func:`extract_tool_name`.
    """
    params = msg.get("params", {})
    if not isinstance(params, dict):
        return {}
    arguments = params.get("arguments", {})
    return arguments if isinstance(arguments, dict) else {}


def extract_declared_tools(msg: dict) -> list[str]:
    """Extract declared tool names from a tools/list response."""
    result = msg.get("result", {})
    tools = result.get("tools", [])
    return [t.get("name", "") for t in tools if isinstance(t, dict)]


def make_error_response(request_id: int | str | None, code: int, message: str) -> dict:
    """Create a JSON-RPC error response."""
    return {
        "jsonrpc": "2.0",
        "id": request_id,
        "error": {
            "code": code,
            "message": message,
        },
    }


def undeclared_tool_block_reason(block_undeclared: bool, declared_tools: set[str], tool_name: str) -> str | None:
    """Return a hard-block reason for undeclared tools when enforcement is on."""
    if not block_undeclared:
        return None
    if tool_name in declared_tools:
        return None
    if declared_tools:
        return f"Tool '{tool_name}' not in declared tools/list"
    return f"Tool '{tool_name}' blocked because no tools/list declarations are available"


def sandbox_posture_warning(sandbox_evidence: Mapping[str, object]) -> str | None:
    """Return an operator-visible warning when proxy isolation is not active."""
    if sandbox_evidence.get("enabled"):
        return None
    return (
        "agent-bom proxy warning: sandbox isolation is disabled; the MCP server "
        "runs as the current host user. Remove --no-isolate or set "
        "AGENT_BOM_MCP_SANDBOX=1 to run the server in a restricted container."
    )


def _command_name_for_validation(command: str, sandbox_evidence: Mapping[str, object]) -> str:
    """Validate sandbox-generated container runtimes by name, not resolved path."""
    if sandbox_evidence.get("enabled") and sandbox_evidence.get("mode") in {"wrap_command_in_image", "harden_existing_container"}:
        return Path(command).name
    return command


# ─── Proxy core ──────────────────────────────────────────────────────────────


# ─── Gateway evaluator hook ──────────────────────────────────────────────────

_gateway_evaluator = None  # type: ignore[var-annotated]


def set_gateway_evaluator(fn) -> None:  # noqa: ANN001
    """Register a gateway evaluator for runtime enforcement.

    The callable signature must be
    ``(agent_name: str, tool_name: str, arguments: dict) -> (allowed, reason)``
    where *allowed* is a bool.
    """
    global _gateway_evaluator
    _gateway_evaluator = fn


# ─── Inter-agent firewall evaluator hook (#982 PR 3) ─────────────────────────

_firewall_evaluator = None  # type: ignore[var-annotated]
_firewall_target_id: str | None = None


def set_firewall_evaluator(fn, *, target_id: str | None = None) -> None:  # noqa: ANN001
    """Register an async inter-agent firewall evaluator.

    The callable signature must be
    ``async (source_agent: str, target_agent: str, source_roles: frozenset[str],
              target_roles: frozenset[str]) -> FirewallEvaluation``.

    `target_id` is the agent identity this proxy is wrapping (the *target*
    side of the source -> target firewall pair). When set, the proxy uses
    it for every firewall lookup; when unset, the firewall is not consulted.
    """
    global _firewall_evaluator
    global _firewall_target_id
    _firewall_evaluator = fn
    _firewall_target_id = target_id


def clear_firewall_evaluator() -> None:
    """Test/teardown helper — drop the registered evaluator."""
    global _firewall_evaluator
    global _firewall_target_id
    _firewall_evaluator = None
    _firewall_target_id = None


def _firewall_target_for_proxy() -> str | None:
    return _firewall_target_id


async def _maybe_block_on_firewall(
    *,
    source_agent: str,
    target_agent: str,
    tool_name: str,
    arguments: dict,
    log_file,  # noqa: ANN001 — proxy uses an open file handle / RotatingAuditLog
    payload_sha256: str | None,
    message_id,  # noqa: ANN001 — JSON-RPC id can be int / str / None
    tenant_id: str | None,
    metrics=None,  # noqa: ANN001 — ProxyMetrics; SSE proxy path doesn't track metrics
) -> str | None:
    """Run the registered firewall evaluator for source -> target.

    Returns:
        - the reason string when the call should be blocked (caller emits the
          JSON-RPC error response so this helper stays decision-only),
        - None when the call may proceed.

    On exception inside the evaluator the proxy fails open here. The
    `FirewallClient` already encodes the gateway fail-mode (open / closed)
    internally, so unexpected raises here are out-of-policy errors.
    """

    from agent_bom.firewall import FirewallDecision

    if _firewall_evaluator is None:
        return None
    try:
        evaluation = await _firewall_evaluator(
            source_agent,
            target_agent,
            frozenset(),
            frozenset(),
        )
    except Exception as exc:  # noqa: BLE001
        logger.warning(
            "firewall evaluator raised; allowing call (source=%s, target=%s): %s",
            source_agent,
            target_agent,
            sanitize_text(exc),
        )
        return None

    effective = evaluation.effective_decision
    if effective == FirewallDecision.ALLOW:
        return None

    matched = evaluation.matched_rule
    rule_desc = (
        f"{matched.source} -> {matched.target} ({matched.decision.value})" + (f" · {matched.description}" if matched.description else "")
        if matched is not None
        else "default"
    )

    if effective == FirewallDecision.WARN:
        if metrics is not None:
            metrics.record_blocked("firewall_warn")
        if log_file:
            log_tool_call(
                log_file,
                tool_name,
                arguments,
                "warn",
                f"firewall warn: {source_agent} -> {target_agent} [{rule_desc}]",
                payload_sha256=payload_sha256 or "",
                message_id=message_id,
                agent_id=source_agent,
                tenant_id=tenant_id or "default",
            )
        return None

    # DENY
    reason = f"firewall: {source_agent} -> {target_agent} blocked [{rule_desc}]"
    if metrics is not None:
        metrics.record_blocked("firewall")
    if log_file:
        log_tool_call(
            log_file,
            tool_name,
            arguments,
            "blocked",
            reason,
            payload_sha256=payload_sha256 or "",
            message_id=message_id,
            agent_id=source_agent,
            tenant_id=tenant_id or "default",
        )
    return reason


def _sanitize_for_log(value: object) -> str:
    return str(value).replace("\r", "").replace("\n", "")


def _generate_proxy_source_id() -> str:
    hostname = platform.node() or "unknown"
    return hashlib.sha256(hostname.encode()).hexdigest()[:12]


def _proxy_audit_delivery_paths(
    control_plane_url: str,
    tenant_id: str,
    source_id: str,
) -> AuditDeliveryPaths:
    """Resolve restart-stable, secret-free proxy audit backlog paths."""

    state_dir = state_home.state_dir()
    identity = "\x00".join((control_plane_url.rstrip("/"), tenant_id, source_id))
    return audit_delivery_paths(state_dir, surface="proxy", identity=identity)


def _control_plane_headers(token: str | None, etag: str | None = None) -> dict[str, str]:
    headers = {"Content-Type": "application/json"}
    if token:
        headers["Authorization"] = f"Bearer {token}"
    if etag:
        headers["If-None-Match"] = etag
    return inject_current_trace_headers(headers)


def _proxy_request_headers(
    headers: dict[str, str] | None = None,
    *,
    traceparent: str | None = None,
    tracestate: str | None = None,
    baggage: str | None = None,
) -> dict[str, str]:
    if traceparent or tracestate or baggage:
        return inject_trace_headers(
            headers,
            traceparent=traceparent,
            tracestate=tracestate,
            baggage=baggage,
        )
    return inject_current_trace_headers(headers)


def _extract_jsonrpc_trace_meta(message: dict[str, object]) -> dict[str, str]:
    """Return bounded W3C trace metadata carried in JSON-RPC `_meta`.

    stdio JSON-RPC has no native header channel, so `_meta` is the least
    surprising place to preserve trace context across proxy boundaries.
    """
    raw_meta = message.get("_meta")
    if not isinstance(raw_meta, dict):
        return {}
    trace_meta: dict[str, str] = {}
    traceparent = parse_traceparent(str(raw_meta.get("traceparent", "")).strip())
    if traceparent:
        trace_meta["traceparent"] = build_traceparent(
            traceparent["trace_id"],
            traceparent["parent_span_id"],
            traceparent["trace_flags"],
        )
    tracestate = parse_tracestate(str(raw_meta.get("tracestate", "")).strip())
    if tracestate:
        trace_meta["tracestate"] = tracestate
    baggage = parse_baggage(str(raw_meta.get("baggage", "")).strip())
    if baggage:
        trace_meta["baggage"] = baggage
    return trace_meta


def _stitch_jsonrpc_trace_meta(
    message: dict[str, object],
    fallback_trace_meta: dict[str, str] | None,
) -> dict[str, object]:
    """Preserve response trace metadata or rehydrate it from the paired request."""
    response_trace_meta = _extract_jsonrpc_trace_meta(message)
    merged = {
        "traceparent": response_trace_meta.get("traceparent") or (fallback_trace_meta or {}).get("traceparent"),
        "tracestate": response_trace_meta.get("tracestate") or (fallback_trace_meta or {}).get("tracestate"),
        "baggage": response_trace_meta.get("baggage") or (fallback_trace_meta or {}).get("baggage"),
    }
    return _inject_jsonrpc_trace_meta(
        message,
        traceparent=merged["traceparent"],
        tracestate=merged["tracestate"],
        baggage=merged["baggage"],
    )


def _gateway_policy_cache_path() -> Path:
    configured = os.environ.get("AGENT_BOM_PROXY_POLICY_CACHE_PATH")
    if configured:
        return Path(configured).expanduser()
    return state_home.state_path("cache", "gateway-policies.json")


def _gateway_policy_cache_signature_path(cache_path: Path) -> Path:
    return cache_path.with_name(f"{cache_path.name}.sig")


class _GatewayPolicyCacheSigner:
    def __init__(self, pem: str) -> None:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        loaded = serialization.load_pem_private_key(pem.encode(), password=None)
        if not isinstance(loaded, Ed25519PrivateKey):
            raise ValueError(f"{_PROXY_POLICY_CACHE_SIGNING_ENV_VAR} is not an Ed25519 key")
        self._private_key = loaded
        public_bytes: bytes = loaded.public_key().public_bytes(
            encoding=serialization.Encoding.DER,
            format=serialization.PublicFormat.SubjectPublicKeyInfo,
        )
        self.key_id = hashlib.sha256(public_bytes).hexdigest()[:16]

    def sign(self, payload: bytes) -> str:
        return self._private_key.sign(payload).hex()

    def verify(self, payload: bytes, signature_hex: str) -> None:
        self._private_key.public_key().verify(bytes.fromhex(signature_hex), payload)


_gateway_policy_cache_signer: _GatewayPolicyCacheSigner | None = None
_gateway_policy_cache_signer_error: str | None = None


def _load_gateway_policy_cache_signer() -> _GatewayPolicyCacheSigner | None:
    global _gateway_policy_cache_signer, _gateway_policy_cache_signer_error
    if _gateway_policy_cache_signer is not None:
        return _gateway_policy_cache_signer
    pem = _proxy_policy_cache_signing_pem()
    if not pem:
        return None
    if _gateway_policy_cache_signer_error is not None:
        return None
    try:
        _gateway_policy_cache_signer = _GatewayPolicyCacheSigner(pem)
        logger.info(
            "proxy gateway policy cache signing enabled (key_id=%s)",
            _gateway_policy_cache_signer.key_id,
        )
        return _gateway_policy_cache_signer
    except Exception as exc:  # noqa: BLE001
        _gateway_policy_cache_signer_error = str(exc)
        logger.error("%s could not be parsed: %s", _PROXY_POLICY_CACHE_SIGNING_ENV_VAR, sanitize_text(exc))
        return None


def _reset_gateway_policy_cache_signer_for_tests() -> None:
    global _gateway_policy_cache_signer, _gateway_policy_cache_signer_error
    _gateway_policy_cache_signer = None
    _gateway_policy_cache_signer_error = None


def _canonicalize_gateway_policy_cache(payload: Mapping[str, object]) -> bytes:
    return json.dumps(payload, sort_keys=True, separators=(",", ":")).encode("utf-8")


def _load_cached_gateway_policies(
    cache_path: Path,
    max_age_seconds: int,
) -> tuple[list["GatewayPolicy"] | None, str | None]:
    from agent_bom.api.policy_store import GatewayPolicy

    try:
        payload = json.loads(cache_path.read_text())
    except FileNotFoundError:
        return None, None
    except (json.JSONDecodeError, OSError) as exc:
        logger.warning("Ignoring unreadable gateway policy cache %s: %s", cache_path, sanitize_text(exc))
        return None, None

    fetched_at = payload.get("fetched_at")
    if not isinstance(fetched_at, (int, float)):
        logger.warning("Ignoring gateway policy cache %s with missing fetched_at", cache_path)
        return None, None
    age_seconds = time.time() - float(fetched_at)
    if age_seconds > max(max_age_seconds, 0):
        logger.warning(
            "Ignoring stale gateway policy cache %s (age=%ss, max=%ss)",
            cache_path,
            int(age_seconds),
            max(max_age_seconds, 0),
        )
        return None, None

    signer = _load_gateway_policy_cache_signer()
    if _proxy_policy_cache_signing_pem():
        if signer is None:
            logger.warning("Ignoring gateway policy cache %s because cache signing is misconfigured", cache_path)
            return None, None
        signature_path = _gateway_policy_cache_signature_path(cache_path)
        try:
            signature_payload = json.loads(signature_path.read_text())
            signature_hex = str(signature_payload["signature_hex"])
            key_id = str(signature_payload["key_id"])
        except FileNotFoundError:
            logger.warning("Ignoring unsigned gateway policy cache %s because signing is required", cache_path)
            return None, None
        except (KeyError, TypeError, json.JSONDecodeError, OSError) as exc:
            logger.warning("Ignoring unreadable gateway policy cache signature %s: %s", signature_path, sanitize_text(exc))
            return None, None
        if key_id != signer.key_id:
            logger.warning(
                "Ignoring gateway policy cache %s signed with unexpected key_id=%s (expected %s)",
                cache_path,
                key_id,
                signer.key_id,
            )
            return None, None
        try:
            signer.verify(_canonicalize_gateway_policy_cache(payload), signature_hex)
        except Exception as exc:  # noqa: BLE001
            logger.warning("Ignoring gateway policy cache %s with invalid signature: %s", cache_path, sanitize_text(exc))
            return None, None

    try:
        policies = [GatewayPolicy(**item) for item in payload.get("policies", [])]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Ignoring invalid gateway policy cache %s: %s", cache_path, sanitize_text(exc))
        return None, None
    return policies, payload.get("etag")


def _persist_gateway_policies_cache(
    cache_path: Path,
    policies: list["GatewayPolicy"],
    etag: str | None,
) -> None:
    payload = {
        "fetched_at": time.time(),
        "etag": etag,
        "policies": [policy.model_dump(mode="json") for policy in policies],
    }
    try:
        cache_path.parent.mkdir(parents=True, exist_ok=True)
        signature_path = _gateway_policy_cache_signature_path(cache_path)
        signer = _load_gateway_policy_cache_signer()
        with tempfile.NamedTemporaryFile(
            "w",
            encoding="utf-8",
            dir=str(cache_path.parent),
            prefix=f"{cache_path.name}.",
            suffix=".tmp",
            delete=False,
        ) as handle:
            json.dump(payload, handle, sort_keys=True)
            handle.flush()
            os.fsync(handle.fileno())
            temp_path = Path(handle.name)
        temp_path.replace(cache_path)
        if signer is not None:
            signature_payload = {
                "algorithm": "Ed25519",
                "key_id": signer.key_id,
                "signature_hex": signer.sign(_canonicalize_gateway_policy_cache(payload)),
            }
            with tempfile.NamedTemporaryFile(
                "w",
                encoding="utf-8",
                dir=str(signature_path.parent),
                prefix=f"{signature_path.name}.",
                suffix=".tmp",
                delete=False,
            ) as handle:
                json.dump(signature_payload, handle, sort_keys=True)
                handle.flush()
                os.fsync(handle.fileno())
                temp_sig_path = Path(handle.name)
            temp_sig_path.replace(signature_path)
    except OSError as exc:
        logger.warning("Failed to persist gateway policy cache %s: %s", cache_path, sanitize_text(exc))


async def _fetch_enabled_gateway_policies(
    base_url: str,
    token: str | None,
    etag: str | None = None,
) -> tuple[list["GatewayPolicy"] | None, str | None]:
    from agent_bom.api.policy_store import GatewayPolicy
    from agent_bom.http_client import create_client

    url = base_url.rstrip("/") + "/v1/gateway/policies?enabled=true"
    span_cm = _PROXY_TRACER.start_as_current_span("proxy.fetch_gateway_policies") if _PROXY_TRACER else nullcontext()
    with span_cm as span:
        if span is not None:
            span.set_attribute("agent_bom.proxy.control_plane_url", base_url.rstrip("/"))
            span.set_attribute("agent_bom.proxy.gateway_policy_etag_present", bool(etag))
        async with create_client(timeout=15.0) as client:
            response = await client.get(url, headers=_control_plane_headers(token, etag))
    if response.status_code == 304:
        return None, response.headers.get("ETag", etag)
    response.raise_for_status()
    payload = response.json()
    policies = [GatewayPolicy(**item) for item in payload.get("policies", [])]
    if span is not None:
        span.set_attribute("agent_bom.proxy.gateway_policy_count", len(policies))
    return policies, response.headers.get("ETag")


def _resolve_control_plane_rate_limit_threshold(policies: list["GatewayPolicy"], agent_name: str | None = None) -> int | None:
    from agent_bom.gateway import gateway_policy_to_proxy_format

    limits: list[int] = []
    for policy in policies:
        if not getattr(policy, "enabled", False):
            continue
        if agent_name and getattr(policy, "bound_agents", None) and agent_name not in getattr(policy, "bound_agents", []):
            continue
        proxy_fmt = gateway_policy_to_proxy_format(policy)
        limit = resolve_rate_limit_threshold(proxy_fmt)
        if limit is not None:
            limits.append(limit)
    return min(limits) if limits else None


async def _push_proxy_audit_batch(
    base_url: str,
    token: str | None,
    source_id: str,
    session_id: str,
    alerts: list[dict],
    summary: dict | None = None,
) -> bool:
    from agent_bom.http_client import create_client

    if not alerts and summary is None:
        return True
    url = base_url.rstrip("/") + "/v1/proxy/audit"
    payload = {
        "source_id": source_id,
        "session_id": session_id,
        "alerts": alerts,
        "summary": summary,
    }
    span_cm = _PROXY_TRACER.start_as_current_span("proxy.push_audit_batch") if _PROXY_TRACER else nullcontext()
    with span_cm as span:
        if span is not None:
            span.set_attribute("agent_bom.proxy.audit_alert_count", len(alerts))
            span.set_attribute("agent_bom.proxy.audit_has_summary", summary is not None)
        async with create_client(timeout=15.0) as client:
            response = await client.post(url, json=payload, headers=_control_plane_headers(token))
    response.raise_for_status()
    return True


# Strong references to in-flight webhook tasks. asyncio holds only a weak
# reference to a running task, so a bare ensure_future(_send_webhook(...)) can be
# garbage-collected mid-send and silently drop the alert ("Task was destroyed but
# it is pending"). Retaining the task until it completes fixes that (#3911).
_WEBHOOK_TASKS: set[asyncio.Task] = set()


def _fire_webhook(url: str, payload: dict) -> None:
    """Dispatch an alert webhook without letting the task be GC'd mid-flight."""
    task = asyncio.ensure_future(_send_webhook(url, payload))
    _WEBHOOK_TASKS.add(task)
    task.add_done_callback(_WEBHOOK_TASKS.discard)


async def _send_webhook(url: str, payload: dict) -> None:
    """Fire-and-forget POST to an alert webhook URL.

    Validates the URL before sending to prevent SSRF via --alert-webhook.
    """
    from agent_bom.security import SecurityError, validate_url

    try:
        validate_url(url)
    except SecurityError as e:
        logger.warning("Webhook URL rejected: %s", sanitize_text(e))
        return

    try:
        import httpx

        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)) as client:
            await client.post(url, json=sanitize_sensitive_payload(payload, max_str_len=3_000))
    except Exception:  # noqa: BLE001
        logger.debug("Failed to send webhook to %s", redact_secret_url(url))


def _response_scan_alerts(findings, subject: str):
    """Convert shared response detections to transport-specific alert sinks."""
    from agent_bom.runtime.detectors import Alert, AlertSeverity

    return [
        Alert(
            detector=f"scanner:{finding.scanner}",
            severity=AlertSeverity.CRITICAL
            if finding.severity == "critical"
            else (AlertSeverity.HIGH if finding.severity == "high" else AlertSeverity.MEDIUM),
            message=f"Inline scan (response): {finding.scanner}/{finding.rule_id} from '{subject}'",
            details={"rule_id": finding.rule_id, "excerpt": finding.excerpt, "confidence": finding.confidence},
        )
        for finding in findings
    ]


def _write_client_error(request_id: int | str | None, reason: str) -> None:
    """Answer a rejected request directly on the client's stdout."""
    error_resp = make_error_response(request_id, -32600, reason)
    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
    sys.stdout.buffer.flush()


def _reject_tool_call(
    log_file,  # noqa: ANN001
    tool_name: str,
    arguments: dict,
    reason: str,
    *,
    payload_sha256: str,
    message_id: int | str | None,
    agent_id: str,
    tenant_id: str,
) -> None:
    """Audit a blocked policy-gated call, then answer the client with an error."""
    if log_file:
        log_tool_call(
            log_file,
            tool_name,
            arguments,
            "blocked",
            reason,
            payload_sha256=payload_sha256,
            message_id=message_id,
            agent_id=agent_id,
            tenant_id=tenant_id,
        )
    _write_client_error(message_id, reason)


def _execution_posture(sandbox_evidence: Mapping[str, object]) -> dict[str, object]:
    return {
        "mode": "container_isolated" if sandbox_evidence.get("enabled") else "observation_only",
        "sandbox_evidence": sandbox_evidence,
    }


def _load_proxy_policy(policy_path: Optional[str]) -> dict:
    """Load the local policy file (path-validated, 10 MB-capped JSON) or exit 1."""
    if not policy_path:
        return {}
    try:
        from agent_bom.security import SecurityError, validate_json_file

        return validate_json_file(Path(policy_path))
    except (json.JSONDecodeError, OSError, SecurityError) as exc:
        logger.error("Failed to load policy from %s: %s", policy_path, sanitize_text(exc))
        raise SystemExit(1) from exc


@dataclass
class _ProxyAuditDelivery:
    max_buffer_bytes: int
    max_spillover_bytes: int
    spill_path: Path
    dlq_path: Path
    controller: AuditDeliveryController
    spillover: AuditSpilloverStore
    state: AuditDeliveryState


def _build_audit_delivery(
    control_plane_url: Optional[str],
    tenant_id: str,
    source_id: str,
    audit_push_interval: int,
) -> _ProxyAuditDelivery:
    """Resolve bounded audit buffer/spillover/DLQ settings and delivery backoff."""
    max_buffer_bytes = max(64 * 1024, int(os.environ.get("AGENT_BOM_PROXY_AUDIT_BUFFER_MAX_BYTES", "1048576")))
    max_spillover_bytes = max(
        max_buffer_bytes,
        int(os.environ.get("AGENT_BOM_PROXY_AUDIT_SPILLOVER_MAX_BYTES", str(max_buffer_bytes * 8))),
    )
    stable_paths = _proxy_audit_delivery_paths(control_plane_url or "local", tenant_id, source_id)
    spill_path = Path(os.environ.get("AGENT_BOM_PROXY_AUDIT_SPILLOVER_PATH", str(stable_paths.spill_path)))
    dlq_path = Path(os.environ.get("AGENT_BOM_PROXY_AUDIT_DLQ_PATH", str(stable_paths.dlq_path)))
    base_interval = max(audit_push_interval, 5)
    controller = AuditDeliveryController(
        base_interval_seconds=base_interval,
        max_backoff_seconds=max(
            base_interval,
            int(os.environ.get("AGENT_BOM_PROXY_AUDIT_PUSH_BACKOFF_MAX_SECONDS", "300")),
        ),
        breaker_failure_threshold=max(
            1,
            int(os.environ.get("AGENT_BOM_PROXY_AUDIT_CIRCUIT_BREAKER_THRESHOLD", "3")),
        ),
        breaker_cooldown_seconds=max(
            base_interval,
            int(os.environ.get("AGENT_BOM_PROXY_AUDIT_CIRCUIT_BREAKER_COOLDOWN_SECONDS", "60")),
        ),
    )
    spillover = AuditSpilloverStore(spill_path=spill_path, dlq_path=dlq_path, max_spillover_bytes=max_spillover_bytes)
    return _ProxyAuditDelivery(
        max_buffer_bytes=max_buffer_bytes,
        max_spillover_bytes=max_spillover_bytes,
        spill_path=spill_path,
        dlq_path=dlq_path,
        controller=controller,
        spillover=spillover,
        state=AuditDeliveryState(controller=controller, store=spillover),
    )


def _build_firewall_client(
    target_id: Optional[str],
    gateway_url: Optional[str],
    gateway_token: Optional[str],
    local_policy_path: Optional[str],
    cache_ttl_seconds: float,
    fail_mode: str,
):  # noqa: ANN201
    """Create and register the inter-agent firewall client; None when not configured.

    Active when a target id is set together with a gateway URL or a local
    policy file. The client is cache-first; the gateway is consulted on cache
    miss / TTL expiry.
    """
    if not (target_id and (gateway_url or local_policy_path)):
        return None
    from agent_bom.firewall import FirewallPolicyError, load_firewall_policy_file
    from agent_bom.firewall_client import FirewallClient, FirewallFailMode

    local_policy = None
    if local_policy_path:
        try:
            local_policy = load_firewall_policy_file(Path(local_policy_path))
        except FirewallPolicyError as exc:
            logger.error("invalid firewall policy at %s: %s", local_policy_path, sanitize_text(exc))
            raise SystemExit(1) from exc
    try:
        fw_fail_mode = FirewallFailMode(fail_mode)
    except ValueError as exc:
        raise SystemExit(f"invalid --firewall-fail-mode {fail_mode!r}") from exc
    firewall_client = FirewallClient(
        gateway_url=gateway_url,
        bearer_token=gateway_token,
        cache_ttl_seconds=max(0.0, cache_ttl_seconds),
        fail_mode=fw_fail_mode,
        local_policy=local_policy,
    )

    async def _firewall_evaluator_fn(source, target, source_roles, target_roles):
        return await firewall_client.decision(
            source_agent=source,
            target_agent=target,
            source_roles=source_roles,
            target_roles=target_roles,
        )

    set_firewall_evaluator(_firewall_evaluator_fn, target_id=target_id)
    return firewall_client


def _prepare_server_command(
    server_cmd: list[str],
    sandbox_config: SandboxConfig | None,
    log_file,  # noqa: ANN001
) -> tuple[list[str], dict[str, object]]:
    """Apply sandbox wrapping, launch-hygiene checks and the posture audit record."""
    sandbox_evidence: dict[str, object] = {"enabled": False}
    if sandbox_config and sandbox_config.enabled:
        server_cmd, sandbox_evidence = build_sandboxed_command(server_cmd, sandbox_config)
        logger.info(
            "MCP server isolation enabled using %s (%s)",
            sandbox_evidence.get("runtime"),
            sandbox_evidence.get("mode"),
        )
    elif sandbox_config:
        sandbox_evidence = sandbox_config.evidence()

    if warning := sandbox_posture_warning(sandbox_evidence):
        # Single emission via the logger: the default handler already writes
        # to stderr, and the `mcp_execution_posture` audit event carries the
        # same detail in machine-readable form.
        logger.warning(warning)

    # Launch-hygiene checks on the effective server command before spawning.
    # These catch typos and shell-interpolation configs; they are NOT the
    # isolation boundary — that is the container sandbox wired above.
    require_recognized_launcher(_command_name_for_validation(server_cmd[0], sandbox_evidence))
    if len(server_cmd) > 1:
        validate_arguments(list(server_cmd[1:]))

    if log_file:
        write_audit_record(
            log_file,
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "type": "mcp_execution_posture",
                "execution_posture": _execution_posture(sandbox_evidence),
            },
        )
    return server_cmd, sandbox_evidence


def _start_sandbox_timeout(
    process: asyncio.subprocess.Process,
    sandbox_config: SandboxConfig | None,
    sandbox_evidence: dict[str, object],
    log_file,  # noqa: ANN001
) -> asyncio.Task | None:
    """Terminate the sandboxed server once its configured timeout elapses."""
    if not (sandbox_config and sandbox_config.enabled and sandbox_config.timeout_seconds):
        return None
    timeout_seconds = sandbox_config.timeout_seconds

    async def _sandbox_timeout_watchdog() -> None:
        await asyncio.sleep(timeout_seconds or 0)
        if process.returncode is None:
            logger.error("MCP sandbox timeout reached after %s seconds; terminating server", timeout_seconds)
            if log_file:
                write_audit_record(
                    log_file,
                    {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "type": "mcp_sandbox_timeout",
                        "timeout_seconds": timeout_seconds,
                        "execution_posture": {
                            "mode": "container_isolated",
                            "sandbox_evidence": sandbox_evidence,
                        },
                    },
                )
            process.terminate()

    return asyncio.create_task(_sandbox_timeout_watchdog())


def _record_relay_errors(results: list, metrics: ProxyMetrics, log_file) -> None:  # noqa: ANN001
    """Count and audit unexpected relay-task failures (pipe teardown is expected)."""
    for result in results:
        if isinstance(result, Exception) and not isinstance(result, (BrokenPipeError, ConnectionResetError, asyncio.CancelledError)):
            metrics.relay_errors += 1
            logger.warning("Relay task exited with unexpected error: %s", sanitize_text(result))
            if log_file:
                err_entry = {
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "type": "relay_error",
                    "error": str(result),
                    "error_type": type(result).__name__,
                }
                write_audit_record(log_file, err_entry)


async def _proxy_sse_server(
    url: str,
    policy_path: Optional[str] = None,
    log_path: Optional[str] = None,
    block_undeclared: bool = False,
    alert_webhook: Optional[str] = None,
) -> int:
    """Proxy an SSE/HTTP MCP server through the protection engine.

    Connects to a remote MCP server that exposes an SSE or HTTP transport
    instead of spawning a subprocess.  Tool calls received on stdin are
    forwarded through the protection engine then POSTed to the server URL.
    Responses are written back to stdout.

    Args:
        url: Base URL of the remote SSE/HTTP MCP server.
        policy_path: Optional path to a runtime policy JSON file.
        log_path: Optional path to audit JSONL log.
        block_undeclared: Block tools not in initial tools/list.
        alert_webhook: Optional webhook URL for alert notifications.

    Returns:
        0 on clean shutdown, 1 on connection or policy load error.
    """
    import httpx

    from agent_bom.runtime.detectors import (
        ArgumentAnalyzer,
        SequenceAnalyzer,
    )

    # Load policy
    policy: dict = {}
    if policy_path:
        try:
            from agent_bom.security import SecurityError, validate_json_file

            policy = validate_json_file(Path(policy_path))
        except (json.JSONDecodeError, OSError, SecurityError) as exc:
            logger.error("Failed to load policy from %s: %s", policy_path, sanitize_text(exc))
            return 1

    # Open audit log
    log_file = None
    if log_path:
        log_file = RotatingAuditLog(log_path)

    arg_analyzer = ArgumentAnalyzer()
    seq_analyzer = SequenceAnalyzer()
    replay_detector = ReplayDetector()
    scan_config = load_scan_config(policy) if policy else ScanConfig()
    control_plane_tenant_id = (os.environ.get("AGENT_BOM_TENANT_ID") or "default").strip() or "default"

    def _handle_alerts_sse(alerts, log_f=None):
        for alert in alerts:
            alert_dict = alert.to_dict()
            logger.warning("Runtime alert: %s", sanitize_text(alert_dict.get("message", "runtime alert")))
            if log_f:
                write_audit_record(log_f, alert_dict)
                log_f.flush()
            if alert_webhook:
                _fire_webhook(alert_webhook, alert_dict)

    def _scan_response_sse(response: dict, subject: str) -> dict:
        safe_response, findings = scan_jsonrpc_response(response, scan_config)
        _handle_alerts_sse(_response_scan_alerts(findings, subject), log_file)
        return safe_response

    declared_tools: set[str] = set()

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Fetch tool list from the remote server
            try:
                span_cm = _PROXY_TRACER.start_as_current_span("proxy.sse_tools_list") if _PROXY_TRACER else nullcontext()
                with span_cm as span:
                    if span is not None:
                        span.set_attribute("agent_bom.proxy.upstream_url", url.rstrip("/"))
                    tools_resp = await client.post(
                        url.rstrip("/") + "/tools/list",
                        json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                        headers=_proxy_request_headers(),
                    )
                tools_resp.raise_for_status()
                tools_data = tools_resp.json()
                if isinstance(tools_data, dict) and "result" in tools_data:
                    result = tools_data["result"]
                    if isinstance(result, dict) and "tools" in result:
                        declared_tools = {t["name"] for t in result["tools"] if isinstance(t, dict) and "name" in t}
                        if span is not None:
                            span.set_attribute("agent_bom.proxy.declared_tool_count", len(declared_tools))
                        logger.info("SSE proxy: discovered %d declared tools", len(declared_tools))
            except Exception as exc:  # noqa: BLE001
                logger.warning("SSE proxy: could not fetch tools/list from %s: %s", url, sanitize_text(exc))

            # Read JSON-RPC from stdin and forward through protection engine
            reader = await create_async_stdin_reader()

            call_counter = 0
            while True:
                try:
                    line = await asyncio.wait_for(read_async_stdin_line(reader), timeout=120.0)
                except asyncio.TimeoutError:
                    logger.debug("SSE proxy: client readline timed out")
                    break
                if not line:
                    break

                if len(line) > _MAX_MESSAGE_BYTES:
                    logger.warning("SSE proxy: oversized message from client (%d bytes) — dropped", len(line))
                    continue

                line_str = line.decode("utf-8", errors="replace")
                msg = parse_jsonrpc(line_str)

                policy_subject = policy_subject_from_message(msg) if msg else None
                if not msg or not policy_subject:
                    # Non-tool-call messages (initialize, notifications, etc.) — pass through
                    try:
                        fwd = await client.post(
                            url.rstrip("/") + "/message",
                            json=msg or json.loads(line_str),
                            timeout=30,
                            headers=_proxy_request_headers(),
                        )
                        response_data = _scan_response_sse(fwd.json(), str((msg or {}).get("method", "unknown")))
                        sys.stdout.buffer.write((json.dumps(response_data) + "\n").encode())
                        sys.stdout.buffer.flush()
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("SSE proxy: pass-through failed: %s", sanitize_text(exc))
                    continue

                tool_name, arguments = policy_subject
                is_tool_call = is_tools_call(msg)
                request_trace_meta = _extract_jsonrpc_trace_meta(msg)
                msg_id = msg.get("id")
                p_hash = compute_payload_hash(msg)
                agent_id, identity_block_reason = check_identity(msg, policy)

                if identity_block_reason:
                    _reject_tool_call(
                        log_file,
                        tool_name,
                        arguments,
                        identity_block_reason,
                        payload_sha256=p_hash,
                        message_id=msg_id,
                        agent_id=agent_id,
                        tenant_id=control_plane_tenant_id,
                    )
                    continue

                if replay_detector.check(msg):
                    reason = "Replayed payload detected"
                    _reject_tool_call(
                        log_file,
                        tool_name,
                        arguments,
                        reason,
                        payload_sha256=p_hash,
                        message_id=msg_id,
                        agent_id=agent_id,
                        tenant_id=control_plane_tenant_id,
                    )
                    continue

                undeclared_reason = undeclared_tool_block_reason(block_undeclared and is_tool_call, declared_tools, tool_name)
                if undeclared_reason:
                    _reject_tool_call(
                        log_file,
                        tool_name,
                        arguments,
                        undeclared_reason,
                        payload_sha256=p_hash,
                        message_id=msg_id,
                        agent_id=agent_id,
                        tenant_id=control_plane_tenant_id,
                    )
                    continue

                if policy:
                    allowed, reason = check_policy(policy, tool_name, arguments)
                    if not allowed:
                        _reject_tool_call(
                            log_file,
                            tool_name,
                            arguments,
                            reason,
                            payload_sha256=p_hash,
                            message_id=msg_id,
                            agent_id=agent_id,
                            tenant_id=control_plane_tenant_id,
                        )
                        continue

                # Inter-agent firewall (#982 PR 3) — same hook as the stdio path.
                # SSE proxy doesn't carry a ProxyMetrics object so metrics arg is omitted.
                fw_target_id = _firewall_target_for_proxy()
                if _firewall_evaluator is not None and fw_target_id:
                    fw_outcome = await _maybe_block_on_firewall(
                        source_agent=agent_id or "unknown",
                        target_agent=fw_target_id,
                        tool_name=tool_name,
                        arguments=arguments,
                        log_file=log_file,
                        payload_sha256=p_hash,
                        message_id=msg_id,
                        tenant_id=control_plane_tenant_id,
                    )
                    if fw_outcome is not None:
                        error_resp = make_error_response(msg_id, -32600, fw_outcome)
                        sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                        sys.stdout.buffer.flush()
                        continue

                # Argument analysis
                arg_alerts = arg_analyzer.check(tool_name, arguments)
                _handle_alerts_sse(arg_alerts, log_file)

                # Sequence analysis
                seq_alerts = seq_analyzer.record(tool_name)
                _handle_alerts_sse(seq_alerts, log_file)

                # Inline content scanning
                if scan_config.enabled:
                    from agent_bom.runtime.detectors import Alert, AlertSeverity

                    s_results = scan_tool_call(tool_name, arguments, scan_config)
                    for sr in s_results:
                        alert = Alert(
                            detector=f"scanner:{sr.scanner}",
                            severity=AlertSeverity.CRITICAL
                            if sr.severity == "critical"
                            else (AlertSeverity.HIGH if sr.severity == "high" else AlertSeverity.MEDIUM),
                            message=f"Inline scan: {sr.scanner}/{sr.rule_id} in tool '{tool_name}'",
                            details={"rule_id": sr.rule_id, "excerpt": sr.excerpt, "confidence": sr.confidence},
                        )
                        _handle_alerts_sse([alert], log_file)
                    if scan_config.mode == "enforce" and any(sr.blocked for sr in s_results):
                        first = next(sr for sr in s_results if sr.blocked)
                        reason = f"Blocked by inline scanner: {first.scanner}/{first.rule_id}"
                        _reject_tool_call(
                            log_file,
                            tool_name,
                            arguments,
                            reason,
                            payload_sha256=p_hash,
                            message_id=msg_id,
                            agent_id=agent_id,
                            tenant_id=control_plane_tenant_id,
                        )
                        continue

                if log_file:
                    log_tool_call(
                        log_file,
                        tool_name,
                        arguments,
                        "allowed",
                        payload_sha256=p_hash,
                        message_id=msg_id,
                        agent_id=agent_id,
                        tenant_id=control_plane_tenant_id,
                    )  # type: ignore[arg-type]

                # Forward the gated JSON-RPC request to the remote SSE/HTTP
                # server. Tool calls use the compatibility /tools/call path;
                # resources/prompts/sampling/extension methods retain their
                # original method and go through the generic /message path.
                call_counter += 1
                try:
                    span_name = "proxy.sse_tools_call" if is_tool_call else "proxy.sse_gated_message"
                    span_cm = _PROXY_TRACER.start_as_current_span(span_name) if _PROXY_TRACER else nullcontext()
                    with span_cm as span:
                        if span is not None:
                            span.set_attribute("agent_bom.proxy.subject", tool_name)
                            span.set_attribute("agent_bom.proxy.method", msg.get("method", "unknown"))
                            span.set_attribute("agent_bom.proxy.call_counter", call_counter)
                            set_langfuse_runtime_attributes(
                                span,
                                surface="proxy",
                                tenant_id=control_plane_tenant_id,
                                method=str(msg.get("method", "unknown")),
                                tool_name=tool_name,
                                decision="allowed",
                                agent_id=agent_id,
                                trace_id=str(request_trace_meta.get("trace_id") or ""),
                                arguments=arguments,
                            )
                        forwarded_message = _inject_jsonrpc_trace_meta(
                            msg,
                            traceparent=request_trace_meta.get("traceparent"),
                            tracestate=request_trace_meta.get("tracestate"),
                            baggage=request_trace_meta.get("baggage"),
                        )
                        forward_path = "/tools/call" if is_tool_call else "/message"
                        resp = await client.post(
                            url.rstrip("/") + forward_path,
                            json=forwarded_message,
                            timeout=30,
                            headers=_proxy_request_headers(
                                traceparent=request_trace_meta.get("traceparent"),
                                tracestate=request_trace_meta.get("tracestate"),
                                baggage=request_trace_meta.get("baggage"),
                            ),
                        )
                    resp.raise_for_status()
                    response_data = resp.json()
                except httpx.HTTPStatusError as exc:
                    logger.warning("SSE proxy: server returned %d for %s: %s", exc.response.status_code, tool_name, sanitize_text(exc))
                    error_resp = make_error_response(msg_id, -32603, f"Upstream server error: {exc.response.status_code}")
                    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                    sys.stdout.buffer.flush()
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.warning("SSE proxy: connection error for %s: %s", tool_name, sanitize_text(exc))
                    error_resp = make_error_response(msg_id, -32603, "Upstream connection error")
                    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                    sys.stdout.buffer.flush()
                    continue

                # Process response through protection engine
                resp_text = json.dumps(response_data.get("result", response_data))
                from agent_bom.runtime.detectors import CredentialLeakDetector, ResponseInspector

                cred_alerts = CredentialLeakDetector().check(tool_name, resp_text)
                _handle_alerts_sse(cred_alerts, log_file)
                ri_alerts = ResponseInspector().check(tool_name, resp_text)
                _handle_alerts_sse(ri_alerts, log_file)

                response_data = _scan_response_sse(response_data, tool_name)
                response_data = _stitch_jsonrpc_trace_meta(response_data, request_trace_meta)
                sys.stdout.buffer.write((json.dumps(response_data) + "\n").encode())
                sys.stdout.buffer.flush()

    finally:
        if log_file:
            log_file.close()

    return 0


async def _reap_server(process: asyncio.subprocess.Process, *, grace_seconds: float = 1.0) -> None:
    """Allow the child watcher to observe normal exit before signaling a server.

    Stream EOF can precede the watcher callback. Signaling during that window
    races Python 3.11's waitpid ownership and can replace the real status with
    255 (CPython issue 87744). Unresponsive servers still receive TERM/KILL.
    """
    try:
        await asyncio.wait_for(process.wait(), timeout=grace_seconds)
        return
    except asyncio.TimeoutError:
        pass
    if process.returncode is None:
        try:
            process.terminate()
        except ProcessLookupError:
            pass  # The watcher still owns collecting the exit status.
    try:
        await asyncio.wait_for(process.wait(), timeout=5.0)
    except asyncio.TimeoutError:
        if process.returncode is None:
            try:
                process.kill()
            except ProcessLookupError:
                pass
        await process.wait()


async def run_proxy(
    server_cmd: list[str],
    policy_path: Optional[str] = None,
    log_path: Optional[str] = None,
    block_undeclared: bool = False,
    detect_credentials: bool = False,
    detect_visual_leaks: bool = False,
    rate_limit_threshold: int = 0,
    log_only: bool = False,
    alert_webhook: Optional[str] = None,
    metrics_port: int = 8422,
    metrics_token: Optional[str] = None,
    control_plane_url: Optional[str] = None,
    control_plane_token: Optional[str] = None,
    policy_refresh_seconds: int = 30,
    audit_push_interval: int = 10,
    response_signing_key: Optional[str] = None,
    sandbox_config: SandboxConfig | None = None,
    firewall_gateway_url: Optional[str] = None,
    firewall_gateway_token: Optional[str] = None,
    firewall_local_policy_path: Optional[str] = None,
    firewall_target_id: Optional[str] = None,
    firewall_cache_ttl_seconds: float = 60.0,
    firewall_fail_mode: str = "open",
) -> int:
    """Main proxy loop. Spawns server subprocess, relays JSON-RPC.

    Args:
        server_cmd: Command to spawn the MCP server.
        policy_path: Path to policy JSON file.
        log_path: Path to audit JSONL log.
        block_undeclared: Block tools not in initial tools/list.
        detect_credentials: Enable credential leak detection in responses.
        detect_visual_leaks: Enable OCR-based credential/PII detection on
            image tool responses (Playwright-MCP, Puppeteer-MCP, screen
            capture tools — see issue #1568). Requires the ``visual`` extra
            and tesseract on PATH; startup now fails closed when requested
            without the OCR runtime.
        rate_limit_threshold: Max calls per tool per 60s (0 = disabled).
        log_only: Log alerts without blocking (advisory mode).
        alert_webhook: Optional webhook URL for runtime alert notifications.
        metrics_token: Optional bearer token for Prometheus /metrics endpoint.
        control_plane_url: Optional control-plane URL for policy pull and audit push.
        control_plane_token: Optional bearer/API token for control-plane auth.
        sandbox_config: Optional container isolation posture for stdio MCP servers.

    Returns the server process exit code.
    """
    policy: dict = _load_proxy_policy(policy_path)
    log_file = RotatingAuditLog(log_path) if log_path else None  # 0o600, symlink-refusing, rotates at 100 MB
    metrics, status_strip_active = _proxy_session.start_metrics(sys.modules[__name__])
    metrics_server = ProxyMetricsServer(metrics, port=metrics_port, token=metrics_token)
    await metrics_server.start()
    detectors = _proxy_session.build_detectors(
        sys.modules[__name__],
        policy,
        detect_credentials=detect_credentials,
        detect_visual_leaks=detect_visual_leaks,
        rate_limit_threshold=rate_limit_threshold,
    )
    options = _proxy_session.RelayOptions(
        block_undeclared=block_undeclared,
        log_only=log_only,
        rate_limit_threshold=rate_limit_threshold,
        alert_webhook=alert_webhook,
        response_signing_key=response_signing_key,
        policy_refresh_seconds=policy_refresh_seconds,
    )
    session = _compose_session(policy, log_file, metrics, detectors, options, control_plane_url, control_plane_token, audit_push_interval)
    await session.connect_control_plane()
    firewall_client = _build_firewall_client(
        firewall_target_id,
        firewall_gateway_url,
        firewall_gateway_token,
        firewall_local_policy_path,
        firewall_cache_ttl_seconds,
        firewall_fail_mode,
    )
    teardown = _SessionTeardown(status_strip_active, metrics_server, firewall_client)
    return await _supervise_session(session, server_cmd, sandbox_config, teardown)


def _compose_session(
    policy: dict,
    log_file: RotatingAuditLog | None,
    metrics: ProxyMetrics,
    detectors: _proxy_session.RuntimeDetectors,
    options: _proxy_session.RelayOptions,
    control_plane_url: str | None,
    control_plane_token: str | None,
    audit_push_interval: int,
) -> _proxy_session.ProxySession:
    scan_config = load_scan_config(policy) if policy else ScanConfig()
    source_id = _generate_proxy_source_id()
    session_id = str(uuid.uuid4())
    tenant_id = (os.environ.get("AGENT_BOM_TENANT_ID") or "default").strip() or "default"
    cache_path = _gateway_policy_cache_path()
    cache_max_age_seconds = max(60, int(os.environ.get("AGENT_BOM_PROXY_POLICY_CACHE_MAX_AGE_SECONDS", "3600")))
    audit = _build_audit_delivery(control_plane_url, tenant_id, source_id, audit_push_interval)
    control = _proxy_session.ControlPlane(
        url=control_plane_url,
        token=control_plane_token,
        tenant_id=tenant_id,
        source_id=source_id,
        session_id=session_id,
        cache_path=cache_path,
        cache_max_age_seconds=cache_max_age_seconds,
    )
    return _proxy_session.ProxySession(
        host=sys.modules[__name__],
        policy=policy,
        log_file=log_file,
        metrics=metrics,
        detectors=detectors,
        scan_config=scan_config,
        options=options,
        control=control,
        audit=audit,
    )


@dataclass
class _SessionTeardown:
    status_strip_active: bool
    metrics_server: ProxyMetricsServer
    firewall_client: Any
    tasks: tuple[asyncio.Task | None, ...] = ()


@dataclass
class _ShutdownRequest:
    """SIGTERM cancels the owning task once so the relay unwinds through teardown."""

    owner_task: asyncio.Task | None
    signal_number: int = 0

    def request(self) -> None:
        if not self.signal_number and self.owner_task is not None:
            self.signal_number = signal.SIGTERM
            self.owner_task.cancel()


async def _supervise_session(
    session: _proxy_session.ProxySession,
    server_cmd: list[str],
    sandbox_config: SandboxConfig | None,
    teardown: _SessionTeardown,
) -> int:
    """Spawn the server, run both relays until either side closes, then tear down."""
    log_file = session.log_file
    server_cmd, sandbox_evidence = _prepare_server_command(server_cmd, sandbox_config, log_file)
    process = await asyncio.create_subprocess_exec(
        *server_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=_MAX_MESSAGE_BYTES + 1,
    )
    session.process = process
    sandbox_timeout_task = _start_sandbox_timeout(process, sandbox_config, sandbox_evidence, log_file)
    refresh_task = asyncio.create_task(session.policy_refresh_loop()) if session.control.url else None
    audit_task = asyncio.create_task(session.audit_push_loop()) if session.control.url else None
    teardown.tasks = (audit_task, refresh_task, sandbox_timeout_task)

    loop = asyncio.get_running_loop()
    shutdown = _ShutdownRequest(asyncio.current_task())
    previous_sigterm = signal.getsignal(signal.SIGTERM)
    signal_installed = False
    try:
        loop.add_signal_handler(signal.SIGTERM, shutdown.request)
        signal_installed = True
    except (NotImplementedError, RuntimeError, ValueError):
        pass  # Non-POSIX platforms and embedded non-main-thread event loops.

    try:
        results = await asyncio.gather(
            _proxy_relay.relay_client_to_server(session),
            _proxy_relay.relay_server_to_client(session),
            _proxy_relay.forward_stderr(session),
            return_exceptions=True,
        )
        _record_relay_errors(list(results), session.metrics, log_file)
    except asyncio.CancelledError:
        if not shutdown.signal_number:
            raise
    finally:
        # Reap first: slow audit delivery must not orphan an upstream on TERM.
        try:
            await _reap_server(process)
        finally:
            if signal_installed:
                loop.remove_signal_handler(signal.SIGTERM)
                signal.signal(signal.SIGTERM, previous_sigterm)
        await _close_session(session, sandbox_evidence, teardown)

    return 128 + shutdown.signal_number if shutdown.signal_number else process.returncode or 0


async def _close_session(session: _proxy_session.ProxySession, sandbox_evidence: Mapping[str, object], teardown: _SessionTeardown) -> None:
    """Write the run summary, drain audit delivery, and release every runtime hook."""
    if teardown.status_strip_active:
        sys.stderr.write("\n")
        sys.stderr.flush()
    summary = session.metrics.summary()
    summary.update(summarize_runtime_alerts(session.runtime_alerts))
    summary["execution_posture"] = _execution_posture(sandbox_evidence)
    for task in teardown.tasks:
        if task:
            task.cancel()
    if session.control.url:
        await session.flush_audit_buffer(summary=summary)
    if session.log_file:
        write_audit_record(session.log_file, summary)
        session.log_file.close()
    await teardown.metrics_server.stop()
    set_gateway_evaluator(None)
    clear_firewall_evaluator()
    if teardown.firewall_client is not None:
        await teardown.firewall_client.aclose()
