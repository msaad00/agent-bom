"""MCP runtime proxy — intercept JSON-RPC between client and server.

A stdio proxy that sits between an MCP client (Claude Desktop, Cursor, etc.)
and an MCP server. It intercepts all JSON-RPC messages, logs tool call
invocations, compares actual usage against declared capabilities, and
optionally enforces security policy in real-time.

Usage:
    agent-bom proxy [--policy policy.json] [--log audit.jsonl] -- npx @mcp/server-filesystem /tmp
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import platform
import sys
import tempfile
import time
import uuid
from contextlib import nullcontext
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING, Mapping, Optional

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
from agent_bom.proxy_sandbox import SandboxConfig, build_sandboxed_command
from agent_bom.proxy_scanner import ScanConfig, load_scan_config, scan_tool_call, scan_tool_response
from agent_bom.security import validate_arguments, validate_command

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
AuditSpilloverStore = _proxy_audit.AuditSpilloverStore
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
    """Extract the tool name from a tools/call request."""
    params = msg.get("params", {})
    return params.get("name")


def extract_tool_arguments(msg: dict) -> dict:
    """Extract tool arguments from a tools/call request."""
    params = msg.get("params", {})
    return params.get("arguments", {})


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


def sandbox_posture_warning(sandbox_evidence: Mapping[str, object]) -> str | None:
    """Return an operator-visible warning when proxy isolation is not active."""
    if sandbox_evidence.get("enabled"):
        return None
    return (
        "agent-bom proxy warning: sandbox isolation is disabled; the MCP server "
        "runs as the current host user. Set AGENT_BOM_MCP_SANDBOX=1 or pass "
        "--sandbox to run the server in a restricted container."
    )


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


def _sanitize_for_log(value: object) -> str:
    return str(value).replace("\r", "").replace("\n", "")


def _generate_proxy_source_id() -> str:
    hostname = platform.node() or "unknown"
    return hashlib.sha256(hostname.encode()).hexdigest()[:12]


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


def _inject_jsonrpc_trace_meta(
    message: dict[str, object],
    *,
    traceparent: str | None = None,
    tracestate: str | None = None,
    baggage: str | None = None,
) -> dict[str, object]:
    """Return a JSON-RPC message with bounded W3C trace context in `_meta`."""
    if not traceparent and not tracestate and not baggage:
        return message
    enriched = dict(message)
    raw_meta = message.get("_meta")
    meta = dict(raw_meta) if isinstance(raw_meta, dict) else {}
    if traceparent:
        meta["traceparent"] = traceparent
    if tracestate:
        meta["tracestate"] = tracestate
    if baggage:
        meta["baggage"] = baggage
    enriched["_meta"] = meta
    return enriched


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
    return Path.home() / ".agent-bom" / "cache" / "gateway-policies.json"


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
    pem = os.environ.get(_PROXY_POLICY_CACHE_SIGNING_ENV_VAR, "").strip()
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
        logger.error("%s could not be parsed: %s", _PROXY_POLICY_CACHE_SIGNING_ENV_VAR, exc)
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
        logger.warning("Ignoring unreadable gateway policy cache %s: %s", cache_path, exc)
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
    if os.environ.get(_PROXY_POLICY_CACHE_SIGNING_ENV_VAR, "").strip():
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
            logger.warning("Ignoring unreadable gateway policy cache signature %s: %s", signature_path, exc)
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
            logger.warning("Ignoring gateway policy cache %s with invalid signature: %s", cache_path, exc)
            return None, None

    try:
        policies = [GatewayPolicy(**item) for item in payload.get("policies", [])]
    except Exception as exc:  # noqa: BLE001
        logger.warning("Ignoring invalid gateway policy cache %s: %s", cache_path, exc)
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
        logger.warning("Failed to persist gateway policy cache %s: %s", cache_path, exc)


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


def _evaluate_gateway_policy_bundle(policies: list["GatewayPolicy"], agent_name: str, tool_name: str, arguments: dict) -> tuple[bool, str]:
    from agent_bom.gateway import evaluate_gateway_policies

    scoped = []
    for policy in policies:
        if getattr(policy, "bound_agents", None) and agent_name not in getattr(policy, "bound_agents", []):
            continue
        scoped.append(policy)
    allowed, reason, _policy_id = evaluate_gateway_policies(scoped, tool_name, arguments)
    return allowed, reason


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


async def _send_webhook(url: str, payload: dict) -> None:
    """Fire-and-forget POST to an alert webhook URL.

    Validates the URL before sending to prevent SSRF via --alert-webhook.
    """
    from agent_bom.security import SecurityError, validate_url

    try:
        validate_url(url)
    except SecurityError as e:
        logger.warning("Webhook URL rejected: %s", e)
        return

    try:
        import httpx

        async with httpx.AsyncClient(timeout=httpx.Timeout(connect=5.0, read=10.0, write=10.0, pool=5.0)) as client:
            await client.post(url, json=payload)
    except Exception:  # noqa: BLE001
        logger.debug("Failed to send webhook to %s", url)


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
            logger.error("Failed to load policy from %s: %s", policy_path, exc)
            return 1

    # Open audit log
    log_file = None
    if log_path:
        log_file = RotatingAuditLog(log_path)

    arg_analyzer = ArgumentAnalyzer()
    seq_analyzer = SequenceAnalyzer()
    replay_detector = ReplayDetector()
    scan_config = load_scan_config(policy) if policy else ScanConfig()
    runtime_alerts: list[dict] = []
    control_plane_tenant_id = (os.environ.get("AGENT_BOM_TENANT_ID") or "default").strip() or "default"

    def _handle_alerts_sse(alerts, log_f=None):
        for alert in alerts:
            alert_dict = alert.to_dict()
            runtime_alerts.append(alert_dict)
            logger.warning("Runtime alert: %s", alert_dict.get("message", "runtime alert"))
            if log_f:
                write_audit_record(log_f, alert_dict)
                log_f.flush()
            if alert_webhook:
                asyncio.ensure_future(_send_webhook(alert_webhook, alert_dict))

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
                logger.warning("SSE proxy: could not fetch tools/list from %s: %s", url, exc)

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

                if not msg or not is_tools_call(msg):
                    # Non-tool-call messages (initialize, notifications, etc.) — pass through
                    try:
                        fwd = await client.post(
                            url.rstrip("/") + "/message",
                            json=msg or json.loads(line_str),
                            timeout=30,
                            headers=_proxy_request_headers(),
                        )
                        sys.stdout.buffer.write((json.dumps(fwd.json()) + "\n").encode())
                        sys.stdout.buffer.flush()
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("SSE proxy: pass-through failed: %s", exc)
                    continue

                tool_name = extract_tool_name(msg) or "unknown"
                request_trace_meta = _extract_jsonrpc_trace_meta(msg)
                arguments = extract_tool_arguments(msg)
                msg_id = msg.get("id")
                p_hash = compute_payload_hash(msg)
                agent_id, identity_block_reason = check_identity(msg, policy)

                if identity_block_reason:
                    if log_file:
                        log_tool_call(
                            log_file,
                            tool_name,
                            arguments,
                            "blocked",
                            identity_block_reason,
                            payload_sha256=p_hash,
                            message_id=msg_id,
                            agent_id=agent_id,
                            tenant_id=control_plane_tenant_id,
                        )
                    error_resp = make_error_response(msg_id, -32600, identity_block_reason)
                    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                    sys.stdout.buffer.flush()
                    continue

                if replay_detector.check(msg):
                    reason = "Replayed payload detected"
                    if log_file:
                        log_tool_call(
                            log_file,
                            tool_name,
                            arguments,
                            "blocked",
                            reason,
                            payload_sha256=p_hash,
                            message_id=msg_id,
                            agent_id=agent_id,
                            tenant_id=control_plane_tenant_id,
                        )
                    error_resp = make_error_response(msg_id, -32600, reason)
                    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                    sys.stdout.buffer.flush()
                    continue

                if block_undeclared and declared_tools and tool_name not in declared_tools:
                    reason = f"Tool '{tool_name}' not in declared tools/list"
                    if log_file:
                        log_tool_call(
                            log_file,
                            tool_name,
                            arguments,
                            "blocked",
                            reason,
                            payload_sha256=p_hash,
                            message_id=msg_id,
                            agent_id=agent_id,
                            tenant_id=control_plane_tenant_id,
                        )
                    error_resp = make_error_response(msg_id, -32600, reason)
                    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                    sys.stdout.buffer.flush()
                    continue

                if policy:
                    allowed, reason = check_policy(policy, tool_name, arguments)
                    if not allowed:
                        if log_file:
                            log_tool_call(
                                log_file,
                                tool_name,
                                arguments,
                                "blocked",
                                reason,
                                payload_sha256=p_hash,
                                message_id=msg_id,
                                agent_id=agent_id,
                                tenant_id=control_plane_tenant_id,
                            )
                        error_resp = make_error_response(msg_id, -32600, reason)
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
                        if log_file:
                            log_tool_call(
                                log_file,
                                tool_name,
                                arguments,
                                "blocked",
                                reason,
                                payload_sha256=p_hash,
                                message_id=msg_id,
                                agent_id=agent_id,
                                tenant_id=control_plane_tenant_id,
                            )
                        error_resp = make_error_response(msg_id, -32600, reason)
                        sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                        sys.stdout.buffer.flush()
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

                # Forward tool call to remote SSE/HTTP server
                call_counter += 1
                try:
                    span_cm = _PROXY_TRACER.start_as_current_span("proxy.sse_tools_call") if _PROXY_TRACER else nullcontext()
                    with span_cm as span:
                        if span is not None:
                            span.set_attribute("agent_bom.proxy.tool_name", tool_name)
                            span.set_attribute("agent_bom.proxy.call_counter", call_counter)
                        forwarded_message = _inject_jsonrpc_trace_meta(
                            msg,
                            traceparent=request_trace_meta.get("traceparent"),
                            tracestate=request_trace_meta.get("tracestate"),
                            baggage=request_trace_meta.get("baggage"),
                        )
                        resp = await client.post(
                            url.rstrip("/") + "/tools/call",
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
                    logger.warning("SSE proxy: server returned %d for %s: %s", exc.response.status_code, tool_name, exc)
                    error_resp = make_error_response(msg_id, -32603, f"Upstream server error: {exc.response.status_code}")
                    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                    sys.stdout.buffer.flush()
                    continue
                except Exception as exc:  # noqa: BLE001
                    logger.warning("SSE proxy: connection error for %s: %s", tool_name, exc)
                    error_resp = make_error_response(msg_id, -32603, f"Upstream connection error: {exc}")
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

                response_data = _stitch_jsonrpc_trace_meta(response_data, request_trace_meta)
                sys.stdout.buffer.write((json.dumps(response_data) + "\n").encode())
                sys.stdout.buffer.flush()

    finally:
        if log_file:
            log_file.close()

    return 0


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
    # Load policy if provided — use validate_json_file for path validation,
    # 10 MB size cap (DoS prevention), and safe JSON parsing.
    policy: dict = {}
    if policy_path:
        try:
            from agent_bom.security import SecurityError, validate_json_file

            policy = validate_json_file(Path(policy_path))
        except (json.JSONDecodeError, OSError, SecurityError) as exc:
            logger.error("Failed to load policy from %s: %s", policy_path, exc)
            raise SystemExit(1) from exc

    # Open audit log with restricted permissions (0o600)
    # Reject symlinks to prevent log injection attacks (attacker creates
    # symlink to overwrite another file via the proxy's audit writes).
    # RotatingAuditLog handles automatic rotation at 100 MB.
    log_file = None
    if log_path:
        log_file = RotatingAuditLog(log_path)

    # Metrics
    metrics = ProxyMetrics()

    # Prometheus metrics server
    metrics_server = ProxyMetricsServer(metrics, port=metrics_port, token=metrics_token)
    await metrics_server.start()

    # Runtime detectors
    from agent_bom.runtime.detectors import (
        ArgumentAnalyzer,
        CredentialLeakDetector,
        RateLimitTracker,
        ResponseInspector,
        SequenceAnalyzer,
        ToolDriftDetector,
        VectorDBInjectionDetector,
    )

    drift_detector = ToolDriftDetector()
    arg_analyzer = ArgumentAnalyzer()
    cred_detector = CredentialLeakDetector() if detect_credentials else None
    visual_detector = None
    if detect_visual_leaks:
        from agent_bom.runtime.visual_leak_detector import VisualLeakDetector, require_visual_leak_runtime

        require_visual_leak_runtime()
        visual_detector = VisualLeakDetector()
    local_policy_rate_limit = resolve_rate_limit_threshold(policy) if policy else None
    effective_rate_limit_threshold = rate_limit_threshold or local_policy_rate_limit or 0
    rate_tracker = RateLimitTracker(threshold=max(effective_rate_limit_threshold, 0))
    seq_analyzer = SequenceAnalyzer()
    response_inspector = ResponseInspector()
    vector_detector = VectorDBInjectionDetector()
    replay_detector = ReplayDetector()
    scan_config = load_scan_config(policy) if policy else ScanConfig()
    runtime_alerts: list[dict] = []
    control_plane_source_id = _generate_proxy_source_id()
    control_plane_session_id = str(uuid.uuid4())
    control_plane_tenant_id = (os.environ.get("AGENT_BOM_TENANT_ID") or "default").strip() or "default"
    control_plane_policies: list["GatewayPolicy"] = []
    control_plane_etag: str | None = None
    control_plane_policy_cache_path = _gateway_policy_cache_path()
    control_plane_policy_cache_max_age_seconds = max(
        60,
        int(os.environ.get("AGENT_BOM_PROXY_POLICY_CACHE_MAX_AGE_SECONDS", "3600")),
    )
    audit_buffer: list[dict] = []
    audit_buffer_bytes = 0
    audit_lock = asyncio.Lock()
    max_audit_buffer_bytes = max(64 * 1024, int(os.environ.get("AGENT_BOM_PROXY_AUDIT_BUFFER_MAX_BYTES", "1048576")))
    max_audit_spillover_bytes = max(
        max_audit_buffer_bytes,
        int(os.environ.get("AGENT_BOM_PROXY_AUDIT_SPILLOVER_MAX_BYTES", str(max_audit_buffer_bytes * 8))),
    )
    audit_spill_path = Path(
        os.environ.get(
            "AGENT_BOM_PROXY_AUDIT_SPILLOVER_PATH",
            str(Path(tempfile.gettempdir()) / f"agent-bom-proxy-audit-{control_plane_session_id}.jsonl"),
        )
    )
    audit_dlq_path = Path(
        os.environ.get(
            "AGENT_BOM_PROXY_AUDIT_DLQ_PATH",
            str(Path(tempfile.gettempdir()) / f"agent-bom-proxy-audit-{control_plane_session_id}.dlq.jsonl"),
        )
    )
    audit_delivery = AuditDeliveryController(
        base_interval_seconds=max(audit_push_interval, 5),
        max_backoff_seconds=max(
            max(audit_push_interval, 5),
            int(os.environ.get("AGENT_BOM_PROXY_AUDIT_PUSH_BACKOFF_MAX_SECONDS", "300")),
        ),
        breaker_failure_threshold=max(
            1,
            int(os.environ.get("AGENT_BOM_PROXY_AUDIT_CIRCUIT_BREAKER_THRESHOLD", "3")),
        ),
        breaker_cooldown_seconds=max(
            max(audit_push_interval, 5),
            int(os.environ.get("AGENT_BOM_PROXY_AUDIT_CIRCUIT_BREAKER_COOLDOWN_SECONDS", "60")),
        ),
    )
    audit_spillover = AuditSpilloverStore(
        spill_path=audit_spill_path,
        dlq_path=audit_dlq_path,
        max_spillover_bytes=max_audit_spillover_bytes,
    )

    def _event_size_bytes(payload: dict) -> int:
        return len(json.dumps(payload, separators=(",", ":"), sort_keys=True).encode("utf-8"))

    def _sync_audit_metrics() -> None:
        metrics.set_audit_buffer_bytes(audit_buffer_bytes)
        metrics.set_audit_spillover_bytes(audit_spillover.spillover_size_bytes())
        metrics.set_audit_dlq_bytes(audit_spillover.dlq_size_bytes())
        metrics.set_audit_push_backoff_seconds(audit_delivery.current_backoff_seconds())
        metrics.set_audit_circuit_open(audit_delivery.is_circuit_open())

    async def _queue_control_plane_alert(alert_payload: dict) -> None:
        nonlocal audit_buffer_bytes
        event_size = _event_size_bytes(alert_payload)
        async with audit_lock:
            if audit_buffer_bytes + event_size <= max_audit_buffer_bytes:
                audit_buffer.append(alert_payload)
                audit_buffer_bytes += event_size
            else:
                destination = audit_spillover.append_events([alert_payload])
                if destination == "dlq":
                    logger.error(
                        "Proxy audit spillover exceeded %s bytes; diverting alert backlog to DLQ %s",
                        max_audit_spillover_bytes,
                        audit_dlq_path,
                    )
                else:
                    logger.warning(
                        "Proxy audit buffer exceeded %s bytes; spilling alert backlog to %s",
                        max_audit_buffer_bytes,
                        audit_spill_path,
                    )
            _sync_audit_metrics()

    async def _refresh_control_plane_policies(initial: bool = False) -> None:
        nonlocal control_plane_policies, control_plane_etag
        if not control_plane_url:
            return
        try:
            policies, next_etag = await _fetch_enabled_gateway_policies(
                control_plane_url,
                control_plane_token,
                control_plane_etag,
            )
        except Exception as exc:  # noqa: BLE001
            metrics.record_policy_fetch_failure()
            if initial:
                cached_policies, cached_etag = _load_cached_gateway_policies(
                    control_plane_policy_cache_path,
                    control_plane_policy_cache_max_age_seconds,
                )
                if cached_policies is not None:
                    control_plane_policies = cached_policies
                    control_plane_etag = cached_etag
                    logger.warning(
                        "Gateway policy fetch failed from %s; using cached bundle from %s: %s",
                        control_plane_url,
                        control_plane_policy_cache_path,
                        exc,
                    )
                else:
                    logger.error("Failed to load enabled gateway policies from %s: %s", control_plane_url, exc)
                    raise SystemExit(1) from exc
            else:
                logger.warning("Gateway policy refresh failed: %s", exc)
                return
        if policies is not None:
            control_plane_policies = policies
            _persist_gateway_policies_cache(control_plane_policy_cache_path, policies, next_etag)
        if next_etag:
            control_plane_etag = next_etag
        if rate_limit_threshold <= 0:
            control_plane_limit = _resolve_control_plane_rate_limit_threshold(control_plane_policies)
            if control_plane_limit and control_plane_limit > 0:
                rate_tracker._threshold = control_plane_limit
            else:
                rate_tracker._threshold = local_policy_rate_limit or 0

    async def _flush_audit_buffer(summary: dict | None = None) -> bool:
        nonlocal audit_buffer_bytes
        if not control_plane_url:
            return True
        async with audit_lock:
            alerts = list(audit_buffer)
            in_memory_bytes = audit_buffer_bytes
            spillover_alerts = audit_spillover.read_spillover()
            audit_buffer.clear()
            audit_buffer_bytes = 0
            _sync_audit_metrics()
        combined_alerts = spillover_alerts + alerts
        if not combined_alerts and summary is None:
            return True
        spillover_had_data = bool(spillover_alerts)
        try:
            await _push_proxy_audit_batch(
                control_plane_url,
                control_plane_token,
                control_plane_source_id,
                control_plane_session_id,
                combined_alerts,
                summary,
            )
        except Exception as exc:  # noqa: BLE001
            metrics.record_audit_push_failure()
            logger.warning("Proxy audit push failed: %s", exc)
            async with audit_lock:
                audit_buffer[:0] = alerts
                audit_buffer_bytes += in_memory_bytes
                _sync_audit_metrics()
            return False
        else:
            if spillover_had_data:
                audit_spillover.clear_spillover()
            _sync_audit_metrics()
            return True

    if control_plane_url:
        await _refresh_control_plane_policies(initial=True)

        def _control_plane_gateway_evaluator(agent_id, tool_name, arguments):
            return _evaluate_gateway_policy_bundle(control_plane_policies, agent_id, tool_name, arguments)

        set_gateway_evaluator(_control_plane_gateway_evaluator)

    async def _policy_refresh_loop() -> None:
        if not control_plane_url:
            return
        while True:
            await asyncio.sleep(max(policy_refresh_seconds, 5))
            await _refresh_control_plane_policies()

    async def _audit_push_loop() -> None:
        if not control_plane_url:
            return
        while True:
            await asyncio.sleep(audit_delivery.current_backoff_seconds())
            if audit_delivery.is_circuit_open():
                _sync_audit_metrics()
                continue
            if await _flush_audit_buffer():
                audit_delivery.record_success()
            else:
                audit_delivery.record_failure()
            _sync_audit_metrics()

    async def _handle_alerts(alerts, log_f=None):
        """Log alerts and optionally record them + dispatch webhook."""
        for alert in alerts:
            alert_dict = alert.to_dict()
            runtime_alerts.append(alert_dict)
            logger.warning("Runtime alert: %s", alert.message)
            if log_f:
                write_audit_record(log_f, alert_dict)
                log_f.flush()
            if alert_webhook:
                asyncio.ensure_future(_send_webhook(alert_webhook, alert_dict))
            if control_plane_url:
                enriched = dict(alert_dict)
                enriched.setdefault("source_id", control_plane_source_id)
                enriched.setdefault("session_id", control_plane_session_id)
                await _queue_control_plane_alert(enriched)

    # Track declared tools from tools/list responses
    declared_tools: set[str] = set()
    tools_list_request_ids: set[int | str] = set()
    # Track in-flight tool calls for latency measurement (with TTL cleanup)
    pending_calls: dict[int | str, tuple[str, float, dict[str, str]]] = {}  # id → (tool_name, start_time, trace_meta)
    pending_call_ttl = 300.0  # 5 minutes — evict orphaned entries

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
        sys.stderr.write(warning + "\n")
        logger.warning(warning)

    # Validate the effective server command before spawning
    validate_command(server_cmd[0])
    if len(server_cmd) > 1:
        validate_arguments(list(server_cmd[1:]))

    if log_file:
        write_audit_record(
            log_file,
            {
                "ts": datetime.now(timezone.utc).isoformat(),
                "type": "mcp_execution_posture",
                "execution_posture": {
                    "mode": "container_isolated" if sandbox_evidence.get("enabled") else "observation_only",
                    "sandbox_evidence": sandbox_evidence,
                },
            },
        )

    # Spawn the actual MCP server
    process = await asyncio.create_subprocess_exec(
        *server_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
        limit=_MAX_MESSAGE_BYTES + 1,
    )
    sandbox_timeout_task = None
    if sandbox_config and sandbox_config.enabled and sandbox_config.timeout_seconds:

        async def _sandbox_timeout_watchdog() -> None:
            await asyncio.sleep(sandbox_config.timeout_seconds or 0)
            if process.returncode is None:
                logger.error("MCP sandbox timeout reached after %s seconds; terminating server", sandbox_config.timeout_seconds)
                if log_file:
                    write_audit_record(
                        log_file,
                        {
                            "ts": datetime.now(timezone.utc).isoformat(),
                            "type": "mcp_sandbox_timeout",
                            "timeout_seconds": sandbox_config.timeout_seconds,
                            "execution_posture": {
                                "mode": "container_isolated",
                                "sandbox_evidence": sandbox_evidence,
                            },
                        },
                    )
                process.terminate()

        sandbox_timeout_task = asyncio.create_task(_sandbox_timeout_watchdog())

    async def relay_client_to_server():
        """Read from our stdin, forward to server stdin."""
        reader = await create_async_stdin_reader()

        while True:
            try:
                line = await asyncio.wait_for(read_async_stdin_line(reader), timeout=120.0)
            except asyncio.TimeoutError:
                logger.debug("Client readline timed out — closing relay")
                break
            if not line:
                break

            if len(line) > _MAX_MESSAGE_BYTES:
                logger.warning("Oversized message from client (%d bytes) — dropped", len(line))
                continue

            line_str = line.decode("utf-8", errors="replace")
            msg = parse_jsonrpc(line_str)
            request_trace_meta = _extract_jsonrpc_trace_meta(msg) if msg else {}

            if msg:
                metrics.total_messages_client_to_server += 1

                # Track tools/list requests so we can identify responses
                if msg.get("method") == "tools/list" and "id" in msg:
                    tools_list_request_ids.add(msg["id"])

                # Intercept policy-gated JSON-RPC requests.
                policy_subject = policy_subject_from_message(msg)
                if policy_subject:
                    tool_name, arguments = policy_subject
                    msg_id = msg.get("id")

                    # Payload integrity: hash the full message
                    p_hash = compute_payload_hash(msg)

                    # Agent identity: extract + resolve from _meta.agent_identity
                    agent_id, identity_block_reason = check_identity(msg, policy)
                    if identity_block_reason:
                        metrics.record_blocked("identity")
                        if log_file:
                            log_tool_call(
                                log_file,
                                tool_name,
                                arguments,
                                "blocked",
                                identity_block_reason,
                                payload_sha256=p_hash,
                                message_id=msg_id,
                                agent_id=agent_id,
                                tenant_id=control_plane_tenant_id,
                            )
                        error_resp = make_error_response(msg_id, -32600, identity_block_reason)
                        sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                        sys.stdout.buffer.flush()
                        continue

                    # Replay detection
                    if replay_detector.check(msg):
                        metrics.replay_rejections += 1
                        reason = "Replayed payload detected"
                        if not log_only:
                            metrics.record_blocked("replay")
                            if log_file:
                                log_tool_call(
                                    log_file,
                                    tool_name,
                                    arguments,
                                    "blocked",
                                    reason,
                                    payload_sha256=p_hash,
                                    message_id=msg_id,
                                    agent_id=agent_id,
                                    tenant_id=control_plane_tenant_id,
                                )
                            error_resp = make_error_response(msg_id, -32600, reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue
                        # log_only: warn but don't block
                        logger.warning("Replay detected (advisory): %s", tool_name)

                    # Check if tool is declared
                    if block_undeclared and declared_tools and tool_name not in declared_tools:
                        reason = f"Tool '{tool_name}' not in declared tools/list"
                        metrics.record_blocked("undeclared")
                        if log_file:
                            log_tool_call(
                                log_file,
                                tool_name,
                                arguments,
                                "blocked",
                                reason,
                                payload_sha256=p_hash,
                                message_id=msg_id,
                                agent_id=agent_id,
                                tenant_id=control_plane_tenant_id,
                            )
                        error_resp = make_error_response(msg_id, -32600, reason)
                        sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                        sys.stdout.buffer.flush()
                        continue

                    # Check policy
                    if policy:
                        allowed, reason = check_policy(policy, tool_name, arguments)
                        if not allowed:
                            metrics.record_blocked("policy")
                            if log_file:
                                log_tool_call(
                                    log_file,
                                    tool_name,
                                    arguments,
                                    "blocked",
                                    reason,
                                    payload_sha256=p_hash,
                                    message_id=msg_id,
                                    agent_id=agent_id,
                                    tenant_id=control_plane_tenant_id,
                                )
                            error_resp = make_error_response(msg.get("id"), -32600, reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue

                    # Gateway policy evaluation
                    if _gateway_evaluator is not None:
                        gw_allowed, gw_reason = _gateway_evaluator(agent_id, tool_name, arguments)
                        if not gw_allowed:
                            metrics.record_blocked("gateway_policy")
                            if log_file:
                                log_tool_call(
                                    log_file,
                                    tool_name,
                                    arguments,
                                    "blocked",
                                    gw_reason,
                                    payload_sha256=p_hash,
                                    message_id=msg_id,
                                    agent_id=agent_id,
                                    tenant_id=control_plane_tenant_id,
                                )
                            error_resp = make_error_response(msg.get("id"), -32600, gw_reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue

                    # Runtime detectors: argument analysis
                    arg_alerts = arg_analyzer.check(tool_name, arguments)
                    await _handle_alerts(arg_alerts, log_file)

                    # Runtime detectors: rate limiting
                    effective_rule_rate_limit = 0
                    if _gateway_evaluator is not None and control_plane_policies:
                        effective_rule_rate_limit = _resolve_control_plane_rate_limit_threshold(control_plane_policies, agent_id) or 0
                    if effective_rule_rate_limit <= 0 and local_policy_rate_limit:
                        effective_rule_rate_limit = local_policy_rate_limit
                    if rate_limit_threshold > 0:
                        effective_rule_rate_limit = rate_limit_threshold
                    if rate_tracker and effective_rule_rate_limit > 0:
                        rate_alerts = rate_tracker.record(tool_name, threshold=effective_rule_rate_limit)
                        await _handle_alerts(rate_alerts, log_file)
                        if rate_alerts and not log_only:
                            rl_reason = rate_alerts[0].message
                            metrics.record_blocked("rate_limit")
                            if log_file:
                                log_tool_call(
                                    log_file,
                                    tool_name,
                                    arguments,
                                    "blocked",
                                    rl_reason,
                                    payload_sha256=p_hash,
                                    message_id=msg_id,
                                    agent_id=agent_id,
                                    tenant_id=control_plane_tenant_id,
                                )
                            error_resp = make_error_response(msg_id, -32600, rl_reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue

                    # Runtime detectors: sequence analysis
                    seq_alerts = seq_analyzer.record(tool_name)
                    await _handle_alerts(seq_alerts, log_file)

                    # Inline content scanning (prompt injection, PII, secrets, payload vuln)
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
                            await _handle_alerts([alert], log_file)
                        if scan_config.mode == "enforce" and any(sr.blocked for sr in s_results):
                            first = next(sr for sr in s_results if sr.blocked)
                            reason = f"Blocked by inline scanner: {first.scanner}/{first.rule_id}"
                            metrics.record_blocked(f"scanner:{first.scanner}")
                            if log_file:
                                log_tool_call(
                                    log_file,
                                    tool_name,
                                    arguments,
                                    "blocked",
                                    reason,
                                    payload_sha256=p_hash,
                                    message_id=msg_id,
                                    agent_id=agent_id,
                                    tenant_id=control_plane_tenant_id,
                                )
                            error_resp = make_error_response(msg_id, -32600, reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue

                    # Record allowed call + start latency timer
                    metrics.record_call(tool_name)
                    if "id" in msg:
                        pending_calls[msg["id"]] = (tool_name, time.monotonic(), request_trace_meta)

                    # Log allowed call with integrity fields
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
                        )

            span_cm = _PROXY_TRACER.start_as_current_span("proxy.relay_client_to_server") if (msg and _PROXY_TRACER) else nullcontext()
            with span_cm as span:
                if span is not None and msg is not None:
                    span.set_attribute("agent_bom.proxy.message_kind", msg.get("method", "unknown"))
                    if is_tools_call(msg):
                        span.set_attribute("agent_bom.proxy.tool_name", extract_tool_name(msg) or "unknown")
                # Forward to server
                if process.stdin:
                    if msg is not None:
                        forwarded_message = _inject_jsonrpc_trace_meta(
                            msg,
                            traceparent=request_trace_meta.get("traceparent"),
                            tracestate=request_trace_meta.get("tracestate"),
                            baggage=request_trace_meta.get("baggage"),
                        )
                        line = (json.dumps(forwarded_message) + "\n").encode()
                    process.stdin.write(line)
                    await process.stdin.drain()

    async def relay_server_to_client():
        """Read from server stdout, forward to our stdout."""
        while True:
            if not process.stdout:
                break
            line = await _read_bounded_line(process.stdout)
            if line is None:
                logger.warning("Oversized message from server exceeded %d bytes; dropped", _MAX_MESSAGE_BYTES)
                continue
            if not line:
                break

            line_str = line.decode("utf-8", errors="replace")
            msg = parse_jsonrpc(line_str)

            if msg:
                metrics.total_messages_server_to_client += 1

                # Capture tools/list responses to track declared tools
                if is_tools_list_response(msg):
                    new_tools = extract_declared_tools(msg)
                    declared_tools.update(new_tools)
                    logger.debug("Declared tools updated: %s", declared_tools)

                    # Runtime detector: tool drift
                    drift_alerts = drift_detector.check(new_tools)
                    await _handle_alerts(drift_alerts, log_file)

                # Runtime detector: credential leak in responses AND errors
                # Error fields can contain exception messages that include secrets.
                if cred_detector and ("result" in msg or "error" in msg):
                    resp_content = msg.get("result") if "result" in msg else msg.get("error", "")
                    result_text = json.dumps(resp_content)
                    resp_id = msg.get("id")
                    tool_for_resp = ""
                    if resp_id is not None and resp_id in pending_calls:
                        tool_for_resp = pending_calls[resp_id][0]
                    cred_alerts = cred_detector.check(tool_for_resp or "unknown", result_text)
                    await _handle_alerts(cred_alerts, log_file)

                # Runtime detector: response content inspection (cloaking, SVG, invisible chars,
                # prompt injection). For confirmed vector DB / RAG retrieval tools, also run
                # VectorDBInjectionDetector which upgrades injection alerts to CRITICAL and tags
                # them cache_poison_*. Non-vector tools only run ResponseInspector to avoid
                # duplicate injection alerts.
                if "result" in msg:
                    ri_text = json.dumps(msg.get("result", ""))
                    ri_id = msg.get("id")
                    ri_tool = ""
                    if ri_id is not None and ri_id in pending_calls:
                        ri_tool = pending_calls[ri_id][0]
                    ri_alerts = response_inspector.check(ri_tool or "unknown", ri_text)
                    await _handle_alerts(ri_alerts, log_file)
                    # Vector DB / RAG tools get specialized cache-poison detection on top
                    if vector_detector.is_vector_tool(ri_tool or ""):
                        vec_alerts = vector_detector.check(ri_tool or "unknown", ri_text)
                        await _handle_alerts(vec_alerts, log_file)

                # Response signing — compute HMAC on ORIGINAL response before
                # inline scanning may modify msg (tamper detection must sign
                # the server's actual response, not a scanner-modified version).
                if response_signing_key and log_file:
                    sig = compute_response_hmac(msg, response_signing_key)
                    sig_entry = {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "type": "response_hmac",
                        "id": msg.get("id"),
                        "hmac_sha256": sig,
                    }
                    write_audit_record(
                        log_file,
                        sig_entry,
                    )

                # Visual leak detection — OCR-scan image blocks in the result
                # and either log (log_only) or paint redactions over the
                # matched regions, then re-encode the line so the client
                # never sees the raw pixels. Runs after HMAC so the signature
                # still pins the server's actual response.
                if visual_detector is not None and visual_detector.enabled and "result" in msg:
                    vis_result = msg.get("result")
                    vis_content = vis_result.get("content") if isinstance(vis_result, dict) else None
                    if isinstance(vis_content, list) and vis_content:
                        from agent_bom.runtime.visual_leak_detector import run_visual_leak_check, run_visual_leak_redact

                        vis_id = msg.get("id")
                        vis_tool = ""
                        if vis_id is not None and vis_id in pending_calls:
                            vis_tool = pending_calls[vis_id][0]
                        safe_vis_tool = _sanitize_for_log(vis_tool or "unknown")
                        try:
                            vis_alerts = await run_visual_leak_check(visual_detector, vis_tool or "unknown", vis_content)
                        except asyncio.TimeoutError:
                            logger.warning("Visual leak scan timed out for tool=%s", safe_vis_tool)
                            vis_alerts = []
                        if vis_alerts:
                            await _handle_alerts(vis_alerts, log_file)
                            if not log_only:
                                try:
                                    redacted = await run_visual_leak_redact(visual_detector, vis_content)
                                except asyncio.TimeoutError:
                                    logger.warning("Visual leak redaction timed out for tool=%s", safe_vis_tool)
                                else:
                                    msg["result"]["content"] = redacted
                                    line = (json.dumps(msg) + "\n").encode()

                # Inline response scanning (PII, secrets, payload vuln)
                if scan_config.enabled and "result" in msg:
                    resp_text = json.dumps(msg.get("result", ""))
                    resp_id_scan = msg.get("id")
                    tool_for_scan = ""
                    if resp_id_scan is not None and resp_id_scan in pending_calls:
                        tool_for_scan = pending_calls[resp_id_scan][0]

                    from agent_bom.runtime.detectors import Alert, AlertSeverity

                    resp_results = scan_tool_response(resp_text, scan_config)
                    for sr in resp_results:
                        alert = Alert(
                            detector=f"scanner:{sr.scanner}",
                            severity=AlertSeverity.CRITICAL
                            if sr.severity == "critical"
                            else (AlertSeverity.HIGH if sr.severity == "high" else AlertSeverity.MEDIUM),
                            message=f"Inline scan (response): {sr.scanner}/{sr.rule_id} from '{tool_for_scan or 'unknown'}'",
                            details={"rule_id": sr.rule_id, "excerpt": sr.excerpt, "confidence": sr.confidence},
                        )
                        await _handle_alerts([alert], log_file)
                    if scan_config.mode == "enforce" and any(sr.blocked for sr in resp_results):
                        # Return a JSON-RPC error instead of modifying the result structure,
                        # which preserves protocol compatibility with all MCP clients.
                        msg.pop("result", None)
                        msg["error"] = {
                            "code": -32600,
                            "message": "[BLOCKED] Security scanner detected sensitive content in response",
                        }
                        line = (json.dumps(msg) + "\n").encode()

                # Complete latency tracking for tool call responses
                resp_id = msg.get("id")
                fallback_trace_meta: dict[str, str] | None = None
                if resp_id is not None and resp_id in pending_calls:
                    _tool_name, start, fallback_trace_meta = pending_calls.pop(resp_id)
                    metrics.record_latency((time.monotonic() - start) * 1000)
                msg = _stitch_jsonrpc_trace_meta(msg, fallback_trace_meta)
                line = (json.dumps(msg) + "\n").encode()

                # Evict orphaned pending_calls older than TTL
                now_mono = time.monotonic()
                stale = [k for k, (_tool, t, _trace) in pending_calls.items() if now_mono - t > pending_call_ttl]
                for k in stale:
                    pending_calls.pop(k, None)

            # Forward to client
            sys.stdout.buffer.write(line)
            sys.stdout.buffer.flush()

    async def forward_stderr():
        """Forward server stderr to our stderr."""
        while True:
            if not process.stderr:
                break
            line = await process.stderr.readline()
            if not line:
                break
            sys.stderr.buffer.write(line)
            sys.stderr.buffer.flush()

    refresh_task = asyncio.create_task(_policy_refresh_loop()) if control_plane_url else None
    audit_task = asyncio.create_task(_audit_push_loop()) if control_plane_url else None

    try:
        results = await asyncio.gather(
            relay_client_to_server(),
            relay_server_to_client(),
            forward_stderr(),
            return_exceptions=True,
        )
        for result in results:
            if isinstance(result, Exception) and not isinstance(result, (BrokenPipeError, ConnectionResetError, asyncio.CancelledError)):
                metrics.relay_errors += 1
                logger.warning("Relay task exited with unexpected error: %s", result)
                if log_file:
                    err_entry = {
                        "ts": datetime.now(timezone.utc).isoformat(),
                        "type": "relay_error",
                        "error": str(result),
                        "error_type": type(result).__name__,
                    }
                    write_audit_record(
                        log_file,
                        err_entry,
                    )
    finally:
        # Write metrics summary + runtime alerts to audit log before closing
        summary = metrics.summary()
        summary.update(summarize_runtime_alerts(runtime_alerts))
        summary["execution_posture"] = {
            "mode": "container_isolated" if sandbox_evidence.get("enabled") else "observation_only",
            "sandbox_evidence": sandbox_evidence,
        }
        if audit_task:
            audit_task.cancel()
        if refresh_task:
            refresh_task.cancel()
        if sandbox_timeout_task:
            sandbox_timeout_task.cancel()
        if control_plane_url:
            await _flush_audit_buffer(summary=summary)
        if log_file:
            write_audit_record(log_file, summary)
            log_file.close()
        await metrics_server.stop()
        set_gateway_evaluator(None)
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                process.kill()

    return process.returncode or 0
