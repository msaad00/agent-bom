"""Stdio relay stages for the MCP runtime proxy.

Each direction is an ordered tuple of small stages defined in one place:

* :data:`CLIENT_CALL_STAGES` gate a policy-subject request on its way to the
  server. A stage returns ``True`` once it has answered the client itself
  (blocked), which stops the pipeline and drops the request.
* :data:`SERVER_MESSAGE_STAGES` inspect, redact, sign and annotate each server
  JSON-RPC message on its way back to the client.

Names owned by :mod:`agent_bom.proxy` are resolved through that module at call
time, so its public helpers and module-level evaluators stay authoritative.
"""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import sys
import time
from contextlib import nullcontext
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import TYPE_CHECKING, Awaitable, Callable

from agent_bom import proxy as _proxy

if TYPE_CHECKING:
    from agent_bom.proxy_session import ProxySession

CLIENT_READ_TIMEOUT_SECONDS = 120.0


@dataclass
class ToolCall:
    """A policy-gated client request travelling through the client stages."""

    msg: dict
    tool_name: str
    arguments: dict
    msg_id: int | str | None
    payload_sha256: str
    trace_meta: dict[str, str]
    agent_id: str = ""


@dataclass
class ServerMessage:
    """A parsed server message plus the exact bytes that will reach the client."""

    msg: dict
    line: bytes
    trace_meta: dict[str, str] | None = field(default=None)


ClientCallStage = Callable[["ProxySession", ToolCall], Awaitable[bool]]
ServerMessageStage = Callable[["ProxySession", ServerMessage], Awaitable[None]]


def _reject(session: ProxySession, call: ToolCall, reason: str) -> bool:
    _proxy._reject_tool_call(
        session.log_file,
        call.tool_name,
        call.arguments,
        reason,
        payload_sha256=call.payload_sha256,
        message_id=call.msg_id,
        agent_id=call.agent_id,
        tenant_id=session.control.tenant_id,
    )
    return True


async def check_agent_identity(session: ProxySession, call: ToolCall) -> bool:
    call.agent_id, identity_block_reason = _proxy.check_identity(call.msg, session.policy)
    if not identity_block_reason:
        return False
    session.metrics.record_blocked("identity")
    return _reject(session, call, identity_block_reason)


async def check_replay(session: ProxySession, call: ToolCall) -> bool:
    if not session.detectors.replay.check(call.msg):
        return False
    session.metrics.replay_rejections += 1
    if session.options.log_only:
        _proxy.logger.warning("Replay detected (advisory): %s", call.tool_name)
        return False
    session.metrics.record_blocked("replay")
    return _reject(session, call, "Replayed payload detected")


async def check_declared_tool(session: ProxySession, call: ToolCall) -> bool:
    # With --block-undeclared, missing tools/list evidence is deny, not advisory.
    reason = _proxy.undeclared_tool_block_reason(session.options.block_undeclared, session.declared_tools, call.tool_name)
    if not reason:
        return False
    session.metrics.record_blocked("undeclared")
    return _reject(session, call, reason)


async def check_local_policy(session: ProxySession, call: ToolCall) -> bool:
    if not session.policy:
        return False
    allowed, reason = _proxy.check_policy(session.policy, call.tool_name, call.arguments)
    if allowed:
        return False
    session.metrics.record_blocked("policy")
    return _reject(session, call, reason)


async def check_gateway_policy(session: ProxySession, call: ToolCall) -> bool:
    evaluator = _proxy._gateway_evaluator
    if evaluator is None:
        return False
    gw_allowed, gw_reason = evaluator(call.agent_id, call.tool_name, call.arguments)
    if gw_allowed:
        return False
    session.metrics.record_blocked("gateway_policy")
    return _reject(session, call, gw_reason)


async def check_firewall(session: ProxySession, call: ToolCall) -> bool:
    # The gateway is authoritative; FirewallClient owns cache, fail mode and local fallback.
    fw_target_id = _proxy._firewall_target_for_proxy()
    if _proxy._firewall_evaluator is None or not fw_target_id:
        return False
    fw_outcome = await _proxy._maybe_block_on_firewall(
        source_agent=call.agent_id or "unknown",
        target_agent=fw_target_id,
        tool_name=call.tool_name,
        arguments=call.arguments,
        log_file=session.log_file,
        payload_sha256=call.payload_sha256,
        message_id=call.msg_id,
        tenant_id=session.control.tenant_id,
        metrics=session.metrics,
    )
    if fw_outcome is None:
        return False
    _proxy._write_client_error(call.msg_id, fw_outcome)
    return True


async def analyze_arguments(session: ProxySession, call: ToolCall) -> bool:
    await session.handle_alerts(session.detectors.arguments.check(call.tool_name, call.arguments), session.log_file)
    return False


def _effective_rate_limit(session: ProxySession, agent_id: str) -> int:
    effective = 0
    if _proxy._gateway_evaluator is not None and session.control.policies:
        effective = _proxy._resolve_control_plane_rate_limit_threshold(session.control.policies, agent_id) or 0
    if effective <= 0 and session.detectors.local_policy_rate_limit:
        effective = session.detectors.local_policy_rate_limit
    if session.options.rate_limit_threshold > 0:
        effective = session.options.rate_limit_threshold
    return effective


async def enforce_rate_limit(session: ProxySession, call: ToolCall) -> bool:
    limit = _effective_rate_limit(session, call.agent_id)
    tracker = session.detectors.rate
    if not (tracker and limit > 0):
        return False
    rate_alerts = tracker.record(call.tool_name, threshold=limit, source_agent=call.agent_id or "anonymous")
    await session.handle_alerts(rate_alerts, session.log_file)
    if not rate_alerts or session.options.log_only:
        return False
    session.metrics.record_blocked("rate_limit")
    return _reject(session, call, rate_alerts[0].message)


async def analyze_sequence(session: ProxySession, call: ToolCall) -> bool:
    await session.handle_alerts(session.detectors.sequence.record(call.tool_name), session.log_file)
    return False


async def scan_request_content(session: ProxySession, call: ToolCall) -> bool:
    """Inline content scanning (prompt injection, PII, secrets, payload vuln)."""
    scan_config = session.scan_config
    if not scan_config.enabled:
        return False
    from agent_bom.runtime.detectors import Alert, AlertSeverity

    s_results = _proxy.scan_tool_call(call.tool_name, call.arguments, scan_config)
    for sr in s_results:
        alert = Alert(
            detector=f"scanner:{sr.scanner}",
            severity=AlertSeverity.CRITICAL
            if sr.severity == "critical"
            else (AlertSeverity.HIGH if sr.severity == "high" else AlertSeverity.MEDIUM),
            message=f"Inline scan: {sr.scanner}/{sr.rule_id} in tool '{call.tool_name}'",
            details={"rule_id": sr.rule_id, "excerpt": sr.excerpt, "confidence": sr.confidence},
        )
        await session.handle_alerts([alert], session.log_file)
    if not (scan_config.mode == "enforce" and any(sr.blocked for sr in s_results)):
        return False
    first = next(sr for sr in s_results if sr.blocked)
    session.metrics.record_blocked(f"scanner:{first.scanner}")
    return _reject(session, call, f"Blocked by inline scanner: {first.scanner}/{first.rule_id}")


async def record_allowed_call(session: ProxySession, call: ToolCall) -> bool:
    """Count the call, start its latency timer, and audit it as allowed."""
    session.metrics.record_call(call.tool_name)
    if "id" in call.msg:
        session.pending_calls[call.msg["id"]] = (call.tool_name, time.monotonic(), call.trace_meta)
    if session.log_file:
        _proxy.log_tool_call(
            session.log_file,
            call.tool_name,
            call.arguments,
            "allowed",
            payload_sha256=call.payload_sha256,
            message_id=call.msg_id,
            agent_id=call.agent_id,
            tenant_id=session.control.tenant_id,
        )
    return False


CLIENT_CALL_STAGES: tuple[ClientCallStage, ...] = (
    check_agent_identity,
    check_replay,
    check_declared_tool,
    check_local_policy,
    check_gateway_policy,
    check_firewall,
    analyze_arguments,
    enforce_rate_limit,
    analyze_sequence,
    scan_request_content,
    record_allowed_call,
)


async def gate_client_message(session: ProxySession, msg: dict, trace_meta: dict[str, str]) -> tuple[bool, ToolCall | None]:
    """Run a client message through the stages; ``(True, call)`` means it was answered and dropped."""
    session.metrics.total_messages_client_to_server += 1
    if msg.get("method") == "tools/list" and "id" in msg:
        session.tools_list_request_ids.add(msg["id"])
    policy_subject = _proxy.policy_subject_from_message(msg)
    if not policy_subject:
        return False, None
    tool_name, arguments = policy_subject
    call = ToolCall(
        msg=msg,
        tool_name=tool_name,
        arguments=arguments,
        msg_id=msg.get("id"),
        payload_sha256=_proxy.compute_payload_hash(msg),
        trace_meta=trace_meta,
    )
    for stage in CLIENT_CALL_STAGES:
        if await stage(session, call):
            return True, call
    return False, call


def _annotate_client_span(span, msg: dict, call: ToolCall | None, tenant_id: str, trace_meta: dict[str, str]) -> None:  # noqa: ANN001
    span.set_attribute("agent_bom.proxy.message_kind", msg.get("method", "unknown"))
    if not _proxy.is_tools_call(msg):
        return
    tool_name = _proxy.extract_tool_name(msg) or "unknown"
    span.set_attribute("agent_bom.proxy.tool_name", tool_name)
    _proxy.set_langfuse_runtime_attributes(
        span,
        surface="proxy",
        tenant_id=tenant_id,
        method=str(msg.get("method", "unknown")),
        tool_name=tool_name,
        decision="allowed",
        agent_id=call.agent_id if call else None,
        trace_id=str(trace_meta.get("trace_id") or ""),
        arguments=_proxy.extract_tool_arguments(msg),
    )


async def forward_to_server(
    session: ProxySession, line: bytes, msg: dict | None, call: ToolCall | None, trace_meta: dict[str, str]
) -> None:
    tracer = _proxy._PROXY_TRACER
    span_cm = tracer.start_as_current_span("proxy.relay_client_to_server") if (msg and tracer) else nullcontext()
    with span_cm as span:
        if span is not None and msg is not None:
            _annotate_client_span(span, msg, call, session.control.tenant_id, trace_meta)
        process = session.process
        if process is not None and process.stdin:
            if msg is not None:
                forwarded_message = _proxy._inject_jsonrpc_trace_meta(
                    msg,
                    traceparent=trace_meta.get("traceparent"),
                    tracestate=trace_meta.get("tracestate"),
                    baggage=trace_meta.get("baggage"),
                )
                line = (json.dumps(forwarded_message) + "\n").encode()
            process.stdin.write(line)
            await process.stdin.drain()


async def relay_client_line(session: ProxySession, line: bytes) -> None:
    msg = _proxy.parse_jsonrpc(line.decode("utf-8", errors="replace"))
    trace_meta = _proxy._extract_jsonrpc_trace_meta(msg) if msg else {}
    call: ToolCall | None = None
    if msg:
        blocked, call = await gate_client_message(session, msg, trace_meta)
        if blocked:
            return
    await forward_to_server(session, line, msg, call, trace_meta)


async def relay_client_to_server(session: ProxySession) -> None:
    """Read from our stdin, forward to server stdin."""
    reader = await _proxy.create_async_stdin_reader()
    while True:
        try:
            line = await asyncio.wait_for(_proxy.read_async_stdin_line(reader), timeout=CLIENT_READ_TIMEOUT_SECONDS)
        except asyncio.TimeoutError:
            _proxy.logger.debug("Client readline timed out — closing relay")
            break
        if not line:
            break
        if len(line) > _proxy._MAX_MESSAGE_BYTES:
            _proxy.logger.warning("Oversized message from client (%d bytes) — dropped", len(line))
            continue
        await relay_client_line(session, line)


async def track_declared_tools(session: ProxySession, resp: ServerMessage) -> None:
    """Capture tools/list responses as declared-tool evidence and check for drift."""
    if not _proxy.is_tools_list_response(resp.msg):
        return
    new_tools = _proxy.extract_declared_tools(resp.msg)
    session.declared_tools.update(new_tools)
    _proxy.logger.debug("Declared tools updated: %s", session.declared_tools)
    await session.handle_alerts(session.detectors.drift.check(new_tools), session.log_file)


async def redact_leaked_credentials(session: ProxySession, resp: ServerMessage) -> None:
    """Detect credentials in results AND errors (exception text can carry secrets)."""
    msg = resp.msg
    cred_detector = session.detectors.credentials
    if not (cred_detector and ("result" in msg or "error" in msg)):
        return
    key = "result" if "result" in msg else "error"
    resp_content = msg.get("result") if key == "result" else msg.get("error", "")
    result_text = json.dumps(resp_content)
    cred_alerts = cred_detector.check(session.pending_tool(msg) or "unknown", result_text)
    await session.handle_alerts(cred_alerts, session.log_file)
    if not cred_alerts or session.options.log_only:
        return
    from agent_bom.runtime.detectors import CredentialLeakDetector

    redacted_text = CredentialLeakDetector.redact(result_text)
    try:
        msg[key] = json.loads(redacted_text)
    except json.JSONDecodeError:
        msg[key] = redacted_text


async def inspect_response_content(session: ProxySession, resp: ServerMessage) -> None:
    """Cloaking/SVG/invisible-char/injection checks; vector and RAG tools add cache-poison detection."""
    msg = resp.msg
    if "result" not in msg:
        return
    ri_text = json.dumps(msg.get("result", ""))
    ri_tool = session.pending_tool(msg)
    await session.handle_alerts(session.detectors.response.check(ri_tool or "unknown", ri_text), session.log_file)
    vector_detector = session.detectors.vector
    if vector_detector.is_vector_tool(ri_tool or ""):
        await session.handle_alerts(vector_detector.check(ri_tool or "unknown", ri_text), session.log_file)


async def sign_response(session: ProxySession, resp: ServerMessage) -> None:
    """Persist an HMAC over the hash of the server's ORIGINAL response for offline verification.

    Runs before any inline scanning rewrites the message so tamper detection
    pins what the server actually sent.
    """
    signing_key = session.options.response_signing_key
    if not (signing_key and session.log_file):
        return
    response_hash = _proxy.compute_payload_hash(resp.msg)
    sig = hmac.new(signing_key.encode("utf-8"), response_hash.encode("utf-8"), hashlib.sha256).hexdigest()
    sig_entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": "response_hmac",
        "id": resp.msg.get("id"),
        "response_sha256": response_hash,
        "hmac_sha256": sig,
    }
    _proxy.write_audit_record(session.log_file, sig_entry)


async def redact_visual_leaks(session: ProxySession, resp: ServerMessage) -> None:
    """OCR-scan image blocks; redact matched regions unless log-only (after signing)."""
    msg = resp.msg
    visual_detector = session.detectors.visual
    if not (visual_detector is not None and visual_detector.enabled and "result" in msg):
        return
    vis_result = msg.get("result")
    vis_content = vis_result.get("content") if isinstance(vis_result, dict) else None
    if not (isinstance(vis_content, list) and vis_content):
        return
    from agent_bom.runtime.visual_leak_detector import run_visual_leak_check, run_visual_leak_redact

    vis_tool = session.pending_tool(msg)
    safe_vis_tool = _proxy._sanitize_for_log(vis_tool or "unknown")
    try:
        vis_alerts = await run_visual_leak_check(visual_detector, vis_tool or "unknown", vis_content)
    except asyncio.TimeoutError:
        _proxy.logger.warning("Visual leak scan timed out for tool=%s", safe_vis_tool)
        vis_alerts = []
    if not vis_alerts:
        return
    await session.handle_alerts(vis_alerts, session.log_file)
    if session.options.log_only:
        return
    try:
        redacted = await run_visual_leak_redact(visual_detector, vis_content)
    except asyncio.TimeoutError:
        _proxy.logger.warning("Visual leak redaction timed out for tool=%s", safe_vis_tool)
    else:
        msg["result"]["content"] = redacted
        resp.line = (json.dumps(msg) + "\n").encode()


async def scan_response_content(session: ProxySession, resp: ServerMessage) -> None:
    """Inline response scanning (PII, secrets, payload vuln)."""
    if not session.scan_config.enabled:
        return
    tool_for_scan = session.pending_tool(resp.msg)
    resp.msg, resp_results = _proxy.scan_jsonrpc_response(resp.msg, session.scan_config)
    await session.handle_alerts(_proxy._response_scan_alerts(resp_results, tool_for_scan or "unknown"), session.log_file)


async def complete_pending_call(session: ProxySession, resp: ServerMessage) -> None:
    """Record latency, stitch trace metadata, re-encode, and evict orphaned calls."""
    resp_id = resp.msg.get("id")
    if resp_id is not None and resp_id in session.pending_calls:
        _tool_name, start, resp.trace_meta = session.pending_calls.pop(resp_id)
        session.metrics.record_latency((time.monotonic() - start) * 1000)
    resp.msg = _proxy._stitch_jsonrpc_trace_meta(resp.msg, resp.trace_meta)
    resp.line = (json.dumps(resp.msg) + "\n").encode()
    now_mono = time.monotonic()
    stale = [k for k, (_tool, t, _trace) in session.pending_calls.items() if now_mono - t > session.pending_call_ttl]
    for k in stale:
        session.pending_calls.pop(k, None)


SERVER_MESSAGE_STAGES: tuple[ServerMessageStage, ...] = (
    track_declared_tools,
    redact_leaked_credentials,
    inspect_response_content,
    sign_response,
    redact_visual_leaks,
    scan_response_content,
    complete_pending_call,
)


async def _drop_unparsed_server_output(session: ProxySession, line_str: str) -> bool:
    """Scan non-JSON-RPC stdout (still an outbound channel); enforce mode never relays it."""
    _, findings = _proxy.scan_jsonrpc_response({"result": line_str}, session.scan_config)
    await session.handle_alerts(_proxy._response_scan_alerts(findings, "upstream stdout"), session.log_file)
    if session.scan_config.mode != "enforce":
        return False
    _proxy.logger.warning("Dropped non-JSON-RPC upstream stdout")
    return True


async def relay_server_line(session: ProxySession, line: bytes) -> None:
    line_str = line.decode("utf-8", errors="replace")
    msg = _proxy.parse_jsonrpc(line_str)
    if msg is None and session.scan_config.enabled and await _drop_unparsed_server_output(session, line_str):
        return
    if msg:
        session.metrics.total_messages_server_to_client += 1
        resp = ServerMessage(msg=msg, line=line)
        for stage in SERVER_MESSAGE_STAGES:
            await stage(session, resp)
        line = resp.line
    sys.stdout.buffer.write(line)
    sys.stdout.buffer.flush()


async def relay_server_to_client(session: ProxySession) -> None:
    """Read from server stdout, forward to our stdout."""
    process = session.process
    while True:
        if process is None or not process.stdout:
            break
        line = await _proxy._read_bounded_line(process.stdout)
        if line is None:
            _proxy.logger.warning("Oversized message from server exceeded %d bytes; dropped", _proxy._MAX_MESSAGE_BYTES)
            continue
        if not line:
            break
        await relay_server_line(session, line)


async def forward_stderr(session: ProxySession) -> None:
    """Forward server stderr to our stderr."""
    process = session.process
    while True:
        if process is None or not process.stderr:
            break
        line = await process.stderr.readline()
        if not line:
            break
        sys.stderr.buffer.write(line)
        sys.stderr.buffer.flush()
