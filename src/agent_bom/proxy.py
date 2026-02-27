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
import json
import logging
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ─── Proxy metrics ──────────────────────────────────────────────────────────


@dataclass
class ProxyMetrics:
    """Runtime observability metrics collected during proxy operation."""

    start_time: float = field(default_factory=time.monotonic)
    tool_calls: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    blocked_calls: dict[str, int] = field(default_factory=lambda: defaultdict(int))
    latencies_ms: list[float] = field(default_factory=list)
    total_messages_client_to_server: int = 0
    total_messages_server_to_client: int = 0

    def record_call(self, tool_name: str) -> None:
        """Record an allowed tool call."""
        self.tool_calls[tool_name] += 1

    def record_blocked(self, reason: str) -> None:
        """Record a blocked tool call by reason category."""
        self.blocked_calls[reason] += 1

    def record_latency(self, duration_ms: float) -> None:
        """Record tool call round-trip latency in milliseconds."""
        self.latencies_ms.append(duration_ms)

    def summary(self) -> dict:
        """Generate a metrics summary dict for JSONL export."""
        elapsed = time.monotonic() - self.start_time
        total_calls = sum(self.tool_calls.values())
        total_blocked = sum(self.blocked_calls.values())

        latency_stats: dict = {}
        if self.latencies_ms:
            sorted_lat = sorted(self.latencies_ms)
            latency_stats = {
                "min_ms": round(sorted_lat[0], 2),
                "max_ms": round(sorted_lat[-1], 2),
                "avg_ms": round(sum(sorted_lat) / len(sorted_lat), 2),
                "p50_ms": round(sorted_lat[len(sorted_lat) // 2], 2),
                "p95_ms": round(sorted_lat[int(len(sorted_lat) * 0.95)], 2),
                "count": len(sorted_lat),
            }

        return {
            "ts": datetime.now(timezone.utc).isoformat(),
            "type": "proxy_summary",
            "uptime_seconds": round(elapsed, 2),
            "total_tool_calls": total_calls,
            "total_blocked": total_blocked,
            "calls_by_tool": dict(self.tool_calls),
            "blocked_by_reason": dict(self.blocked_calls),
            "latency": latency_stats,
            "messages_client_to_server": self.total_messages_client_to_server,
            "messages_server_to_client": self.total_messages_server_to_client,
        }


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


# ─── Audit logging ───────────────────────────────────────────────────────────


def log_tool_call(
    log_file: object,
    tool_name: str,
    arguments: dict,
    policy_result: str = "allowed",
    reason: str = "",
) -> None:
    """Append a tool call record to the audit JSONL log.

    Args:
        log_file: File-like object opened for writing/appending.
        tool_name: Name of the tool being called.
        arguments: Tool call arguments.
        policy_result: "allowed" or "blocked".
        reason: Reason for blocking (if blocked).
    """
    record = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": "tools/call",
        "tool": tool_name,
        "args": _truncate_args(arguments),
        "policy": policy_result,
    }
    if reason:
        record["reason"] = reason

    log_file.write(json.dumps(record) + "\n")  # type: ignore[union-attr]
    log_file.flush()  # type: ignore[union-attr]


def _truncate_args(args: dict, max_value_len: int = 200) -> dict:
    """Truncate long argument values for logging."""
    result = {}
    for k, v in args.items():
        if isinstance(v, str) and len(v) > max_value_len:
            result[k] = v[:max_value_len] + "...<truncated>"
        else:
            result[k] = v
    return result


# ─── Policy checking ─────────────────────────────────────────────────────────


def check_policy(
    policy: dict,
    tool_name: str,
    arguments: dict,
) -> tuple[bool, str]:
    """Evaluate runtime policy against a tools/call request.

    Args:
        policy: Policy dict with runtime rules.
        tool_name: Name of the tool being called.
        arguments: Tool call arguments.

    Returns:
        (allowed, reason) tuple. If blocked, reason explains why.
    """
    rules = policy.get("rules", [])
    for rule in rules:
        action = rule.get("action", "warn")
        if action not in ("fail", "block"):
            continue  # Only enforce blocking rules at runtime

        # block_tools: list of tool names to block entirely
        blocked = rule.get("block_tools", [])
        if blocked and tool_name in blocked:
            return False, f"Tool '{tool_name}' is blocked by rule '{rule.get('id', '?')}'"

        # tool_name match (exact)
        rule_tool = rule.get("tool_name")
        if rule_tool and rule_tool == tool_name:
            return False, f"Tool '{tool_name}' blocked by rule '{rule.get('id', '?')}'"

        # tool_name_pattern match (regex)
        pattern = rule.get("tool_name_pattern")
        if pattern:
            try:
                if re.match(pattern, tool_name):
                    return False, f"Tool '{tool_name}' matches blocked pattern '{pattern}'"
            except re.error:
                pass

        # arg_pattern: {arg_name: regex_pattern}
        arg_patterns = rule.get("arg_pattern", {})
        for arg_name, arg_regex in arg_patterns.items():
            arg_value = str(arguments.get(arg_name, ""))
            try:
                if re.search(arg_regex, arg_value):
                    return False, f"Argument '{arg_name}' matches blocked pattern '{arg_regex}'"
            except re.error:
                pass

    return True, ""


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


async def _send_webhook(url: str, payload: dict) -> None:
    """Fire-and-forget POST to an alert webhook URL."""
    try:
        import httpx
        async with httpx.AsyncClient(timeout=10.0) as client:
            await client.post(url, json=payload)
    except Exception:  # noqa: BLE001
        logger.debug("Failed to send webhook to %s", url)


async def run_proxy(
    server_cmd: list[str],
    policy_path: Optional[str] = None,
    log_path: Optional[str] = None,
    block_undeclared: bool = False,
    detect_credentials: bool = False,
    rate_limit_threshold: int = 0,
    log_only: bool = False,
    alert_webhook: Optional[str] = None,
) -> int:
    """Main proxy loop. Spawns server subprocess, relays JSON-RPC.

    Args:
        server_cmd: Command to spawn the MCP server.
        policy_path: Path to policy JSON file.
        log_path: Path to audit JSONL log.
        block_undeclared: Block tools not in initial tools/list.
        detect_credentials: Enable credential leak detection in responses.
        rate_limit_threshold: Max calls per tool per 60s (0 = disabled).
        log_only: Log alerts without blocking (advisory mode).
        alert_webhook: Optional webhook URL for runtime alert notifications.

    Returns the server process exit code.
    """
    # Load policy if provided
    policy: dict = {}
    if policy_path:
        policy = json.loads(Path(policy_path).read_text())

    # Open audit log
    log_file = None
    if log_path:
        log_file = open(log_path, "a")  # noqa: SIM115

    # Metrics
    metrics = ProxyMetrics()

    # Runtime detectors
    from agent_bom.runtime.detectors import (
        ArgumentAnalyzer,
        CredentialLeakDetector,
        RateLimitTracker,
        SequenceAnalyzer,
        ToolDriftDetector,
    )

    drift_detector = ToolDriftDetector()
    arg_analyzer = ArgumentAnalyzer()
    cred_detector = CredentialLeakDetector() if detect_credentials else None
    rate_tracker = RateLimitTracker(threshold=rate_limit_threshold) if rate_limit_threshold > 0 else None
    seq_analyzer = SequenceAnalyzer()
    runtime_alerts: list[dict] = []

    def _handle_alerts(alerts, log_f=None):
        """Log alerts and optionally record them + dispatch webhook."""
        for alert in alerts:
            alert_dict = alert.to_dict()
            runtime_alerts.append(alert_dict)
            logger.warning("Runtime alert: %s", alert.message)
            if log_f:
                log_f.write(json.dumps(alert_dict) + "\n")
                log_f.flush()
            if alert_webhook:
                asyncio.ensure_future(_send_webhook(alert_webhook, alert_dict))

    # Track declared tools from tools/list responses
    declared_tools: set[str] = set()
    tools_list_request_ids: set[int | str] = set()
    # Track in-flight tool calls for latency measurement
    pending_calls: dict[int | str, tuple[str, float]] = {}  # id → (tool_name, start_time)

    # Spawn the actual MCP server
    process = await asyncio.create_subprocess_exec(
        *server_cmd,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.PIPE,
    )

    async def relay_client_to_server():
        """Read from our stdin, forward to server stdin."""
        reader = asyncio.StreamReader()
        protocol = asyncio.StreamReaderProtocol(reader)
        await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        while True:
            line = await reader.readline()
            if not line:
                break

            line_str = line.decode("utf-8", errors="replace")
            msg = parse_jsonrpc(line_str)

            if msg:
                metrics.total_messages_client_to_server += 1

                # Track tools/list requests so we can identify responses
                if msg.get("method") == "tools/list" and "id" in msg:
                    tools_list_request_ids.add(msg["id"])

                # Intercept tools/call requests
                if is_tools_call(msg):
                    tool_name = extract_tool_name(msg) or "unknown"
                    arguments = extract_tool_arguments(msg)

                    # Check if tool is declared
                    if block_undeclared and declared_tools and tool_name not in declared_tools:
                        reason = f"Tool '{tool_name}' not in declared tools/list"
                        metrics.record_blocked("undeclared")
                        if log_file:
                            log_tool_call(log_file, tool_name, arguments, "blocked", reason)
                        # Send error back to client
                        error_resp = make_error_response(msg.get("id"), -32600, reason)
                        sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                        sys.stdout.buffer.flush()
                        continue

                    # Check policy
                    if policy:
                        allowed, reason = check_policy(policy, tool_name, arguments)
                        if not allowed:
                            metrics.record_blocked("policy")
                            if log_file:
                                log_tool_call(log_file, tool_name, arguments, "blocked", reason)
                            error_resp = make_error_response(msg.get("id"), -32600, reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue

                    # Gateway policy evaluation
                    if _gateway_evaluator is not None:
                        gw_allowed, gw_reason = _gateway_evaluator(tool_name, arguments)
                        if not gw_allowed:
                            metrics.record_blocked("gateway_policy")
                            if log_file:
                                log_tool_call(log_file, tool_name, arguments, "blocked", gw_reason)
                            error_resp = make_error_response(msg.get("id"), -32600, gw_reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue

                    # Runtime detectors: argument analysis
                    arg_alerts = arg_analyzer.check(tool_name, arguments)
                    _handle_alerts(arg_alerts, log_file)

                    # Runtime detectors: rate limiting
                    if rate_tracker:
                        rate_alerts = rate_tracker.record(tool_name)
                        _handle_alerts(rate_alerts, log_file)

                    # Runtime detectors: sequence analysis
                    seq_alerts = seq_analyzer.record(tool_name)
                    _handle_alerts(seq_alerts, log_file)

                    # Record allowed call + start latency timer
                    metrics.record_call(tool_name)
                    if "id" in msg:
                        pending_calls[msg["id"]] = (tool_name, time.monotonic())

                    # Log allowed call
                    if log_file:
                        log_tool_call(log_file, tool_name, arguments, "allowed")

            # Forward to server
            if process.stdin:
                process.stdin.write(line)
                await process.stdin.drain()

    async def relay_server_to_client():
        """Read from server stdout, forward to our stdout."""
        while True:
            if not process.stdout:
                break
            line = await process.stdout.readline()
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
                    _handle_alerts(drift_alerts, log_file)

                # Runtime detector: credential leak in responses
                if cred_detector and "result" in msg:
                    result_text = json.dumps(msg.get("result", ""))
                    resp_id = msg.get("id")
                    tool_for_resp = ""
                    if resp_id is not None and resp_id in pending_calls:
                        tool_for_resp = pending_calls[resp_id][0]
                    cred_alerts = cred_detector.check(tool_for_resp or "unknown", result_text)
                    _handle_alerts(cred_alerts, log_file)

                # Complete latency tracking for tool call responses
                resp_id = msg.get("id")
                if resp_id is not None and resp_id in pending_calls:
                    _tool_name, start = pending_calls.pop(resp_id)
                    metrics.record_latency((time.monotonic() - start) * 1000)

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

    try:
        await asyncio.gather(
            relay_client_to_server(),
            relay_server_to_client(),
            forward_stderr(),
            return_exceptions=True,
        )
    except (BrokenPipeError, ConnectionResetError):
        pass
    finally:
        # Write metrics summary + runtime alerts to audit log before closing
        if log_file:
            summary = metrics.summary()
            summary["runtime_alerts"] = len(runtime_alerts)
            summary_line = json.dumps(summary) + "\n"
            log_file.write(summary_line)
            log_file.close()
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                process.kill()

    return process.returncode or 0
