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
import re
import sys
import time
from collections import defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from agent_bom.agent_identity import ANONYMOUS, check_identity
from agent_bom.proxy_scanner import ScanConfig, load_scan_config, scan_tool_call, scan_tool_response
from agent_bom.security import validate_arguments, validate_command

logger = logging.getLogger(__name__)

# Maximum JSON-RPC message size accepted from client or server (10 MB).
# Guards against DoS via oversized payloads in the stdio relay loop.
_MAX_MESSAGE_BYTES = 10 * 1024 * 1024  # 10 MB


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
    replay_rejections: int = 0

    def record_call(self, tool_name: str) -> None:
        """Record an allowed tool call."""
        self.tool_calls[tool_name] += 1

    def record_blocked(self, reason: str) -> None:
        """Record a blocked tool call by reason category."""
        self.blocked_calls[reason] += 1

    _MAX_LATENCY_ENTRIES = 10_000

    def record_latency(self, duration_ms: float) -> None:
        """Record tool call round-trip latency in milliseconds (bounded)."""
        self.latencies_ms.append(duration_ms)
        if len(self.latencies_ms) > self._MAX_LATENCY_ENTRIES:
            # Keep only the most recent half
            self.latencies_ms = self.latencies_ms[self._MAX_LATENCY_ENTRIES // 2 :]

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
            "replay_rejections": self.replay_rejections,
        }


# ─── Prometheus metrics server ────────────────────────────────────────────────


class ProxyMetricsServer:
    """Lightweight HTTP server exposing Prometheus text exposition format on /metrics."""

    def __init__(self, metrics: ProxyMetrics, port: int = 8422, token: Optional[str] = None) -> None:
        self.metrics = metrics
        self.port = port
        self.token = token
        self._server: Optional[asyncio.AbstractServer] = None

    def render_metrics(self) -> str:
        """Render ProxyMetrics as Prometheus text exposition format."""
        summary = self.metrics.summary()
        lines: list[str] = []

        # Tool call counters
        lines.append("# HELP agent_bom_proxy_tool_calls_total Total tool calls proxied")
        lines.append("# TYPE agent_bom_proxy_tool_calls_total counter")
        for tool, count in summary.get("calls_by_tool", {}).items():
            lines.append(f'agent_bom_proxy_tool_calls_total{{tool="{tool}"}} {count}')

        # Blocked counters
        lines.append("# HELP agent_bom_proxy_blocked_total Total blocked tool calls")
        lines.append("# TYPE agent_bom_proxy_blocked_total counter")
        for reason, count in summary.get("blocked_by_reason", {}).items():
            lines.append(f'agent_bom_proxy_blocked_total{{reason="{reason}"}} {count}')

        # Uptime
        lines.append("# HELP agent_bom_proxy_uptime_seconds Proxy uptime in seconds")
        lines.append("# TYPE agent_bom_proxy_uptime_seconds gauge")
        lines.append(f"agent_bom_proxy_uptime_seconds {summary.get('uptime_seconds', 0)}")

        # Totals
        lines.append("# HELP agent_bom_proxy_total_tool_calls Total tool calls")
        lines.append("# TYPE agent_bom_proxy_total_tool_calls counter")
        lines.append(f"agent_bom_proxy_total_tool_calls {summary.get('total_tool_calls', 0)}")

        lines.append("# HELP agent_bom_proxy_total_blocked Total blocked calls")
        lines.append("# TYPE agent_bom_proxy_total_blocked counter")
        lines.append(f"agent_bom_proxy_total_blocked {summary.get('total_blocked', 0)}")

        # Latency
        latency = summary.get("latency", {})
        if latency:
            lines.append("# HELP agent_bom_proxy_latency_ms Tool call round-trip latency")
            lines.append("# TYPE agent_bom_proxy_latency_ms summary")
            if "p50_ms" in latency:
                lines.append(f'agent_bom_proxy_latency_ms{{quantile="0.5"}} {latency["p50_ms"]}')
            if "p95_ms" in latency:
                lines.append(f'agent_bom_proxy_latency_ms{{quantile="0.95"}} {latency["p95_ms"]}')

        # Replay rejections
        lines.append("# HELP agent_bom_proxy_replay_rejections_total Replay attack rejections")
        lines.append("# TYPE agent_bom_proxy_replay_rejections_total counter")
        lines.append(f"agent_bom_proxy_replay_rejections_total {summary.get('replay_rejections', 0)}")

        # Messages
        lines.append("# HELP agent_bom_proxy_messages_total Total JSON-RPC messages")
        lines.append("# TYPE agent_bom_proxy_messages_total counter")
        lines.append(f'agent_bom_proxy_messages_total{{direction="client_to_server"}} {summary.get("messages_client_to_server", 0)}')
        lines.append(f'agent_bom_proxy_messages_total{{direction="server_to_client"}} {summary.get("messages_server_to_client", 0)}')

        return "\n".join(lines) + "\n"

    async def start(self) -> None:
        """Start the metrics HTTP server."""
        if self.port <= 0:
            return

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await asyncio.wait_for(reader.readline(), timeout=10)
                # Read remaining headers and capture Authorization
                auth_header = ""
                while True:
                    header = await asyncio.wait_for(reader.readline(), timeout=5)
                    if not header or header == b"\r\n":
                        break
                    header_str = header.decode("utf-8", errors="replace").strip()
                    if header_str.lower().startswith("authorization:"):
                        auth_header = header_str.split(":", 1)[1].strip()

                # Bearer token auth (optional — enabled via --metrics-token)
                if self.token:
                    expected = f"Bearer {self.token}"
                    if auth_header != expected:
                        response = "HTTP/1.1 401 Unauthorized\r\nContent-Length: 12\r\n\r\nUnauthorized"
                        writer.write(response.encode())
                        await writer.drain()
                        return

                body = self.render_metrics()
                response = (
                    "HTTP/1.1 200 OK\r\n"
                    "Content-Type: text/plain; version=0.0.4; charset=utf-8\r\n"
                    f"Content-Length: {len(body)}\r\n"
                    "\r\n"
                    f"{body}"
                )
                writer.write(response.encode())
                await writer.drain()
            except (asyncio.TimeoutError, ConnectionResetError):
                pass
            finally:
                writer.close()

        self._server = await asyncio.start_server(handle, "0.0.0.0", self.port)  # nosec B104 — container/K8s metrics endpoint must bind all interfaces
        logger.info("Prometheus metrics server listening on port %d", self.port)

    async def stop(self) -> None:
        """Stop the metrics server."""
        if self._server:
            self._server.close()
            await self._server.wait_closed()


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
    payload_sha256: str = "",
    message_id: int | str | None = None,
    agent_id: str = ANONYMOUS,
) -> None:
    """Append a tool call record to the audit JSONL log.

    Args:
        log_file: File-like object opened for writing/appending.
        tool_name: Name of the tool being called.
        arguments: Tool call arguments.
        policy_result: "allowed" or "blocked".
        reason: Reason for blocking (if blocked).
        payload_sha256: SHA-256 hash of the full JSON-RPC payload.
        message_id: JSON-RPC ``id`` field for correlation.
        agent_id: Resolved caller identity (from _meta.agent_identity).
    """
    record: dict = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "type": "tools/call",
        "tool": tool_name,
        "agent_id": agent_id,
        "args": _truncate_args(arguments),
        "policy": policy_result,
    }
    if reason:
        record["reason"] = reason
    if payload_sha256:
        record["payload_sha256"] = payload_sha256
    if message_id is not None:
        record["message_id"] = message_id

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


# ─── Payload integrity ───────────────────────────────────────────────────────


def compute_payload_hash(payload: dict) -> str:
    """SHA-256 hash of the canonical JSON representation of a payload.

    Uses sorted keys and compact separators so identical payloads always
    produce the same digest regardless of dict ordering.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


@dataclass
class ReplayDetector:
    """Detect replayed JSON-RPC messages by tracking payload hashes.

    Maintains a bounded dict of ``hash → timestamp`` with a sliding time
    window.  Messages whose hash was already seen within the window are
    flagged as replays.
    """

    window_seconds: float = 300.0  # 5-minute sliding window
    max_entries: int = 10_000
    _seen: dict[str, float] = field(default_factory=dict)

    def check(self, msg: dict) -> bool:
        """Return *True* if *msg* is a replay (duplicate within the window)."""
        h = compute_payload_hash(msg)
        now = time.monotonic()

        # Evict stale entries when approaching the cap
        if len(self._seen) >= self.max_entries:
            self._seen = {k: v for k, v in self._seen.items() if (now - v) < self.window_seconds}

        if h in self._seen and (now - self._seen[h]) < self.window_seconds:
            return True

        self._seen[h] = now
        return False


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

    # Allowlist mode: if a rule has mode=allowlist, only listed tools pass.
    # Checked first — allowlist takes precedence over blocklist rules.
    for rule in rules:
        if rule.get("mode") != "allowlist":
            continue
        action = rule.get("action", "warn")
        if action not in ("fail", "block"):
            continue
        allowed_tools = rule.get("allow_tools", [])
        if tool_name not in allowed_tools:
            return False, f"Tool '{tool_name}' not in allowlist for rule '{rule.get('id', '?')}'"
        # Tool is in the allowlist — still fall through to arg_pattern checks
        break

    for rule in rules:
        action = rule.get("action", "warn")
        if action not in ("fail", "block"):
            continue  # Only enforce blocking rules at runtime

        # Skip allowlist rules in the blocklist loop (already handled above)
        if rule.get("mode") == "allowlist":
            continue

        # block_tools: list of tool names to block entirely
        blocked = rule.get("block_tools", [])
        if blocked and tool_name in blocked:
            return False, f"Tool '{tool_name}' is blocked by rule '{rule.get('id', '?')}'"

        # tool_name match (exact)
        rule_tool = rule.get("tool_name")
        if rule_tool and rule_tool == tool_name:
            return False, f"Tool '{tool_name}' blocked by rule '{rule.get('id', '?')}'"

        # tool_name_pattern match (regex) — compile with length guard to mitigate ReDoS
        pattern = rule.get("tool_name_pattern")
        if pattern:
            try:
                if len(pattern) > 500:
                    logger.warning("Skipping oversized tool_name_pattern (%d chars)", len(pattern))
                elif re.match(pattern, tool_name):
                    return False, f"Tool '{tool_name}' matches blocked pattern '{pattern}'"
            except re.error:
                pass

        # arg_pattern: {arg_name: regex_pattern} — length guard to mitigate ReDoS
        arg_patterns = rule.get("arg_pattern", {})
        for arg_name, arg_regex in arg_patterns.items():
            arg_value = str(arguments.get(arg_name, ""))
            try:
                if len(arg_regex) > 500:
                    logger.warning("Skipping oversized arg_pattern for '%s' (%d chars)", arg_name, len(arg_regex))
                    continue
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
    metrics_port: int = 8422,
    metrics_token: Optional[str] = None,
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
        metrics_token: Optional bearer token for Prometheus /metrics endpoint.

    Returns the server process exit code.
    """
    # Load policy if provided
    policy: dict = {}
    if policy_path:
        policy = json.loads(Path(policy_path).read_text())

    # Open audit log with restricted permissions (0o600)
    log_file = None
    if log_path:
        fd = os.open(log_path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        log_file = os.fdopen(fd, "a")

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
    rate_tracker = RateLimitTracker(threshold=rate_limit_threshold) if rate_limit_threshold > 0 else None
    seq_analyzer = SequenceAnalyzer()
    response_inspector = ResponseInspector()
    vector_detector = VectorDBInjectionDetector()
    replay_detector = ReplayDetector()
    scan_config = load_scan_config(policy) if policy else ScanConfig()
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
    # Track in-flight tool calls for latency measurement (with TTL cleanup)
    pending_calls: dict[int | str, tuple[str, float]] = {}  # id → (tool_name, start_time)
    pending_call_ttl = 300.0  # 5 minutes — evict orphaned entries

    # Validate the server command before spawning
    validate_command(server_cmd[0])
    if len(server_cmd) > 1:
        validate_arguments(list(server_cmd[1:]))

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
        await asyncio.get_running_loop().connect_read_pipe(lambda: protocol, sys.stdin.buffer)

        while True:
            line = await reader.readline()
            if not line:
                break

            if len(line) > _MAX_MESSAGE_BYTES:
                logger.warning("Oversized message from client (%d bytes) — dropped", len(line))
                continue

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
                                )
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
                                log_tool_call(
                                    log_file,
                                    tool_name,
                                    arguments,
                                    "blocked",
                                    gw_reason,
                                    payload_sha256=p_hash,
                                    message_id=msg_id,
                                    agent_id=agent_id,
                                )
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
                            _handle_alerts([alert], log_file)
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
                                )
                            error_resp = make_error_response(msg_id, -32600, reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue

                    # Record allowed call + start latency timer
                    metrics.record_call(tool_name)
                    if "id" in msg:
                        pending_calls[msg["id"]] = (tool_name, time.monotonic())

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
                        )

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

            if len(line) > _MAX_MESSAGE_BYTES:
                logger.warning("Oversized message from server (%d bytes) — dropped", len(line))
                continue

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
                    _handle_alerts(ri_alerts, log_file)
                    # Vector DB / RAG tools get specialized cache-poison detection on top
                    if vector_detector.is_vector_tool(ri_tool or ""):
                        vec_alerts = vector_detector.check(ri_tool or "unknown", ri_text)
                        _handle_alerts(vec_alerts, log_file)

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
                        _handle_alerts([alert], log_file)
                    if scan_config.mode == "enforce" and any(sr.blocked for sr in resp_results):
                        # Replace response with safe content
                        msg["result"] = {
                            "content": [{"type": "text", "text": "[BLOCKED: security scanner detected sensitive content in response]"}]
                        }
                        line = (json.dumps(msg) + "\n").encode()

                # Complete latency tracking for tool call responses
                resp_id = msg.get("id")
                if resp_id is not None and resp_id in pending_calls:
                    _tool_name, start = pending_calls.pop(resp_id)
                    metrics.record_latency((time.monotonic() - start) * 1000)

                # Evict orphaned pending_calls older than TTL
                now_mono = time.monotonic()
                stale = [k for k, (_, t) in pending_calls.items() if now_mono - t > pending_call_ttl]
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
        await metrics_server.stop()
        if process.returncode is None:
            process.terminate()
            try:
                await asyncio.wait_for(process.wait(), timeout=5.0)
            except asyncio.TimeoutError:
                process.kill()

    return process.returncode or 0
