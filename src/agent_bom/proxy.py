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
import hmac
import json
import logging
import os
import re
import sys
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Optional
from urllib.parse import urlparse

from agent_bom.agent_identity import ANONYMOUS, check_identity
from agent_bom.async_stdin import create_async_stdin_reader, read_async_stdin_line
from agent_bom.permissions import classify_tool
from agent_bom.proxy_scanner import ScanConfig, load_scan_config, scan_tool_call, scan_tool_response
from agent_bom.security import validate_arguments, validate_command

logger = logging.getLogger(__name__)

# Maximum JSON-RPC message size accepted from client or server (10 MB).
# Guards against DoS via oversized payloads in the stdio relay loop.
_MAX_MESSAGE_BYTES = 10 * 1024 * 1024  # 10 MB

# Regex execution timeout (seconds) — mitigates ReDoS from user-supplied patterns.
_REGEX_TIMEOUT_SECONDS = 0.1

# Pre-compiled pattern cache to avoid recompiling on every policy check.
_compiled_patterns: dict[str, re.Pattern] = {}
_PATH_ARG_KEYS = {
    "path",
    "file",
    "filepath",
    "filename",
    "source",
    "target",
    "destination",
    "cwd",
    "dir",
    "directory",
    "output",
    "input",
}
_URL_ARG_KEYS = {
    "url",
    "uri",
    "endpoint",
    "href",
    "link",
    "host",
    "domain",
    "base_url",
    "target_url",
}
_SECRET_PATH_PATTERNS = (
    ".env",
    ".npmrc",
    ".pypirc",
    ".aws/",
    ".ssh/",
    ".gnupg/",
    ".kube/config",
    "id_rsa",
    "id_ed25519",
    "credentials",
    "authorized_keys",
    "known_hosts",
)
_NETWORK_KEYWORDS = ("http", "fetch", "web", "request", "url", "curl", "download", "upload", "post")


def _safe_compile(pattern: str) -> re.Pattern:
    """Compile and cache a regex pattern, raising re.error on invalid syntax."""
    if pattern not in _compiled_patterns:
        compiled = re.compile(pattern)
        _compiled_patterns[pattern] = compiled
    return _compiled_patterns[pattern]


def _safe_regex_match(pattern: str, text: str) -> bool:
    """Run re.match with pre-compilation and input length guard against ReDoS."""
    if len(text) > 10_000:
        logger.warning("Skipping regex match on oversized input (%d chars)", len(text))
        return False
    compiled = _safe_compile(pattern)
    return compiled.match(text) is not None


def _safe_regex_search(pattern: str, text: str) -> bool:
    """Run re.search with pre-compilation and input length guard against ReDoS."""
    if len(text) > 10_000:
        logger.warning("Skipping regex search on oversized input (%d chars)", len(text))
        return False
    compiled = _safe_compile(pattern)
    return compiled.search(text) is not None


def _iter_argument_strings(value: object, key_hint: str = "") -> list[tuple[str, str]]:
    """Flatten nested tool arguments into ``(key_hint, value)`` string pairs."""
    pairs: list[tuple[str, str]] = []
    if isinstance(value, dict):
        for key, child in value.items():
            pairs.extend(_iter_argument_strings(child, str(key)))
    elif isinstance(value, list):
        for child in value:
            pairs.extend(_iter_argument_strings(child, key_hint))
    elif isinstance(value, str):
        pairs.append((key_hint.lower(), value))
    return pairs


def _extract_argument_paths(arguments: dict) -> list[str]:
    """Collect path-like argument values from nested tool arguments."""
    paths: list[str] = []
    for key, value in _iter_argument_strings(arguments):
        lowered = value.lower()
        if key in _PATH_ARG_KEYS or "/" in value or "\\" in value or lowered.startswith("~"):
            paths.append(value)
    return paths


def _extract_argument_hosts(arguments: dict) -> list[str]:
    """Collect outbound hosts from URL-like argument values."""
    hosts: list[str] = []
    for key, value in _iter_argument_strings(arguments):
        candidate = value.strip()
        lowered = candidate.lower()
        if key not in _URL_ARG_KEYS and not lowered.startswith(("http://", "https://")):
            continue
        parsed = urlparse(candidate if "://" in candidate else f"https://{candidate}")
        if parsed.hostname:
            hosts.append(parsed.hostname.lower())
    return hosts


def _matches_secret_path(path: str) -> bool:
    lowered = path.lower()
    return any(pattern in lowered for pattern in _SECRET_PATH_PATTERNS)


def _classify_tool_classes(tool_name: str, arguments: dict) -> set[str]:
    """Infer coarse policy classes for a tool call."""
    classes = {classify_tool(tool_name)}
    combined = f"{tool_name} " + " ".join(str(v) for _, v in _iter_argument_strings(arguments))
    lowered = combined.lower()
    if any(keyword in lowered for keyword in _NETWORK_KEYWORDS) or _extract_argument_hosts(arguments):
        classes.add("network")
    if any(term in lowered for term in ("sql", "query", "database", "db", "postgres", "mysql")):
        classes.add("database")
    if any(term in lowered for term in ("file", "path", "directory", "filesystem")) or _extract_argument_paths(arguments):
        classes.add("filesystem")
    return classes


def _host_allowed(host: str, allowed_hosts: list[str]) -> bool:
    normalized = [entry.lower() for entry in allowed_hosts if entry]
    for allowed in normalized:
        if host == allowed or host.endswith(f".{allowed}"):
            return True
    return False


# ─── Rotating audit log ─────────────────────────────────────────────────────

# Maximum audit log size before rotation (100 MB). Prevents disk exhaustion
# on long-running proxy instances.
_AUDIT_LOG_MAX_BYTES = 100 * 1024 * 1024


class RotatingAuditLog:
    """File-like wrapper that rotates the JSONL audit log at a size threshold.

    Checks file size every 1000 writes (not every line) to minimize stat() overhead.
    Keeps one rotated backup (.1). Rejects symlinks on open.
    """

    def __init__(self, path: str, max_bytes: int = _AUDIT_LOG_MAX_BYTES) -> None:
        self._path = path
        self._max_bytes = max_bytes
        self._writes = 0
        self._file = self._open(path)

    @staticmethod
    def _open(path: str) -> IO[str]:
        p = Path(path)
        if p.is_symlink():
            raise ValueError(f"Audit log path must not be a symlink: {path}")
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        return os.fdopen(fd, "a")

    def write(self, data: str) -> int:
        result = self._file.write(data)
        self._writes += 1
        if self._writes % 1000 == 0:
            self._maybe_rotate()
        return result

    def flush(self) -> None:
        self._file.flush()

    def close(self) -> None:
        self._file.close()

    def _maybe_rotate(self) -> None:
        try:
            size = Path(self._path).stat().st_size
            if size >= self._max_bytes:
                self._file.close()
                rotated = self._path + ".1"
                if Path(rotated).exists():
                    Path(rotated).unlink()
                Path(self._path).rename(rotated)
                self._file = self._open(self._path)
                logger.info("Rotated audit log at %d bytes", size)
        except OSError as _exc:
            logger.warning("Audit log rotation failed: %s — log may grow unbounded", _exc)


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
    relay_errors: int = 0

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
            "relay_errors": self.relay_errors,
        }


# ─── Prometheus metrics server ────────────────────────────────────────────────


class ProxyMetricsServer:
    """Lightweight HTTP server exposing Prometheus text exposition format on /metrics."""

    def __init__(self, metrics: ProxyMetrics, port: int = 8422, token: Optional[str] = None, host: str = "127.0.0.1") -> None:
        self.metrics = metrics
        self.port = port
        self.token = token
        self.host = host
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

                # Bearer token auth (optional — enabled via --metrics-token).
                # hmac.compare_digest prevents timing-based token enumeration.
                if self.token:
                    expected = f"Bearer {self.token}"
                    if not hmac.compare_digest(auth_header or "", expected):
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

        self._server = await asyncio.start_server(handle, self.host, self.port)
        logger.info("Prometheus metrics server listening on %s:%d", self.host, self.port)

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
    log_file: "IO[str] | RotatingAuditLog",
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

    log_file.write(json.dumps(record) + "\n")
    log_file.flush()


def summarize_runtime_alerts(alerts: list[dict]) -> dict[str, object]:
    """Aggregate runtime alerts for audit-log summaries and status surfaces."""
    severity_counts: Counter[str] = Counter()
    detector_counts: Counter[str] = Counter()
    blocked_alerts = 0

    for alert in alerts:
        severity = str(alert.get("severity", "unknown")).lower()
        detector = str(alert.get("detector", "unknown"))
        severity_counts[severity] += 1
        detector_counts[detector] += 1
        details = alert.get("details", {})
        if isinstance(details, dict) and details.get("action") == "blocked":
            blocked_alerts += 1

    latest_ts = ""
    if alerts:
        latest_ts = max(str(alert.get("ts", "")) for alert in alerts)

    return {
        "runtime_alerts": len(alerts),
        "runtime_alerts_by_severity": dict(sorted(severity_counts.items())),
        "runtime_alerts_by_detector": dict(sorted(detector_counts.items())),
        "blocked_runtime_alerts": blocked_alerts,
        "latest_runtime_alert_at": latest_ts,
    }


def _truncate_args(args: dict, max_value_len: int = 200) -> dict:
    """Truncate long argument values for logging; redact credential keys/values.

    Applies the same key-name (SENSITIVE_PATTERNS) and value-pattern
    (_VALUE_CREDENTIAL_PATTERNS) redaction used by ``sanitize_env_vars()``
    so that tool call arguments containing API keys, tokens, or passwords
    are never written to the audit log in plaintext.
    """
    from agent_bom.security import sanitize_env_vars

    # Only string values are eligible for credential detection; collect them.
    str_vals = {k: v for k, v in args.items() if isinstance(v, str)}
    sanitized = sanitize_env_vars(str_vals)

    result = {}
    for k, v in args.items():
        if isinstance(v, str):
            san = sanitized.get(k, v)
            if san == "***REDACTED***":
                result[k] = san
            elif len(san) > max_value_len:
                result[k] = san[:max_value_len] + "...<truncated>"
            else:
                result[k] = san
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


def compute_response_hmac(payload: dict, key: str) -> str:
    """HMAC-SHA256 of the canonical JSON response payload.

    Written to the audit log so operators can verify responses were not
    tampered with between the MCP server and this proxy.  The signature is
    NOT inserted into the wire protocol (that would break the MCP spec).

    Args:
        payload: The parsed JSON-RPC response dict.
        key: A shared secret known to both the proxy operator and the
             verification tool.  Must be non-empty.

    Returns:
        Hex-encoded HMAC-SHA256 digest.
    """
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


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

        # Evict stale entries when approaching the cap.
        # Only evict the oldest half to prevent flood-based eviction attacks —
        # an attacker cannot flush the entire history by sending many unique messages.
        if len(self._seen) >= self.max_entries:
            # First try time-based eviction
            self._seen = {k: v for k, v in self._seen.items() if (now - v) < self.window_seconds}
            # If still over capacity (all entries are within window), evict oldest half
            if len(self._seen) >= self.max_entries:
                sorted_entries = sorted(self._seen.items(), key=lambda x: x[1])
                keep_from = len(sorted_entries) // 2
                self._seen = dict(sorted_entries[keep_from:])

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
    tool_classes = _classify_tool_classes(tool_name, arguments)
    argument_paths = _extract_argument_paths(arguments)
    argument_hosts = _extract_argument_hosts(arguments)

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

        denied_classes = {str(item).lower() for item in rule.get("deny_tool_classes", [])}
        if denied_classes:
            matched_classes = sorted(tool_classes & denied_classes)
            if matched_classes:
                joined = ", ".join(matched_classes)
                return False, f"Tool '{tool_name}' matched denied tool class(es) {joined} in rule '{rule.get('id', '?')}'"

        if rule.get("read_only") and tool_classes & {"write", "execute", "destructive"}:
            return False, f"Tool '{tool_name}' violates read-only mode in rule '{rule.get('id', '?')}'"

        if rule.get("block_secret_paths"):
            matched_path = next((path for path in argument_paths if _matches_secret_path(path)), None)
            if matched_path:
                return False, f"Argument path '{matched_path}' matches a protected secret path in rule '{rule.get('id', '?')}'"

        if rule.get("block_unknown_egress"):
            allowed_hosts = [str(host) for host in rule.get("allowed_hosts", [])]
            unmatched_host = next((host for host in argument_hosts if not _host_allowed(host, allowed_hosts)), None)
            if unmatched_host:
                return False, f"Outbound host '{unmatched_host}' is not allowlisted in rule '{rule.get('id', '?')}'"

        # tool_name match (exact)
        rule_tool = rule.get("tool_name")
        if rule_tool and rule_tool == tool_name:
            return False, f"Tool '{tool_name}' blocked by rule '{rule.get('id', '?')}'"

        # tool_name_pattern match (regex) — compile with length + timeout guard to mitigate ReDoS
        pattern = rule.get("tool_name_pattern")
        if pattern:
            try:
                if len(pattern) > 500:
                    logger.warning("Skipping oversized tool_name_pattern (%d chars)", len(pattern))
                elif _safe_regex_match(pattern, tool_name):
                    return False, f"Tool '{tool_name}' matches blocked pattern '{pattern}'"
            except re.error:
                pass

        # arg_pattern: {arg_name: regex_pattern} — length + timeout guard to mitigate ReDoS
        arg_patterns = rule.get("arg_pattern", {})
        for arg_name, arg_regex in arg_patterns.items():
            arg_value = str(arguments.get(arg_name, ""))
            try:
                if len(arg_regex) > 500:
                    logger.warning("Skipping oversized arg_pattern for '%s' (%d chars)", arg_name, len(arg_regex))
                    continue
                if _safe_regex_search(arg_regex, arg_value):
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

    def _handle_alerts_sse(alerts, log_f=None):
        for alert in alerts:
            alert_dict = alert.to_dict()
            runtime_alerts.append(alert_dict)
            logger.warning("Runtime alert: %s", alert.message)
            if log_f:
                log_f.write(json.dumps(alert_dict) + "\n")
                log_f.flush()
            if alert_webhook:
                asyncio.ensure_future(_send_webhook(alert_webhook, alert_dict))

    declared_tools: set[str] = set()

    try:
        async with httpx.AsyncClient(timeout=30) as client:
            # Fetch tool list from the remote server
            try:
                tools_resp = await client.post(
                    url.rstrip("/") + "/tools/list",
                    json={"jsonrpc": "2.0", "id": 1, "method": "tools/list", "params": {}},
                )
                tools_resp.raise_for_status()
                tools_data = tools_resp.json()
                if isinstance(tools_data, dict) and "result" in tools_data:
                    result = tools_data["result"]
                    if isinstance(result, dict) and "tools" in result:
                        declared_tools = {t["name"] for t in result["tools"] if isinstance(t, dict) and "name" in t}
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
                        )
                        sys.stdout.buffer.write((json.dumps(fwd.json()) + "\n").encode())
                        sys.stdout.buffer.flush()
                    except Exception as exc:  # noqa: BLE001
                        logger.debug("SSE proxy: pass-through failed: %s", exc)
                    continue

                tool_name = extract_tool_name(msg) or "unknown"
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
                        )
                    error_resp = make_error_response(msg_id, -32600, identity_block_reason)
                    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                    sys.stdout.buffer.flush()
                    continue

                if replay_detector.check(msg):
                    reason = "Replayed payload detected"
                    if log_file:
                        log_tool_call(
                            log_file, tool_name, arguments, "blocked", reason, payload_sha256=p_hash, message_id=msg_id, agent_id=agent_id
                        )
                    error_resp = make_error_response(msg_id, -32600, reason)
                    sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                    sys.stdout.buffer.flush()
                    continue

                if block_undeclared and declared_tools and tool_name not in declared_tools:
                    reason = f"Tool '{tool_name}' not in declared tools/list"
                    if log_file:
                        log_tool_call(
                            log_file, tool_name, arguments, "blocked", reason, payload_sha256=p_hash, message_id=msg_id, agent_id=agent_id
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
                            )
                        error_resp = make_error_response(msg_id, -32600, reason)
                        sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                        sys.stdout.buffer.flush()
                        continue

                if log_file:
                    log_tool_call(log_file, tool_name, arguments, "allowed", payload_sha256=p_hash, message_id=msg_id, agent_id=agent_id)  # type: ignore[arg-type]

                # Forward tool call to remote SSE/HTTP server
                call_counter += 1
                try:
                    resp = await client.post(
                        url.rstrip("/") + "/tools/call",
                        json=msg,
                        timeout=30,
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
    rate_limit_threshold: int = 0,
    log_only: bool = False,
    alert_webhook: Optional[str] = None,
    metrics_port: int = 8422,
    metrics_token: Optional[str] = None,
    response_signing_key: Optional[str] = None,
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
                                )
                            error_resp = make_error_response(msg_id, -32600, rl_reason)
                            sys.stdout.buffer.write((json.dumps(error_resp) + "\n").encode())
                            sys.stdout.buffer.flush()
                            continue

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

                # Response signing — compute HMAC on ORIGINAL response before
                # inline scanning may modify msg (tamper detection must sign
                # the server's actual response, not a scanner-modified version).
                if response_signing_key and log_file:
                    sig = compute_response_hmac(msg, response_signing_key)
                    sig_entry = (
                        json.dumps(
                            {
                                "ts": datetime.now(timezone.utc).isoformat(),
                                "type": "response_hmac",
                                "id": msg.get("id"),
                                "hmac_sha256": sig,
                            }
                        )
                        + "\n"
                    )
                    log_file.write(sig_entry)

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
                    err_entry = (
                        json.dumps(
                            {
                                "ts": datetime.now(timezone.utc).isoformat(),
                                "type": "relay_error",
                                "error": str(result),
                                "error_type": type(result).__name__,
                            }
                        )
                        + "\n"
                    )
                    log_file.write(err_entry)
    finally:
        # Write metrics summary + runtime alerts to audit log before closing
        if log_file:
            summary = metrics.summary()
            summary.update(summarize_runtime_alerts(runtime_alerts))
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
