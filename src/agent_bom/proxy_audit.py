"""Audit, integrity, replay, and metrics helpers for the MCP runtime proxy."""

from __future__ import annotations

import asyncio
import hashlib
import hmac
import json
import logging
import os
import time
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import IO, Optional

from agent_bom.agent_identity import ANONYMOUS
from agent_bom.event_normalization import build_proxy_event_relationships

logger = logging.getLogger(__name__)

# Maximum audit log size before rotation (100 MB). Prevents disk exhaustion
# on long-running proxy instances.
_AUDIT_LOG_MAX_BYTES = 100 * 1024 * 1024


class RotatingAuditLog:
    """File-like wrapper that rotates the JSONL audit log at a size threshold."""

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
        except OSError as exc:
            logger.warning("Audit log rotation failed: %s — log may grow unbounded", exc)


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
    audit_buffer_bytes: int = 0
    audit_spillover_bytes: int = 0
    policy_fetch_failures: int = 0
    audit_push_failures: int = 0

    _MAX_LATENCY_ENTRIES = 10_000

    def record_call(self, tool_name: str) -> None:
        self.tool_calls[tool_name] += 1

    def record_blocked(self, reason: str) -> None:
        self.blocked_calls[reason] += 1

    def record_latency(self, duration_ms: float) -> None:
        self.latencies_ms.append(duration_ms)
        if len(self.latencies_ms) > self._MAX_LATENCY_ENTRIES:
            self.latencies_ms = self.latencies_ms[self._MAX_LATENCY_ENTRIES // 2 :]

    def set_audit_buffer_bytes(self, size_bytes: int) -> None:
        self.audit_buffer_bytes = max(0, size_bytes)

    def set_audit_spillover_bytes(self, size_bytes: int) -> None:
        self.audit_spillover_bytes = max(0, size_bytes)

    def record_policy_fetch_failure(self) -> None:
        self.policy_fetch_failures += 1

    def record_audit_push_failure(self) -> None:
        self.audit_push_failures += 1

    def summary(self) -> dict:
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
            "audit_buffer_bytes": self.audit_buffer_bytes,
            "audit_spillover_bytes": self.audit_spillover_bytes,
            "policy_fetch_failures": self.policy_fetch_failures,
            "audit_push_failures": self.audit_push_failures,
        }


class ProxyMetricsServer:
    """Lightweight HTTP server exposing Prometheus text exposition format on /metrics."""

    def __init__(self, metrics: ProxyMetrics, port: int = 8422, token: Optional[str] = None, host: str = "127.0.0.1") -> None:
        self.metrics = metrics
        self.port = port
        self.token = token
        self.host = host
        self._server: Optional[asyncio.AbstractServer] = None

    def render_metrics(self) -> str:
        summary = self.metrics.summary()
        lines: list[str] = []

        lines.append("# HELP agent_bom_proxy_tool_calls_total Total tool calls proxied")
        lines.append("# TYPE agent_bom_proxy_tool_calls_total counter")
        for tool, count in summary.get("calls_by_tool", {}).items():
            lines.append(f'agent_bom_proxy_tool_calls_total{{tool="{tool}"}} {count}')

        lines.append("# HELP agent_bom_proxy_blocked_total Total blocked tool calls")
        lines.append("# TYPE agent_bom_proxy_blocked_total counter")
        for reason, count in summary.get("blocked_by_reason", {}).items():
            lines.append(f'agent_bom_proxy_blocked_total{{reason="{reason}"}} {count}')

        lines.append("# HELP agent_bom_proxy_uptime_seconds Proxy uptime in seconds")
        lines.append("# TYPE agent_bom_proxy_uptime_seconds gauge")
        lines.append(f"agent_bom_proxy_uptime_seconds {summary.get('uptime_seconds', 0)}")

        lines.append("# HELP agent_bom_proxy_total_tool_calls Total tool calls")
        lines.append("# TYPE agent_bom_proxy_total_tool_calls counter")
        lines.append(f"agent_bom_proxy_total_tool_calls {summary.get('total_tool_calls', 0)}")

        lines.append("# HELP agent_bom_proxy_total_blocked Total blocked calls")
        lines.append("# TYPE agent_bom_proxy_total_blocked counter")
        lines.append(f"agent_bom_proxy_total_blocked {summary.get('total_blocked', 0)}")

        latency = summary.get("latency", {})
        if latency:
            lines.append("# HELP agent_bom_proxy_latency_ms Tool call round-trip latency")
            lines.append("# TYPE agent_bom_proxy_latency_ms summary")
            if "p50_ms" in latency:
                lines.append(f'agent_bom_proxy_latency_ms{{quantile="0.5"}} {latency["p50_ms"]}')
            if "p95_ms" in latency:
                lines.append(f'agent_bom_proxy_latency_ms{{quantile="0.95"}} {latency["p95_ms"]}')

        lines.append("# HELP agent_bom_proxy_replay_rejections_total Replay attack rejections")
        lines.append("# TYPE agent_bom_proxy_replay_rejections_total counter")
        lines.append(f"agent_bom_proxy_replay_rejections_total {summary.get('replay_rejections', 0)}")

        lines.append("# HELP agent_bom_proxy_messages_total Total JSON-RPC messages")
        lines.append("# TYPE agent_bom_proxy_messages_total counter")
        lines.append(f'agent_bom_proxy_messages_total{{direction="client_to_server"}} {summary.get("messages_client_to_server", 0)}')
        lines.append(f'agent_bom_proxy_messages_total{{direction="server_to_client"}} {summary.get("messages_server_to_client", 0)}')

        lines.append("# HELP agent_bom_proxy_audit_buffer_bytes In-memory audit backlog waiting to be pushed")
        lines.append("# TYPE agent_bom_proxy_audit_buffer_bytes gauge")
        lines.append(f"agent_bom_proxy_audit_buffer_bytes {summary.get('audit_buffer_bytes', 0)}")

        lines.append("# HELP agent_bom_proxy_audit_spillover_bytes On-disk audit backlog spilled from memory")
        lines.append("# TYPE agent_bom_proxy_audit_spillover_bytes gauge")
        lines.append(f"agent_bom_proxy_audit_spillover_bytes {summary.get('audit_spillover_bytes', 0)}")

        lines.append("# HELP agent_bom_proxy_policy_fetch_failures_total Failed policy refresh attempts")
        lines.append("# TYPE agent_bom_proxy_policy_fetch_failures_total counter")
        lines.append(f"agent_bom_proxy_policy_fetch_failures_total {summary.get('policy_fetch_failures', 0)}")

        lines.append("# HELP agent_bom_proxy_audit_push_failures_total Failed audit push attempts")
        lines.append("# TYPE agent_bom_proxy_audit_push_failures_total counter")
        lines.append(f"agent_bom_proxy_audit_push_failures_total {summary.get('audit_push_failures', 0)}")

        return "\n".join(lines) + "\n"

    async def start(self) -> None:
        if self.port <= 0:
            return

        async def handle(reader: asyncio.StreamReader, writer: asyncio.StreamWriter) -> None:
            try:
                await asyncio.wait_for(reader.readline(), timeout=10)
                auth_header = ""
                while True:
                    header = await asyncio.wait_for(reader.readline(), timeout=5)
                    if not header or header == b"\r\n":
                        break
                    header_str = header.decode("utf-8", errors="replace").strip()
                    if header_str.lower().startswith("authorization:"):
                        auth_header = header_str.split(":", 1)[1].strip()

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
        if self._server:
            self._server.close()
            await self._server.wait_closed()


def _truncate_args(args: dict, max_value_len: int = 200) -> dict:
    """Truncate long argument values for logging; redact credential keys/values."""
    from agent_bom.security import sanitize_env_vars

    str_vals = {k: v for k, v in args.items() if isinstance(v, str)}
    sanitized = sanitize_env_vars(str_vals)

    result = {}
    for key, value in args.items():
        if isinstance(value, str):
            san = sanitized.get(key, value)
            if san == "***REDACTED***":
                result[key] = san
            elif len(san) > max_value_len:
                result[key] = san[:max_value_len] + "...<truncated>"
            else:
                result[key] = san
        else:
            result[key] = value
    return result


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
    """Append a tool call record to the audit JSONL log."""
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
    event_relationships = build_proxy_event_relationships(
        tool_name=tool_name,
        arguments=arguments,
        agent_id=agent_id,
        anonymous_id=ANONYMOUS,
    )
    if event_relationships is not None:
        record["event_relationships"] = event_relationships

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


def compute_payload_hash(payload: dict) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def compute_response_hmac(payload: dict, key: str) -> str:
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"))
    return hmac.new(key.encode("utf-8"), canonical.encode("utf-8"), hashlib.sha256).hexdigest()


@dataclass
class ReplayDetector:
    """Detect replayed JSON-RPC messages by tracking payload hashes."""

    window_seconds: float = 300.0
    max_entries: int = 10_000
    _seen: dict[str, float] = field(default_factory=dict)

    def check(self, msg: dict) -> bool:
        h = compute_payload_hash(msg)
        now = time.monotonic()

        if len(self._seen) >= self.max_entries:
            self._seen = {k: v for k, v in self._seen.items() if (now - v) < self.window_seconds}
            if len(self._seen) >= self.max_entries:
                sorted_entries = sorted(self._seen.items(), key=lambda item: item[1])
                keep_from = len(sorted_entries) // 2
                self._seen = dict(sorted_entries[keep_from:])

        if h in self._seen and (now - self._seen[h]) < self.window_seconds:
            return True

        self._seen[h] = now
        return False
