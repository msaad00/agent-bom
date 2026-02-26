"""Runtime MCP traffic detectors — anomaly and threat detection.

Pluggable detectors that analyze MCP JSON-RPC traffic in real-time:
- ToolDriftDetector — new tools appearing after startup (rug pull)
- ArgumentAnalyzer — shell injection, path traversal, credential values in args
- CredentialLeakDetector — API keys/tokens in tool responses
- RateLimitTracker — excessive tool calls per window
- SequenceAnalyzer — suspicious multi-step call patterns (exfiltration, recon)
"""

from __future__ import annotations

import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum

from agent_bom.runtime.patterns import (
    CREDENTIAL_PATTERNS,
    DANGEROUS_ARG_PATTERNS,
    SUSPICIOUS_SEQUENCES,
)


class AlertSeverity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Alert:
    """A runtime security alert."""

    detector: str
    severity: AlertSeverity
    message: str
    details: dict = field(default_factory=dict)
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())

    def to_dict(self) -> dict:
        return {
            "type": "runtime_alert",
            "ts": self.timestamp,
            "detector": self.detector,
            "severity": self.severity.value,
            "message": self.message,
            "details": self.details,
        }


# ─── Tool Drift Detector ────────────────────────────────────────────────────


class ToolDriftDetector:
    """Detect new tools appearing after initial tools/list (rug pull detection).

    Compares the initial tools/list snapshot against subsequent ones.
    New tools that weren't in the initial set trigger HIGH alerts.
    """

    def __init__(self) -> None:
        self._baseline: set[str] | None = None

    def set_baseline(self, tools: list[str]) -> None:
        """Set the initial tool baseline from the first tools/list response."""
        self._baseline = set(tools)

    def check(self, current_tools: list[str]) -> list[Alert]:
        """Compare current tools against baseline. Returns alerts for new tools."""
        if self._baseline is None:
            self.set_baseline(current_tools)
            return []

        current = set(current_tools)
        new_tools = current - self._baseline
        removed_tools = self._baseline - current

        alerts: list[Alert] = []
        if new_tools:
            alerts.append(Alert(
                detector="tool_drift",
                severity=AlertSeverity.HIGH,
                message=f"New tools detected after startup: {', '.join(sorted(new_tools))}",
                details={"new_tools": sorted(new_tools), "baseline_count": len(self._baseline)},
            ))
        if removed_tools:
            alerts.append(Alert(
                detector="tool_drift",
                severity=AlertSeverity.MEDIUM,
                message=f"Tools removed after startup: {', '.join(sorted(removed_tools))}",
                details={"removed_tools": sorted(removed_tools)},
            ))
        return alerts

    @property
    def baseline(self) -> set[str] | None:
        return self._baseline


# ─── Argument Analyzer ───────────────────────────────────────────────────────


class ArgumentAnalyzer:
    """Detect dangerous patterns in tool call arguments.

    Checks for shell metacharacters, path traversal, command injection,
    and credential-like values in argument strings.
    """

    def check(self, tool_name: str, arguments: dict) -> list[Alert]:
        """Analyze tool arguments for dangerous patterns."""
        alerts: list[Alert] = []
        for arg_name, arg_value in arguments.items():
            if not isinstance(arg_value, str):
                arg_value = str(arg_value)
            for pattern_name, pattern in DANGEROUS_ARG_PATTERNS:
                if pattern.search(arg_value):
                    alerts.append(Alert(
                        detector="argument_analyzer",
                        severity=AlertSeverity.HIGH,
                        message=f"Dangerous argument pattern '{pattern_name}' in {tool_name}.{arg_name}",
                        details={
                            "tool": tool_name,
                            "argument": arg_name,
                            "pattern": pattern_name,
                            "value_preview": arg_value[:100],
                        },
                    ))
        return alerts


# ─── Credential Leak Detector ────────────────────────────────────────────────


class CredentialLeakDetector:
    """Detect API keys and tokens in tool response content.

    Scans the text content of tool call responses for known credential
    patterns (AWS keys, GitHub tokens, OpenAI keys, etc.).
    """

    def check(self, tool_name: str, response_text: str) -> list[Alert]:
        """Scan response text for credential patterns."""
        alerts: list[Alert] = []
        for cred_name, pattern in CREDENTIAL_PATTERNS:
            matches = pattern.findall(response_text)
            if matches:
                # Redact the actual credential value
                redacted = [m[:8] + "..." if len(m) > 8 else "***" for m in matches[:3]]
                alerts.append(Alert(
                    detector="credential_leak",
                    severity=AlertSeverity.CRITICAL,
                    message=f"Credential leak detected: {cred_name} in response from {tool_name}",
                    details={
                        "tool": tool_name,
                        "credential_type": cred_name,
                        "match_count": len(matches),
                        "redacted_preview": redacted,
                    },
                ))
        return alerts


# ─── Rate Limit Tracker ──────────────────────────────────────────────────────


class RateLimitTracker:
    """Track tool call rates and alert on excessive usage.

    Uses a sliding window to track calls per tool. Alerts when any tool
    exceeds the configured threshold within the window.
    """

    def __init__(self, threshold: int = 50, window_seconds: float = 60.0) -> None:
        self._threshold = threshold
        self._window = window_seconds
        self._calls: dict[str, deque[float]] = {}

    def record(self, tool_name: str) -> list[Alert]:
        """Record a tool call and check rate limits."""
        now = time.monotonic()
        if tool_name not in self._calls:
            self._calls[tool_name] = deque()

        q = self._calls[tool_name]
        q.append(now)

        # Prune old entries
        while q and q[0] < now - self._window:
            q.popleft()

        alerts: list[Alert] = []
        if len(q) >= self._threshold:
            alerts.append(Alert(
                detector="rate_limit",
                severity=AlertSeverity.MEDIUM,
                message=f"Excessive tool calls: {tool_name} called {len(q)} times in {self._window}s (threshold: {self._threshold})",
                details={
                    "tool": tool_name,
                    "count": len(q),
                    "threshold": self._threshold,
                    "window_seconds": self._window,
                },
            ))
        return alerts

    @property
    def threshold(self) -> int:
        return self._threshold

    @property
    def window(self) -> float:
        return self._window


# ─── Sequence Analyzer ────────────────────────────────────────────────────────


class SequenceAnalyzer:
    """Detect suspicious multi-step tool call patterns.

    Maintains a sliding window of recent tool calls and checks for
    known attack sequences (e.g., read_file → http_request = exfiltration).
    """

    def __init__(self, window_size: int = 10) -> None:
        self._window_size = window_size
        self._recent_calls: deque[str] = deque(maxlen=window_size)

    def record(self, tool_name: str) -> list[Alert]:
        """Record a tool call and check for suspicious sequences."""
        self._recent_calls.append(tool_name)
        calls_list = list(self._recent_calls)
        alerts: list[Alert] = []

        for seq_name, patterns, description in SUSPICIOUS_SEQUENCES:
            if self._matches_sequence(calls_list, patterns):
                alerts.append(Alert(
                    detector="sequence_analyzer",
                    severity=AlertSeverity.HIGH,
                    message=description,
                    details={
                        "sequence_name": seq_name,
                        "recent_calls": calls_list[-len(patterns):],
                        "window_size": self._window_size,
                    },
                ))
        return alerts

    @staticmethod
    def _matches_sequence(calls: list[str], patterns: list[str]) -> bool:
        """Check if the tail of calls matches a pattern sequence."""
        if len(calls) < len(patterns):
            return False

        # Check the last N calls against the patterns
        tail = calls[-len(patterns):]
        for call, pattern in zip(tail, patterns):
            if not re.search(pattern, call, re.IGNORECASE):
                return False
        return True

    @property
    def recent_calls(self) -> list[str]:
        return list(self._recent_calls)
