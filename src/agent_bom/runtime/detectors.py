"""Runtime MCP traffic detectors — anomaly and threat detection.

Pluggable detectors that analyze MCP JSON-RPC traffic in real-time:
- ToolDriftDetector — new tools appearing after startup (rug pull)
- ArgumentAnalyzer — shell injection, path traversal, credential values in args
- CredentialLeakDetector — API keys/tokens in tool responses
- RateLimitTracker — excessive tool calls per window
- SequenceAnalyzer — suspicious multi-step call patterns (exfiltration, recon)
- ResponseInspector — HTML/CSS cloaking, SVG payloads, invisible chars in responses
"""

from __future__ import annotations

import json
import os
import re
import time
from collections import deque
from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from agent_bom.runtime.patterns import (
    CREDENTIAL_PATTERNS,
    DANGEROUS_ARG_PATTERNS,
    RESPONSE_BASE64_PATTERN,
    RESPONSE_CLOAKING_PATTERNS,
    RESPONSE_INJECTION_PATTERNS,
    RESPONSE_INVISIBLE_CHARS,
    RESPONSE_SVG_PATTERNS,
    SUSPICIOUS_SEQUENCES,
    detect_cortex_models,
    score_semantic_injection,
)
from agent_bom.runtime.patterns import (
    PII_PATTERNS as _PII_PATTERNS,
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


# ─── Detector Telemetry ───────────────────────────────────────────────────
#
# Tracks fire counts, suppression counts, and false positive feedback
# per detector. Exposed via Prometheus metrics when proxy runs with
# --metrics-port.


@dataclass
class DetectorMetrics:
    """Per-detector telemetry counters."""

    fires: int = 0
    suppressed: int = 0
    false_positives: int = 0

    def record_fire(self) -> None:
        self.fires += 1

    def record_suppression(self) -> None:
        self.suppressed += 1

    def record_false_positive(self) -> None:
        self.false_positives += 1

    @property
    def false_positive_rate(self) -> float:
        """False positive rate (0.0-1.0). Returns 0.0 if no fires."""
        if self.fires == 0:
            return 0.0
        return self.false_positives / self.fires

    def to_dict(self) -> dict:
        return {
            "fires": self.fires,
            "suppressed": self.suppressed,
            "false_positives": self.false_positives,
            "false_positive_rate": round(self.false_positive_rate, 4),
        }


# Global metrics registry — one entry per detector name
_DETECTOR_METRICS: dict[str, DetectorMetrics] = {}


def get_detector_metrics(detector_name: str) -> DetectorMetrics:
    """Get or create metrics for a detector."""
    if detector_name not in _DETECTOR_METRICS:
        _DETECTOR_METRICS[detector_name] = DetectorMetrics()
    return _DETECTOR_METRICS[detector_name]


def all_detector_metrics() -> dict[str, dict]:
    """Return all detector metrics as a dict for API/Prometheus export."""
    return {name: m.to_dict() for name, m in _DETECTOR_METRICS.items()}


def reset_detector_metrics() -> None:
    """Reset all metrics (for testing)."""
    _DETECTOR_METRICS.clear()


# ─── Detector Sensitivity Config ──────────────────────────────────────────
#
# Per-detector sensitivity levels loaded from .agent-bom.yaml:
#   detectors:
#     ArgumentAnalyzer: high       # high, medium, low, off
#     RateLimitTracker: medium
#     ResponseInspector: low

_SENSITIVITY_LEVELS = ("off", "low", "medium", "high")
_DEFAULT_SENSITIVITY = "high"
_DETECTOR_SENSITIVITY: dict[str, str] = {}


def configure_detector_sensitivity(config: dict[str, str]) -> None:
    """Set per-detector sensitivity from project config."""
    for name, level in config.items():
        if level.lower() in _SENSITIVITY_LEVELS:
            _DETECTOR_SENSITIVITY[name] = level.lower()


def get_detector_sensitivity(detector_name: str) -> str:
    """Get sensitivity level for a detector (default: high)."""
    return _DETECTOR_SENSITIVITY.get(detector_name, _DEFAULT_SENSITIVITY)


def is_detector_enabled(detector_name: str) -> bool:
    """Check if a detector is enabled (sensitivity != off)."""
    return get_detector_sensitivity(detector_name) != "off"


# ─── Tool Drift Detector ────────────────────────────────────────────────────


class ToolDriftDetector:
    """Detect new tools appearing after initial tools/list (rug pull detection).

    Compares the initial tools/list snapshot against subsequent ones.
    New tools that weren't in the initial set trigger HIGH alerts.
    Persists baseline to disk so it survives engine restarts.
    """

    def __init__(self, *, restore: bool = False) -> None:
        self._baseline: set[str] | None = None
        if restore:
            self._restore_baseline()

    @staticmethod
    def _baseline_path() -> Path:
        state_dir = Path(os.environ.get("AGENT_BOM_STATE_DIR", Path.home() / ".agent-bom"))
        state_dir.mkdir(parents=True, exist_ok=True)
        return state_dir / "drift_baseline.json"

    def _persist_baseline(self) -> None:
        try:
            path = self._baseline_path()
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(sorted(self._baseline or [])))
            tmp.replace(path)
        except OSError:
            pass

    def _restore_baseline(self) -> None:
        try:
            path = self._baseline_path()
            if path.exists():
                tools = json.loads(path.read_text())
                if isinstance(tools, list):
                    self._baseline = set(tools)
        except (OSError, json.JSONDecodeError):
            pass

    def set_baseline(self, tools: list[str]) -> None:
        """Set the initial tool baseline from the first tools/list response."""
        self._baseline = set(tools)
        self._persist_baseline()

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
            alerts.append(
                Alert(
                    detector="tool_drift",
                    severity=AlertSeverity.HIGH,
                    message=f"New tools detected after startup: {', '.join(sorted(new_tools))}",
                    details={"new_tools": sorted(new_tools), "baseline_count": len(self._baseline)},
                )
            )
        if removed_tools:
            alerts.append(
                Alert(
                    detector="tool_drift",
                    severity=AlertSeverity.MEDIUM,
                    message=f"Tools removed after startup: {', '.join(sorted(removed_tools))}",
                    details={"removed_tools": sorted(removed_tools)},
                )
            )
        return alerts

    @property
    def baseline(self) -> set[str] | None:
        return self._baseline


# ─── Argument Analyzer ───────────────────────────────────────────────────────


class ArgumentAnalyzer:
    """Detect dangerous patterns and AI model invocations in tool call arguments.

    Checks for shell metacharacters, path traversal, command injection,
    credential-like values, and Cortex AI model calls in argument strings.
    """

    def check(self, tool_name: str, arguments: dict | None) -> list[Alert]:
        """Analyze tool arguments for dangerous patterns and AI model usage."""
        alerts: list[Alert] = []
        if not arguments:
            return alerts
        for arg_name, arg_value in arguments.items():
            if not isinstance(arg_value, str):
                arg_value = str(arg_value)
            for pattern_name, pattern in DANGEROUS_ARG_PATTERNS:
                if pattern.search(arg_value):
                    alerts.append(
                        Alert(
                            detector="argument_analyzer",
                            severity=AlertSeverity.HIGH,
                            message=f"Dangerous argument pattern '{pattern_name}' in {tool_name}.{arg_name}",
                            details={
                                "tool": tool_name,
                                "argument": arg_name,
                                "pattern": pattern_name,
                                "value_preview": arg_value[:100],
                            },
                        )
                    )

            # Cortex AI model detection — INFO-level observability alerts
            cortex_hits = detect_cortex_models(arg_value)
            for cx_pattern, cx_model in cortex_hits:
                alerts.append(
                    Alert(
                        detector="argument_analyzer",
                        severity=AlertSeverity.INFO,
                        message=(
                            f"Cortex AI model invocation detected: {cx_pattern}"
                            f"{f' (model: {cx_model})' if cx_model else ''}"
                            f" in {tool_name}.{arg_name}"
                        ),
                        details={
                            "tool": tool_name,
                            "argument": arg_name,
                            "pattern": cx_pattern,
                            "model": cx_model,
                            "category": "cortex_model_usage",
                        },
                    )
                )

        return alerts


# ─── Credential Leak Detector ────────────────────────────────────────────────


class CredentialLeakDetector:
    """Detect and optionally redact API keys, tokens, and PII in tool responses.

    Scans the text content of tool call responses for known credential
    patterns (AWS keys, GitHub tokens, OpenAI keys, etc.) and PII
    (email addresses, phone numbers, SSNs, credit card numbers).

    When ``redact=True``, returns sanitized text with sensitive values
    replaced by ``[REDACTED:<type>]`` markers.
    """

    def check(self, tool_name: str, response_text: str) -> list[Alert]:
        """Scan response text for credential and PII patterns."""
        alerts: list[Alert] = []
        for cred_name, pattern in CREDENTIAL_PATTERNS:
            matches = pattern.findall(response_text)
            if matches:
                redacted = [m[:4] + "..." if len(m) > 4 else "***" for m in matches[:3]]
                alerts.append(
                    Alert(
                        detector="credential_leak",
                        severity=AlertSeverity.CRITICAL,
                        message=f"Credential leak detected: {cred_name} in response from {tool_name}",
                        details={
                            "tool": tool_name,
                            "credential_type": cred_name,
                            "match_count": len(matches),
                            "redacted_preview": redacted,
                        },
                    )
                )
        # PII detection
        for pii_name, pattern in _PII_PATTERNS:
            matches = pattern.findall(response_text)
            if matches:
                alerts.append(
                    Alert(
                        detector="pii_leak",
                        severity=AlertSeverity.HIGH,
                        message=f"PII detected: {pii_name} in response from {tool_name}",
                        details={
                            "tool": tool_name,
                            "pii_type": pii_name,
                            "match_count": len(matches),
                        },
                    )
                )
        return alerts

    @staticmethod
    def redact(text: str) -> str:
        """Return a copy of *text* with credentials and PII replaced.

        Replaces matched values with ``[REDACTED:<type>]`` markers.
        The original text is never modified.
        """
        result = text
        for cred_name, pattern in CREDENTIAL_PATTERNS:
            result = pattern.sub(f"[REDACTED:{cred_name}]", result)
        for pii_name, pattern in _PII_PATTERNS:
            result = pattern.sub(f"[REDACTED:{pii_name}]", result)
        return result


# ─── Rate Limit Tracker ──────────────────────────────────────────────────────


class RateLimitTracker:
    """Track tool call rates and block on excessive usage.

    Uses a sliding window to track calls per tool. When any tool exceeds
    the threshold, returns a CRITICAL alert with ``blocked=True`` so the
    caller can enforce the rate limit (zero trust — deny by default).
    """

    def __init__(self, threshold: int = 50, window_seconds: float = 60.0) -> None:
        self._threshold = threshold
        self._window = window_seconds
        self._calls: dict[str, deque[float]] = {}

    def record(self, tool_name: str) -> list[Alert]:
        """Record a tool call and check rate limits.

        Returns a CRITICAL alert with ``details.blocked = True`` when the
        rate limit is exceeded, signaling the caller to deny the call.
        """
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
            # Escalate severity based on how far over the limit
            over_ratio = len(q) / self._threshold
            severity = AlertSeverity.CRITICAL if over_ratio >= 2.0 else AlertSeverity.HIGH
            alerts.append(
                Alert(
                    detector="rate_limit",
                    severity=severity,
                    message=f"Rate limit exceeded: {tool_name} called {len(q)} times in {self._window}s (threshold: {self._threshold})",
                    details={
                        "tool": tool_name,
                        "count": len(q),
                        "threshold": self._threshold,
                        "window_seconds": self._window,
                        "blocked": True,
                    },
                )
            )
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
                alerts.append(
                    Alert(
                        detector="sequence_analyzer",
                        severity=AlertSeverity.HIGH,
                        message=description,
                        details={
                            "sequence_name": seq_name,
                            "recent_calls": calls_list[-len(patterns) :],
                            "window_size": self._window_size,
                        },
                    )
                )
        return alerts

    @staticmethod
    def _matches_sequence(calls: list[str], patterns: list[str]) -> bool:
        """Check if patterns appear as a subsequence within calls.

        Uses subsequence matching instead of exact-tail matching so that
        inserting benign calls between attack steps (e.g., read_file →
        benign_tool → http_request) cannot evade detection.
        """
        if len(calls) < len(patterns):
            return False

        pattern_idx = 0
        for call in calls:
            # Normalize separators to spaces so word boundaries work on
            # tool names like "read_file" or "http-request" — prevents
            # false positives like "spreadsheet" matching "read"
            normalized = re.sub(r"[_\-.]", " ", call)
            bounded = rf"\b(?:{patterns[pattern_idx]})\b"
            if re.search(bounded, normalized, re.IGNORECASE):
                pattern_idx += 1
                if pattern_idx == len(patterns):
                    return True
        return False

    @property
    def recent_calls(self) -> list[str]:
        return list(self._recent_calls)


# ─── Response Inspector ──────────────────────────────────────────────────────


class ResponseInspector:
    """Detect hidden content and payloads in tool response text.

    Scans for HTML/CSS cloaking (display:none, visibility:hidden, opacity:0),
    SVG-based payloads (script tags, foreignObject), invisible Unicode
    characters (zero-width, RTL overrides, tag chars), and large base64
    blobs that may indicate exfiltration staging.

    Based on Unit42 research showing 85% of real-world prompt injections
    use social engineering via tool responses with hidden instructions.
    """

    def check(self, tool_name: str, response_text: str) -> list[Alert]:
        """Scan response text for cloaking, SVG payloads, and invisible chars."""
        alerts: list[Alert] = []

        # HTML/CSS cloaking
        for pattern_name, pattern in RESPONSE_CLOAKING_PATTERNS:
            matches = pattern.findall(response_text)
            if matches:
                alerts.append(
                    Alert(
                        detector="response_inspector",
                        severity=AlertSeverity.HIGH,
                        message=f"HTML/CSS cloaking detected: {pattern_name} in response from {tool_name}",
                        details={
                            "tool": tool_name,
                            "pattern": pattern_name,
                            "category": "cloaking",
                            "match_count": len(matches),
                        },
                    )
                )

        # SVG payloads
        for pattern_name, pattern in RESPONSE_SVG_PATTERNS:
            matches = pattern.findall(response_text)
            if matches:
                alerts.append(
                    Alert(
                        detector="response_inspector",
                        severity=AlertSeverity.CRITICAL,
                        message=f"SVG payload detected: {pattern_name} in response from {tool_name}",
                        details={
                            "tool": tool_name,
                            "pattern": pattern_name,
                            "category": "svg_payload",
                            "match_count": len(matches),
                        },
                    )
                )

        # Invisible Unicode characters
        for pattern_name, pattern in RESPONSE_INVISIBLE_CHARS:
            matches = pattern.findall(response_text)
            if matches:
                alerts.append(
                    Alert(
                        detector="response_inspector",
                        severity=AlertSeverity.HIGH,
                        message=f"Invisible characters detected: {pattern_name} in response from {tool_name}",
                        details={
                            "tool": tool_name,
                            "pattern": pattern_name,
                            "category": "invisible_text",
                            "match_count": len(matches),
                        },
                    )
                )

        # Base64 blobs in responses (potential exfil staging)
        b64_matches = RESPONSE_BASE64_PATTERN.findall(response_text)
        if b64_matches:
            alerts.append(
                Alert(
                    detector="response_inspector",
                    severity=AlertSeverity.MEDIUM,
                    message=f"Large base64 blob in response from {tool_name} — potential exfiltration staging",
                    details={
                        "tool": tool_name,
                        "category": "base64_blob",
                        "match_count": len(b64_matches),
                        "largest_length": max(len(m) for m in b64_matches),
                    },
                )
            )

        # Prompt injection patterns (cache poisoning / cross-agent injection)
        for pattern_name, pattern in RESPONSE_INJECTION_PATTERNS:
            matches = pattern.findall(response_text)
            if matches:
                alerts.append(
                    Alert(
                        detector="response_inspector",
                        severity=AlertSeverity.CRITICAL,
                        message=f"Prompt injection detected: {pattern_name} in response from {tool_name}",
                        details={
                            "tool": tool_name,
                            "pattern": pattern_name,
                            "category": "prompt_injection",
                            "match_count": len(matches),
                            "preview": matches[0][:120] if matches else "",
                        },
                    )
                )

        # Semantic injection scoring — catches natural-language instruction
        # hijacking that evades binary pattern matching.
        semantic_score, triggered_signals = score_semantic_injection(response_text)
        if semantic_score >= 0.4:
            severity = AlertSeverity.HIGH if semantic_score >= 0.7 else AlertSeverity.MEDIUM
            alerts.append(
                Alert(
                    detector="response_inspector",
                    severity=severity,
                    message=(
                        f"Semantic injection risk ({semantic_score:.2f}) in response from {tool_name} "
                        f"— signals: {', '.join(triggered_signals)}"
                    ),
                    details={
                        "tool": tool_name,
                        "category": "semantic_injection",
                        "score": round(semantic_score, 3),
                        "signals": triggered_signals,
                    },
                )
            )

        return alerts


# ─── Vector DB Injection Detector ────────────────────────────────────────────


class VectorDBInjectionDetector:
    """Detect prompt injection in vector DB / RAG retrieval responses.

    Vector databases are a cache poisoning attack surface: an attacker who
    can write to the vector store (or poison upstream documents) can inject
    instructions that the LLM will execute when the agent retrieves context.

    This detector identifies tool calls that look like vector DB retrievals
    (similarity_search, query, retrieve, search, fetch_context, etc.) and
    applies full prompt injection scanning to their responses.

    See also: ToxicPattern.CACHE_POISON and ToxicPattern.CROSS_AGENT_POISON
    in toxic_combos.py.
    """

    # Tool name patterns that indicate a vector DB / RAG retrieval
    _VECTOR_TOOL_PATTERNS = re.compile(
        r"(?:similarity[_\s]search|semantic[_\s]search|vector[_\s](?:search|query|lookup)|"
        r"retriev(?:e|al)|fetch[_\s](?:context|docs?|chunks?)|rag[_\s](?:query|search)|"
        r"search[_\s](?:docs?|knowledge|embeddings?)|query[_\s](?:index|store|db|database)|"
        r"get[_\s]context|lookup[_\s](?:docs?|knowledge))",
        re.IGNORECASE,
    )

    def __init__(self) -> None:
        self._inspector = ResponseInspector()

    def is_vector_tool(self, tool_name: str) -> bool:
        """Return True if tool_name looks like a vector DB retrieval tool."""
        return bool(self._VECTOR_TOOL_PATTERNS.search(tool_name))

    def check(self, tool_name: str, response_text: str) -> list[Alert]:
        """Check a tool response for prompt injection (cache poisoning).

        Always runs injection pattern checks regardless of tool name.
        If the tool looks like a vector DB retrieval, also runs the full
        ResponseInspector suite and upgrades severity to CRITICAL.
        """
        alerts: list[Alert] = []

        # Injection patterns — always check
        for pattern_name, pattern in RESPONSE_INJECTION_PATTERNS:
            matches = pattern.findall(response_text)
            if matches:
                is_vector = self.is_vector_tool(tool_name)
                alerts.append(
                    Alert(
                        detector="vector_db_injection",
                        severity=AlertSeverity.CRITICAL,
                        message=(
                            f"{'Cache poisoning' if is_vector else 'Content injection'} detected: "
                            f"{pattern_name} in {'vector DB retrieval' if is_vector else 'tool response'} "
                            f"from {tool_name}"
                        ),
                        details={
                            "tool": tool_name,
                            "pattern": pattern_name,
                            "category": "cache_poison" if is_vector else "content_injection",
                            "is_vector_tool": is_vector,
                            "match_count": len(matches),
                            "preview": matches[0][:120] if matches else "",
                        },
                    )
                )

        # For confirmed vector tools also run full cloaking/SVG/invisible checks
        if self.is_vector_tool(tool_name):
            for alert in self._inspector.check(tool_name, response_text):
                # Re-tag detector and upgrade severity
                alert.detector = "vector_db_injection"
                if alert.severity == AlertSeverity.HIGH:
                    alert.severity = AlertSeverity.CRITICAL
                alert.details["category"] = "cache_poison_" + alert.details.get("category", "unknown")
                alerts.append(alert)

        return alerts


# ─── Cross-Agent Correlator ──────────────────────────────────────────────────


class CrossAgentCorrelator:
    """Detect suspicious patterns across multiple agent sessions.

    Maintains per-agent tool call history and detects lateral movement
    when multiple agents converge on the same sensitive tools within a
    short time window — a strong signal of coordinated compromise or
    credential-sharing between agents.
    """

    def __init__(self) -> None:
        self._agent_calls: dict[str, list[dict]] = {}  # agent_id -> recent calls
        self._baselines: dict[str, dict] = {}  # agent_id -> tool frequency baseline
        self._max_history = 1000

    def record_call(self, agent_id: str, tool_name: str, timestamp: float) -> None:
        """Record a tool call for cross-agent analysis."""
        if agent_id not in self._agent_calls:
            self._agent_calls[agent_id] = []
        self._agent_calls[agent_id].append(
            {
                "tool": tool_name,
                "timestamp": timestamp,
            }
        )
        # Trim history to bounded size to prevent unbounded memory growth
        if len(self._agent_calls[agent_id]) > self._max_history:
            self._agent_calls[agent_id] = self._agent_calls[agent_id][-self._max_history :]

    def detect_lateral_movement(self) -> list[dict]:
        """Detect when multiple agents access the same sensitive tools in sequence.

        Flags tools used by 3 or more distinct agents within a 5-minute window.
        This pattern indicates lateral movement, credential sharing, or a
        coordinated attack across agent sessions.

        Returns:
            List of alert dicts with type ``cross_agent_tool_convergence``.
        """
        alerts: list[dict] = []
        recent_window = time.time() - 300  # 5-minute window

        # Collect which agents used each tool in the window
        tool_agents: dict[str, list[str]] = {}
        for agent_id, calls in self._agent_calls.items():
            for call in calls:
                if call["timestamp"] > recent_window:
                    tool = call["tool"]
                    if tool not in tool_agents:
                        tool_agents[tool] = []
                    if agent_id not in tool_agents[tool]:
                        tool_agents[tool].append(agent_id)

        # Flag tools used by 3+ different agents in the window
        for tool, agents in tool_agents.items():
            if len(agents) >= 3:
                alerts.append(
                    {
                        "type": "cross_agent_tool_convergence",
                        "tool": tool,
                        "agents": agents,
                        "severity": "high",
                        "message": (
                            f"Tool '{tool}' used by {len(agents)} agents in 5-minute window — "
                            "possible lateral movement or coordinated access"
                        ),
                    }
                )

        return alerts

    def compute_baseline(self, agent_id: str) -> dict:
        """Compute tool frequency baseline for anomaly detection.

        Returns a dict mapping tool name to its relative frequency (0.0–1.0)
        in the agent's historical call log.
        """
        calls = self._agent_calls.get(agent_id, [])
        freq: dict[str, int] = {}
        for call in calls:
            freq[call["tool"]] = freq.get(call["tool"], 0) + 1
        total = sum(freq.values()) or 1
        return {tool: count / total for tool, count in freq.items()}

    def update_baseline(self, agent_id: str) -> None:
        """Compute and store the tool frequency baseline for an agent.

        Should be called periodically (e.g. after every N calls) to keep
        the baseline current without paying compute cost on every call.
        """
        self._baselines[agent_id] = self.compute_baseline(agent_id)

    def detect_anomaly(self, agent_id: str, tool_name: str) -> bool:
        """Check if a tool call is anomalous based on historical baseline.

        Returns True when the tool has never been seen in the stored baseline,
        which indicates either a new capability being exercised or an agent
        behaving outside its normal operational envelope.

        The baseline must be stored via ``update_baseline()`` before this
        method will return meaningful results.  Returns False (not anomalous)
        when no baseline exists for the agent.
        """
        baseline = self._baselines.get(agent_id)
        if not baseline:
            return False
        expected_freq = baseline.get(tool_name, 0.0)
        # Tool never seen in baseline = anomalous
        return expected_freq == 0.0
