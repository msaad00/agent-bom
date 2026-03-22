"""Runtime protection engine — unified detector orchestration.

Connects all seven runtime detectors, OTel trace ingestion, and the alert
dispatcher into a single protection pipeline. Activated via the API
(``POST /v1/protect/start``) or CLI (``agent-bom protect``).

**Deep Defense Mode** (``shield=True``):
Adds correlated multi-detector threat scoring, automatic threat-level
escalation, sliding-window alert correlation, and kill-switch capability.
When multiple detectors fire within a short window, deep defense mode
computes a composite threat score and can escalate the session to
CRITICAL, triggering automated containment (block tool calls, freeze
baseline, notify SIEM).
"""

from __future__ import annotations

import json
import logging
import os
import time
from collections import deque
from dataclasses import dataclass
from datetime import datetime, timezone
from enum import Enum
from pathlib import Path

from agent_bom.alerts.dispatcher import AlertDispatcher
from agent_bom.otel_ingest import parse_otel_traces
from agent_bom.runtime.detectors import (
    ArgumentAnalyzer,
    CredentialLeakDetector,
    RateLimitTracker,
    ResponseInspector,
    SequenceAnalyzer,
    ToolDriftDetector,
    VectorDBInjectionDetector,
)

logger = logging.getLogger(__name__)


# ── Deep defense: threat levels ──────────────────────────────────────────────


class ThreatLevel(str, Enum):
    """Session-wide threat level, escalated by correlated alerts."""

    NORMAL = "normal"
    ELEVATED = "elevated"  # 2+ detectors firing in window
    HIGH = "high"  # 3+ detectors OR critical alert
    CRITICAL = "critical"  # correlated attack pattern confirmed


# Severity weights for composite scoring
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high": 2.5,
    "medium": 1.0,
    "low": 0.3,
    "info": 0.0,
}

# Threat level thresholds (composite score within correlation window)
_THREAT_THRESHOLDS = {
    ThreatLevel.ELEVATED: 3.0,
    ThreatLevel.HIGH: 6.0,
    ThreatLevel.CRITICAL: 10.0,
}


@dataclass
class _CorrelationEntry:
    """A single alert in the correlation window."""

    timestamp: float
    detector: str
    severity: str
    tool_name: str


@dataclass
class ShieldAssessment:
    """Result of deep defense correlation analysis."""

    threat_level: ThreatLevel
    composite_score: float
    detectors_triggered: list[str]
    correlation_window_seconds: float
    alert_count_in_window: int
    escalated: bool  # True if threat level changed this cycle
    blocked: bool  # True if kill-switch activated


@dataclass
class ProtectionStats:
    """Lifetime statistics for a protection engine session."""

    started_at: str = ""
    traces_processed: int = 0
    tool_calls_analyzed: int = 0
    alerts_generated: int = 0
    detectors_active: int = 7
    # Deep defense stats
    shield_active: bool = False
    threat_level: str = ThreatLevel.NORMAL.value
    escalations: int = 0
    blocks: int = 0
    correlation_window_alerts: int = 0


class ProtectionEngine:
    """Orchestrates runtime detectors with OTel ingestion and alert dispatch.

    Args:
        dispatcher: Alert dispatcher for routing alerts to SIEM/Slack/etc.
        shield: Enable deep defense mode (correlated multi-detector scoring,
            threat-level escalation, kill-switch capability).
        correlation_window: Seconds to correlate alerts across detectors (default 30s).
        block_on_critical: Auto-block tool calls when threat level reaches CRITICAL.

    Typical lifecycle::

        engine = ProtectionEngine(dispatcher, shield=True)
        engine.start()
        alerts = await engine.process_tool_call("read_file", {"path": "/etc/passwd"})
        assessment = engine.assess_threat()  # deep defense assessment
        engine.stop()
    """

    def __init__(
        self,
        dispatcher: AlertDispatcher | None = None,
        *,
        shield: bool = False,
        correlation_window: float = 30.0,
        block_on_critical: bool = True,
    ) -> None:
        self.drift_detector = ToolDriftDetector()
        self.arg_analyzer = ArgumentAnalyzer()
        self.cred_detector = CredentialLeakDetector()
        self.rate_tracker = RateLimitTracker()
        self.seq_analyzer = SequenceAnalyzer()
        self.response_inspector = ResponseInspector()
        self.vector_db_detector = VectorDBInjectionDetector()
        self.dispatcher = dispatcher or AlertDispatcher()
        self._active = False
        self._stats = ProtectionStats()

        # Deep defense state
        self._shield = shield
        self._correlation_window = correlation_window
        self._block_on_critical = block_on_critical
        self._threat_level = ThreatLevel.NORMAL
        self._correlation_buffer: deque[_CorrelationEntry] = deque()
        self._blocked = False
        self._allowed_tools: set[str] | None = None  # None = all allowed

    # ── Persistent kill-switch state ──────────────────────────────────────

    @staticmethod
    def _state_path() -> Path:
        """Path to the persistent kill-switch state file."""
        state_dir = Path(os.environ.get("AGENT_BOM_STATE_DIR", Path.home() / ".agent-bom"))
        state_dir.mkdir(parents=True, exist_ok=True)
        return state_dir / "killswitch.json"

    def _persist_state(self) -> None:
        """Write kill-switch state to disk so it survives process restarts."""
        try:
            state = {
                "blocked": self._blocked,
                "threat_level": self._threat_level.value,
                "updated_at": datetime.now(timezone.utc).isoformat(),
            }
            path = self._state_path()
            tmp = path.with_suffix(".tmp")
            tmp.write_text(json.dumps(state))
            tmp.replace(path)  # atomic
        except OSError:
            logger.debug("Could not persist kill-switch state (non-fatal)")

    def _restore_state(self) -> None:
        """Restore kill-switch state from disk on startup."""
        try:
            path = self._state_path()
            if not path.exists():
                return
            state = json.loads(path.read_text())
            if state.get("blocked"):
                self._blocked = True
                self._threat_level = ThreatLevel(state.get("threat_level", ThreatLevel.CRITICAL.value))
                logger.warning(
                    "Restored kill-switch state from disk — session was blocked at %s",
                    state.get("updated_at", "unknown"),
                )
        except (OSError, json.JSONDecodeError, ValueError):
            logger.debug("Could not restore kill-switch state (non-fatal)")

    def start(self) -> None:
        """Activate protection engine."""
        self._active = True
        self._stats.started_at = datetime.now(timezone.utc).isoformat()
        self._stats.shield_active = self._shield
        if self._shield:
            self._restore_state()
            logger.info("Protection engine started (deep defense mode)")
        else:
            logger.info("Protection engine started")

    def stop(self) -> None:
        """Deactivate protection engine."""
        self._active = False
        self._blocked = False
        self._threat_level = ThreatLevel.NORMAL
        logger.info("Protection engine stopped")

    @property
    def active(self) -> bool:
        return self._active

    @property
    def shield_active(self) -> bool:
        """True if deep defense mode is enabled."""
        return self._shield

    @property
    def threat_level(self) -> ThreatLevel:
        """Current session threat level."""
        return self._threat_level

    @property
    def is_blocked(self) -> bool:
        """True if kill-switch has been activated (CRITICAL threat)."""
        return self._blocked

    def set_allowed_tools(self, tools: list[str]) -> None:
        """Restrict tool calls to an explicit allowlist (deep defense containment)."""
        self._allowed_tools = set(tools)

    def unblock(self) -> None:
        """Manually deactivate kill-switch and reset to ELEVATED."""
        self._blocked = False
        self._threat_level = ThreatLevel.ELEVATED
        self._allowed_tools = None
        self._persist_state()
        logger.info("Kill-switch deactivated, threat level reset to ELEVATED")

    def status(self) -> dict:
        """Return current engine status and statistics."""
        base = {
            "active": self._active,
            "started_at": self._stats.started_at,
            "traces_processed": self._stats.traces_processed,
            "tool_calls_analyzed": self._stats.tool_calls_analyzed,
            "alerts_generated": self._stats.alerts_generated,
            "detectors": [
                "ToolDriftDetector",
                "ArgumentAnalyzer",
                "CredentialLeakDetector",
                "RateLimitTracker",
                "SequenceAnalyzer",
                "ResponseInspector",
                "VectorDBInjectionDetector",
            ],
            "detectors_active": self._stats.detectors_active,
        }
        if self._shield:
            base["shield"] = {
                "active": True,
                "threat_level": self._threat_level.value,
                "blocked": self._blocked,
                "escalations": self._stats.escalations,
                "blocks": self._stats.blocks,
                "correlation_window_seconds": self._correlation_window,
                "alerts_in_window": self._count_window_alerts(),
            }
        return base

    # ── Deep defense internals ───────────────────────────────────────────

    def _prune_correlation_buffer(self) -> None:
        """Remove entries older than the correlation window."""
        cutoff = time.monotonic() - self._correlation_window
        while self._correlation_buffer and self._correlation_buffer[0].timestamp < cutoff:
            self._correlation_buffer.popleft()

    def _count_window_alerts(self) -> int:
        self._prune_correlation_buffer()
        return len(self._correlation_buffer)

    def _record_alerts(self, alerts: list[dict], tool_name: str = "") -> None:
        """Add alerts to the correlation buffer (deep defense mode only)."""
        if not self._shield:
            return
        now = time.monotonic()
        for alert in alerts:
            self._correlation_buffer.append(
                _CorrelationEntry(
                    timestamp=now,
                    detector=alert.get("detector", "unknown"),
                    severity=alert.get("severity", "info"),
                    tool_name=tool_name or alert.get("details", {}).get("tool", ""),
                )
            )

    def assess_threat(self) -> ShieldAssessment:
        """Compute correlated threat assessment from recent alerts.

        Scores all alerts within the correlation window, identifies which
        detectors fired, and escalates threat level when thresholds are crossed.
        """
        self._prune_correlation_buffer()

        entries = list(self._correlation_buffer)
        if not entries:
            return ShieldAssessment(
                threat_level=self._threat_level,
                composite_score=0.0,
                detectors_triggered=[],
                correlation_window_seconds=self._correlation_window,
                alert_count_in_window=0,
                escalated=False,
                blocked=self._blocked,
            )

        # Composite score: sum of severity weights, with detector diversity bonus
        score = sum(_SEVERITY_WEIGHTS.get(e.severity, 0) for e in entries)
        detectors = sorted(set(e.detector for e in entries))
        # Diversity bonus: multiple independent detectors firing = correlated attack
        if len(detectors) >= 3:
            score *= 1.5
        elif len(detectors) >= 2:
            score *= 1.2

        # Determine new threat level
        previous = self._threat_level
        new_level = ThreatLevel.NORMAL
        for level in (ThreatLevel.CRITICAL, ThreatLevel.HIGH, ThreatLevel.ELEVATED):
            if score >= _THREAT_THRESHOLDS[level]:
                new_level = level
                break

        escalated = new_level.value > previous.value if new_level != previous else False
        self._threat_level = new_level
        self._stats.threat_level = new_level.value

        if escalated:
            self._stats.escalations += 1
            logger.warning("Threat level escalated: %s → %s (score=%.1f, detectors=%s)", previous.value, new_level.value, score, detectors)

        # Kill-switch on CRITICAL
        blocked = False
        if new_level == ThreatLevel.CRITICAL and self._block_on_critical and not self._blocked:
            self._blocked = True
            self._stats.blocks += 1
            blocked = True
            self._persist_state()
            logger.critical("KILL-SWITCH ACTIVATED — blocking tool calls (score=%.1f)", score)

        return ShieldAssessment(
            threat_level=new_level,
            composite_score=round(score, 2),
            detectors_triggered=detectors,
            correlation_window_seconds=self._correlation_window,
            alert_count_in_window=len(entries),
            escalated=escalated,
            blocked=blocked,
        )

    def _check_blocked(self, tool_name: str) -> list[dict]:
        """Return a block alert if kill-switch is active and tool is not allowed."""
        if not self._blocked:
            return []
        if self._allowed_tools is not None and tool_name in self._allowed_tools:
            return []
        return [
            {
                "type": "runtime_alert",
                "ts": datetime.now(timezone.utc).isoformat(),
                "detector": "shield_killswitch",
                "severity": "critical",
                "message": f"Tool call BLOCKED by deep defense kill-switch: {tool_name}",
                "details": {
                    "tool": tool_name,
                    "threat_level": self._threat_level.value,
                    "action": "blocked",
                },
            }
        ]

    # ── Public API ───────────────────────────────────────────────────────

    async def process_trace(self, trace_data: dict) -> list[dict]:
        """Process an OTel trace export through all detectors.

        Args:
            trace_data: OTel JSON export (``resourceSpans`` format).

        Returns:
            List of alert dicts generated by detectors.
        """
        traces = parse_otel_traces(trace_data)
        self._stats.traces_processed += len(traces)

        all_alerts: list[dict] = []
        for trace in traces:
            alerts = await self.process_tool_call(trace.tool_name, trace.parameters or {})
            all_alerts.extend(alerts)

        return all_alerts

    async def process_tool_call(self, tool_name: str, arguments: dict) -> list[dict]:
        """Analyze a single tool call through all detectors.

        In deep defense mode, also checks kill-switch status and correlates
        alerts for threat-level escalation.

        Args:
            tool_name: MCP tool being invoked.
            arguments: Tool call arguments.

        Returns:
            List of alert dicts for any findings.
        """
        self._stats.tool_calls_analyzed += 1

        # Deep defense: check kill-switch before processing
        if self._shield:
            block_alerts = self._check_blocked(tool_name)
            if block_alerts:
                for alert_dict in block_alerts:
                    await self.dispatcher.dispatch(alert_dict)
                self._stats.alerts_generated += len(block_alerts)
                return block_alerts

        all_alerts: list[dict] = []

        # Argument analysis — shell injection, path traversal, etc.
        arg_alerts = self.arg_analyzer.check(tool_name, arguments)
        all_alerts.extend(a.to_dict() for a in arg_alerts)

        # Rate limiting
        rate_alerts = self.rate_tracker.record(tool_name)
        all_alerts.extend(a.to_dict() for a in rate_alerts)

        # Sequence analysis — suspicious multi-step patterns
        seq_alerts = self.seq_analyzer.record(tool_name)
        all_alerts.extend(a.to_dict() for a in seq_alerts)

        # Dispatch all alerts
        for alert_dict in all_alerts:
            await self.dispatcher.dispatch(alert_dict)

        self._stats.alerts_generated += len(all_alerts)

        # Deep defense: correlate and assess
        if self._shield and all_alerts:
            self._record_alerts(all_alerts, tool_name)
            assessment = self.assess_threat()
            if assessment.escalated:
                escalation_alert = {
                    "type": "runtime_alert",
                    "ts": datetime.now(timezone.utc).isoformat(),
                    "detector": "shield_correlation",
                    "severity": assessment.threat_level.value,
                    "message": (
                        f"Threat level escalated to {assessment.threat_level.value.upper()} "
                        f"(score={assessment.composite_score}, "
                        f"detectors={assessment.detectors_triggered})"
                    ),
                    "details": {
                        "threat_level": assessment.threat_level.value,
                        "composite_score": assessment.composite_score,
                        "detectors_triggered": assessment.detectors_triggered,
                        "alert_count_in_window": assessment.alert_count_in_window,
                        "blocked": assessment.blocked,
                    },
                }
                all_alerts.append(escalation_alert)
                await self.dispatcher.dispatch(escalation_alert)

        return all_alerts

    async def process_tool_response(self, tool_name: str, response_text: str) -> list[dict]:
        """Check a tool response for credential leaks, injection, and cloaking.

        Runs all response-path detectors: CredentialLeakDetector,
        ResponseInspector, and VectorDBInjectionDetector.

        Args:
            tool_name: MCP tool that produced the response.
            response_text: Response text to analyze.

        Returns:
            List of alert dicts for any findings detected.
        """
        all_alerts: list[dict] = []

        # Credential leak detection
        cred_alerts = self.cred_detector.check(tool_name, response_text)
        all_alerts.extend(a.to_dict() for a in cred_alerts)

        # Response inspection — cloaking, SVG, invisible unicode, injection
        resp_alerts = self.response_inspector.check(tool_name, response_text)
        all_alerts.extend(a.to_dict() for a in resp_alerts)

        # Vector DB injection — elevated severity for RAG/retrieval tools
        vec_alerts = self.vector_db_detector.check(tool_name, response_text)
        all_alerts.extend(a.to_dict() for a in vec_alerts)

        for alert_dict in all_alerts:
            await self.dispatcher.dispatch(alert_dict)

        self._stats.alerts_generated += len(all_alerts)

        # Deep defense: correlate response-path alerts
        if self._shield and all_alerts:
            self._record_alerts(all_alerts, tool_name)
            self.assess_threat()

        return all_alerts

    async def check_tool_drift(self, current_tools: list[str]) -> list[dict]:
        """Check for tool drift (new tools appearing after baseline).

        Args:
            current_tools: Current tool names from tools/list.

        Returns:
            List of alert dicts for any drift detected.
        """
        drift_alerts = self.drift_detector.check(current_tools)
        all_alerts = [a.to_dict() for a in drift_alerts]

        for alert_dict in all_alerts:
            await self.dispatcher.dispatch(alert_dict)

        self._stats.alerts_generated += len(all_alerts)

        # Deep defense: tool drift is a strong signal — weight it heavily
        if self._shield and all_alerts:
            self._record_alerts(all_alerts)
            self.assess_threat()

        return all_alerts
