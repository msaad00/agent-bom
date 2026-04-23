"""agent-bom Shield SDK — importable runtime protection for AI agents.

Use as a Python middleware in any AI agent pipeline:

    from agent_bom.shield import Shield

    shield = Shield()

    # Check tool calls before execution
    alerts = shield.check_tool_call("read_file", {"path": "/etc/passwd"})
    if alerts:
        raise RuntimeError(alerts[0]["message"])

    # Check and redact tool responses
    alerts = shield.check_response("read_file", response_text)
    safe_text = shield.redact(response_text)

    # Assess overall threat level (deep defense)
    assessment = shield.assess()

Works with any framework: Anthropic SDK, OpenAI, LangChain, CrewAI, etc.
Zero external dependencies beyond agent-bom itself.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import ThreadPoolExecutor

from agent_bom.config import SHIELD_ASYNC_BRIDGE_MAX_WORKERS
from agent_bom.runtime.detectors import (
    CredentialLeakDetector,
)
from agent_bom.runtime.protection import (
    ProtectionEngine,
    ShieldAssessment,
    ThreatLevel,
)

_SHIELD_ASYNC_BRIDGE = ThreadPoolExecutor(
    max_workers=max(SHIELD_ASYNC_BRIDGE_MAX_WORKERS, 1),
    thread_name_prefix="agent-bom-shield",
)


def _run_async_bridge(coro):
    """Run a Shield coroutine from sync code, even inside an active event loop."""
    try:
        loop = asyncio.get_running_loop()
    except RuntimeError:
        loop = None

    if loop and loop.is_running():
        return _SHIELD_ASYNC_BRIDGE.submit(asyncio.run, coro).result()
    return asyncio.run(coro)


class Shield:
    """In-process AI agent security middleware.

    Drop-in protection for any AI agent pipeline. Runs all 8 detectors
    locally with 112 patterns. No proxy needed, no network, no config.

    Args:
        deep: Enable deep defense mode (correlated threat scoring,
            threat-level escalation, automatic kill-switch).
        correlation_window: Seconds for alert correlation (default 30).
        block_on_critical: Auto-block when threat reaches CRITICAL.

    Example::

        shield = Shield(deep=True)

        # In your agent's tool execution loop:
        alerts = shield.check_tool_call(tool_name, arguments)
        if shield.is_blocked:
            raise SecurityError("Tool calls blocked by Shield")

        result = execute_tool(tool_name, arguments)

        alerts = shield.check_response(tool_name, result)
        safe_result = shield.redact(result)
    """

    def __init__(
        self,
        *,
        deep: bool = False,
        correlation_window: float = 30.0,
        block_on_critical: bool = True,
    ) -> None:
        self._engine = ProtectionEngine(
            shield=deep,
            correlation_window=correlation_window,
            block_on_critical=block_on_critical,
        )
        self._engine.start()
        self._cred_detector = CredentialLeakDetector()

    def check_tool_call(self, tool_name: str, arguments: dict) -> list[dict]:
        """Check a tool call for security threats.

        Runs all request-path detectors: argument analysis, rate limiting,
        sequence analysis. Returns alert dicts for any findings.
        """
        return _run_async_bridge(self._engine.process_tool_call(tool_name, arguments))

    def check_response(self, tool_name: str, response_text: str) -> list[dict]:
        """Check a tool response for credential leaks, injection, cloaking.

        Runs all response-path detectors: credential leak, PII detection,
        response inspection, vector DB injection.
        """
        return _run_async_bridge(self._engine.process_tool_response(tool_name, response_text))

    def check_drift(self, current_tools: list[str]) -> list[dict]:
        """Check for tool drift (new tools appearing after baseline)."""
        return _run_async_bridge(self._engine.check_tool_drift(current_tools))

    @staticmethod
    def redact(text: str) -> str:
        """Redact credentials and PII from text.

        Returns a copy with sensitive values replaced by
        ``[REDACTED:<type>]`` markers.
        """
        return CredentialLeakDetector.redact(text)

    def assess(self) -> ShieldAssessment:
        """Get current threat assessment (deep defense mode only).

        Returns threat level, composite score, triggered detectors,
        and kill-switch status.
        """
        return self._engine.assess_threat()

    @property
    def threat_level(self) -> ThreatLevel:
        """Current session threat level."""
        return self._engine.threat_level

    @property
    def is_blocked(self) -> bool:
        """True if kill-switch has been activated."""
        return self._engine.is_blocked

    def unblock(self) -> None:
        """Deactivate kill-switch and reset to ELEVATED."""
        self._engine.unblock()

    def status(self) -> dict:
        """Get engine status and statistics."""
        return self._engine.status()
