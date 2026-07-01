"""Small interactive runtime status strips for local demos."""

from __future__ import annotations

import sys
from collections.abc import Callable
from typing import TextIO

from agent_bom.proxy_audit import ProxyMetrics

_MAX_DECISION_CHARS = 56


def _clean_decision(value: object) -> str:
    decision = str(value or "waiting").replace("\n", " ").replace("\r", " ").strip()
    if len(decision) > _MAX_DECISION_CHARS:
        return decision[: _MAX_DECISION_CHARS - 1] + "..."
    return decision or "waiting"


def render_runtime_status_strip(
    surface: str,
    *,
    calls: int,
    blocked: int,
    last_decision: object,
    quit_hint: str = "Ctrl+C to stop",
) -> str:
    """Return a single-line runtime status strip that fits terminal logs."""
    return (
        f"  agent-bom {surface} live | calls={max(calls, 0)} blocked={max(blocked, 0)} last={_clean_decision(last_decision)} | {quit_hint}"
    )


def stream_is_interactive(stream: TextIO | None = None) -> bool:
    """True when it is safe to draw an updating status strip."""
    stream = stream or sys.stderr
    try:
        return bool(stream.isatty())
    except Exception:  # noqa: BLE001 - defensive for custom test streams
        return False


def emit_runtime_status_strip(
    surface: str,
    *,
    calls: int = 0,
    blocked: int = 0,
    last_decision: object = "waiting",
    stream: TextIO | None = None,
    quit_hint: str = "Ctrl+C to stop",
) -> bool:
    """Print one TTY-only status strip to stderr and return whether it was emitted."""
    stream = stream or sys.stderr
    if not stream_is_interactive(stream):
        return False
    stream.write(
        render_runtime_status_strip(
            surface,
            calls=calls,
            blocked=blocked,
            last_decision=last_decision,
            quit_hint=quit_hint,
        )
        + "\n"
    )
    stream.flush()
    return True


def proxy_metrics_status_callback(
    *,
    stream: TextIO | None = None,
    surface: str = "proxy",
) -> tuple[bool, Callable[[ProxyMetrics], None]]:
    """Return a best-effort callback that redraws proxy status on metric updates."""
    stream = stream or sys.stderr
    if not stream_is_interactive(stream):
        return False, lambda _metrics: None

    def _callback(metrics: ProxyMetrics) -> None:
        summary = metrics.summary()
        stream.write(
            "\r"
            + render_runtime_status_strip(
                surface,
                calls=int(summary.get("total_tool_calls", 0)),
                blocked=int(summary.get("total_blocked", 0)),
                last_decision=summary.get("last_decision", "waiting"),
                quit_hint="Ctrl+C to stop",
            )
        )
        stream.flush()

    return True, _callback
