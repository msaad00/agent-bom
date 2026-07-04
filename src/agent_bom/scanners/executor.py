"""Runtime dispatch for registered scanner drivers.

Registry metadata declares ``run_attr`` and ``failure_mode`` for each driver.
This module resolves the callable on the declared module and executes it while
honoring the configured failure semantics.
"""

from __future__ import annotations

import importlib
import logging
import time
from dataclasses import dataclass
from typing import Any, Callable

from agent_bom.scanners.base import (
    ScannerExecutionState,
    ScannerFailureMode,
    ScannerRegistration,
    ScannerRunTelemetry,
)
from agent_bom.scanners.registry import get_scanner_registration
from agent_bom.security import sanitize_error

_logger = logging.getLogger(__name__)


class ScannerDriverError(RuntimeError):
    """Raised when a driver with ``fail_closed`` failure mode errors."""

    def __init__(self, scanner: str, message: str) -> None:
        self.scanner = scanner
        super().__init__(message)


@dataclass(frozen=True)
class ScannerDriverRunResult:
    """Outcome of one scanner-driver execution attempt."""

    registration: ScannerRegistration
    telemetry: ScannerRunTelemetry
    payload: dict[str, Any] | None = None


def _resolve_runner(registration: ScannerRegistration) -> Callable[..., Any]:
    module = importlib.import_module(registration.module)
    run_attr = registration.run_attr or "run"
    runner = getattr(module, run_attr, None)
    if runner is None or not callable(runner):
        raise AttributeError(f"{registration.module} has no callable {run_attr}")
    return runner


def _telemetry(
    registration: ScannerRegistration,
    *,
    status: str,
    duration_ms: float,
    warnings: list[str] | None = None,
    findings_emitted: int = 0,
) -> ScannerRunTelemetry:
    return ScannerRunTelemetry(
        scanner=registration.name,
        status=status,
        duration_ms=duration_ms,
        warnings=list(warnings or []),
        findings_emitted=findings_emitted,
    )


def _coerce_payload(raw: Any) -> dict[str, Any] | None:
    if raw is None:
        return None
    if isinstance(raw, dict):
        return raw
    return {"result": raw}


def _count_findings(payload: dict[str, Any] | None) -> int:
    if not payload:
        return 0
    for key in ("findings", "findings_emitted", "finding_count"):
        value = payload.get(key)
        if isinstance(value, int):
            return value
        if isinstance(value, list):
            return len(value)
    return 0


def run_scanner_driver(
    name: str,
    *,
    allow_planned: bool = False,
    **kwargs: Any,
) -> ScannerDriverRunResult:
    """Execute one registered scanner driver and honor its failure semantics."""

    registration = get_scanner_registration(name)
    if registration.execution_state is ScannerExecutionState.PLANNED and not allow_planned:
        return _handle_unavailable(
            registration,
            reason=f"scanner driver {registration.name} is planned but not executable",
            duration_ms=0.0,
        )

    started = time.perf_counter()
    try:
        runner = _resolve_runner(registration)
    except Exception as exc:  # noqa: BLE001
        return _handle_unavailable(
            registration,
            reason=sanitize_error(exc),
            duration_ms=(time.perf_counter() - started) * 1000.0,
            exc=exc,
        )

    try:
        payload = _coerce_payload(runner(**kwargs))
    except Exception as exc:  # noqa: BLE001
        return _handle_failure(
            registration,
            reason=sanitize_error(exc),
            duration_ms=(time.perf_counter() - started) * 1000.0,
            exc=exc,
        )

    duration_ms = (time.perf_counter() - started) * 1000.0
    findings = _count_findings(payload)
    return ScannerDriverRunResult(
        registration=registration,
        telemetry=_telemetry(
            registration,
            status="ok",
            duration_ms=duration_ms,
            findings_emitted=findings,
        ),
        payload=payload,
    )


def _handle_unavailable(
    registration: ScannerRegistration,
    *,
    reason: str,
    duration_ms: float,
    exc: Exception | None = None,
) -> ScannerDriverRunResult:
    mode = registration.failure_mode
    if mode is ScannerFailureMode.FAIL_CLOSED:
        message = f"Scanner driver {registration.name} unavailable: {reason}"
        _logger.error(message)
        raise ScannerDriverError(registration.name, message) from exc
    if mode is ScannerFailureMode.SKIP_WHEN_UNAVAILABLE:
        _logger.info("Skipping unavailable scanner driver %s: %s", registration.name, reason)
        return ScannerDriverRunResult(
            registration=registration,
            telemetry=_telemetry(
                registration,
                status="skipped",
                duration_ms=duration_ms,
                warnings=[reason],
            ),
        )
    _logger.warning("Scanner driver %s unavailable; continuing: %s", registration.name, reason)
    return ScannerDriverRunResult(
        registration=registration,
        telemetry=_telemetry(
            registration,
            status="warning",
            duration_ms=duration_ms,
            warnings=[reason],
        ),
    )


def _handle_failure(
    registration: ScannerRegistration,
    *,
    reason: str,
    duration_ms: float,
    exc: Exception | None = None,
) -> ScannerDriverRunResult:
    mode = registration.failure_mode
    if mode is ScannerFailureMode.FAIL_CLOSED:
        message = f"Scanner driver {registration.name} failed: {reason}"
        _logger.error(message)
        raise ScannerDriverError(registration.name, message) from exc
    if mode is ScannerFailureMode.SKIP_WHEN_UNAVAILABLE:
        _logger.info("Skipping failed scanner driver %s: %s", registration.name, reason)
        return ScannerDriverRunResult(
            registration=registration,
            telemetry=_telemetry(
                registration,
                status="skipped",
                duration_ms=duration_ms,
                warnings=[reason],
            ),
        )
    _logger.warning("Scanner driver %s failed; continuing: %s", registration.name, reason)
    return ScannerDriverRunResult(
        registration=registration,
        telemetry=_telemetry(
            registration,
            status="warning",
            duration_ms=duration_ms,
            warnings=[reason],
        ),
    )


__all__ = [
    "ScannerDriverError",
    "ScannerDriverRunResult",
    "run_scanner_driver",
]
