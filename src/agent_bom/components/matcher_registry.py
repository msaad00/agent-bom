"""Matcher/correlator component registry.

Mirrors :mod:`agent_bom.scanners.registry`. Registers the built-in
matchers/correlators (`correlate.py`, `cross_env_correlation.py`,
`runtime_correlation.py`) as descriptive capability metadata. These
registrations do NOT change how correlation runs today — the existing pipeline
still calls each correlator directly.
"""

from __future__ import annotations

from typing import Any

from agent_bom.components.base import MatcherRegistration, local_analysis_capabilities
from agent_bom.extensions import ExtensionCapabilities, iter_entry_point_registrations
from agent_bom.scanners.base import ScannerExecutionState, ScannerPhase

_ENTRY_POINT_GROUP = "agent_bom.matcher_drivers"

_MATCHER_REGISTRY: dict[str, MatcherRegistration] = {}
_MATCHER_REGISTRY_WARNINGS: list[str] = []
_MATCHER_REGISTRY_LOADED = False


def builtin_matcher_registrations() -> list[MatcherRegistration]:
    """Return built-in matcher/correlator registrations with capability metadata."""

    return [
        MatcherRegistration(
            name="agent-dedup",
            module="agent_bom.correlate",
            phase=ScannerPhase.ANALYSIS,
            run_attr="correlate_agents",
            input_types=("agents",),
            output_types=("agents", "correlation_result"),
            correlation_types=("agent-merge", "package-dedup", "source-provenance"),
            summary="Cross-source agent deduplication and package merge with provenance tracking.",
            capabilities=local_analysis_capabilities(),
        ),
        MatcherRegistration(
            name="cross-environment",
            module="agent_bom.cross_env_correlation",
            phase=ScannerPhase.ANALYSIS,
            run_attr="correlate_cross_environment",
            input_types=("agents", "cloud_inventory"),
            output_types=("cross_environment_result",),
            correlation_types=("bedrock", "azure-openai", "gcp-vertex", "local-to-cloud"),
            summary="Local-to-cloud agent correlation across Bedrock, Azure OpenAI, and GCP Vertex evidence.",
            capabilities=local_analysis_capabilities(scan_modes=("analysis", "cloud")),
        ),
        MatcherRegistration(
            name="runtime-correlation",
            module="agent_bom.runtime_correlation",
            phase=ScannerPhase.ANALYSIS,
            run_attr="correlate",
            input_types=("runtime_audit_log", "findings"),
            output_types=("correlation_report",),
            correlation_types=("tool-call-amplifier", "runtime-to-finding"),
            summary="Runtime proxy audit-log correlation linking tool-call activity to findings.",
            capabilities=local_analysis_capabilities(scan_modes=("runtime",)),
        ),
    ]


def _coerce_matcher_registration(value: Any, entry_point_name: str) -> MatcherRegistration:
    if isinstance(value, MatcherRegistration):
        return value
    name = str(getattr(value, "name", entry_point_name)).strip()
    module = str(getattr(value, "module", "")).strip()
    if not name or not module:
        raise ValueError("matcher registration must declare name and module")
    capabilities = getattr(value, "capabilities", ExtensionCapabilities())
    if not isinstance(capabilities, ExtensionCapabilities):
        capabilities = ExtensionCapabilities()
    phase = getattr(value, "phase", ScannerPhase.ANALYSIS)
    if not isinstance(phase, ScannerPhase):
        phase = ScannerPhase(str(phase))
    execution_state = getattr(value, "execution_state", ScannerExecutionState.ACTIVE)
    if not isinstance(execution_state, ScannerExecutionState):
        execution_state = ScannerExecutionState(str(execution_state))
    return MatcherRegistration(
        name=name,
        module=module,
        capabilities=capabilities,
        source=str(getattr(value, "source", "entry_point")),
        phase=phase,
        execution_state=execution_state,
        enabled_by_default=bool(getattr(value, "enabled_by_default", True)),
        run_attr=str(getattr(value, "run_attr", "run")),
        input_types=tuple(str(item) for item in getattr(value, "input_types", ())),
        output_types=tuple(str(item) for item in getattr(value, "output_types", ())),
        correlation_types=tuple(str(item) for item in getattr(value, "correlation_types", ())),
        summary=str(getattr(value, "summary", "")),
    )


def register_matcher(registration: MatcherRegistration) -> None:
    """Register a matcher/correlator component with capability metadata."""

    if not registration.name:
        raise ValueError("matcher registration must declare a name")
    if registration.name in _MATCHER_REGISTRY:
        raise ValueError(f"duplicate matcher registration: {registration.name}")
    _MATCHER_REGISTRY[registration.name] = registration


def _ensure_matcher_registry_loaded() -> None:
    global _MATCHER_REGISTRY_LOADED
    if _MATCHER_REGISTRY_LOADED:
        return
    for registration in builtin_matcher_registrations():
        register_matcher(registration)
    for registration in iter_entry_point_registrations(
        group=_ENTRY_POINT_GROUP,
        coerce=_coerce_matcher_registration,
        warnings=_MATCHER_REGISTRY_WARNINGS,
    ):
        register_matcher(registration)
    _MATCHER_REGISTRY_LOADED = True


def list_registered_matchers(*, include_planned: bool = True) -> list[MatcherRegistration]:
    """Return registered matcher/correlator components sorted by name."""

    _ensure_matcher_registry_loaded()
    registrations = [_MATCHER_REGISTRY[name] for name in sorted(_MATCHER_REGISTRY)]
    if include_planned:
        return registrations
    return [registration for registration in registrations if registration.execution_state != ScannerExecutionState.PLANNED]


def get_matcher_registration(name: str) -> MatcherRegistration:
    """Return one matcher registration or raise ``KeyError``."""

    _ensure_matcher_registry_loaded()
    return _MATCHER_REGISTRY[name]


def matcher_registry_warnings() -> list[str]:
    """Return sanitized non-fatal registry loading warnings."""

    _ensure_matcher_registry_loaded()
    return list(_MATCHER_REGISTRY_WARNINGS)


def matcher_registry_summary() -> dict[str, object]:
    """Return a compact matcher registry summary for API/UI surfaces."""

    registrations = list_registered_matchers(include_planned=True)
    by_phase: dict[str, int] = {}
    by_state: dict[str, int] = {}
    for registration in registrations:
        by_phase[registration.phase.value] = by_phase.get(registration.phase.value, 0) + 1
        by_state[registration.execution_state.value] = by_state.get(registration.execution_state.value, 0) + 1
    return {
        "total": len(registrations),
        "active": by_state.get(ScannerExecutionState.ACTIVE.value, 0),
        "passive": by_state.get(ScannerExecutionState.PASSIVE.value, 0),
        "planned": by_state.get(ScannerExecutionState.PLANNED.value, 0),
        "by_phase": by_phase,
        "by_state": by_state,
    }


def _reset_matcher_registry_for_tests() -> None:
    _MATCHER_REGISTRY.clear()
    _MATCHER_REGISTRY_WARNINGS.clear()
    global _MATCHER_REGISTRY_LOADED
    _MATCHER_REGISTRY_LOADED = False


__all__ = [
    "MatcherRegistration",
    "builtin_matcher_registrations",
    "get_matcher_registration",
    "list_registered_matchers",
    "matcher_registry_summary",
    "matcher_registry_warnings",
    "register_matcher",
]
