"""Shared scanner driver registry types.

The first driver-registry layer is intentionally metadata-first. Existing scan
execution remains wired through the current CLI/API pipeline, while each scanner
declares its inputs, outputs, failure semantics, telemetry, and execution state.
That gives product/API/UI surfaces a stable contract before individual scanner
families are migrated behind a common run interface.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any, Protocol

from agent_bom.extensions import ExtensionCapabilities, RegistryEntry


class ScannerPhase(str, Enum):
    """Pipeline phase where a scanner driver contributes evidence."""

    DISCOVERY = "discovery"
    EXTRACTION = "extraction"
    SCANNING = "scanning"
    ENRICHMENT = "enrichment"
    ANALYSIS = "analysis"
    OUTPUT = "output"


class ScannerExecutionState(str, Enum):
    """Whether a driver is executable today or declared as a roadmap slot."""

    ACTIVE = "active"
    PASSIVE = "passive"
    PLANNED = "planned"


class ScannerFailureMode(str, Enum):
    """How the orchestrator should treat driver failures."""

    FAIL_CLOSED = "fail_closed"
    WARN_AND_CONTINUE = "warn_and_continue"
    SKIP_WHEN_UNAVAILABLE = "skip_when_unavailable"


@dataclass(frozen=True)
class ScannerRegistration(RegistryEntry):
    """Registry metadata for a scanner driver implementation."""

    phase: ScannerPhase = ScannerPhase.SCANNING
    execution_state: ScannerExecutionState = ScannerExecutionState.ACTIVE
    failure_mode: ScannerFailureMode = ScannerFailureMode.WARN_AND_CONTINUE
    enabled_by_default: bool = True
    run_attr: str = ""
    input_types: tuple[str, ...] = ()
    output_types: tuple[str, ...] = ()
    finding_types: tuple[str, ...] = ()
    skip_when: tuple[str, ...] = ()
    telemetry_keys: tuple[str, ...] = ()
    standards: tuple[str, ...] = ()
    summary: str = ""

    def to_dict(self) -> dict[str, Any]:
        """Return a stable API/CLI-safe representation."""

        return {
            "name": self.name,
            "module": self.module,
            "source": self.source,
            "phase": self.phase.value,
            "execution_state": self.execution_state.value,
            "failure_mode": self.failure_mode.value,
            "enabled_by_default": self.enabled_by_default,
            "run_attr": self.run_attr,
            "input_types": list(self.input_types),
            "output_types": list(self.output_types),
            "finding_types": list(self.finding_types),
            "skip_when": list(self.skip_when),
            "telemetry_keys": list(self.telemetry_keys),
            "standards": list(self.standards),
            "summary": self.summary,
            "capabilities": {
                "scan_modes": list(self.capabilities.scan_modes),
                "required_scopes": list(self.capabilities.required_scopes),
                "permissions_used": list(self.capabilities.permissions_used),
                "outbound_destinations": list(self.capabilities.outbound_destinations),
                "data_boundary": self.capabilities.data_boundary,
                "writes": self.capabilities.writes,
                "network_access": self.capabilities.network_access,
                "guarantees": list(self.capabilities.guarantees),
            },
        }


class ScannerDriver(Protocol):
    """Protocol implemented by future executable scanner-driver extensions."""

    name: str
    capabilities: ExtensionCapabilities

    def run(self, **kwargs: Any) -> dict[str, Any]:
        """Run the scanner and return a serializable result payload."""


@dataclass
class ScannerRunTelemetry:
    """Common telemetry envelope for future scanner-driver execution."""

    scanner: str
    status: str
    duration_ms: float = 0.0
    inputs_seen: int = 0
    outputs_emitted: int = 0
    findings_emitted: int = 0
    warnings: list[str] = field(default_factory=list)
