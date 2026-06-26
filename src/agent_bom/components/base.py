"""Shared registry types for enricher and matcher components.

Mirrors :mod:`agent_bom.scanners.base`. Like the scanner-driver registry, this
layer is metadata-first: each enricher/matcher declares its inputs, outputs,
phase, and execution state so surfaces have a stable contract, while the actual
enrichment/correlation execution remains wired through the existing pipeline.

Phase and execution-state vocabularies are reused from the scanner registry so
all three component roles share one capability model.
"""

from __future__ import annotations

from dataclasses import dataclass
from enum import Enum
from typing import Any

from agent_bom.extensions import ExtensionCapabilities, RegistryEntry
from agent_bom.scanners.base import ScannerExecutionState, ScannerPhase


class ComponentRole(str, Enum):
    """Pipeline component role a registration describes."""

    ENRICHER = "enricher"
    MATCHER = "matcher"


def local_analysis_capabilities(
    *,
    scan_modes: tuple[str, ...] = ("analysis",),
    guarantees: tuple[str, ...] = ("read_only",),
) -> ExtensionCapabilities:
    """In-memory, no-network component capabilities."""

    return ExtensionCapabilities(
        scan_modes=scan_modes,
        required_scopes=("local_analysis_read",),
        outbound_destinations=(),
        data_boundary="local_in_memory_analysis",
        network_access=False,
        guarantees=guarantees,
    )


def network_lookup_capabilities(
    *,
    destinations: tuple[str, ...],
    scan_modes: tuple[str, ...] = ("online",),
    required_scopes: tuple[str, ...] = ("network_egress",),
) -> ExtensionCapabilities:
    """Read-only metadata lookup capabilities with bounded egress."""

    return ExtensionCapabilities(
        scan_modes=scan_modes,
        required_scopes=required_scopes,
        outbound_destinations=destinations,
        data_boundary="read_only_metadata_lookup",
        network_access=True,
        guarantees=("read_only", "bounded_egress"),
    )


def _capabilities_dict(capabilities: ExtensionCapabilities) -> dict[str, Any]:
    return {
        "scan_modes": list(capabilities.scan_modes),
        "required_scopes": list(capabilities.required_scopes),
        "permissions_used": list(capabilities.permissions_used),
        "outbound_destinations": list(capabilities.outbound_destinations),
        "data_boundary": capabilities.data_boundary,
        "writes": capabilities.writes,
        "network_access": capabilities.network_access,
        "guarantees": list(capabilities.guarantees),
    }


@dataclass(frozen=True)
class EnricherRegistration(RegistryEntry):
    """Registry metadata for an enricher component implementation."""

    phase: ScannerPhase = ScannerPhase.ENRICHMENT
    execution_state: ScannerExecutionState = ScannerExecutionState.ACTIVE
    enabled_by_default: bool = True
    run_attr: str = ""
    input_types: tuple[str, ...] = ()
    output_types: tuple[str, ...] = ()
    enriches: tuple[str, ...] = ()
    summary: str = ""

    @property
    def role(self) -> ComponentRole:
        return ComponentRole.ENRICHER

    def to_dict(self) -> dict[str, Any]:
        """Return a stable API/CLI-safe representation."""

        return {
            "name": self.name,
            "role": ComponentRole.ENRICHER.value,
            "module": self.module,
            "source": self.source,
            "phase": self.phase.value,
            "execution_state": self.execution_state.value,
            "enabled_by_default": self.enabled_by_default,
            "run_attr": self.run_attr,
            "input_types": list(self.input_types),
            "output_types": list(self.output_types),
            "enriches": list(self.enriches),
            "summary": self.summary,
            "capabilities": _capabilities_dict(self.capabilities),
        }


@dataclass(frozen=True)
class MatcherRegistration(RegistryEntry):
    """Registry metadata for a matcher/correlator component implementation."""

    phase: ScannerPhase = ScannerPhase.ANALYSIS
    execution_state: ScannerExecutionState = ScannerExecutionState.ACTIVE
    enabled_by_default: bool = True
    run_attr: str = ""
    input_types: tuple[str, ...] = ()
    output_types: tuple[str, ...] = ()
    correlation_types: tuple[str, ...] = ()
    summary: str = ""

    @property
    def role(self) -> ComponentRole:
        return ComponentRole.MATCHER

    def to_dict(self) -> dict[str, Any]:
        """Return a stable API/CLI-safe representation."""

        return {
            "name": self.name,
            "role": ComponentRole.MATCHER.value,
            "module": self.module,
            "source": self.source,
            "phase": self.phase.value,
            "execution_state": self.execution_state.value,
            "enabled_by_default": self.enabled_by_default,
            "run_attr": self.run_attr,
            "input_types": list(self.input_types),
            "output_types": list(self.output_types),
            "correlation_types": list(self.correlation_types),
            "summary": self.summary,
            "capabilities": _capabilities_dict(self.capabilities),
        }


__all__ = [
    "ComponentRole",
    "EnricherRegistration",
    "MatcherRegistration",
    "local_analysis_capabilities",
    "network_lookup_capabilities",
]
