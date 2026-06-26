"""Enricher component registry.

Mirrors :mod:`agent_bom.scanners.registry`. Registers the built-in enrichers as
descriptive capability metadata so they are discoverable on the same surface as
scanner drivers. These registrations do NOT change how enrichment runs today —
the existing pipeline still calls each enricher directly.
"""

from __future__ import annotations

from typing import Any

from agent_bom.components.base import (
    EnricherRegistration,
    local_analysis_capabilities,
    network_lookup_capabilities,
)
from agent_bom.extensions import ExtensionCapabilities, iter_entry_point_registrations
from agent_bom.scanners.base import ScannerExecutionState, ScannerPhase

_ENTRY_POINT_GROUP = "agent_bom.enricher_drivers"

_ENRICHER_REGISTRY: dict[str, EnricherRegistration] = {}
_ENRICHER_REGISTRY_WARNINGS: list[str] = []
_ENRICHER_REGISTRY_LOADED = False


def builtin_enricher_registrations() -> list[EnricherRegistration]:
    """Return built-in enricher registrations with capability metadata."""

    return [
        EnricherRegistration(
            name="vulnerability-intel",
            module="agent_bom.enrichment",
            phase=ScannerPhase.ENRICHMENT,
            run_attr="enrich_vulnerabilities",
            input_types=("vulnerabilities", "cve_ids"),
            output_types=("enriched_vulnerabilities",),
            enriches=("cvss", "epss", "kev", "ghsa", "exploitability"),
            summary="NVD CVSS, FIRST EPSS, CISA KEV, and GHSA enrichment with caching and circuit breaking.",
            capabilities=network_lookup_capabilities(
                destinations=("nvd.nist.gov", "first.org_epss", "cisa_kev_catalog", "github_advisory_database")
            ),
        ),
        EnricherRegistration(
            name="enrichment-posture",
            module="agent_bom.enrichment_posture",
            phase=ScannerPhase.ENRICHMENT,
            run_attr="describe_enrichment_posture",
            input_types=("enrichment_source_events",),
            output_types=("enrichment_posture",),
            enriches=("source_slo", "circuit_state", "freshness"),
            summary="Per-source enrichment SLO, failure-threshold, and circuit-breaker posture tracking.",
            capabilities=local_analysis_capabilities(scan_modes=("posture",)),
            execution_state=ScannerExecutionState.PASSIVE,
        ),
        EnricherRegistration(
            name="registry-reputation",
            module="agent_bom.registry_enrichment",
            phase=ScannerPhase.ENRICHMENT,
            run_attr="enrich_registry",
            input_types=("mcp_servers", "registry_entries"),
            output_types=("registry_reputation",),
            enriches=("registry_metadata", "risk_flags", "popularity"),
            summary="MCP server registry reputation enrichment across Smithery, Docker Hub, and GitHub.",
            capabilities=network_lookup_capabilities(
                destinations=("smithery_registry", "docker_hub_registry", "github_api"),
            ),
        ),
        EnricherRegistration(
            name="estate-discovery",
            module="agent_bom.scan_enrichment",
            phase=ScannerPhase.ENRICHMENT,
            run_attr="enrich_report_with_estate_discovery",
            input_types=("report", "cloud_scope"),
            output_types=("estate_inventory", "audit_trail", "identity_discovery"),
            enriches=("cloud_inventory", "audit_trail", "identity"),
            summary="Read-only cloud estate, audit-trail, and identity discovery fused onto the report.",
            capabilities=network_lookup_capabilities(
                destinations=("aws_apis", "azure_apis", "gcp_apis", "snowflake_apis"),
                scan_modes=("cloud",),
            ),
            enabled_by_default=False,
        ),
        EnricherRegistration(
            name="ai-enrichment",
            module="agent_bom.ai_enrich",
            phase=ScannerPhase.ENRICHMENT,
            run_attr="run_ai_enrichment",
            input_types=("blast_radii", "report"),
            output_types=("ai_summaries", "threat_chains"),
            enriches=("executive_summary", "blast_radius_narrative", "threat_chain"),
            summary="Optional LLM-assisted blast-radius, executive-summary, and threat-chain narration.",
            capabilities=ExtensionCapabilities(
                scan_modes=("ai", "online"),
                required_scopes=("llm_inference",),
                outbound_destinations=("litellm_provider", "ollama_local", "huggingface_inference"),
                data_boundary="findings_metadata_to_configured_model",
                network_access=True,
                guarantees=("read_only", "opt_in"),
            ),
            enabled_by_default=False,
        ),
    ]


def _coerce_enricher_registration(value: Any, entry_point_name: str) -> EnricherRegistration:
    if isinstance(value, EnricherRegistration):
        return value
    name = str(getattr(value, "name", entry_point_name)).strip()
    module = str(getattr(value, "module", "")).strip()
    if not name or not module:
        raise ValueError("enricher registration must declare name and module")
    capabilities = getattr(value, "capabilities", ExtensionCapabilities())
    if not isinstance(capabilities, ExtensionCapabilities):
        capabilities = ExtensionCapabilities()
    phase = getattr(value, "phase", ScannerPhase.ENRICHMENT)
    if not isinstance(phase, ScannerPhase):
        phase = ScannerPhase(str(phase))
    execution_state = getattr(value, "execution_state", ScannerExecutionState.ACTIVE)
    if not isinstance(execution_state, ScannerExecutionState):
        execution_state = ScannerExecutionState(str(execution_state))
    return EnricherRegistration(
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
        enriches=tuple(str(item) for item in getattr(value, "enriches", ())),
        summary=str(getattr(value, "summary", "")),
    )


def register_enricher(registration: EnricherRegistration) -> None:
    """Register an enricher component with capability metadata."""

    if not registration.name:
        raise ValueError("enricher registration must declare a name")
    if registration.name in _ENRICHER_REGISTRY:
        raise ValueError(f"duplicate enricher registration: {registration.name}")
    _ENRICHER_REGISTRY[registration.name] = registration


def _ensure_enricher_registry_loaded() -> None:
    global _ENRICHER_REGISTRY_LOADED
    if _ENRICHER_REGISTRY_LOADED:
        return
    for registration in builtin_enricher_registrations():
        register_enricher(registration)
    for registration in iter_entry_point_registrations(
        group=_ENTRY_POINT_GROUP,
        coerce=_coerce_enricher_registration,
        warnings=_ENRICHER_REGISTRY_WARNINGS,
    ):
        register_enricher(registration)
    _ENRICHER_REGISTRY_LOADED = True


def list_registered_enrichers(*, include_planned: bool = True) -> list[EnricherRegistration]:
    """Return registered enricher components sorted by name."""

    _ensure_enricher_registry_loaded()
    registrations = [_ENRICHER_REGISTRY[name] for name in sorted(_ENRICHER_REGISTRY)]
    if include_planned:
        return registrations
    return [registration for registration in registrations if registration.execution_state != ScannerExecutionState.PLANNED]


def get_enricher_registration(name: str) -> EnricherRegistration:
    """Return one enricher registration or raise ``KeyError``."""

    _ensure_enricher_registry_loaded()
    return _ENRICHER_REGISTRY[name]


def enricher_registry_warnings() -> list[str]:
    """Return sanitized non-fatal registry loading warnings."""

    _ensure_enricher_registry_loaded()
    return list(_ENRICHER_REGISTRY_WARNINGS)


def enricher_registry_summary() -> dict[str, object]:
    """Return a compact enricher registry summary for API/UI surfaces."""

    registrations = list_registered_enrichers(include_planned=True)
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


def _reset_enricher_registry_for_tests() -> None:
    _ENRICHER_REGISTRY.clear()
    _ENRICHER_REGISTRY_WARNINGS.clear()
    global _ENRICHER_REGISTRY_LOADED
    _ENRICHER_REGISTRY_LOADED = False


__all__ = [
    "EnricherRegistration",
    "builtin_enricher_registrations",
    "enricher_registry_summary",
    "enricher_registry_warnings",
    "get_enricher_registration",
    "list_registered_enrichers",
    "register_enricher",
]
