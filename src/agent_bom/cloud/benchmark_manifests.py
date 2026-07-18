"""Versioned, repository-grounded cloud benchmark implementation manifests.

Official benchmark denominators are intentionally unset until a licensed or
otherwise authoritative control catalog is repository-provenanced. The
implemented counts below are derived from the named code registries via
:mod:`agent_bom.cloud.benchmark_provenance` (the single source of truth for the
registry specs, the automated/manual classification, and the pinned provenance);
they are not coverage percentages.
"""

from __future__ import annotations

from copy import deepcopy
from typing import Any, Final

from agent_bom.cloud.benchmark_provenance import (
    BENCHMARK_PROVENANCE,
    PROVENANCE_SCHEMA_VERSION,
    REGISTRY_SPECS,
    build_control_inventory,
    coverage_percentage,
)

MANIFEST_SCHEMA_VERSION: Final = 1


def _manifest(provider: str) -> dict[str, Any]:
    inv = build_control_inventory(provider)
    prov = BENCHMARK_PROVENANCE[provider]
    return {
        "manifest_schema_version": MANIFEST_SCHEMA_VERSION,
        "provenance_schema_version": PROVENANCE_SCHEMA_VERSION,
        "benchmark_name": prov.benchmark_name,
        "benchmark_version": prov.benchmark_version,
        "benchmark_type": prov.benchmark_type,
        "implemented_control_count": inv.implemented_control_count,
        "implementation_registry": REGISTRY_SPECS[provider][2],
        "authoritative_source": prov.source_url,
        "authoritative_source_version": prov.benchmark_version,
        "authoritative_source_access": prov.access_mode,
        "authoritative_source_retrieved_at": prov.retrieved_at,
        "authoritative_source_digest": prov.source_digest,
        "authoritative_source_license_note": prov.license_note,
        "authoritative_catalog_repository_provenance": prov.catalog_repository_provenance,
        "automated_control_ids": list(inv.automated_control_ids),
        "manual_control_ids": list(inv.manual_control_ids),
        "unsupported_control_ids": None,
        "unsupported_control_ids_reason": "Unknown until an authoritative versioned control catalog is repository-provenanced.",
        "unsupported_control_count": inv.unsupported_control_count,
        "official_control_count": inv.official_control_count,
        "inventory_digest": inv.inventory_digest,
        "coverage_percentage": coverage_percentage(inv),
        "coverage_note": "Official denominator not repository-provenanced; percentage intentionally unpublished.",
    }


CLOUD_BENCHMARK_MANIFESTS: Final[dict[str, dict[str, Any]]] = {provider: _manifest(provider) for provider in REGISTRY_SPECS}


def benchmark_manifest(provider: str) -> dict[str, Any]:
    """Return an independent manifest safe to expose in report JSON."""
    return deepcopy(CLOUD_BENCHMARK_MANIFESTS[provider])
