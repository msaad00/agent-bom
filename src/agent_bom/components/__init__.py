"""Component-model registries for enrichers and matchers/correlators.

This package mirrors :mod:`agent_bom.scanners.registry` for the two pipeline
component roles that have no registry today: **enrichers** (CVSS/EPSS/KEV/GHSA,
AI, registry reputation, estate context) and **matchers/correlators**
(`correlate.py`, `cross_env_correlation.py`, `runtime_correlation.py`).

The registrations here are metadata-first and descriptive. Existing enrichment
and correlation execution stays wired through the current CLI/API pipeline;
these entries give product/API/UI surfaces a capability contract before any
component is migrated behind a common run interface. No execution path is
changed by importing or reading these registries.
"""

from __future__ import annotations

from agent_bom.components.base import (
    ComponentRole,
    EnricherRegistration,
    MatcherRegistration,
)
from agent_bom.components.enricher_registry import (
    builtin_enricher_registrations,
    enricher_registry_summary,
    enricher_registry_warnings,
    get_enricher_registration,
    list_registered_enrichers,
    register_enricher,
)
from agent_bom.components.matcher_registry import (
    builtin_matcher_registrations,
    get_matcher_registration,
    list_registered_matchers,
    matcher_registry_summary,
    matcher_registry_warnings,
    register_matcher,
)

__all__ = [
    "ComponentRole",
    "EnricherRegistration",
    "MatcherRegistration",
    "builtin_enricher_registrations",
    "builtin_matcher_registrations",
    "enricher_registry_summary",
    "enricher_registry_warnings",
    "get_enricher_registration",
    "get_matcher_registration",
    "list_registered_enrichers",
    "list_registered_matchers",
    "matcher_registry_summary",
    "matcher_registry_warnings",
    "register_enricher",
    "register_matcher",
]
