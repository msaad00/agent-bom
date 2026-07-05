"""Threat-intel MCP tool implementations."""

from __future__ import annotations

import json
import logging

from agent_bom.intel_lookup import build_daily_brief, list_intel_sources, lookup_advisory, match_packages
from agent_bom.mcp_errors import CODE_INTERNAL_UNEXPECTED, CODE_VALIDATION_INVALID_ARGUMENT, mcp_error_json
from agent_bom.security import sanitize_error

logger = logging.getLogger(__name__)


async def intel_lookup_impl(*, advisory_id: str, _truncate_response=lambda value: value) -> str:
    """Look up one CVE/GHSA/OSV advisory from local intel."""

    try:
        advisory = (advisory_id or "").strip()
        if not advisory:
            return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, "advisory_id is required", details={"argument": "advisory_id"})
        result = lookup_advisory(advisory)
        # Opt-in operator advisory source plugins augment the local record with
        # provenance-tagged metadata (off by default; see plugin_activation).
        from agent_bom.plugin_activation import advisory_source_lookup

        operator_sources = advisory_source_lookup(advisory)
        if operator_sources and isinstance(result, dict):
            result = {**result, "operator_advisory_sources": operator_sources}
        return _truncate_response(json.dumps(result, indent=2, default=str))
    except ValueError as exc:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, sanitize_error(exc), details={"argument": "advisory_id"})
    except Exception as exc:  # pragma: no cover - defensive redaction
        logger.exception("MCP intel lookup failed")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "Intel lookup failed.", details={"error": sanitize_error(exc)})


async def intel_match_impl(
    *,
    packages: list[dict] | None = None,
    purl: str | None = None,
    ecosystem: str | None = None,
    name: str | None = None,
    version: str | None = None,
    limit: int = 100,
    _truncate_response=lambda value: value,
) -> str:
    """Match package inventory coordinates to local advisory intel."""

    try:
        submitted = list(packages or [])
        if purl or ecosystem or name:
            submitted.append({"purl": purl or "", "ecosystem": ecosystem or "", "name": name or "", "version": version or ""})
        if not submitted:
            return mcp_error_json(
                CODE_VALIDATION_INVALID_ARGUMENT,
                "Provide packages or a single purl/ecosystem/name package.",
                details={"argument": "packages"},
            )
        return _truncate_response(json.dumps(match_packages(submitted, limit=limit), indent=2, default=str))
    except ValueError as exc:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, sanitize_error(exc), details={"argument": "packages"})
    except Exception as exc:  # pragma: no cover - defensive redaction
        logger.exception("MCP intel match failed")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "Intel match failed.", details={"error": sanitize_error(exc)})


async def intel_sources_impl(*, _truncate_response=lambda value: value) -> str:
    """Return canonical threat-intel source and feed-run metadata."""

    try:
        return _truncate_response(json.dumps(list_intel_sources(), indent=2, default=str))
    except Exception as exc:  # pragma: no cover - defensive redaction
        logger.exception("MCP intel sources failed")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "Intel sources failed.", details={"error": sanitize_error(exc)})


async def intel_daily_brief_impl(
    *,
    packages: list[dict] | None = None,
    telemetry_indicators: list[dict] | None = None,
    campaign_activity: list[dict] | None = None,
    ransomware_claims: list[dict] | None = None,
    tenant_profile: dict | None = None,
    epss_threshold: float = 0.7,
    kev_window_hours: int = 24,
    limit: int = 100,
    _truncate_response=lambda value: value,
) -> str:
    """Return a local analyst threat brief from governed intel sources."""

    try:
        return _truncate_response(
            json.dumps(
                build_daily_brief(
                    packages or [],
                    telemetry_indicators=telemetry_indicators or [],
                    campaign_activity=campaign_activity or [],
                    ransomware_claims=ransomware_claims or [],
                    tenant_profile=tenant_profile or {},
                    epss_threshold=epss_threshold,
                    kev_window_hours=kev_window_hours,
                    limit=limit,
                ),
                indent=2,
                default=str,
            )
        )
    except ValueError as exc:
        return mcp_error_json(CODE_VALIDATION_INVALID_ARGUMENT, sanitize_error(exc), details={"argument": "daily_brief"})
    except Exception as exc:  # pragma: no cover - defensive redaction
        logger.exception("MCP intel daily brief failed")
        return mcp_error_json(CODE_INTERNAL_UNEXPECTED, "Intel daily brief failed.", details={"error": sanitize_error(exc)})
