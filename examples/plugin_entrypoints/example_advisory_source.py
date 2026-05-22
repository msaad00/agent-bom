"""Example third-party advisory source plugin registration."""

from __future__ import annotations

from datetime import UTC, datetime
from typing import Any

from agent_bom.extensions import ExtensionCapabilities
from agent_bom.plugin_entrypoints import AdvisorySourcePluginRegistration


def registration() -> AdvisorySourcePluginRegistration:
    """Return a metadata registration for an operator-owned advisory feed."""

    return AdvisorySourcePluginRegistration(
        name="example-advisory-source",
        module="example_advisory_source",
        lookup_attr="lookup",
        sync_attr="sync",
        capabilities=ExtensionCapabilities(
            scan_modes=("advisory_lookup", "advisory_sync"),
            required_scopes=("advisory_source_read",),
            outbound_destinations=("security-advisories.internal",),
            data_boundary="operator_owned_advisory_metadata",
            network_access=True,
            writes=False,
            guarantees=("license_declared", "source_url_required", "metadata_only"),
        ),
        source="example",
    )


def lookup(advisory_id: str) -> dict[str, Any]:
    """Return one normalized advisory metadata record.

    The example intentionally returns a short summary and source URL, not a
    redistributed full advisory body.
    """

    return {
        "id": advisory_id,
        "schema_version": "example.advisory_lookup.v1",
        "summary": "Example advisory metadata returned by an operator-owned feed.",
        "source_url": f"https://security-advisories.internal/advisories/{advisory_id}",
        "license": "link-only",
        "redistribution": "summary_only",
        "last_seen": datetime.now(UTC).isoformat(),
    }


def sync(*, since: str | None = None) -> dict[str, Any]:
    """Return freshness metadata for a feed sync run."""

    return {
        "schema_version": "example.advisory_sync.v1",
        "since": since,
        "items_seen": 0,
        "last_synced_at": datetime.now(UTC).isoformat(),
        "license": "link-only",
    }
