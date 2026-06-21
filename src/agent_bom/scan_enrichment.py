"""Optional, gated estate-enrichment of a scan report.

These helpers fold *opt-in* cloud-inventory and non-human-identity (NHI)
discovery into a freshly built :class:`~agent_bom.models.AIBOMReport` so the
graph builder, which already consumes ``report["cloud_inventory"]`` and
``report["identity_discovery"]``, sees real data on an ordinary scan instead of
the always-empty default.

Every enrichment here is:

- **Default OFF** — guarded by the same per-provider env flags the discovery
  modules already own (``AGENT_BOM_CLOUD_INVENTORY`` / ``AGENT_BOM_AZURE_INVENTORY``
  / ``AGENT_BOM_GCP_INVENTORY`` for inventory; ``AGENT_BOM_OKTA_DISCOVERY`` /
  ``AGENT_BOM_ENTRA_DISCOVERY`` for NHIs). With all flags off these functions do
  no network I/O and leave the report untouched.
- **Read-only / reference-only** — the underlying connectors never read secret
  material and never call a write API.
- **Crash-safe** — each provider is wrapped so a connector raising never breaks
  a scan; the failure is logged and that provider is skipped.

Both the API scan pipeline and the CLI scan path call these so the two surfaces
stay identical.
"""

from __future__ import annotations

import logging
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:  # pragma: no cover - typing only
    from agent_bom.models import AIBOMReport

_logger = logging.getLogger(__name__)


def collect_cloud_inventory() -> list[dict[str, Any]]:
    """Run opt-in estate-wide cloud inventory for every enabled provider.

    Returns a list of per-provider inventory payloads (the exact shape the graph
    builder's ``_iter_cloud_inventories`` consumes). Providers whose flag is off
    are skipped entirely — no client construction, no network call. An empty
    list means nothing was enabled (or every enabled provider produced no
    estate), in which case the caller should leave ``cloud_inventory_data``
    unset so default behaviour is unchanged.
    """
    payloads: list[dict[str, Any]] = []

    # AWS — AGENT_BOM_CLOUD_INVENTORY
    try:
        from agent_bom.cloud import aws_inventory

        if aws_inventory.inventory_enabled():
            payloads.append(aws_inventory.discover_inventory())
    except Exception:  # noqa: BLE001 — a connector failure must never break a scan
        _logger.warning("AWS estate inventory enrichment failed", exc_info=True)

    # Azure — AGENT_BOM_AZURE_INVENTORY
    try:
        from agent_bom.cloud import azure_inventory

        if azure_inventory.inventory_enabled():
            payloads.append(azure_inventory.discover_inventory())
    except Exception:  # noqa: BLE001
        _logger.warning("Azure estate inventory enrichment failed", exc_info=True)

    # GCP — AGENT_BOM_GCP_INVENTORY
    try:
        from agent_bom.cloud import gcp_inventory

        if gcp_inventory.inventory_enabled():
            payloads.append(gcp_inventory.discover_inventory())
    except Exception:  # noqa: BLE001
        _logger.warning("GCP estate inventory enrichment failed", exc_info=True)

    return payloads


def collect_identity_discovery() -> dict[str, Any] | None:
    """Run opt-in NHI discovery for every enabled IdP and merge the results.

    Returns the merged ``identity_discovery`` block (the shape produced by
    :func:`agent_bom.graph.nhi_overlay.merge_discovery_results`, which the graph
    builder's NHI overlay consumes) when at least one provider is enabled, or
    ``None`` when both Okta and Entra discovery are off so the caller leaves
    ``identity_discovery_data`` unset and default behaviour is unchanged.
    """
    import os

    from agent_bom.identity.entra_nhi import _DISCOVERY_FLAG_ENV as _ENTRA_FLAG
    from agent_bom.identity.entra_nhi import _is_truthy as _entra_truthy
    from agent_bom.identity.okta_nhi import _DISCOVERY_FLAG_ENV as _OKTA_FLAG
    from agent_bom.identity.okta_nhi import _is_truthy as _okta_truthy

    okta_on = _okta_truthy(os.environ.get(_OKTA_FLAG))
    entra_on = _entra_truthy(os.environ.get(_ENTRA_FLAG))
    if not okta_on and not entra_on:
        return None

    from agent_bom.graph.nhi_overlay import merge_discovery_results
    from agent_bom.identity import (
        discover_entra_non_human_identities,
        discover_okta_non_human_identities,
    )

    results = []
    if okta_on:
        try:
            results.append(discover_okta_non_human_identities())
        except Exception:  # noqa: BLE001
            _logger.warning("Okta NHI discovery enrichment failed", exc_info=True)
    if entra_on:
        try:
            results.append(discover_entra_non_human_identities())
        except Exception:  # noqa: BLE001
            _logger.warning("Entra NHI discovery enrichment failed", exc_info=True)

    if not results:
        return None
    return merge_discovery_results(results)


def enrich_report_with_estate_discovery(report: AIBOMReport) -> None:
    """Attach gated cloud-inventory + NHI-discovery blocks to a scan report.

    Mutates ``report`` in place: when the relevant env flags are on, populates
    ``report.cloud_inventory_data`` and/or ``report.identity_discovery_data`` so
    the downstream graph builder projects estate assets and managed-identity
    nodes. A no-op (and no network I/O) when every flag is off. Never raises.
    """
    try:
        inventories = collect_cloud_inventory()
        if inventories:
            report.cloud_inventory_data = inventories
    except Exception:  # noqa: BLE001
        _logger.warning("Cloud inventory enrichment skipped", exc_info=True)

    try:
        discovery = collect_identity_discovery()
        if discovery is not None:
            report.identity_discovery_data = discovery
    except Exception:  # noqa: BLE001
        _logger.warning("Identity discovery enrichment skipped", exc_info=True)
