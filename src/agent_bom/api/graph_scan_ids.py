"""Resolve a scan job id to the graph snapshot id its report was stored under.

API-run scans store their graph under the job id, but a pushed report keeps the
``scan_id`` the CLI minted, while the push response hands back only a job id.
Graph reads accept either: a completed job of the caller's own tenant resolves
to its report's snapshot id; anything else passes through unchanged.
"""

from __future__ import annotations

import logging

_logger = logging.getLogger(__name__)


def resolve_graph_scan_id(tenant_id: str, scan_id: str | None) -> str:
    requested = str(scan_id or "")
    if not requested:
        return requested
    try:
        from agent_bom.api.stores import _get_store

        job = _get_store().get(requested, tenant_id=tenant_id or "default")
    except Exception:  # noqa: BLE001 - an unavailable job store must not break graph reads
        _logger.debug("graph scan id resolution skipped: job store unavailable")
        return requested
    if job is None or (job.tenant_id or "default") != (tenant_id or "default"):
        return requested
    result = job.result if isinstance(job.result, dict) else {}
    graph_scan_id = result.get("scan_id")
    return str(graph_scan_id) if isinstance(graph_scan_id, str) and graph_scan_id else requested
