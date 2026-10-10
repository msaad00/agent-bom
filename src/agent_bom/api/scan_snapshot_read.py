"""Opt-in, differential-verified reads of intrinsic finding snapshots.

The existing collector remains the authority during qualification. A candidate
is served only when its enriched rows match that collector exactly. This mode
adds work; it is not the metadata-only or default-on performance rollout.
"""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from copy import deepcopy
from typing import Any

from agent_bom.api.models import ScanJob
from agent_bom.api.scan_snapshot_store import SCAN_SNAPSHOT_ROW_SCHEMA_VERSION, get_scan_snapshot_store
from agent_bom.core.settings import env_flag

_logger = logging.getLogger(__name__)


def verified_snapshot_findings(
    job: ScanJob,
    collect: Callable[[], list[dict[str, Any]]],
    attach: Callable[[dict[str, Any]], dict[str, Any]],
) -> list[dict[str, Any]]:
    """Return matching snapshot rows, otherwise preserve the authoritative read.

    Store access always uses the retained job's explicit tenant and job IDs.
    Candidate enrichment receives detached payloads and the same live indexes
    as the collector. Never log finding values or backend exceptions here.
    Errors from the authoritative collector propagate unchanged.
    """
    expected = collect()
    if not env_flag("AGENT_BOM_SCAN_SNAPSHOT_READS"):
        return expected
    try:
        candidate = _candidate_rows(job, attach)
        if candidate is None:
            return expected
        if json.dumps(candidate, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False):
            _logger.debug("scan_snapshot_read outcome=match")
            return candidate
        _logger.warning("scan_snapshot_read outcome=mismatch; using current findings")
    except Exception:  # broad-except: derived read or enrichment failures must preserve the successful authoritative read
        _logger.warning("scan_snapshot_read outcome=unavailable; using current findings")
    return expected


def _candidate_rows(job: ScanJob, attach: Callable[[dict[str, Any]], dict[str, Any]]) -> list[dict[str, Any]] | None:
    store = get_scan_snapshot_store()
    meta = store.get_meta(job.tenant_id, [job.job_id]).get(job.job_id)
    if meta is None or meta.get("row_schema_version") != SCAN_SNAPSHOT_ROW_SCHEMA_VERSION:
        _logger.debug("scan_snapshot_read outcome=missing_or_stale")
        return None
    rows = store.get_rows(job.tenant_id, job.job_id)
    if len(rows) != meta.get("row_count") or any(
        row.get("ordinal") != ordinal or not isinstance(row.get("payload"), dict) for ordinal, row in enumerate(rows)
    ):
        _logger.warning("scan_snapshot_read outcome=invalid; using current findings")
        return None
    return [attach(deepcopy(row["payload"])) for row in rows]
