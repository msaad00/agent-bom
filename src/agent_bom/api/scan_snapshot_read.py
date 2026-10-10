"""Opt-in versioned snapshot reads, with an independent differential mode."""

from __future__ import annotations

import json
import logging
from collections.abc import Callable
from copy import deepcopy
from typing import Any

from agent_bom.api.models import ScanJob
from agent_bom.api.scan_snapshot_integrity import snapshot_content_digest, snapshot_source_digest
from agent_bom.api.scan_snapshot_store import SCAN_SNAPSHOT_ROW_SCHEMA_VERSION, get_scan_snapshot_store
from agent_bom.core.settings import env_flag

_logger = logging.getLogger(__name__)


def verified_snapshot_findings(
    job: ScanJob,
    collect: Callable[[], list[dict[str, Any]]],
    attach: Callable[[dict[str, Any]], dict[str, Any]],
    *,
    merge: Callable[[list[dict[str, Any]], Callable[[dict[str, Any]], dict[str, Any]]], list[dict[str, Any]]],
    use_reach: Callable[[dict[str, dict[str, Any]] | None], None] = lambda _: None,
) -> list[dict[str, Any]]:
    """Skip rebuilding valid snapshots in fast mode; compare in qualification.

    Qualification takes precedence when both flags are set. Authoritative
    collection failures propagate. Invalid derived data falls back without
    exposing payloads or backend errors. Store calls are per job, never per row.
    Full retained history still loads for first-seen and manual-SLA semantics.
    """
    qualify = env_flag("AGENT_BOM_SCAN_SNAPSHOT_READS")
    fast = env_flag("AGENT_BOM_SCAN_SNAPSHOT_FAST_READS")
    if not (qualify or fast):
        return collect()
    expected = collect() if qualify else None
    try:
        candidate = _candidate_rows(job, attach, use_reach, merge)
        if candidate is not None:
            if not qualify:
                return candidate
            if json.dumps(candidate, sort_keys=True, allow_nan=False) == json.dumps(expected, sort_keys=True, allow_nan=False):
                _logger.debug("scan_snapshot_read outcome=match")
                return candidate
            _logger.warning("scan_snapshot_read outcome=mismatch; using current findings")
    except Exception:  # broad-except: derived data is optional; authoritative fallback errors propagate below
        _logger.warning("scan_snapshot_read outcome=unavailable; using current findings")
    use_reach(None)
    return expected if expected is not None else collect()


def _candidate_rows(
    job: ScanJob,
    attach: Callable[[dict[str, Any]], dict[str, Any]],
    use_reach: Callable[[dict[str, dict[str, Any]] | None], None],
    merge: Callable[[list[dict[str, Any]], Callable[[dict[str, Any]], dict[str, Any]]], list[dict[str, Any]]],
) -> list[dict[str, Any]] | None:
    store = get_scan_snapshot_store()
    meta = store.get_meta(job.tenant_id, [job.job_id]).get(job.job_id)
    if meta is None or type(meta.get("row_schema_version")) is not int or meta["row_schema_version"] != SCAN_SNAPSHOT_ROW_SCHEMA_VERSION:
        _logger.debug("scan_snapshot_read outcome=missing_or_stale")
        return None
    rows = store.get_rows(job.tenant_id, job.job_id)
    if (
        not rows
        or type(meta.get("row_count")) is not int
        or len(rows) != meta["row_count"]
        or any(
            type(row.get("ordinal")) is not int or row["ordinal"] != ordinal or not isinstance(row.get("payload"), dict)
            for ordinal, row in enumerate(rows)
        )
    ):
        _logger.warning("scan_snapshot_read outcome=invalid; using current findings")
        return None
    context = rows[0]["payload"]
    reach = context.get("reach")
    if (
        not isinstance(reach, dict)
        or any(not isinstance(value, dict) for value in reach.values())
        or context.get("source_digest") != snapshot_source_digest(job)
        or context.get("content_digest") != snapshot_content_digest(reach, rows[1:])
    ):
        _logger.warning("scan_snapshot_read outcome=invalid; using current findings")
        return None
    use_reach(deepcopy(reach))
    return merge([deepcopy(row["payload"]) for row in rows[1:]], attach)
