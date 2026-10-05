"""Pure collection of retained finding representations, before tenant enrichment."""

from __future__ import annotations

from collections.abc import Callable
from types import ModuleType
from typing import Any

from agent_bom.api.models import ScanJob


def _matching_key(scan: ModuleType, row: dict, key: str, grouped: dict, package_groups: dict) -> str:
    if scan._row_vuln_id(row) and key not in grouped:
        name, version, ecosystem = scan._package_identity(row)
        candidates = []
        for candidate in package_groups.get((scan._row_vuln_id(row).lower(), name), []):
            if scan._row_asset_key(row) and scan._row_asset_key(row) != scan._row_asset_key(grouped[candidate]):
                continue
            _, candidate_version, candidate_ecosystem = scan._package_identity(grouped[candidate])
            if version and candidate_version and version != candidate_version:
                continue
            if ecosystem and candidate_ecosystem and ecosystem != candidate_ecosystem:
                continue
            candidates.append(candidate)
            if len(candidates) > 1:
                break  # Ambiguous asset identity; never merge distinct assets.
        if len(candidates) == 1:
            return candidates[0]
    return key


def collect_scan_findings(job: ScanJob, attach: Callable[[dict[str, Any]], dict[str, Any]] | None = None) -> list[dict[str, Any]]:
    # The route owns legacy identity adapters; import at call time to avoid a
    # cycle while preserving the API's established canonical merge semantics.
    from agent_bom.api.routes import scan

    result = job.result or {}
    attach = attach or (lambda row: row)
    # Collapse the three per-vulnerability representations (unified ``findings``
    # stream, ``blast_radius`` projection, nested ``package_vulnerability``) onto
    # one row per canonical id. The unified stream is processed first and stays
    # authoritative; later representations only backfill descriptive fields the
    # unified row is missing (package/CVE metadata) — never reachability or VEX,
    # so the unified-stream-wins contract holds. This keeps ``/v1/findings`` in
    # step with the overview count instead of emitting one row per representation.
    grouped: dict[str, dict[str, Any]] = {}
    order: list[str] = []
    package_groups: dict[tuple[str, str], list[str]] = {}

    def _absorb(row: dict[str, Any]) -> None:
        key = scan._canonical_group_key(row)
        # Older persisted blast/package projections did not carry ``asset``.
        # Match known version/ecosystem fields before backfilling. A missing
        # field can match one unambiguous representation; conflicting known
        # versions cannot. Never guess when multiple assets match. Index by
        # vulnerability/package rather than rescanning every estate finding.
        key = _matching_key(scan, row, key, grouped, package_groups)
        existing = grouped.get(key)
        if existing is None:
            grouped[key] = row
            order.append(key)
            if scan._row_vuln_id(row):
                package_groups.setdefault((scan._row_vuln_id(row).lower(), scan._package_base_name(row)), []).append(key)
            return
        scan._backfill_supplementary_fields(existing, row)

    for item in result.get("findings", []) or []:
        if not isinstance(item, dict):
            continue
        row = dict(item)
        row.setdefault("scan_id", str(result.get("scan_id") or job.job_id))
        row.setdefault("scan_sources", scan._scan_source_labels(job))
        _absorb(attach(row))

    for item in result.get("blast_radius", []) or result.get("blast_radii", []) or []:
        if not isinstance(item, dict):
            continue
        _absorb(attach(scan._finding_from_blast_radius(item, job)))

    for row in scan._iter_package_findings(job):
        _absorb(attach(row))

    return [grouped[key] for key in order]
