"""Comparable scan history; absence is never an audited remediation event."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping
from datetime import datetime, timezone
from statistics import median
from typing import Any

from agent_bom.baseline import TrendPoint

MAX_COMPARISON_OBSERVATIONS = 10_000
MAX_COMPARISON_METADATA_BYTES = 2 * 1024 * 1024


def _digest(value: Any) -> str:
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(",", ":")).encode()).hexdigest()


def scan_scope_id(request: Any) -> str | None:
    """Identify explicit targets; ambient discovery lacks stable host identity."""
    data = request.model_dump(mode="json")
    targets = (
        "repo_url",
        "inventory",
        "images",
        "tf_dirs",
        "gha_path",
        "agent_projects",
        "jupyter_dirs",
        "filesystem_paths",
        "sbom",
        "external_scan",
    )
    if not any(data.get(key) for key in targets):
        return None
    # Runtime defaults such as kubectl context or connector credentials can change
    # independently from this request, so mixed ambient scopes are not comparable.
    if data.get("k8s") or data.get("connectors") or data.get("discover_host"):
        return None
    excluded = {"format", "ai_enrich", "ai_model", "ai_deterministic", "dry_run", "auto_update_db"}
    return "scan:" + _digest({key: value for key, value in data.items() if key not in excluded})


def connection_scope_id(record: Any) -> str:
    """A connection edit that changes its target must start a new comparison scope."""
    return "cloud-connection:" + _digest(
        [
            record.id,
            record.provider,
            record.role_ref,
            sorted(record.regions),
            record.auth_params,
            record.inventory_scope,
        ]
    )


def parse_time(value: Any) -> datetime | None:
    if not isinstance(value, str):
        return None
    try:
        parsed = datetime.fromisoformat(value.replace("Z", "+00:00"))
        return parsed.astimezone(timezone.utc) if parsed.tzinfo else None
    except ValueError:
        return None


def finding_observed_at(row: Mapping[str, Any]) -> str | None:
    """Latest source observation, not scan generation or advisory publication."""
    candidates = [row.get("observed_at")]
    evidence = row.get("evidence")
    if isinstance(evidence, Mapping):
        candidates.append(evidence.get("observed_at"))
    workload = row.get("workload_runtime_evidence")
    if isinstance(workload, Mapping):
        # RuntimeWorkloadEvidenceIndex.summary_for uses actual signal timestamps.
        candidates.append(workload.get("latest_observed_at"))
    runtime = row.get("runtime_evidence")
    if isinstance(runtime, Mapping):
        candidates.extend(event.get("timestamp") for event in runtime.get("events", []) if isinstance(event, Mapping))
    observed = [value for candidate in candidates if (value := parse_time(candidate)) is not None]
    return max(observed).isoformat() if observed else None


def comparison_metadata(result: Mapping[str, Any], scope_id: str | None, timestamp: str | None = None) -> dict:
    run = result.get("scan_run")
    run = run if isinstance(run, Mapping) else {}
    scopes = run.get("scopes") or []
    requested = [s for s in scopes if isinstance(s, Mapping) and s.get("requested", True)]
    complete = run.get("outcome") == "complete" and not result.get("coverage_warnings")
    complete = complete and all(s.get("status") == "complete" for s in requested)
    complete = complete and not any(i.get("affects_coverage", True) for i in run.get("issues", []) if isinstance(i, Mapping))
    rows = result.get("findings")
    identities_complete = isinstance(rows, list)
    observations: list[dict[str, Any]] = []
    detail_bytes = 1024
    exceeded = False
    completed = parse_time(timestamp or result.get("generated_at"))
    age_samples: dict[str, list[float]] = {"first_seen": [], "observed_at": []}
    for row in rows if isinstance(rows, list) else []:
        if not isinstance(row, Mapping):
            identities_complete = False
            continue
        observed_at = finding_observed_at(row)
        for key in age_samples:
            observed = parse_time(row.get(key) if key == "first_seen" else observed_at)
            if completed and observed and observed <= completed:
                age_samples[key].append((completed - observed).total_seconds() / 86400)
        if exceeded:
            continue
        asset = row.get("asset") or {}
        asset_id = asset.get("canonical_id") or asset.get("stable_id") or asset.get("identifier")
        advisory_ids = {str(v) for key in ("advisory_ids", "advisory_aliases", "cve_ids") for v in row.get(key, []) or []}
        advisory_ids.update(str(row[key]) for key in ("cve_id", "vulnerability_id") if row.get(key))
        finding_id = row.get("canonical_id") or row.get("id")
        if asset_id and advisory_ids:
            keys = sorted(_digest([asset_id, advisory]) for advisory in advisory_ids)
        elif finding_id:
            keys = [_digest(["finding", finding_id])]
        else:
            identities_complete = False
            continue
        observation = {"keys": keys, "first_seen": row.get("first_seen"), "observed_at": observed_at}
        detail_bytes += len(json.dumps(observation).encode()) + 2
        if len(observations) >= MAX_COMPARISON_OBSERVATIONS or detail_bytes > MAX_COMPARISON_METADATA_BYTES:
            exceeded = True
            observations.clear()
            identities_complete = False
        else:
            observations.append(observation)
    return {
        "scope_id": scope_id,
        "measurement_version": 1,
        "collection_coverage": "complete" if complete else "partial" if run else "unknown",
        "coverage_key": _digest([sorted(str(s.get("name")) for s in requested), sorted(result.get("scan_sources") or [])]),
        "identities_complete": identities_complete,
        "observations": observations,
        "comparison_limit_exceeded": exceeded,
        "source_age_summary": {
            key: {"median": median(values) if values else None, "count": len(values)} for key, values in age_samples.items()
        }
        if exceeded
        else None,
    }


def _groups(observations: list[dict]) -> list[set[str]]:
    """Collapse aliases and duplicate observations without comparing display labels."""
    groups: list[set[str]] = []
    index: dict[str, int] = {}
    for row in observations:
        keys = set(row["keys"])
        matches = {index[k] for k in keys if k in index}
        target = min(matches) if matches else len(groups)
        if not matches:
            groups.append(set())
        for match in matches - {target}:
            keys.update(groups[match])
            groups[match].clear()
        groups[target].update(keys)
        for key in groups[target]:
            index[key] = target
    return [group for group in groups if group]


def public_trend_point(point: TrendPoint, previous: TrendPoint | None) -> dict:
    meta = point.comparison_metadata
    prior = previous.comparison_metadata if previous else {}
    current_time = parse_time(point.timestamp)
    previous_time = parse_time(previous.timestamp) if previous else None
    reason = None
    if meta.get("history_processing_limit") or prior.get("history_processing_limit"):
        reason = "history_processing_limit"
    elif meta.get("comparison_limit_exceeded") or prior.get("comparison_limit_exceeded"):
        reason = "comparison_limit_exceeded"
    elif not meta.get("scope_id") or not meta.get("measurement_version"):
        reason = "missing_comparison_metadata"
    elif not previous:
        reason = "no_previous_snapshot"
    elif point.tenant_id != previous.tenant_id or meta.get("scope_id") != prior.get("scope_id"):
        reason = "different_scope"
    elif meta.get("measurement_version") != prior.get("measurement_version"):
        reason = "different_measurement_version"
    elif meta.get("collection_coverage") != "complete" or prior.get("collection_coverage") != "complete":
        reason = "incomplete_collection"
    elif meta.get("coverage_key") != prior.get("coverage_key"):
        reason = "different_collection_coverage"
    elif not meta.get("identities_complete") or not prior.get("identities_complete"):
        reason = "missing_finding_identities"
    elif current_time is None or previous_time is None or current_time <= previous_time:
        reason = "invalid_snapshot_order"
    comparison: dict[str, Any] = {
        "status": "unavailable" if reason else "comparable",
        "reason": reason,
        "previous_scan_id": previous.scan_id if previous else None,
        "new_findings": None,
        "still_open": None,
        "no_longer_detected": None,
    }
    if reason is None:
        old = _groups(prior["observations"])
        current = _groups(meta["observations"])
        old_keys = set().union(*old) if old else set()
        current_keys = set().union(*current) if current else set()
        comparison.update(
            new_findings=sum(not bool(g & old_keys) for g in current),
            still_open=sum(bool(g & old_keys) for g in current),
            no_longer_detected=sum(not bool(g & current_keys) for g in old),
        )
    completed = parse_time(point.timestamp)
    ages: dict[str, list[float]] = {"first_seen": [], "observed_at": []}
    for row in meta.get("observations", []):
        for key in ages:
            observed = parse_time(row.get(key))
            if completed and observed and observed <= completed:
                ages[key].append((completed - observed).total_seconds() / 86400)
    source_summary = meta.get("source_age_summary") or {}
    return {
        **point.to_dict(),
        "scope_id": meta.get("scope_id"),
        "collection_coverage": meta.get("collection_coverage", "unknown"),
        "measurement_version": meta.get("measurement_version"),
        "comparison": comparison,
        "open_finding_age_days": median(ages["first_seen"]) if ages["first_seen"] else source_summary.get("first_seen", {}).get("median"),
        "evidence_age_days": median(ages["observed_at"]) if ages["observed_at"] else source_summary.get("observed_at", {}).get("median"),
        "age_sample_count": len(ages["first_seen"]) or source_summary.get("first_seen", {}).get("count", 0),
        "evidence_sample_count": len(ages["observed_at"]) or source_summary.get("observed_at", {}).get("count", 0),
        "verified_remediations": None,
        "verified_remediation_duration_days": None,
    }


def retain_open_interval(point: TrendPoint, history: list[TrendPoint]) -> None:
    """Carry first observation only across comparable consecutive snapshots."""
    current_time = parse_time(point.timestamp)
    candidates = [
        old
        for old in history
        if old.tenant_id == point.tenant_id
        and old.comparison_metadata.get("scope_id") == point.comparison_metadata.get("scope_id")
        and old.scan_id != point.scan_id
        and (old_time := parse_time(old.timestamp)) is not None
        and current_time is not None
        and old_time < current_time
    ]
    previous = (
        max(candidates, key=lambda old: parse_time(old.timestamp) or datetime.min.replace(tzinfo=timezone.utc)) if candidates else None
    )
    if public_trend_point(point, previous)["comparison"]["status"] != "comparable" or previous is None:
        return
    first_seen_by_key = {}
    for observation in previous.comparison_metadata.get("observations", []):
        first_seen = parse_time(observation.get("first_seen"))
        if first_seen is not None:
            for key in observation["keys"]:
                first_seen_by_key[key] = first_seen
    for observation in point.comparison_metadata.get("observations", []):
        prior_dates = [first_seen_by_key[key] for key in observation["keys"] if key in first_seen_by_key]
        current = parse_time(observation.get("first_seen"))
        if prior_dates:
            if current:
                prior_dates.append(current)
            observation["first_seen"] = min(prior_dates).isoformat()
