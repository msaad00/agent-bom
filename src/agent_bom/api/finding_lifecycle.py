"""Monotone current-state merge for hub findings (#3465).

One row per ``(tenant_id, canonical_id)`` with ``first_seen`` / ``last_seen``
driven by ``observed_at``. The occurrence log dedups on
``(tenant_id, canonical_id, scan_id)``; ``scan_count`` advances only when a new
scan sighting inserts into the log (L2).
"""

from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from agent_bom.api.compliance_hub_store import _severity_rank, compute_effective_reach_score
from agent_bom.canonical_ids import canonical_finding_id, canonical_id

FindingLifecycleMetrics = dict[str, Any]


def normalize_observed_at(value: str | datetime | None) -> str:
    """Return a UTC ISO-8601 timestamp suitable for monotone comparisons."""
    if value is None or value == "":
        return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    if isinstance(value, datetime):
        dt = value if value.tzinfo is not None else value.replace(tzinfo=timezone.utc)
        return dt.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    text = str(value).strip()
    if text.endswith("Z"):
        return text
    if "+" in text[10:] or text.endswith("+00:00"):
        try:
            parsed = datetime.fromisoformat(text.replace("Z", "+00:00"))
            return parsed.astimezone(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
        except ValueError:
            return text
    return text


def resolve_canonical_id(payload: dict[str, Any], *, source: str = "") -> str:
    """Return the stable canonical id for a hub finding payload."""
    explicit = payload.get("canonical_id") or payload.get("id")
    if explicit:
        return str(explicit)

    raw_asset = payload.get("asset")
    asset = raw_asset if isinstance(raw_asset, dict) else {}
    asset_stable = asset.get("stable_id") or asset.get("canonical_id")
    if not asset_stable:
        asset_type = str(asset.get("asset_type") or "external")
        identifier = asset.get("identifier") or f"{asset.get('name', '')}:{asset.get('location') or ''}"
        asset_stable = canonical_id(asset_type, identifier)

    rule = (
        payload.get("vulnerability_id")
        or payload.get("cve_id")
        or payload.get("rule_id")
        or payload.get("title")
        or ""
    )
    location = payload.get("location") or payload.get("file_path") or asset.get("location") or ""
    package = payload.get("package") or payload.get("package_name") or asset.get("name") or asset.get("identifier") or ""
    pkg_version = str(payload.get("package_version") or "")
    if source and not payload.get("asset"):
        return canonical_finding_id(source, str(rule), str(location), str(package))
    return canonical_finding_id(str(asset_stable), str(rule), str(package), pkg_version, str(location))


def lifecycle_metrics(payload: dict[str, Any]) -> FindingLifecycleMetrics:
    """Extract denormalised lifecycle columns from a finding payload."""
    severity = str(payload.get("severity") or "unknown").lower()
    cvss_raw = payload.get("cvss_score")
    cvss_score: float | None
    try:
        cvss_score = float(cvss_raw) if cvss_raw is not None else None
    except (TypeError, ValueError):
        cvss_score = None
    return {
        "severity": severity,
        "severity_rank": _severity_rank(payload),
        "cvss_score": cvss_score,
        "effective_reach_score": compute_effective_reach_score(payload),
    }


def merge_status_on_observation(existing_status: str | None, *, is_new_row: bool) -> str:
    """Apply reopen semantics when a resolved finding is observed again."""
    if is_new_row or not existing_status:
        return "open"
    if existing_status == "resolved":
        return "reopened"
    return existing_status


def apply_observation_to_current(
    existing: dict[str, Any] | None,
    *,
    canonical_id: str,
    observed_at: str,
    metrics: FindingLifecycleMetrics,
    payload: dict[str, Any],
    updated_at: str,
) -> dict[str, Any]:
    """Return the merged current-state row after a new observation timestamp."""
    if existing is None:
        return {
            "canonical_id": canonical_id,
            "first_seen": observed_at,
            "last_seen": observed_at,
            "status": "open",
            "severity": metrics["severity"],
            "severity_rank": metrics["severity_rank"],
            "cvss_score": metrics["cvss_score"],
            "effective_reach_score": metrics["effective_reach_score"],
            "scan_count": 1,
            "resolved_at": None,
            "reopened_at": None,
            "updated_at": updated_at,
            "payload": payload,
        }

    prior_status = str(existing.get("status") or "open")
    first_seen = observed_at if observed_at < str(existing["first_seen"]) else str(existing["first_seen"])
    last_seen = observed_at if observed_at > str(existing["last_seen"]) else str(existing["last_seen"])
    reopened_at = existing.get("reopened_at")
    if prior_status == "resolved":
        reopened_at = observed_at
    return {
        "canonical_id": canonical_id,
        "first_seen": first_seen,
        "last_seen": last_seen,
        "status": merge_status_on_observation(prior_status, is_new_row=False),
        "severity": metrics["severity"],
        "severity_rank": metrics["severity_rank"],
        "cvss_score": metrics["cvss_score"],
        "effective_reach_score": metrics["effective_reach_score"],
        "scan_count": int(existing.get("scan_count") or 0) + 1,
        "resolved_at": existing.get("resolved_at"),
        "reopened_at": reopened_at,
        "updated_at": updated_at,
        "payload": payload,
    }


_CURRENT_LIFECYCLE_SQLITE_DDL = """
CREATE TABLE IF NOT EXISTS hub_findings_current (
    tenant_id TEXT NOT NULL,
    canonical_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT '',
    severity_rank INTEGER NOT NULL DEFAULT 0,
    cvss_score REAL,
    effective_reach_score REAL NOT NULL DEFAULT 0,
    scan_count INTEGER NOT NULL DEFAULT 1,
    resolved_at TEXT,
    reopened_at TEXT,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    PRIMARY KEY (tenant_id, canonical_id)
);

CREATE TABLE IF NOT EXISTS hub_findings_current_observations (
    tenant_id TEXT NOT NULL,
    canonical_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, canonical_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_last_seen
    ON hub_findings_current(tenant_id, last_seen DESC);
"""


_CURRENT_LIFECYCLE_POSTGRES_DDL = """
CREATE TABLE IF NOT EXISTS hub_findings_current (
    tenant_id TEXT NOT NULL,
    canonical_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT '',
    severity_rank INTEGER NOT NULL DEFAULT 0,
    cvss_score DOUBLE PRECISION,
    effective_reach_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    scan_count INTEGER NOT NULL DEFAULT 1,
    resolved_at TEXT,
    reopened_at TEXT,
    updated_at TEXT NOT NULL,
    payload JSONB NOT NULL,
    PRIMARY KEY (tenant_id, canonical_id)
);

CREATE TABLE IF NOT EXISTS hub_findings_current_observations (
    tenant_id TEXT NOT NULL,
    canonical_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, canonical_id, scan_id)
);

CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_last_seen
    ON hub_findings_current(tenant_id, last_seen DESC);
"""
