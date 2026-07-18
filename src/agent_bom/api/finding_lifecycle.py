"""Monotone current-state merge for hub findings (#3465).

One row per ``(tenant_id, canonical_id)`` with ``first_seen`` / ``last_seen``
driven by ``observed_at``. The occurrence log dedups on
``(tenant_id, canonical_id, scan_id)``; ``scan_count`` advances only when a new
scan sighting inserts into the log (L2).
"""

from __future__ import annotations

from collections.abc import Sequence
from datetime import datetime, timezone
from typing import Any

from agent_bom.api.compliance_hub_store import _cvss_value, _severity_rank, compute_effective_reach_score
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
    return {
        "severity": severity,
        "severity_rank": _severity_rank(payload),
        "cvss_score": _cvss_value(payload),
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
    cvss_score REAL NOT NULL DEFAULT 0,
    effective_reach_score REAL NOT NULL DEFAULT 0,
    scan_count INTEGER NOT NULL DEFAULT 1,
    resolved_at TEXT,
    reopened_at TEXT,
    updated_at TEXT NOT NULL,
    payload TEXT NOT NULL,
    ledger_finding_id TEXT,
    origin TEXT NOT NULL DEFAULT '',
    scan_id TEXT NOT NULL DEFAULT '',
    ledger_ordinal INTEGER NOT NULL DEFAULT 9223372036854775807,
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

_CURRENT_LIFECYCLE_SORT_INDEXES_SQLITE = """
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_reach
    ON hub_findings_current(tenant_id, effective_reach_score DESC, last_seen DESC, canonical_id ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_cvss
    ON hub_findings_current(tenant_id, cvss_score DESC, last_seen DESC, canonical_id ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity
    ON hub_findings_current(tenant_id, severity_rank DESC, last_seen DESC, canonical_id ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_origin_cvss
    ON hub_findings_current(tenant_id, origin, cvss_score DESC, last_seen DESC, canonical_id ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_ordinal
    ON hub_findings_current(tenant_id, ledger_ordinal ASC, first_seen ASC, canonical_id ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_reach
    ON hub_findings_current(tenant_id, LOWER(severity), effective_reach_score DESC, last_seen DESC, canonical_id ASC)
    WHERE severity != '';
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_cvss
    ON hub_findings_current(tenant_id, LOWER(severity), cvss_score DESC, last_seen DESC, canonical_id ASC)
    WHERE severity != '';
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_open_reach
    ON hub_findings_current(tenant_id, effective_reach_score DESC, last_seen DESC, canonical_id ASC)
    WHERE status IN ('open', 'reopened');
"""


def collect_present_canonical_ids(
    findings: Sequence[dict[str, Any]],
    *,
    source: str = "",
) -> set[str]:
    """Return canonical ids observed in a scan batch for resolve-reconcile."""
    return {resolve_canonical_id(payload, source=source) for payload in findings}


def enriched_finding_payload(current_row: dict[str, Any]) -> dict[str, Any]:
    """Merge lifecycle fields from a current-state row into the API payload."""
    payload = dict(current_row.get("payload") or {})
    payload["status"] = current_row.get("status")
    payload["first_seen"] = current_row.get("first_seen")
    payload["last_seen"] = current_row.get("last_seen")
    payload["scan_count"] = current_row.get("scan_count")
    canonical = current_row.get("canonical_id")
    if canonical:
        payload["canonical_id"] = canonical
    if current_row.get("resolved_at"):
        payload["resolved_at"] = current_row["resolved_at"]
    if current_row.get("reopened_at"):
        payload["reopened_at"] = current_row["reopened_at"]
    return payload


_CURRENT_LIFECYCLE_POSTGRES_DDL = """
CREATE TABLE IF NOT EXISTS hub_findings_current (
    tenant_id TEXT NOT NULL,
    canonical_id TEXT NOT NULL,
    first_seen TEXT NOT NULL,
    last_seen TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'open',
    severity TEXT NOT NULL DEFAULT '',
    severity_rank INTEGER NOT NULL DEFAULT 0,
    cvss_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    effective_reach_score DOUBLE PRECISION NOT NULL DEFAULT 0,
    scan_count INTEGER NOT NULL DEFAULT 1,
    resolved_at TEXT,
    reopened_at TEXT,
    updated_at TEXT NOT NULL,
    payload JSONB NOT NULL,
    ledger_finding_id TEXT,
    origin TEXT NOT NULL DEFAULT '',
    scan_id TEXT NOT NULL DEFAULT '',
    ledger_ordinal BIGINT NOT NULL DEFAULT 9223372036854775807,
    PRIMARY KEY (tenant_id, canonical_id)
);

CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_last_seen
    ON hub_findings_current(tenant_id, last_seen DESC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_reach
    ON hub_findings_current(tenant_id, effective_reach_score DESC, last_seen DESC, canonical_id ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_cvss
    ON hub_findings_current(tenant_id, cvss_score DESC, last_seen DESC, canonical_id ASC);
CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity
    ON hub_findings_current(tenant_id, severity_rank DESC, last_seen DESC, canonical_id ASC);
"""

# Ordinal + severity-composite sort indexes for hub_findings_current, created
# after the ``ledger_ordinal`` column migration (the column post-dates the base
# DDL for pre-existing Postgres deployments, so these cannot live in the CREATE
# TABLE block). The ordinal index backs the ``sort=ordinal`` order clause as an
# index range scan (replacing a per-row correlated ledger subquery, #3984); the
# severity composites let a severity-filtered reach/cvss-ordered page ride one
# index for both the filter and the sort instead of an equality index + sort.
_CURRENT_LIFECYCLE_SORT_INDEXES_POSTGRES = (
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_ordinal "
    "ON hub_findings_current(tenant_id, ledger_ordinal ASC, first_seen ASC, canonical_id ASC)",
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_reach "
    "ON hub_findings_current(tenant_id, LOWER(severity), effective_reach_score DESC, last_seen DESC, canonical_id ASC) "
    "WHERE severity <> ''",
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_severity_cvss "
    "ON hub_findings_current(tenant_id, LOWER(severity), cvss_score DESC, last_seen DESC, canonical_id ASC) "
    "WHERE severity <> ''",
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_open_reach "
    "ON hub_findings_current(tenant_id, effective_reach_score DESC, last_seen DESC, canonical_id ASC) "
    "WHERE status IN ('open', 'reopened')",
)

# Origin-scoped composite index — created after the ``origin`` column migration
# (the column post-dates the base DDL, so it cannot live in the CREATE TABLE
# block for pre-existing Postgres deployments). Backs both the cvss-sorted page
# read and the exact COUNT(*) over ``(tenant_id, origin)`` (#3641).
_CURRENT_LIFECYCLE_ORIGIN_INDEX_POSTGRES = (
    "CREATE INDEX IF NOT EXISTS idx_hub_findings_current_tenant_origin_cvss "
    "ON hub_findings_current(tenant_id, origin, cvss_score DESC, last_seen DESC, canonical_id ASC)"
)

# Legacy unpartitioned observations DDL for existing Postgres deployments that
# have not yet run the partition migration (#3463). New installs use
# hub_observations_partition.partitioned_observations_parent_ddl() instead.
_CURRENT_LIFECYCLE_POSTGRES_OBSERVATIONS_LEGACY_DDL = """
CREATE TABLE IF NOT EXISTS hub_findings_current_observations (
    tenant_id TEXT NOT NULL,
    canonical_id TEXT NOT NULL,
    scan_id TEXT NOT NULL,
    observed_at TEXT NOT NULL,
    PRIMARY KEY (tenant_id, canonical_id, scan_id)
);
"""
