"""Vulnerability-data freshness model and refresh-decision helpers.

Surfaces a single structured object that answers: where did the vuln data
come from, how old is it, and is it stale enough that recent CVEs may be
missed? The same object is rendered for the CLI and exposed on the report so
the API and MCP tool can return it.

Design notes:
    * Age is computed from an *injected* ``now`` so tests are deterministic and
      never call the wall clock inside the core logic.
    * Reading freshness never opens the DB read-write and never raises — a
      missing or corrupt cache degrades to ``mode="live"`` (OSV/GHSA/NVD over
      the network) rather than blocking the scan.
    * ``should_refresh`` is the single source of truth for the auto-refresh
      decision. It honors ``--offline`` / ``AGENT_BOM_VULN_DB_OFFLINE`` (never
      touch the network) and the ``AGENT_BOM_VULN_DB_MAX_AGE_HOURS`` threshold.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path

# Default freshness target: refresh / mark stale once the cache crosses a day.
DEFAULT_MAX_AGE_HOURS = 24
# Clear-danger threshold: results past this almost certainly miss recent CVEs.
STALE_DANGER_HOURS = 7 * 24

# Human-facing labels for the structured-feed sources the local cache is built
# from. Kept in primary-then-enrichment order so the rendered line reads well.
_PRIMARY_SOURCE_LABELS: dict[str, str] = {
    "osv": "OSV",
    "ghsa": "GHSA",
}
_ENRICHMENT_SOURCE_LABELS: dict[str, str] = {
    "nvd": "NVD",
    "epss": "EPSS",
    "kev": "KEV",
}
_SOURCE_LABELS: dict[str, str] = {**_PRIMARY_SOURCE_LABELS, **_ENRICHMENT_SOURCE_LABELS}

# Sources surfaced as the live default when no local cache exists. OSV+GHSA are
# the live advisory feeds; NVD provides on-demand enrichment.
_LIVE_SOURCES: tuple[str, ...] = ("OSV", "GHSA", "NVD")


def max_age_hours() -> int:
    """Resolve the staleness threshold (hours) from the environment.

    Reads ``AGENT_BOM_VULN_DB_MAX_AGE_HOURS``. Invalid or non-positive values
    fall back to :data:`DEFAULT_MAX_AGE_HOURS` so a typo can never disable the
    freshness signal entirely.
    """
    raw = os.environ.get("AGENT_BOM_VULN_DB_MAX_AGE_HOURS")
    if not raw:
        return DEFAULT_MAX_AGE_HOURS
    try:
        value = int(raw)
    except (TypeError, ValueError):
        return DEFAULT_MAX_AGE_HOURS
    return value if value > 0 else DEFAULT_MAX_AGE_HOURS


def offline_env() -> bool:
    """True when an env flag forces airgapped / offline operation.

    Mirrors the CLI ``--offline`` flag for callers (MCP, server) that have no
    Click context. Any truthy-ish value enables it.
    """
    raw = os.environ.get("AGENT_BOM_VULN_DB_OFFLINE", "")
    return raw.strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class VulnDataFreshness:
    """Structured freshness snapshot of the vulnerability data backing a scan.

    Attributes:
        mode: ``"local"`` when a local cache is used, ``"live"`` when scanning
            falls back to the OSV/GHSA/NVD APIs, ``"offline"`` when network is
            disabled and only the existing cache is consulted.
        sources: Human labels of the feeds in play (e.g. ``["OSV", "GHSA"]``).
        last_updated: ISO-8601 UTC timestamp of the oldest synced source, or
            ``None`` when there is no cache.
        age_hours: Age of the cache in whole hours, or ``None`` for live mode.
        record_count: Advisory/record count in the cache (0 in live mode).
        stale: True when the cache is older than the configured threshold or
            absent — a signal that recent CVEs may be missed.
        danger: True when the cache crosses the clear-danger threshold (default
            7 days) or the network is unreachable, warranting a loud warning.
    """

    mode: str
    sources: list[str] = field(default_factory=list)
    last_updated: str | None = None
    age_hours: int | None = None
    record_count: int = 0
    stale: bool = False
    danger: bool = False
    max_age_hours: int = DEFAULT_MAX_AGE_HOURS

    @property
    def age_days(self) -> int | None:
        """Whole-day age, or ``None`` when there is no local cache."""
        if self.age_hours is None:
            return None
        return self.age_hours // 24

    def to_dict(self) -> dict:
        """JSON-serializable view for API / MCP / report embedding."""
        return {
            "mode": self.mode,
            "sources": list(self.sources),
            "last_updated": self.last_updated,
            "age_hours": self.age_hours,
            "age_days": self.age_days,
            "record_count": self.record_count,
            "stale": self.stale,
            "danger": self.danger,
            "max_age_hours": self.max_age_hours,
        }

    def summary_line(self) -> str:
        """One-line, plain-text (no Rich markup) freshness statement.

        Rendered verbatim by the CLI in place of the bare
        "No local vulnerability DB found" warning, and reusable by any other
        text surface. Markup-free so it is safe for logs and JSON notes.
        """
        sources = "+".join(self.sources) if self.sources else "OSV"
        if self.mode == "live":
            return f"Vuln data: {sources} live (no local cache — run `agent-bom db update` for faster offline scans)"
        age = _humanize_age(self.age_hours)
        if self.mode == "offline":
            base = f"Vuln data: {sources} local cache, {age} (offline — network skipped)"
        else:
            base = f"Vuln data: {sources} local cache, {age}"
        if self.danger:
            return f"{base} — results may miss recent CVEs; run `agent-bom db update`"
        if self.stale:
            return f"{base} — run `agent-bom db update` for daily freshness"
        return base


def _humanize_age(age_hours: int | None) -> str:
    if age_hours is None:
        return "age unknown"
    if age_hours < 1:
        return "updated <1h ago"
    if age_hours < 48:
        return f"updated {age_hours}h ago"
    return f"updated {age_hours // 24}d ago"


def _read_sync_meta(db_path: Path) -> list[tuple[str, str | None, int]]:
    """Return ``(source, last_synced, record_count)`` rows, or [] on any error.

    Opens the cache read-only and never raises — a corrupt or locked DB simply
    looks like "no cache" to callers.
    """
    import sqlite3

    try:
        if not db_path.exists():
            return []
        conn = sqlite3.connect(f"file:{db_path}?mode=ro", uri=True)
        try:
            cols = {row[1] for row in conn.execute("PRAGMA table_info(sync_meta)").fetchall()}
            if not cols:
                return []
            rows = conn.execute("SELECT source, last_synced, record_count FROM sync_meta").fetchall()
        finally:
            conn.close()
    except Exception:
        return []
    return [(str(r[0]), r[1], int(r[2] or 0)) for r in rows]


def _parse_ts(ts: str | None) -> datetime | None:
    if not ts:
        return None
    try:
        dt = datetime.fromisoformat(ts.replace("Z", "+00:00"))
    except ValueError:
        return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt


def compute_freshness(
    *,
    db_path: Path | None = None,
    now: datetime | None = None,
    offline: bool = False,
    threshold_hours: int | None = None,
) -> VulnDataFreshness:
    """Build a :class:`VulnDataFreshness` snapshot for the active vuln data.

    Args:
        db_path: Override the cache location (defaults to the configured DB).
        now: Injected reference time (UTC). Defaults to ``datetime.now`` only at
            the boundary — pass it explicitly in tests for determinism.
        offline: True when ``--offline`` / the offline env flag is set; selects
            ``offline`` mode (existing cache only, no live fallback).
        threshold_hours: Staleness threshold override; defaults to the env-
            resolved :func:`max_age_hours`.
    """
    from agent_bom.db.schema import DB_PATH

    resolved_path = db_path or DB_PATH
    reference = now or datetime.now(timezone.utc)
    if reference.tzinfo is None:
        reference = reference.replace(tzinfo=timezone.utc)
    threshold = threshold_hours if threshold_hours is not None else max_age_hours()

    rows = _read_sync_meta(resolved_path)

    if not rows:
        # No usable local cache. Offline mode is a danger state — we cannot
        # reach the live APIs and have nothing cached.
        if offline:
            return VulnDataFreshness(
                mode="offline",
                sources=[],
                stale=True,
                danger=True,
                max_age_hours=threshold,
            )
        return VulnDataFreshness(
            mode="live",
            sources=list(_LIVE_SOURCES),
            stale=False,
            danger=False,
            max_age_hours=threshold,
        )

    # Defer to intel_lookup for the canonical id→label map so freshness labels
    # never drift from the advisory-source catalog.
    try:
        from agent_bom.intel_lookup import sync_meta_source_label as _label
    except Exception:

        def _label(source_id: str) -> str:
            return _SOURCE_LABELS.get(source_id, source_id.upper())

    present = {r[0] for r in rows}
    sources: list[str] = []
    for src in (*_PRIMARY_SOURCE_LABELS, *_ENRICHMENT_SOURCE_LABELS):
        if src in present:
            sources.append(_label(src))
    # Surface any unrecognized synced source too, label-cased.
    for src in sorted(present):
        if src not in _SOURCE_LABELS:
            sources.append(_label(src))

    record_count = sum(count for _src, _ts, count in rows)

    oldest: datetime | None = None
    for _src, ts, _count in rows:
        dt = _parse_ts(ts)
        if dt is None:
            continue
        if oldest is None or dt < oldest:
            oldest = dt

    if oldest is None:
        # Cache exists but no parseable sync timestamp — treat as stale.
        return VulnDataFreshness(
            mode="offline" if offline else "local",
            sources=sources,
            last_updated=None,
            age_hours=None,
            record_count=record_count,
            stale=True,
            danger=offline,
            max_age_hours=threshold,
        )

    age_seconds = max(0.0, (reference - oldest).total_seconds())
    age_hours = int(age_seconds // 3600)
    stale = age_hours >= threshold
    danger = age_hours >= STALE_DANGER_HOURS or offline and stale

    return VulnDataFreshness(
        mode="offline" if offline else "local",
        sources=sources,
        last_updated=oldest.isoformat(),
        age_hours=age_hours,
        record_count=record_count,
        stale=stale,
        danger=danger,
        max_age_hours=threshold,
    )


def should_refresh(
    freshness: VulnDataFreshness,
    *,
    offline: bool = False,
) -> bool:
    """Decide whether to kick a network refresh of the local cache.

    Idempotent and threshold-respecting: returns ``False`` once the cache is
    within the freshness window, so repeated checks in one run don't thrash.

    Never returns ``True`` in offline / airgapped mode — those callers must use
    whatever cache exists and skip the network entirely.
    """
    if offline or offline_env():
        return False
    if freshness.mode == "offline":
        return False
    # Missing cache (live mode) or stale local cache → refresh.
    if freshness.mode == "live":
        return True
    return freshness.stale


def freshness_note(freshness: VulnDataFreshness) -> dict:
    """Compact freshness note for embedding in JSON report metadata."""
    return freshness.to_dict()
