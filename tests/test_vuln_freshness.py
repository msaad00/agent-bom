"""Tests for the vuln-data freshness indicator and refresh-decision helpers."""

from __future__ import annotations

import sqlite3
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest

from agent_bom.vuln_freshness import (
    DEFAULT_MAX_AGE_HOURS,
    STALE_DANGER_HOURS,
    VulnDataFreshness,
    compute_freshness,
    max_age_hours,
    should_refresh,
)

_NOW = datetime(2026, 6, 25, 12, 0, 0, tzinfo=timezone.utc)


def _make_db(tmp_path: Path, *, synced_at: datetime | None, sources=("osv", "ghsa"), counts=1000) -> Path:
    """Build a minimal local cache with a sync_meta table for freshness probes."""
    db_path = tmp_path / "vulns.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE sync_meta (source TEXT PRIMARY KEY, last_synced TEXT, record_count INTEGER DEFAULT 0)")
    for src in sources:
        ts = synced_at.isoformat() if synced_at else None
        conn.execute("INSERT INTO sync_meta (source, last_synced, record_count) VALUES (?, ?, ?)", (src, ts, counts))
    conn.commit()
    conn.close()
    return db_path


# ── compute_freshness ─────────────────────────────────────────────────────


def test_missing_cache_is_live_mode_not_stale(tmp_path):
    """No cache → live mode (OSV/GHSA/NVD), with an actionable summary line."""
    fresh = compute_freshness(db_path=tmp_path / "absent.db", now=_NOW, offline=False)
    assert fresh.mode == "live"
    assert fresh.sources == ["OSV", "GHSA", "NVD"]
    assert fresh.stale is False
    assert fresh.record_count == 0
    assert "no local cache" in fresh.summary_line()
    assert "db update" in fresh.summary_line()


def test_missing_cache_offline_is_danger(tmp_path):
    """No cache + offline → danger state (nothing usable, no live fallback)."""
    fresh = compute_freshness(db_path=tmp_path / "absent.db", now=_NOW, offline=True)
    assert fresh.mode == "offline"
    assert fresh.stale is True
    assert fresh.danger is True


def test_fresh_cache_not_stale(tmp_path):
    """A cache synced an hour ago is local, not stale, with parsed sources."""
    db = _make_db(tmp_path, synced_at=_NOW - timedelta(hours=1))
    fresh = compute_freshness(db_path=db, now=_NOW)
    assert fresh.mode == "local"
    assert fresh.sources == ["OSV", "GHSA"]
    assert fresh.age_hours == 1
    assert fresh.stale is False
    assert fresh.danger is False
    assert fresh.record_count == 2000


def test_stale_cache_past_threshold(tmp_path):
    """A cache older than the 24h default is flagged stale (but not danger)."""
    db = _make_db(tmp_path, synced_at=_NOW - timedelta(hours=30))
    fresh = compute_freshness(db_path=db, now=_NOW)
    assert fresh.stale is True
    assert fresh.danger is False
    assert fresh.age_hours == 30
    assert "daily freshness" in fresh.summary_line()


def test_danger_cache_past_seven_days(tmp_path):
    """A cache older than 7 days is danger — warns recent CVEs may be missed."""
    db = _make_db(tmp_path, synced_at=_NOW - timedelta(hours=STALE_DANGER_HOURS + 5))
    fresh = compute_freshness(db_path=db, now=_NOW)
    assert fresh.stale is True
    assert fresh.danger is True
    assert "miss recent CVEs" in fresh.summary_line()


def test_age_uses_oldest_source(tmp_path):
    """Age is computed from the OLDEST synced source, not the newest."""
    db_path = tmp_path / "vulns.db"
    conn = sqlite3.connect(str(db_path))
    conn.execute("CREATE TABLE sync_meta (source TEXT PRIMARY KEY, last_synced TEXT, record_count INTEGER DEFAULT 0)")
    conn.execute("INSERT INTO sync_meta VALUES (?, ?, ?)", ("osv", (_NOW - timedelta(hours=2)).isoformat(), 10))
    conn.execute("INSERT INTO sync_meta VALUES (?, ?, ?)", ("ghsa", (_NOW - timedelta(hours=50)).isoformat(), 20))
    conn.commit()
    conn.close()
    fresh = compute_freshness(db_path=db_path, now=_NOW)
    assert fresh.age_hours == 50  # oldest wins
    assert fresh.stale is True


def test_offline_with_cache_uses_cache_no_crash(tmp_path):
    """Offline + a present cache → offline mode, network never consulted."""
    db = _make_db(tmp_path, synced_at=_NOW - timedelta(hours=2))
    fresh = compute_freshness(db_path=db, now=_NOW, offline=True)
    assert fresh.mode == "offline"
    assert fresh.record_count == 2000
    assert "offline" in fresh.summary_line()


def test_corrupt_db_degrades_to_live(tmp_path):
    """A non-SQLite file at the cache path degrades to live, never crashes."""
    bad = tmp_path / "vulns.db"
    bad.write_text("not a database")
    fresh = compute_freshness(db_path=bad, now=_NOW, offline=False)
    assert fresh.mode == "live"


def test_to_dict_round_trip():
    f = VulnDataFreshness(mode="local", sources=["OSV"], age_hours=49, stale=True)
    d = f.to_dict()
    assert d["mode"] == "local"
    assert d["sources"] == ["OSV"]
    assert d["age_hours"] == 49
    assert d["age_days"] == 2
    assert d["stale"] is True


# ── should_refresh ────────────────────────────────────────────────────────


def test_should_refresh_on_missing_cache():
    fresh = VulnDataFreshness(mode="live")
    assert should_refresh(fresh, offline=False) is True


def test_should_refresh_on_stale_cache():
    fresh = VulnDataFreshness(mode="local", stale=True)
    assert should_refresh(fresh, offline=False) is True


def test_should_not_refresh_when_fresh():
    fresh = VulnDataFreshness(mode="local", stale=False)
    assert should_refresh(fresh, offline=False) is False


def test_should_never_refresh_when_offline():
    """Idempotent + airgap-safe: offline never refreshes, regardless of staleness."""
    fresh = VulnDataFreshness(mode="live", stale=True)
    assert should_refresh(fresh, offline=True) is False
    offline_snapshot = VulnDataFreshness(mode="offline", stale=True, danger=True)
    assert should_refresh(offline_snapshot, offline=False) is False


def test_should_refresh_respects_env_offline(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_VULN_DB_OFFLINE", "1")
    fresh = VulnDataFreshness(mode="live", stale=True)
    assert should_refresh(fresh, offline=False) is False


# ── max_age_hours threshold ───────────────────────────────────────────────


def test_max_age_hours_default(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", raising=False)
    assert max_age_hours() == DEFAULT_MAX_AGE_HOURS


def test_max_age_hours_custom(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", "6")
    assert max_age_hours() == 6


def test_max_age_hours_invalid_falls_back(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", "garbage")
    assert max_age_hours() == DEFAULT_MAX_AGE_HOURS
    monkeypatch.setenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", "-5")
    assert max_age_hours() == DEFAULT_MAX_AGE_HOURS


def test_custom_threshold_marks_stale_sooner(tmp_path, monkeypatch):
    """A 6h threshold marks a 7h-old cache stale; the 24h default would not."""
    db = _make_db(tmp_path, synced_at=_NOW - timedelta(hours=7))
    monkeypatch.setenv("AGENT_BOM_VULN_DB_MAX_AGE_HOURS", "6")
    fresh = compute_freshness(db_path=db, now=_NOW)
    assert fresh.max_age_hours == 6
    assert fresh.stale is True


def test_enrichment_cache_age_hours_injected_now(tmp_path, monkeypatch):
    """enrichment_cache_age_hours uses the injected now and never reads the clock."""
    from agent_bom import enrichment

    cache = tmp_path / "kev_cache.json"
    cache.write_text("{}")
    monkeypatch.setattr(enrichment, "_KEV_CACHE_FILE", cache)
    import os

    old = _NOW - timedelta(hours=10)
    os.utime(cache, (old.timestamp(), old.timestamp()))
    age = enrichment.enrichment_cache_age_hours(now=_NOW)
    assert age == 10


def test_enrichment_cache_age_missing_returns_none(tmp_path, monkeypatch):
    from agent_bom import enrichment

    monkeypatch.setattr(enrichment, "_KEV_CACHE_FILE", tmp_path / "absent.json")
    assert enrichment.enrichment_cache_age_hours(now=_NOW) is None


if __name__ == "__main__":
    pytest.main([__file__, "-q"])
