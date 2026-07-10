"""Phase 0 hardware-backed device identity (#1469).

Covers the deterministic device fingerprint derived from attestation evidence,
its preference over hostname-derived source ids in ``canonical_agent_id``, and
the fleet-store column + idempotent backfill.
"""

from __future__ import annotations

import sqlite3
import tempfile
from pathlib import Path

from agent_bom.api.fleet_store import FleetAgent, SQLiteFleetStore
from agent_bom.canonical_ids import canonical_agent_id
from agent_bom.hardware_evidence import device_fingerprint


def _host(**overrides) -> dict:
    host = {
        "hostname": "gpu-node-01",
        "vendor": "Acme",
        "model": "PowerEdge R760",
        "serial": "ABC123",
        "attestation": {"source": "tpm-quote", "signed": True, "verified": True},
    }
    host.update(overrides)
    return host


# ── device_fingerprint ────────────────────────────────────────────────────────


def test_fingerprint_deterministic_same_evidence():
    assert device_fingerprint(_host()) == device_fingerprint(_host())


def test_fingerprint_is_hashed_and_hides_serial():
    fp = device_fingerprint(_host())
    assert fp is not None
    assert fp.startswith("sha256:")
    assert "ABC123" not in fp


def test_different_serial_different_fingerprint():
    assert device_fingerprint(_host(serial="ABC123")) != device_fingerprint(_host(serial="XYZ789"))


def test_ek_pub_preferred_over_serial():
    with_ek = _host(attestation={"source": "tpm-quote", "ek_pub": "EK-PUBLIC-KEY-BLOB"})
    # EK pub anchors identity, so changing the serial must not change the fingerprint.
    assert device_fingerprint(with_ek) == device_fingerprint({**with_ek, "serial": "different"})
    # ... and it differs from the serial-only fingerprint.
    assert device_fingerprint(with_ek) != device_fingerprint(_host())


def test_different_ek_pub_different_fingerprint():
    a = _host(attestation={"ek_pub": "EK-A"})
    b = _host(attestation={"ek_pub": "EK-B"})
    assert device_fingerprint(a) != device_fingerprint(b)


def test_no_evidence_returns_none():
    assert device_fingerprint({"hostname": "h1"}) is None
    assert device_fingerprint({"hostname": "h1", "attestation": {"signed": True}}) is None
    assert device_fingerprint("not-a-dict") is None  # type: ignore[arg-type]


def test_serial_used_when_attestation_lacks_anchor():
    host = {"hostname": "h1", "serial": "S-1", "attestation": {"signed": True, "verified": True}}
    fp = device_fingerprint(host)
    assert fp is not None and fp.startswith("sha256:")


# ── canonical_agent_id preference ──────────────────────────────────────────────


def test_canonical_id_prefers_fingerprint_over_source():
    fp = device_fingerprint(_host())
    with_fp = canonical_agent_id("claude-desktop", "agent-a", source_id="host-01", device_fingerprint=fp)
    without_fp = canonical_agent_id("claude-desktop", "agent-a", source_id="host-01")
    assert with_fp != without_fp


def test_canonical_id_no_fingerprint_no_regression():
    # Absent a fingerprint, identity is unchanged from prior behavior.
    assert canonical_agent_id("t", "n", source_id="s", device_fingerprint="") == canonical_agent_id("t", "n", source_id="s")
    assert canonical_agent_id("t", "n", device_fingerprint="") == canonical_agent_id("t", "n")


def test_canonical_id_fingerprint_deterministic():
    fp = device_fingerprint(_host())
    assert canonical_agent_id("t", "n", device_fingerprint=fp) == canonical_agent_id("t", "n", device_fingerprint=fp)


def test_fleet_agent_uses_fingerprint_for_canonical_id():
    fp = device_fingerprint(_host())
    with_fp = FleetAgent(agent_id="a1", name="n", agent_type="t", source_id="host-01", device_fingerprint=fp)
    plain = FleetAgent(agent_id="a2", name="n", agent_type="t", source_id="host-01")
    assert with_fp.canonical_id != plain.canonical_id
    assert with_fp.device_fingerprint == fp


# ── fleet store column + backfill ──────────────────────────────────────────────


def _column_value(db_path: str, agent_id: str) -> str:
    conn = sqlite3.connect(db_path)
    try:
        row = conn.execute("SELECT device_fingerprint FROM fleet_agents WHERE agent_id = ?", (agent_id,)).fetchone()
        return row[0] if row else ""
    finally:
        conn.close()


def test_store_persists_fingerprint_column():
    fp = device_fingerprint(_host())
    with tempfile.TemporaryDirectory() as d:
        db = str(Path(d) / "fleet.db")
        store = SQLiteFleetStore(db)
        store.put(FleetAgent(agent_id="a1", name="n", agent_type="t", device_fingerprint=fp))
        store.put(FleetAgent(agent_id="a2", name="n2", agent_type="t"))
        assert _column_value(db, "a1") == fp
        assert _column_value(db, "a2") == ""
        got = store.get("a1", tenant_id="default")
        assert got is not None and got.device_fingerprint == fp


def test_backfill_populates_column_from_data_idempotently():
    fp = device_fingerprint(_host())
    with tempfile.TemporaryDirectory() as d:
        db = str(Path(d) / "fleet.db")
        store = SQLiteFleetStore(db)
        agent = FleetAgent(agent_id="a1", name="n", agent_type="t", device_fingerprint=fp)
        # Simulate a legacy row: JSON carries the fingerprint but the column is stale/empty.
        store.put(agent)
        store._conn.execute("UPDATE fleet_agents SET device_fingerprint = '' WHERE agent_id = 'a1'")
        store._conn.commit()
        assert _column_value(db, "a1") == ""

        store._backfill_device_fingerprints()
        store._conn.commit()
        assert _column_value(db, "a1") == fp

        # Idempotent: a second pass is a no-op and touches no rows.
        store._backfill_device_fingerprints()
        store._conn.commit()
        assert _column_value(db, "a1") == fp


def test_backfill_leaves_evidenceless_rows_null():
    with tempfile.TemporaryDirectory() as d:
        db = str(Path(d) / "fleet.db")
        store = SQLiteFleetStore(db)
        store.put(FleetAgent(agent_id="a1", name="n", agent_type="t"))
        store._backfill_device_fingerprints()
        store._conn.commit()
        assert _column_value(db, "a1") == ""


def test_reopen_store_backfills_existing_db():
    fp = device_fingerprint(_host())
    with tempfile.TemporaryDirectory() as d:
        db = str(Path(d) / "fleet.db")
        store = SQLiteFleetStore(db)
        store.put(FleetAgent(agent_id="a1", name="n", agent_type="t", device_fingerprint=fp))
        # Blank the column to emulate a pre-migration database, then reopen.
        store._conn.execute("UPDATE fleet_agents SET device_fingerprint = '' WHERE agent_id = 'a1'")
        store._conn.commit()

        reopened = SQLiteFleetStore(db)
        assert _column_value(db, "a1") == fp
        got = reopened.get("a1", tenant_id="default")
        assert got is not None and got.device_fingerprint == fp
