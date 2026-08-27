"""Shared runtime audit-delivery foundation contracts.

The stdio proxy remains a compatibility surface, while the implementation is
owned by ``agent_bom.runtime`` so the HTTP gateway can reuse the same bounded
backlog, retry, and health semantics in the next delivery slice.
"""

from __future__ import annotations

import json
import os
import stat
import threading
import time
from pathlib import Path

import pytest

from agent_bom.proxy import AuditDeliveryController as ProxyAuditDeliveryController
from agent_bom.proxy import AuditSpilloverStore as ProxyAuditSpilloverStore
from agent_bom.runtime.audit_delivery import (
    AuditDeliveryController,
    AuditDeliveryState,
    AuditSpilloverStore,
    audit_delivery_paths,
)


def _store(tmp_path: Path, *, spill_bytes: int = 4096, dlq_bytes: int = 4096) -> AuditSpilloverStore:
    return AuditSpilloverStore(
        spill_path=tmp_path / "audit.spill.jsonl",
        dlq_path=tmp_path / "audit.dlq.jsonl",
        max_spillover_bytes=spill_bytes,
        max_dlq_bytes=dlq_bytes,
    )


def test_proxy_exports_the_shared_delivery_primitives_without_behavioral_fork() -> None:
    assert ProxyAuditDeliveryController is AuditDeliveryController
    assert ProxyAuditSpilloverStore is AuditSpilloverStore

    controller = ProxyAuditDeliveryController(
        base_interval_seconds=10,
        max_backoff_seconds=60,
        breaker_failure_threshold=3,
        breaker_cooldown_seconds=30,
    )
    controller.record_failure(now=100.0)
    controller.record_failure(now=101.0)
    controller.record_failure(now=102.0)

    assert controller.is_circuit_open(now=102.0) is True
    assert controller.current_backoff_seconds(now=102.0) == 30
    controller.record_success()
    assert controller.current_backoff_seconds(now=102.0) == 10


def test_persisted_backlog_is_bounded_private_and_secret_safe(tmp_path: Path) -> None:
    store = _store(tmp_path)
    opaque = "sk-" + "audit-delivery-example-value-1234567890"
    event = {
        "event_id": "gw_event_1",
        "api_token": opaque,
        "headers": {"authorization": f"Bearer {opaque}"},
        "safe": "profile_revoked",
    }

    assert store.append_events([event]) == "spillover"

    persisted = store.spill_path.read_text(encoding="utf-8")
    assert opaque not in persisted
    assert "Bearer" not in persisted
    assert json.loads(persisted)["event_id"] == "gw_event_1"
    assert json.loads(persisted)["safe"] == "profile_revoked"
    assert stat.S_IMODE(store.spill_path.stat().st_mode) == 0o600
    assert store.spillover_size_bytes() <= store.max_spillover_bytes

    dlq_store = _store(tmp_path / "dlq", spill_bytes=1)
    assert dlq_store.append_events([event]) == "dlq"
    dlq_persisted = dlq_store.dlq_path.read_text(encoding="utf-8")
    assert opaque not in dlq_persisted
    assert "Bearer" not in dlq_persisted
    assert stat.S_IMODE(dlq_store.dlq_path.stat().st_mode) == 0o600
    assert dlq_store.dlq_size_bytes() <= dlq_store.dlq_limit_bytes


def test_backlog_survives_a_new_delivery_state_and_loads_sanitized_events(tmp_path: Path) -> None:
    first_store = _store(tmp_path)
    assert first_store.append_events([{"event_id": "gw_restart_1", "decision": "deny"}]) == "spillover"

    restarted_store = _store(tmp_path)
    restarted = AuditDeliveryState(
        controller=AuditDeliveryController(base_interval_seconds=5),
        store=restarted_store,
    )

    assert restarted_store.read_spillover() == [{"decision": "deny", "event_id": "gw_restart_1"}]
    assert restarted.health(buffer_bytes=0)["backlog_bytes"] == restarted_store.spillover_size_bytes()


def test_dlq_is_bounded_and_reports_drop_without_persisting_payload(tmp_path: Path) -> None:
    store = _store(tmp_path, spill_bytes=1, dlq_bytes=1)

    assert store.append_events([{"event_id": "too-large", "payload": "x" * 100}]) == "dropped"
    assert store.spillover_size_bytes() == 0
    assert store.dlq_size_bytes() == 0
    assert store.dropped_events == 1


def test_health_contains_only_sanitized_scalar_backlog_state(tmp_path: Path) -> None:
    secret_in_path = "do-not-surface-this-token"
    store = AuditSpilloverStore(
        spill_path=tmp_path / secret_in_path / "spill.jsonl",
        dlq_path=tmp_path / secret_in_path / "dlq.jsonl",
        max_spillover_bytes=4096,
        max_dlq_bytes=4096,
    )
    store.append_events([{"event_id": "gw_health_1", "token": secret_in_path}])
    controller = AuditDeliveryController(base_interval_seconds=10)
    controller.record_failure(now=100.0)
    state = AuditDeliveryState(controller=controller, store=store)

    health = state.health(buffer_bytes=7, now=100.0)

    assert set(health) == {
        "status",
        "buffer_bytes",
        "spillover_bytes",
        "dlq_bytes",
        "backlog_bytes",
        "consecutive_failures",
        "backoff_seconds",
        "circuit_open",
        "dropped_events",
    }
    assert health["status"] == "degraded"
    assert health["backlog_bytes"] == 7 + store.spillover_size_bytes()
    assert secret_in_path not in json.dumps(health)


def test_claim_ack_does_not_delete_an_event_appended_during_delivery(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.append_events([{"event_id": "before-send"}])

    claim = store.claim_spillover()
    assert claim is not None
    assert [event["event_id"] for event in claim.events] == ["before-send"]

    store.append_events([{"event_id": "during-send"}])
    store.acknowledge_claim(claim)

    assert store.read_spillover() == [{"event_id": "during-send"}]


def test_failed_claim_restore_precedes_events_appended_during_delivery(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.append_events([{"event_id": "before-send"}])
    claim = store.claim_spillover()
    assert claim is not None

    store.append_events([{"event_id": "during-send"}])
    store.restore_claim(claim)

    assert store.read_spillover() == [
        {"event_id": "before-send"},
        {"event_id": "during-send"},
    ]


def test_failed_claim_restore_persists_in_memory_snapshot_before_new_appends(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.append_events([{"event_id": "spilled-before-send"}])
    claim = store.claim_spillover()
    assert claim is not None

    store.append_events([{"event_id": "spilled-during-send"}])
    assert store.restore_claim(claim, [{"event_id": "memory-before-send"}]) == "spillover"

    assert store.read_spillover() == [
        {"event_id": "spilled-before-send"},
        {"event_id": "memory-before-send"},
        {"event_id": "spilled-during-send"},
    ]


def test_second_store_does_not_recover_a_live_claim(tmp_path: Path) -> None:
    first = _store(tmp_path)
    second = _store(tmp_path)
    first.append_events([{"event_id": "first-claim"}])
    first_claim = first.claim_spillover()
    assert first_claim is not None

    second.append_events([{"event_id": "second-claim"}])
    second_claim = second.claim_spillover()
    assert second_claim is not None

    assert [event["event_id"] for event in first_claim.events] == ["first-claim"]
    assert [event["event_id"] for event in second_claim.events] == ["second-claim"]
    first.acknowledge_claim(first_claim)
    second.restore_claim(second_claim)
    assert second.read_spillover() == [{"event_id": "second-claim"}]


def test_restart_load_recovers_an_unregistered_claim(tmp_path: Path) -> None:
    store = _store(tmp_path)
    store.append_events([{"event_id": "crash-recovery"}])
    orphan = store.spill_path.with_name(
        f"{store.spill_path.name}.claim-{time.time_ns():020d}-{os.getpid()}-orphan"
    )
    store.spill_path.rename(orphan)

    restarted = _store(tmp_path)
    assert restarted.read_spillover() == [{"event_id": "crash-recovery"}]
    assert not orphan.exists()


def test_two_store_instances_share_one_bound_lock(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    spill = tmp_path / "shared.spill.jsonl"
    dlq = tmp_path / "shared.dlq.jsonl"
    first = AuditSpilloverStore(spill, dlq, max_spillover_bytes=90, max_dlq_bytes=90)
    second = AuditSpilloverStore(spill, dlq, max_spillover_bytes=90, max_dlq_bytes=90)
    original_size = AuditSpilloverStore._size_bytes
    def synchronized_size(path: Path) -> int:
        size = original_size(path)
        if path == spill:
            # Release the GIL between the bound check and append. Independent
            # per-instance locks then deterministically observe the same size;
            # the shared lock must serialize this whole critical section.
            time.sleep(0.05)
        return size

    monkeypatch.setattr(AuditSpilloverStore, "_size_bytes", staticmethod(synchronized_size))
    results: list[str] = []

    def append(store: AuditSpilloverStore, event_id: str) -> None:
        results.append(store.append_events([{"event_id": event_id, "padding": "x" * 30}]))

    threads = [
        threading.Thread(target=append, args=(first, "event-a")),
        threading.Thread(target=append, args=(second, "event-b")),
    ]
    for thread in threads:
        thread.start()
    for thread in threads:
        thread.join(timeout=3)

    assert all(not thread.is_alive() for thread in threads)
    assert first.spillover_size_bytes() <= first.max_spillover_bytes
    assert first.dlq_size_bytes() <= first.dlq_limit_bytes
    assert sorted(results) == ["dlq", "spillover"]


def test_direct_symlink_parent_is_rejected(tmp_path: Path) -> None:
    real_parent = tmp_path / "real"
    real_parent.mkdir()
    symlink_parent = tmp_path / "linked"
    symlink_parent.symlink_to(real_parent, target_is_directory=True)
    store = AuditSpilloverStore(
        spill_path=symlink_parent / "spill.jsonl",
        dlq_path=symlink_parent / "dlq.jsonl",
        max_spillover_bytes=4096,
        max_dlq_bytes=4096,
    )

    with pytest.raises(ValueError, match="parent directory must not be a symlink"):
        store.append_events([{"event_id": "symlink-parent"}])


def test_state_dir_paths_are_stable_and_do_not_embed_identity(tmp_path: Path) -> None:
    identity = "https://user:secret@control.example.test/default/proxy-a"

    first = audit_delivery_paths(tmp_path, surface="proxy", identity=identity)
    second = audit_delivery_paths(tmp_path, surface="proxy", identity=identity)

    assert first == second
    assert first.spill_path.parent == tmp_path / "runtime-audit"
    assert identity not in str(first.spill_path)
    assert "secret" not in str(first.spill_path)
