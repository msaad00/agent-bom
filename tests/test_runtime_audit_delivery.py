"""Shared runtime audit-delivery foundation contracts.

The stdio proxy remains a compatibility surface, while the implementation is
owned by ``agent_bom.runtime`` so the HTTP gateway can reuse the same bounded
backlog, retry, and health semantics in the next delivery slice.
"""

from __future__ import annotations

import json
import stat
from pathlib import Path

from agent_bom.proxy import AuditDeliveryController as ProxyAuditDeliveryController
from agent_bom.proxy import AuditSpilloverStore as ProxyAuditSpilloverStore
from agent_bom.runtime.audit_delivery import (
    AuditDeliveryController,
    AuditDeliveryState,
    AuditSpilloverStore,
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
