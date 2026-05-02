"""In-memory firewall decision tally + recent-events ring buffer.

Backs the runtime-tab dashboard overlay (#982 PR 4). Populated when
`ingest_proxy_audit` sees a `gateway.firewall_decision` event; queried by
the `/v1/firewall/stats` endpoint and surfaced in `/v1/gateway/stats` as a
`firewall_runtime` block.

Design:
- per-tenant counters (total / allow / warn / deny effective decisions)
- per-tenant per-pair counters keyed by (source_agent, target_agent)
- per-tenant ring buffer of the most recent N decisions for the dashboard
  "recent denials" list

The store is in-memory and is rebuilt on process restart. That is a
deliberate trade-off — the firewall decisions themselves are persisted
through the existing /v1/proxy/audit -> analytics_store pipeline (the
HMAC-chained audit table is the source of truth). This store is a
hot-cache for the dashboard so the UI does not have to scan the entire
analytics history on every poll.
"""

from __future__ import annotations

import threading
from collections import OrderedDict, deque
from dataclasses import dataclass, field
from typing import Any


@dataclass
class _PairTally:
    allow: int = 0
    warn: int = 0
    deny: int = 0


@dataclass
class _TenantState:
    total: int = 0
    allow: int = 0
    warn: int = 0
    deny: int = 0
    last_seen_ts: float | None = None
    pairs: OrderedDict[tuple[str, str], _PairTally] = field(default_factory=OrderedDict)
    recent: deque = field(default_factory=lambda: deque(maxlen=200))


@dataclass(frozen=True)
class FirewallDecisionRecord:
    timestamp: float
    source_agent: str
    target_agent: str
    decision: str  # raw policy decision
    effective_decision: str  # after dry_run downgrade
    matched_rule: dict[str, Any] | None
    enforcement_mode: str | None


class FirewallDecisionStore:
    """Thread-safe in-memory tally + ring buffer.

    All public methods are O(1) for ingest and bounded by tenant count for
    aggregation. Safe to call from sync request handlers.
    """

    def __init__(self, *, recent_capacity: int = 200, max_pairs_per_tenant: int = 1024) -> None:
        self._lock = threading.RLock()
        self._tenants: dict[str, _TenantState] = {}
        self._recent_capacity = max(1, recent_capacity)
        self._max_pairs = max(1, max_pairs_per_tenant)

    def record(self, *, tenant_id: str, event: dict[str, Any]) -> None:
        """Ingest a `gateway.firewall_decision` event.

        Silently ignores events that are not firewall decisions or are missing
        required fields, so callers can pass any audit alert without filtering.
        """
        action = event.get("action")
        if action != "gateway.firewall_decision":
            return
        source_agent = event.get("source_agent")
        target_agent = event.get("target_agent")
        decision = event.get("decision")
        effective = event.get("effective_decision", decision)
        if not isinstance(source_agent, str) or not isinstance(target_agent, str):
            return
        if not isinstance(decision, str) or not isinstance(effective, str):
            return

        ts = event.get("timestamp")
        try:
            ts_float = float(ts) if ts is not None else 0.0
        except (TypeError, ValueError):
            ts_float = 0.0

        record = FirewallDecisionRecord(
            timestamp=ts_float,
            source_agent=source_agent,
            target_agent=target_agent,
            decision=decision,
            effective_decision=effective,
            matched_rule=event.get("matched_rule") if isinstance(event.get("matched_rule"), dict) else None,
            enforcement_mode=event.get("enforcement_mode") if isinstance(event.get("enforcement_mode"), str) else None,
        )

        with self._lock:
            state = self._tenants.setdefault(tenant_id, _TenantState(recent=deque(maxlen=self._recent_capacity)))
            state.total += 1
            state.last_seen_ts = ts_float or state.last_seen_ts
            if effective == "allow":
                state.allow += 1
            elif effective == "warn":
                state.warn += 1
            elif effective == "deny":
                state.deny += 1
            pair_key = (source_agent, target_agent)
            tally = state.pairs.get(pair_key)
            if tally is None:
                tally = _PairTally()
                state.pairs[pair_key] = tally
                if len(state.pairs) > self._max_pairs:
                    state.pairs.popitem(last=False)
            else:
                state.pairs.move_to_end(pair_key)
            if effective == "allow":
                tally.allow += 1
            elif effective == "warn":
                tally.warn += 1
            elif effective == "deny":
                tally.deny += 1
            state.recent.append(record)

    def stats(self, *, tenant_id: str, recent_limit: int = 50, top_pairs: int = 10) -> dict[str, Any]:
        """Aggregate decisions for a tenant.

        Returns the canonical shape consumed by `/v1/firewall/stats` and
        embedded under `/v1/gateway/stats.firewall_runtime`.
        """
        with self._lock:
            state = self._tenants.get(tenant_id)
            if state is None:
                return _empty_stats()
            recent_slice = list(state.recent)[-max(0, recent_limit) :]
            pair_items = sorted(
                state.pairs.items(),
                key=lambda kv: (kv[1].deny, kv[1].warn, kv[1].allow),
                reverse=True,
            )[:top_pairs]
            top_pairs_payload = [
                {
                    "source_agent": src,
                    "target_agent": tgt,
                    "allow": tally.allow,
                    "warn": tally.warn,
                    "deny": tally.deny,
                }
                for (src, tgt), tally in pair_items
            ]
            return {
                "total_decisions": state.total,
                "allow": state.allow,
                "warn": state.warn,
                "deny": state.deny,
                "last_seen_ts": state.last_seen_ts,
                "top_pairs": top_pairs_payload,
                "recent": [_record_to_payload(r) for r in reversed(recent_slice)],
            }

    def reset(self, *, tenant_id: str | None = None) -> None:
        """Test/teardown helper — drop all state for one tenant or globally."""
        with self._lock:
            if tenant_id is None:
                self._tenants.clear()
            else:
                self._tenants.pop(tenant_id, None)


def _empty_stats() -> dict[str, Any]:
    return {
        "total_decisions": 0,
        "allow": 0,
        "warn": 0,
        "deny": 0,
        "last_seen_ts": None,
        "top_pairs": [],
        "recent": [],
    }


def _record_to_payload(record: FirewallDecisionRecord) -> dict[str, Any]:
    return {
        "timestamp": record.timestamp,
        "source_agent": record.source_agent,
        "target_agent": record.target_agent,
        "decision": record.decision,
        "effective_decision": record.effective_decision,
        "matched_rule": record.matched_rule,
        "enforcement_mode": record.enforcement_mode,
    }


__all__ = [
    "FirewallDecisionRecord",
    "FirewallDecisionStore",
]
