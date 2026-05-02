"""Async firewall client used by the MCP proxy fast-path (#982 PR 3).

The MCP proxy sits on the hot path of every JSON-RPC message between an MCP
host and an MCP server. Calling the gateway's `/v1/firewall/check` over HTTP
on every message would blow the latency budget. This client adds:

- a per-process TTL cache keyed by (source, target, sorted source_roles,
  sorted target_roles) so repeat decisions in a typical session are local,
- a configurable `fail_mode` (`open` / `closed`) so operators choose between
  availability and safety when the gateway is unreachable,
- a local `AgentFirewallPolicy` fallback so air-gapped / single-host installs
  can run without a control plane.

The gateway stays authoritative for the policy itself — this client just
caches answers and degrades gracefully under failure.
"""

from __future__ import annotations

import logging
import time
from collections import OrderedDict
from dataclasses import dataclass
from enum import Enum
from typing import Any

from agent_bom.firewall import (
    AgentFirewallPolicy,
    FirewallDecision,
    FirewallEvaluation,
    FirewallRule,
)
from agent_bom.firewall import (
    evaluate as evaluate_firewall_policy,
)

logger = logging.getLogger(__name__)


class FirewallFailMode(str, Enum):
    """Behaviour when the gateway is unreachable AND no local policy is set."""

    OPEN = "open"
    """Default-allow on gateway error. Maximises availability."""

    CLOSED = "closed"
    """Default-deny on gateway error. Maximises safety."""


@dataclass(frozen=True)
class _CacheEntry:
    evaluation: FirewallEvaluation
    expires_at: float


class FirewallClient:
    """Async client used by the MCP proxy to consult the gateway firewall.

    Either `gateway_url` or `local_policy` must be provided. When both are
    set, the gateway is consulted first and the local policy is the fallback
    on gateway error / timeout.
    """

    def __init__(
        self,
        *,
        gateway_url: str | None = None,
        bearer_token: str | None = None,
        cache_ttl_seconds: float = 60.0,
        cache_max_entries: int = 1024,
        fail_mode: FirewallFailMode = FirewallFailMode.OPEN,
        local_policy: AgentFirewallPolicy | None = None,
        request_timeout_seconds: float = 2.0,
        http_client: Any | None = None,
        clock: Any = None,
    ) -> None:
        if gateway_url is None and local_policy is None:
            raise ValueError("FirewallClient needs at least one of gateway_url or local_policy")
        self._gateway_url = gateway_url.rstrip("/") if gateway_url else None
        self._bearer_token = bearer_token
        self._cache_ttl_seconds = max(0.0, cache_ttl_seconds)
        self._cache_max_entries = max(1, cache_max_entries)
        self._fail_mode = fail_mode
        self._local_policy = local_policy
        self._timeout = max(0.1, request_timeout_seconds)
        self._cache: OrderedDict[tuple[Any, ...], _CacheEntry] = OrderedDict()
        self._http_client = http_client
        self._owns_http_client = http_client is None
        self._clock = clock or time.monotonic

    async def aclose(self) -> None:
        if self._owns_http_client and self._http_client is not None:
            await self._http_client.aclose()
            self._http_client = None

    async def decision(
        self,
        *,
        source_agent: str,
        target_agent: str,
        source_roles: frozenset[str] | set[str] | tuple[str, ...] = frozenset(),
        target_roles: frozenset[str] | set[str] | tuple[str, ...] = frozenset(),
    ) -> FirewallEvaluation:
        """Return the firewall decision for a source -> target pair."""

        key = self._cache_key(source_agent, target_agent, source_roles, target_roles)
        cached = self._lookup(key)
        if cached is not None:
            return cached

        if self._gateway_url is not None:
            try:
                evaluation = await self._call_gateway(source_agent, target_agent, source_roles, target_roles)
                self._store(key, evaluation)
                return evaluation
            except Exception as exc:  # noqa: BLE001 — any network/timeout/etc. lands in the fallback
                logger.warning(
                    "firewall_client gateway call failed (source=%s, target=%s): %s",
                    source_agent,
                    target_agent,
                    exc,
                )

        evaluation = self._fallback_decision(source_agent, target_agent, source_roles, target_roles)
        self._store(key, evaluation)
        return evaluation

    def invalidate_cache(self) -> None:
        """Drop all cached decisions (call when the policy file mtime changes)."""
        self._cache.clear()

    def _cache_key(
        self,
        source: str,
        target: str,
        source_roles: frozenset[str] | set[str] | tuple[str, ...],
        target_roles: frozenset[str] | set[str] | tuple[str, ...],
    ) -> tuple[Any, ...]:
        return (source, target, tuple(sorted(source_roles)), tuple(sorted(target_roles)))

    def _lookup(self, key: tuple[Any, ...]) -> FirewallEvaluation | None:
        entry = self._cache.get(key)
        if entry is None:
            return None
        if entry.expires_at <= self._clock():
            self._cache.pop(key, None)
            return None
        # Move to end → simple LRU.
        self._cache.move_to_end(key)
        return entry.evaluation

    def _store(self, key: tuple[Any, ...], evaluation: FirewallEvaluation) -> None:
        expires_at = self._clock() + self._cache_ttl_seconds
        self._cache[key] = _CacheEntry(evaluation=evaluation, expires_at=expires_at)
        self._cache.move_to_end(key)
        while len(self._cache) > self._cache_max_entries:
            self._cache.popitem(last=False)

    async def _call_gateway(
        self,
        source: str,
        target: str,
        source_roles: frozenset[str] | set[str] | tuple[str, ...],
        target_roles: frozenset[str] | set[str] | tuple[str, ...],
    ) -> FirewallEvaluation:
        client = await self._client()
        headers: dict[str, str] = {"content-type": "application/json"}
        if self._bearer_token:
            headers["authorization"] = f"Bearer {self._bearer_token}"
        body = {
            "source_agent": source,
            "target_agent": target,
            "source_roles": sorted(source_roles),
            "target_roles": sorted(target_roles),
        }
        response = await client.post(
            f"{self._gateway_url}/v1/firewall/check",
            json=body,
            headers=headers,
            timeout=self._timeout,
        )
        response.raise_for_status()
        payload = response.json()
        return _evaluation_from_payload(payload)

    async def _client(self) -> Any:
        if self._http_client is None:
            import httpx

            self._http_client = httpx.AsyncClient(
                timeout=self._timeout,
                limits=httpx.Limits(max_connections=8, max_keepalive_connections=4),
            )
        return self._http_client

    def _fallback_decision(
        self,
        source: str,
        target: str,
        source_roles: frozenset[str] | set[str] | tuple[str, ...],
        target_roles: frozenset[str] | set[str] | tuple[str, ...],
    ) -> FirewallEvaluation:
        if self._local_policy is not None:
            return evaluate_firewall_policy(
                self._local_policy,
                source_agent=source,
                target_agent=target,
                source_roles=set(source_roles),
                target_roles=set(target_roles),
            )
        decision = FirewallDecision.DENY if self._fail_mode == FirewallFailMode.CLOSED else FirewallDecision.ALLOW
        return FirewallEvaluation(
            decision=decision,
            matched_rule=None,
            effective_decision=decision,
        )


def _evaluation_from_payload(payload: dict[str, Any]) -> FirewallEvaluation:
    """Decode a gateway /v1/firewall/check response into a FirewallEvaluation."""

    decision_raw = payload.get("decision")
    effective_raw = payload.get("effective_decision", decision_raw)
    if not isinstance(decision_raw, str) or not isinstance(effective_raw, str):
        raise ValueError(f"firewall response missing decision fields: {payload!r}")
    decision = FirewallDecision(decision_raw)
    effective = FirewallDecision(effective_raw)
    matched = payload.get("matched_rule")
    matched_rule: FirewallRule | None = None
    if isinstance(matched, dict):
        try:
            matched_rule = FirewallRule(
                source=str(matched["source"]),
                target=str(matched["target"]),
                decision=FirewallDecision(str(matched["decision"])),
                description=str(matched.get("description") or ""),
            )
        except (KeyError, ValueError):
            matched_rule = None
    return FirewallEvaluation(
        decision=decision,
        matched_rule=matched_rule,
        effective_decision=effective,
    )


__all__ = [
    "FirewallClient",
    "FirewallFailMode",
]
