"""Async firewall client tests (#982 PR 3)."""

from __future__ import annotations

from typing import Any

import pytest

from agent_bom.firewall import (
    AgentFirewallPolicy,
    FirewallDecision,
    FirewallEnforcementMode,
    FirewallRule,
)
from agent_bom.firewall_client import FirewallClient, FirewallFailMode


class _FakeResponse:
    def __init__(self, payload: dict[str, Any], status_code: int = 200) -> None:
        self._payload = payload
        self.status_code = status_code

    def json(self) -> dict[str, Any]:
        return self._payload

    def raise_for_status(self) -> None:
        if self.status_code >= 400:
            raise _FakeHTTPError(f"HTTP {self.status_code}")


class _FakeHTTPError(Exception):
    pass


class _FakeAsyncClient:
    def __init__(self, responses: list[_FakeResponse | Exception] | None = None) -> None:
        self.calls: list[dict[str, Any]] = []
        self._responses = list(responses or [])

    def queue(self, response: _FakeResponse | Exception) -> None:
        self._responses.append(response)

    async def post(self, url: str, json: dict[str, Any], headers: dict[str, str], timeout: float) -> _FakeResponse:
        self.calls.append({"url": url, "json": json, "headers": headers, "timeout": timeout})
        if not self._responses:
            raise AssertionError("No fake response queued for FirewallClient call")
        nxt = self._responses.pop(0)
        if isinstance(nxt, Exception):
            raise nxt
        return nxt

    async def aclose(self) -> None:
        pass


class _ManualClock:
    def __init__(self) -> None:
        self.now = 0.0

    def __call__(self) -> float:
        return self.now

    def advance(self, seconds: float) -> None:
        self.now += seconds


def _allow_payload() -> dict[str, Any]:
    return {
        "source_agent": "cursor",
        "target_agent": "claude-desktop",
        "source_roles": [],
        "target_roles": [],
        "decision": "allow",
        "effective_decision": "allow",
        "matched_rule": None,
        "policy": {
            "source": "default-allow",
            "loaded_at": None,
            "default_decision": "allow",
            "enforcement_mode": "enforce",
            "tenant_id": None,
        },
    }


def _deny_payload(*, description: str = "no direct DB") -> dict[str, Any]:
    return {
        "source_agent": "cursor",
        "target_agent": "snowflake-cli",
        "source_roles": [],
        "target_roles": [],
        "decision": "deny",
        "effective_decision": "deny",
        "matched_rule": {
            "source": "cursor",
            "target": "snowflake-cli",
            "decision": "deny",
            "description": description,
        },
        "policy": {
            "source": "/etc/agent-bom/fw.json",
            "loaded_at": 1.0,
            "default_decision": "allow",
            "enforcement_mode": "enforce",
            "tenant_id": None,
        },
    }


@pytest.mark.asyncio
async def test_requires_gateway_or_local_policy() -> None:
    with pytest.raises(ValueError, match="gateway_url or local_policy"):
        FirewallClient()


@pytest.mark.asyncio
async def test_decision_via_gateway() -> None:
    fake = _FakeAsyncClient([_FakeResponse(_deny_payload())])
    client = FirewallClient(gateway_url="http://gateway", http_client=fake)
    result = await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    assert result.decision == FirewallDecision.DENY
    assert result.effective_decision == FirewallDecision.DENY
    assert result.matched_rule is not None
    assert result.matched_rule.description == "no direct DB"
    assert len(fake.calls) == 1
    assert fake.calls[0]["url"] == "http://gateway/v1/firewall/check"
    assert fake.calls[0]["headers"]["content-type"] == "application/json"


@pytest.mark.asyncio
async def test_decision_uses_bearer_token() -> None:
    fake = _FakeAsyncClient([_FakeResponse(_allow_payload())])
    client = FirewallClient(gateway_url="http://gateway", bearer_token="abc123", http_client=fake)
    await client.decision(source_agent="cursor", target_agent="claude-desktop")
    assert fake.calls[0]["headers"]["authorization"] == "Bearer abc123"


@pytest.mark.asyncio
async def test_decision_caches_within_ttl() -> None:
    clock = _ManualClock()
    fake = _FakeAsyncClient([_FakeResponse(_deny_payload())])
    client = FirewallClient(gateway_url="http://gateway", cache_ttl_seconds=10.0, http_client=fake, clock=clock)
    await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    # Second call within TTL must not hit the gateway.
    clock.advance(5)
    await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    assert len(fake.calls) == 1


@pytest.mark.asyncio
async def test_decision_refetches_after_ttl() -> None:
    clock = _ManualClock()
    fake = _FakeAsyncClient([_FakeResponse(_deny_payload()), _FakeResponse(_allow_payload())])
    client = FirewallClient(gateway_url="http://gateway", cache_ttl_seconds=5.0, http_client=fake, clock=clock)
    first = await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    clock.advance(6)
    second = await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    assert first.decision == FirewallDecision.DENY
    assert second.decision == FirewallDecision.ALLOW
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_invalidate_cache_drops_entries() -> None:
    fake = _FakeAsyncClient([_FakeResponse(_deny_payload()), _FakeResponse(_allow_payload())])
    client = FirewallClient(gateway_url="http://gateway", http_client=fake)
    await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    client.invalidate_cache()
    second = await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    assert second.decision == FirewallDecision.ALLOW
    assert len(fake.calls) == 2


@pytest.mark.asyncio
async def test_fail_open_on_gateway_error_without_local_policy() -> None:
    fake = _FakeAsyncClient([_FakeHTTPError("connection refused")])
    client = FirewallClient(
        gateway_url="http://gateway",
        fail_mode=FirewallFailMode.OPEN,
        http_client=fake,
    )
    result = await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    assert result.effective_decision == FirewallDecision.ALLOW


@pytest.mark.asyncio
async def test_fail_closed_on_gateway_error_without_local_policy() -> None:
    fake = _FakeAsyncClient([_FakeHTTPError("connection refused")])
    client = FirewallClient(
        gateway_url="http://gateway",
        fail_mode=FirewallFailMode.CLOSED,
        http_client=fake,
    )
    result = await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    assert result.effective_decision == FirewallDecision.DENY


@pytest.mark.asyncio
async def test_local_policy_used_on_gateway_error() -> None:
    fake = _FakeAsyncClient([_FakeHTTPError("boom")])
    local = AgentFirewallPolicy(
        rules=(FirewallRule(source="cursor", target="snowflake-cli", decision=FirewallDecision.DENY),),
    )
    client = FirewallClient(gateway_url="http://gateway", local_policy=local, http_client=fake)
    result = await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    assert result.decision == FirewallDecision.DENY
    # Different pair → falls through to default-allow on the local policy.
    other = await client.decision(source_agent="other", target_agent="other-target")
    assert other.decision == FirewallDecision.ALLOW


@pytest.mark.asyncio
async def test_local_policy_only_no_gateway() -> None:
    local = AgentFirewallPolicy(
        enforcement_mode=FirewallEnforcementMode.DRY_RUN,
        rules=(FirewallRule(source="*", target="snowflake-*", decision=FirewallDecision.DENY),),
    )
    client = FirewallClient(local_policy=local)
    result = await client.decision(source_agent="cursor", target_agent="snowflake-cli")
    # DENY downgraded to WARN under dry-run.
    assert result.decision == FirewallDecision.DENY
    assert result.effective_decision == FirewallDecision.WARN


@pytest.mark.asyncio
async def test_lru_cap_evicts_oldest() -> None:
    payloads = [_allow_payload() for _ in range(5)]
    fake = _FakeAsyncClient([_FakeResponse(p) for p in payloads])
    client = FirewallClient(gateway_url="http://gateway", cache_max_entries=2, http_client=fake)
    for i in range(3):
        await client.decision(source_agent=f"src{i}", target_agent="t")
    # Cache holds the last 2; first should miss again.
    fake.queue(_FakeResponse(_allow_payload()))
    await client.decision(source_agent="src0", target_agent="t")
    assert len(fake.calls) == 4  # 3 initial + 1 re-fetch after eviction


@pytest.mark.asyncio
async def test_role_tags_round_trip() -> None:
    fake = _FakeAsyncClient([_FakeResponse(_allow_payload())])
    client = FirewallClient(gateway_url="http://gateway", http_client=fake)
    await client.decision(
        source_agent="cursor",
        target_agent="claude",
        source_roles={"trusted", "alpha"},
        target_roles={"data-plane"},
    )
    body = fake.calls[0]["json"]
    assert body["source_roles"] == ["alpha", "trusted"]
    assert body["target_roles"] == ["data-plane"]


@pytest.mark.asyncio
async def test_aclose_no_op_when_external_client_provided() -> None:
    fake = _FakeAsyncClient()
    client = FirewallClient(gateway_url="http://gateway", http_client=fake)
    # Provided an external client → ours should not close it.
    await client.aclose()
    # Re-using the external client should still work.
    fake.queue(_FakeResponse(_allow_payload()))
    await client.decision(source_agent="cursor", target_agent="claude")
    assert len(fake.calls) == 1
