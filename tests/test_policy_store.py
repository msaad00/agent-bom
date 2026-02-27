"""Tests for agent_bom.api.policy_store — gateway policy persistence."""

import tempfile
from datetime import datetime, timezone
from pathlib import Path

from agent_bom.api.policy_store import (
    GatewayPolicy,
    GatewayRule,
    InMemoryPolicyStore,
    PolicyAuditEntry,
    PolicyMode,
    SQLitePolicyStore,
)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _make_policy(
    policy_id: str = "p-1",
    name: str = "test-policy",
    mode: PolicyMode = PolicyMode.AUDIT,
    rules: list[GatewayRule] | None = None,
    **kw,
) -> GatewayPolicy:
    ts = _now()
    return GatewayPolicy(
        policy_id=policy_id,
        name=name,
        mode=mode,
        rules=rules or [GatewayRule(id="r1", action="block", block_tools=["exec"])],
        created_at=ts,
        updated_at=ts,
        **kw,
    )


def _make_audit(
    entry_id: str = "e-1",
    policy_id: str = "p-1",
    agent_name: str = "agent-a",
    action_taken: str = "blocked",
) -> PolicyAuditEntry:
    return PolicyAuditEntry(
        entry_id=entry_id,
        policy_id=policy_id,
        policy_name="test-policy",
        rule_id="r1",
        agent_name=agent_name,
        tool_name="exec",
        action_taken=action_taken,
        reason="blocked by rule",
        timestamp=_now(),
    )


# ── InMemoryPolicyStore ──────────────────────────────────────────────────────


def test_put_and_get():
    store = InMemoryPolicyStore()
    store.put_policy(_make_policy())
    assert store.get_policy("p-1") is not None
    assert store.get_policy("p-1").name == "test-policy"


def test_get_missing():
    store = InMemoryPolicyStore()
    assert store.get_policy("nope") is None


def test_delete():
    store = InMemoryPolicyStore()
    store.put_policy(_make_policy())
    assert store.delete_policy("p-1") is True
    assert store.get_policy("p-1") is None
    assert store.delete_policy("p-1") is False


def test_list_policies():
    store = InMemoryPolicyStore()
    store.put_policy(_make_policy(policy_id="p-1", name="alpha"))
    store.put_policy(_make_policy(policy_id="p-2", name="beta"))
    assert len(store.list_policies()) == 2


def test_get_policies_for_agent_unbound():
    """Policies with no bindings match all agents."""
    store = InMemoryPolicyStore()
    store.put_policy(_make_policy())
    result = store.get_policies_for_agent(agent_name="any")
    assert len(result) == 1


def test_get_policies_for_agent_bound():
    """Policies bound to specific agents filter correctly."""
    store = InMemoryPolicyStore()
    store.put_policy(_make_policy(policy_id="p-1", bound_agents=["agent-a"]))
    store.put_policy(_make_policy(policy_id="p-2", bound_agents=["agent-b"]))
    result = store.get_policies_for_agent(agent_name="agent-a")
    assert len(result) == 1
    assert result[0].policy_id == "p-1"


def test_get_policies_for_agent_disabled():
    """Disabled policies are excluded."""
    store = InMemoryPolicyStore()
    store.put_policy(_make_policy(enabled=False))
    result = store.get_policies_for_agent(agent_name="any")
    assert len(result) == 0


def test_audit_entries():
    store = InMemoryPolicyStore()
    store.put_audit_entry(_make_audit(entry_id="e-1", agent_name="a"))
    store.put_audit_entry(_make_audit(entry_id="e-2", agent_name="b"))
    all_entries = store.list_audit_entries()
    assert len(all_entries) == 2
    filtered = store.list_audit_entries(agent_name="a")
    assert len(filtered) == 1


def test_audit_entries_by_policy():
    store = InMemoryPolicyStore()
    store.put_audit_entry(_make_audit(entry_id="e-1", policy_id="p-1"))
    store.put_audit_entry(_make_audit(entry_id="e-2", policy_id="p-2"))
    result = store.list_audit_entries(policy_id="p-1")
    assert len(result) == 1


# ── SQLitePolicyStore ────────────────────────────────────────────────────────


def _sqlite_store():
    tmp = tempfile.NamedTemporaryFile(suffix=".db", delete=False)
    tmp.close()
    return SQLitePolicyStore(tmp.name), Path(tmp.name)


def test_sqlite_put_get():
    store, path = _sqlite_store()
    try:
        store.put_policy(_make_policy())
        assert store.get_policy("p-1") is not None
        assert store.get_policy("p-1").name == "test-policy"
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_delete():
    store, path = _sqlite_store()
    try:
        store.put_policy(_make_policy())
        assert store.delete_policy("p-1") is True
        assert store.get_policy("p-1") is None
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_list():
    store, path = _sqlite_store()
    try:
        store.put_policy(_make_policy(policy_id="p-1", name="alpha"))
        store.put_policy(_make_policy(policy_id="p-2", name="beta"))
        assert len(store.list_policies()) == 2
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_policies_for_agent():
    store, path = _sqlite_store()
    try:
        store.put_policy(_make_policy(policy_id="p-1", bound_agents=["agent-a"]))
        store.put_policy(_make_policy(policy_id="p-2", bound_agents=["agent-b"]))
        result = store.get_policies_for_agent(agent_name="agent-a")
        assert len(result) == 1
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_audit():
    store, path = _sqlite_store()
    try:
        store.put_audit_entry(_make_audit(entry_id="e-1"))
        store.put_audit_entry(_make_audit(entry_id="e-2", agent_name="b"))
        assert len(store.list_audit_entries()) == 2
        assert len(store.list_audit_entries(agent_name="b")) == 1
    finally:
        path.unlink(missing_ok=True)


def test_sqlite_upsert():
    store, path = _sqlite_store()
    try:
        policy = _make_policy()
        store.put_policy(policy)
        policy.description = "updated"
        store.put_policy(policy)
        assert store.get_policy("p-1").description == "updated"
        assert len(store.list_policies()) == 1
    finally:
        path.unlink(missing_ok=True)
