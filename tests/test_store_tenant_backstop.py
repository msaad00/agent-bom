"""Cross-tenant READ/DELETE backstop for the in-memory stores.

These stores expose ``get()``/``delete()`` with a REQUIRED, keyword-only
``tenant_id``. Even if a future route forgets to pre-check ownership, the store
must never return or delete another tenant's record. One test per store asserts:

  * an entry created under tenant-A is invisible to tenant-B's ``get``,
  * tenant-B's ``delete`` returns False and leaves the entry intact,
  * tenant-A can still read it back.
"""

from __future__ import annotations

from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, issue_identity
from agent_bom.api.credential_store import InMemoryCredentialRefStore
from agent_bom.api.fleet_store import FleetAgent, FleetLifecycleState, InMemoryFleetStore
from agent_bom.api.models import CredentialRefRecord


def test_credential_ref_store_tenant_backstop() -> None:
    store = InMemoryCredentialRefStore()
    store.put(
        CredentialRefRecord(
            credential_ref_id="cred-1",
            tenant_id="tenant-a",
            display_name="A role",
            provider="aws",
            external_ref="arn:aws:iam::111122223333:role/agent-bom",
        )
    )

    assert store.get("cred-1", tenant_id="tenant-b") is None
    assert store.delete("cred-1", tenant_id="tenant-b") is False
    # Still present for the owning tenant after the cross-tenant delete attempt.
    owned = store.get("cred-1", tenant_id="tenant-a")
    assert owned is not None
    assert owned.credential_ref_id == "cred-1"


def test_fleet_store_tenant_backstop() -> None:
    store = InMemoryFleetStore()
    store.put(
        FleetAgent(
            agent_id="a-1",
            name="agent-a",
            agent_type="claude-desktop",
            lifecycle_state=FleetLifecycleState.DISCOVERED,
            tenant_id="tenant-a",
        )
    )

    assert store.get("a-1", tenant_id="tenant-b") is None
    assert store.delete("a-1", tenant_id="tenant-b") is False
    owned = store.get("a-1", tenant_id="tenant-a")
    assert owned is not None
    assert owned.agent_id == "a-1"


def test_agent_identity_store_tenant_backstop() -> None:
    store = InMemoryAgentIdentityStore()
    identity, _raw = issue_identity(store, agent_id="agent-a", tenant_id="tenant-a")

    assert store.get(identity.identity_id, tenant_id="tenant-b") is None
    owned = store.get(identity.identity_id, tenant_id="tenant-a")
    assert owned is not None
    assert owned.identity_id == identity.identity_id
