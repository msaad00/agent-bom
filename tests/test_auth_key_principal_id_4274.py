"""Key <-> stable principal-id binding and id-based deprovision (epic #4274, item 4).

The pre-fix residual: deprovision revoked keys by a name-string / owner heuristic,
so a differently-named CI token bound to a departing subject only by a stable id
survived. These tests bind every key to a stable ``principal_id`` and prove that
revoking a subject by id revokes ALL of its keys, with cross-subject isolation.
"""

from __future__ import annotations

import os
import uuid
from types import SimpleNamespace

import pytest

from agent_bom.api.auth import (
    KeyStore,
    Role,
    create_api_key,
    create_api_key_record,
    get_key_store,
    set_key_store,
)
from agent_bom.api.scim import _scim_key_matches_user, revoke_credentials_for_scim_user


@pytest.fixture
def isolated_key_store():
    original = get_key_store()
    store = KeyStore()
    set_key_store(store)
    try:
        yield store
    finally:
        set_key_store(original)


# ---------------------------------------------------------------------------
# principal_id is stamped at creation
# ---------------------------------------------------------------------------


def test_create_api_key_sets_explicit_principal_id() -> None:
    _raw, key = create_api_key("laptop", Role.ANALYST, principal_id="u-alice-123")
    assert key.principal_id == "u-alice-123"


def test_principal_id_falls_back_to_scim_subject() -> None:
    key = create_api_key_record(
        "abom_test_principal_scim_1234567890",
        name="ci",
        role=Role.ANALYST,
        scim_subject_id="scim-77",
    )
    assert key.principal_id == "scim-77"


def test_principal_id_falls_back_to_owner() -> None:
    key = create_api_key_record(
        "abom_test_principal_owner_123456789",
        name="jenkins-nightly",
        role=Role.ANALYST,
        owner="alice",
    )
    assert key.principal_id == "alice"


def test_explicit_principal_id_wins_over_fallbacks() -> None:
    key = create_api_key_record(
        "abom_test_principal_wins_1234567890",
        name="ci",
        role=Role.ANALYST,
        scim_subject_id="scim-77",
        owner="alice",
        principal_id="u-canonical",
    )
    assert key.principal_id == "u-canonical"


def test_to_dict_surfaces_principal_id() -> None:
    _raw, key = create_api_key("laptop", Role.VIEWER, principal_id="u-1")
    assert key.to_dict()["principal_id"] == "u-1"


def test_matcher_matches_by_principal_id_alone() -> None:
    key = create_api_key_record(
        "abom_test_matcher_principal_12345678",
        name="ci-deploy-token",  # arbitrary, does not name the subject
        role=Role.ANALYST,
        principal_id="u-alice",
    )
    assert key.scim_subject_id is None
    assert key.owner is None
    assert _scim_key_matches_user(
        key,
        subjects={"alice", "u-alice"},
        subjects_lower={"alice", "u-alice"},
        subject_ids={"u-alice", "alice"},
    )


# ---------------------------------------------------------------------------
# store-level id-based revocation
# ---------------------------------------------------------------------------


def test_store_revoke_by_principal_id_returns_revoked_ids(isolated_key_store) -> None:
    store = isolated_key_store
    k1 = create_api_key_record("abom_test_rbp_a_12345678901234567", name="a", role=Role.ANALYST, principal_id="u-x")
    k2 = create_api_key_record("abom_test_rbp_b_12345678901234567", name="b", role=Role.ANALYST, principal_id="u-x")
    other = create_api_key_record("abom_test_rbp_c_12345678901234567", name="c", role=Role.ANALYST, principal_id="u-y")
    for k in (k1, k2, other):
        store.add(k)
    revoked = store.revoke_by_principal_id("u-x", tenant_id="default")
    assert set(revoked) == {k1.key_id, k2.key_id}
    assert k1.is_revoked() and k2.is_revoked()
    assert not other.is_revoked()
    # idempotent: a second call revokes nothing (already revoked)
    assert store.revoke_by_principal_id("u-x", tenant_id="default") == []


# ---------------------------------------------------------------------------
# THE security proof: deprovision-by-id revokes a differently-named CI token
# ---------------------------------------------------------------------------


def test_deprovision_by_id_revokes_all_keys_including_differently_named_ci_token(isolated_key_store, monkeypatch) -> None:
    """A subject with multiple keys (one an arbitrarily-named CI token bound
    only by principal_id) is fully revoked on deprovision.

    Pre-fix, the CI token carried no scim_subject_id/owner and its name did not
    match the subject, so the name-string heuristic left it ALIVE. Id-based
    revocation revokes every key keyed to the subject's stable principal id.
    """
    store = isolated_key_store
    monkeypatch.setattr("agent_bom.api.auth.get_key_store", lambda: store)

    principal = "u-alice-9f3c"
    interactive = create_api_key_record("abom_test_dp_interactive_1234567", name="alice", role=Role.ANALYST, principal_id=principal)
    laptop = create_api_key_record("abom_test_dp_laptop_123456789012", name="alice-laptop", role=Role.ANALYST, principal_id=principal)
    ci_token = create_api_key_record(
        "abom_test_dp_ci_1234567890123456",
        name="ci-deploy-token",  # arbitrary name, no owner, no scim_subject_id
        role=Role.ANALYST,
        principal_id=principal,
    )
    assert ci_token.owner is None and ci_token.scim_subject_id is None
    for k in (interactive, laptop, ci_token):
        store.add(k)

    user = SimpleNamespace(user_id=principal, user_name="alice", external_id=None)
    revoked = revoke_credentials_for_scim_user("default", user)

    assert revoked == 3
    assert interactive.is_revoked()
    assert laptop.is_revoked()
    assert ci_token.is_revoked(), "differently-named CI token must be revoked by principal_id"


def test_deprovision_by_id_isolates_other_subjects(isolated_key_store, monkeypatch) -> None:
    store = isolated_key_store
    monkeypatch.setattr("agent_bom.api.auth.get_key_store", lambda: store)

    alice = create_api_key_record("abom_test_iso_alice_12345678901", name="ci-a", role=Role.ANALYST, principal_id="u-alice")
    bob = create_api_key_record("abom_test_iso_bob_123456789012", name="ci-b", role=Role.ANALYST, principal_id="u-bob")
    store.add(alice)
    store.add(bob)

    user = SimpleNamespace(user_id="u-alice", user_name="alice", external_id=None)
    revoked = revoke_credentials_for_scim_user("default", user)

    assert revoked == 1
    assert alice.is_revoked()
    assert not bob.is_revoked(), "a second subject's keys must be untouched"


# ---------------------------------------------------------------------------
# Live Postgres: fresh migrated DB, indexed id-based revoke, isolation
# ---------------------------------------------------------------------------

_PG_URL = os.environ.get("AGENT_BOM_TEST_PG_URL")


@pytest.mark.skipif(not _PG_URL, reason="AGENT_BOM_TEST_PG_URL not set")
def test_postgres_deprovision_by_id_revokes_ci_token() -> None:
    import psycopg
    from psycopg_pool import ConnectionPool

    from agent_bom.api import postgres_common as pc
    from agent_bom.api.postgres_access import PostgresKeyStore

    pool = ConnectionPool(conninfo=_PG_URL, min_size=1, max_size=2, open=True)
    store = PostgresKeyStore(pool=pool)

    # "default" team pre-exists (api_keys.team_id FKs to teams); isolate by the
    # per-subject principal_id, which is the property under test.
    tenant = "default"
    principal = f"u-{uuid.uuid4().hex[:8]}"
    other_principal = f"u-{uuid.uuid4().hex[:8]}"
    created_ids: list[str] = []

    token = pc.set_current_tenant(tenant)
    try:
        interactive = create_api_key_record(
            f"abom_pg_int_{uuid.uuid4().hex}", name="alice", role=Role.ANALYST, tenant_id=tenant, principal_id=principal
        )
        ci = create_api_key_record(
            f"abom_pg_ci_{uuid.uuid4().hex}",
            name="ci-deploy-token",
            role=Role.ANALYST,
            tenant_id=tenant,
            principal_id=principal,
        )
        other = create_api_key_record(
            f"abom_pg_oth_{uuid.uuid4().hex}",
            name="bob",
            role=Role.ANALYST,
            tenant_id=tenant,
            principal_id=other_principal,
        )
        for k in (interactive, ci, other):
            store.add(k)
            created_ids.append(k.key_id)

        revoked = store.revoke_by_principal_id(principal, tenant_id=tenant)
        assert set(revoked) == {interactive.key_id, ci.key_id}
        assert store.get(interactive.key_id).is_revoked()
        assert store.get(ci.key_id).is_revoked()
        assert not store.get(other.key_id).is_revoked()

        # principal_id round-trips through the store
        assert store.get(ci.key_id).principal_id == principal
    finally:
        pc.reset_current_tenant(token)
        if created_ids:
            with psycopg.connect(_PG_URL) as conn:
                conn.execute("SELECT set_config('app.tenant_id', %s, true)", (tenant,))
                conn.execute("DELETE FROM api_keys WHERE key_id = ANY(%s)", (created_ids,))
                conn.commit()
        pool.close()
