"""Persisted AI-system blueprints: entity, versioning, approval workflow, seed."""

from __future__ import annotations

import pytest

from agent_bom.api.blueprint_store import (
    STATUS_APPROVED,
    STATUS_DRAFT,
    STATUS_PENDING,
    STATUS_REJECTED,
    Blueprint,
    BlueprintApprovalError,
    BlueprintComposition,
    BlueprintSelfApprovalError,
    InMemoryBlueprintStore,
    SQLiteBlueprintStore,
    approve_version,
    build_agent_owner_index,
    create_blueprint,
    create_draft_version,
    diff_versions,
    find_blueprint_by_seed,
    reject_version,
    seed_blueprints_from_archetypes,
    submit_version_for_approval,
)


def _composition() -> BlueprintComposition:
    return BlueprintComposition(agents=["planner"], models=["gpt"], tools=["repo_read"], owners=["appsec"])


# ── entity + versioning ──────────────────────────────────────────────────────


def test_create_blueprint_starts_as_draft_version_one():
    store = InMemoryBlueprintStore()
    blueprint, version = create_blueprint(
        store, tenant_id="t1", name="Planner system", owner="appsec", composition=_composition()
    )
    assert blueprint.approval_status == STATUS_DRAFT
    assert blueprint.current_version == 0  # nothing approved yet
    assert blueprint.latest_version == 1
    assert version.version == 1 and version.status == STATUS_DRAFT
    assert store.get_blueprint("t1", blueprint.blueprint_id) is not None
    # tenant isolation: another tenant cannot see it
    assert store.get_blueprint("t2", blueprint.blueprint_id) is None


def test_new_edit_opens_a_new_draft_version_not_a_mutation():
    store = InMemoryBlueprintStore()
    blueprint, _ = create_blueprint(store, tenant_id="t1", name="bp", owner="o", composition=_composition())
    v2 = create_draft_version(
        store, tenant_id="t1", blueprint_id=blueprint.blueprint_id, composition=BlueprintComposition(tools=["graph_query"])
    )
    assert v2 is not None and v2.version == 2 and v2.status == STATUS_DRAFT
    refreshed = store.get_blueprint("t1", blueprint.blueprint_id)
    assert refreshed is not None and refreshed.latest_version == 2
    assert {v.version for v in store.list_versions("t1", blueprint.blueprint_id)} == {1, 2}


# ── approval workflow ────────────────────────────────────────────────────────


def test_full_approval_workflow_draft_to_approved():
    store = InMemoryBlueprintStore()
    blueprint, version = create_blueprint(store, tenant_id="t1", name="bp", owner="o", composition=_composition())
    bid = blueprint.blueprint_id

    submitted = submit_version_for_approval(store, tenant_id="t1", blueprint_id=bid, version=1, submitted_by="dev")
    assert submitted is not None and submitted.status == STATUS_PENDING

    approved = approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="carol", note="looks good")
    assert approved is not None and approved.status == STATUS_APPROVED
    assert approved.approver == "carol" and approved.decided_at
    header = store.get_blueprint("t1", bid)
    assert header is not None and header.current_version == 1 and header.approval_status == STATUS_APPROVED


def test_approval_requires_accountable_approver():
    store = InMemoryBlueprintStore()
    blueprint, _ = create_blueprint(store, tenant_id="t1", name="bp", owner="o", composition=_composition())
    bid = blueprint.blueprint_id
    submit_version_for_approval(store, tenant_id="t1", blueprint_id=bid, version=1)
    with pytest.raises(BlueprintApprovalError):
        approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="")
    with pytest.raises(BlueprintApprovalError):
        approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="   ")
    # still pending — the failed approval did not orphan an approved version
    assert store.get_version("t1", bid, 1).status == STATUS_PENDING  # type: ignore[union-attr]


def test_cannot_approve_a_draft_directly():
    store = InMemoryBlueprintStore()
    blueprint, _ = create_blueprint(store, tenant_id="t1", name="bp", owner="o", composition=_composition())
    with pytest.raises(BlueprintApprovalError):
        approve_version(store, tenant_id="t1", blueprint_id=blueprint.blueprint_id, version=1, approver="carol")


def test_approved_version_is_immutable():
    store = InMemoryBlueprintStore()
    blueprint, _ = create_blueprint(store, tenant_id="t1", name="bp", owner="o", composition=_composition())
    bid = blueprint.blueprint_id
    submit_version_for_approval(store, tenant_id="t1", blueprint_id=bid, version=1)
    approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="carol")
    record = store.get_version("t1", bid, 1)
    assert record is not None and record.is_immutable()
    with pytest.raises(BlueprintApprovalError):
        approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="dave")


# ── separation of duties (four-eyes) ─────────────────────────────────────────


def test_author_cannot_approve_their_own_version():
    store = InMemoryBlueprintStore()
    blueprint, _ = create_blueprint(
        store, tenant_id="t1", name="bp", owner="o", composition=_composition(), created_by="alice"
    )
    bid = blueprint.blueprint_id
    submit_version_for_approval(store, tenant_id="t1", blueprint_id=bid, version=1, submitted_by="bob")
    # The author (alice) may not approve their own version.
    with pytest.raises(BlueprintSelfApprovalError):
        approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="alice")
    # Neither may the submitter (bob).
    with pytest.raises(BlueprintSelfApprovalError):
        approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="bob")
    # The version stays pending after a rejected self-approval attempt.
    still = store.get_version("t1", bid, 1)
    assert still is not None and still.status == STATUS_PENDING


def test_self_approval_error_is_a_blueprint_approval_error():
    # Subclass so existing generic BlueprintApprovalError handlers still catch it.
    assert issubclass(BlueprintSelfApprovalError, BlueprintApprovalError)


def test_a_different_admin_can_approve_after_self_approval_is_blocked():
    store = InMemoryBlueprintStore()
    blueprint, _ = create_blueprint(
        store, tenant_id="t1", name="bp", owner="o", composition=_composition(), created_by="alice"
    )
    bid = blueprint.blueprint_id
    submit_version_for_approval(store, tenant_id="t1", blueprint_id=bid, version=1, submitted_by="alice")
    with pytest.raises(BlueprintSelfApprovalError):
        approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="alice")
    approved = approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="carol")
    assert approved is not None and approved.status == STATUS_APPROVED and approved.approver == "carol"


def test_mandatory_approver_invariant_still_holds():
    store = InMemoryBlueprintStore()
    blueprint, _ = create_blueprint(
        store, tenant_id="t1", name="bp", owner="o", composition=_composition(), created_by="alice"
    )
    bid = blueprint.blueprint_id
    submit_version_for_approval(store, tenant_id="t1", blueprint_id=bid, version=1, submitted_by="alice")
    # An empty approver is still rejected (before the four-eyes check runs).
    with pytest.raises(BlueprintApprovalError):
        approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="   ")


def test_seed_preapproval_satisfies_four_eyes():
    # System-seeded blueprints are pre-approved but author != approver, so the
    # four-eyes invariant is honoured (not bypassed) even for the bootstrap path.
    store = InMemoryBlueprintStore()
    created = seed_blueprints_from_archetypes(store, tenant_id="t1")
    assert created
    for blueprint in created:
        version = store.get_version("t1", blueprint.blueprint_id, 1)
        assert version is not None
        assert version.status == STATUS_APPROVED
        assert version.approver and version.approver not in {version.created_by, version.submitted_by}


def test_reject_records_reviewer_and_status():
    store = InMemoryBlueprintStore()
    blueprint, _ = create_blueprint(store, tenant_id="t1", name="bp", owner="o", composition=_composition())
    bid = blueprint.blueprint_id
    submit_version_for_approval(store, tenant_id="t1", blueprint_id=bid, version=1)
    rejected = reject_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="carol", note="too broad")
    assert rejected is not None and rejected.status == STATUS_REJECTED and rejected.approver == "carol"
    header = store.get_blueprint("t1", bid)
    assert header is not None and header.current_version == 0 and header.approval_status == STATUS_REJECTED


# ── diff ─────────────────────────────────────────────────────────────────────


def test_diff_between_versions_reports_added_and_removed():
    store = InMemoryBlueprintStore()
    blueprint, _ = create_blueprint(
        store, tenant_id="t1", name="bp", owner="o", composition=BlueprintComposition(tools=["repo_read", "graph_query"])
    )
    bid = blueprint.blueprint_id
    create_draft_version(store, tenant_id="t1", blueprint_id=bid, composition=BlueprintComposition(tools=["graph_query", "threat_intel"]))
    diff = diff_versions(store, tenant_id="t1", blueprint_id=bid, from_version=1, to_version=2)
    assert diff is not None
    assert diff["axes"]["tools"]["added"] == ["threat_intel"]
    assert diff["axes"]["tools"]["removed"] == ["repo_read"]
    assert diff["axes"]["tools"]["persistent"] == ["graph_query"]
    assert diff["added_count"] == 1 and diff["removed_count"] == 1 and diff["net_change"] == 0


# ── seed from archetypes ─────────────────────────────────────────────────────


def test_seed_from_archetypes_creates_preapproved_blueprints():
    store = InMemoryBlueprintStore()
    created = seed_blueprints_from_archetypes(store, tenant_id="t1")
    seeded_ids = {b.seeded_from for b in created}
    assert seeded_ids == {"developer", "security_analyst", "mlops", "finance", "admin"}
    for blueprint in created:
        assert blueprint.approval_status == STATUS_APPROVED
        assert blueprint.current_version == 1
        version = store.get_version("t1", blueprint.blueprint_id, 1)
        assert version is not None and version.status == STATUS_APPROVED
        assert version.seeded_from == blueprint.seeded_from
        # tools axis derives from the archetype's allowed categories
        assert version.composition.tools


def test_seed_is_idempotent():
    store = InMemoryBlueprintStore()
    first = seed_blueprints_from_archetypes(store, tenant_id="t1")
    second = seed_blueprints_from_archetypes(store, tenant_id="t1")
    assert len(first) == 5
    assert second == []  # nothing new created on re-seed
    assert len(store.list_blueprints("t1", limit=100).blueprints) == 5


def test_seed_is_tenant_scoped():
    store = InMemoryBlueprintStore()
    seed_blueprints_from_archetypes(store, tenant_id="t1")
    assert store.list_blueprints("t2", limit=100).blueprints == []


# ── pagination + SQLite backend parity ───────────────────────────────────────


def test_list_blueprints_is_paginated():
    store = InMemoryBlueprintStore()
    for i in range(5):
        create_blueprint(store, tenant_id="t1", name=f"bp{i}", owner="o", composition=_composition())
    page1 = store.list_blueprints("t1", limit=2, offset=0)
    assert len(page1.blueprints) == 2 and page1.next_offset == 2
    page3 = store.list_blueprints("t1", limit=2, offset=4)
    assert len(page3.blueprints) == 1 and page3.next_offset is None


def test_sqlite_backend_round_trips_versions(tmp_path):
    store = SQLiteBlueprintStore(str(tmp_path / "bp.db"))
    blueprint, _ = create_blueprint(store, tenant_id="t1", name="bp", owner="o", composition=_composition())
    bid = blueprint.blueprint_id
    submit_version_for_approval(store, tenant_id="t1", blueprint_id=bid, version=1)
    approve_version(store, tenant_id="t1", blueprint_id=bid, version=1, approver="carol")
    reloaded = SQLiteBlueprintStore(str(tmp_path / "bp.db"))
    header = reloaded.get_blueprint("t1", bid)
    assert header is not None and header.approval_status == STATUS_APPROVED
    version = reloaded.get_version("t1", bid, 1)
    assert version is not None and version.status == STATUS_APPROVED and version.composition.tools == ["repo_read"]
    # cross-tenant read returns nothing
    assert reloaded.get_blueprint("t2", bid) is None


def test_blueprint_dataclass_serialization_round_trip():
    bp = Blueprint(blueprint_id="bp_x", tenant_id="t1", name="n", owner="o", current_version=2)
    assert Blueprint.from_dict(bp.to_dict()) == bp


# ── tenant-scoped iteration (no cross-tenant / RLS bypass) ───────────────────


@pytest.mark.parametrize("backend", ["memory", "sqlite"])
def test_iter_tenant_blueprints_is_scoped_to_one_tenant(backend, tmp_path):
    store = InMemoryBlueprintStore() if backend == "memory" else SQLiteBlueprintStore(str(tmp_path / "bp.db"))
    create_blueprint(store, tenant_id="t1", name="a", owner="o", composition=_composition())
    create_blueprint(store, tenant_id="t1", name="b", owner="o", composition=_composition())
    create_blueprint(store, tenant_id="t2", name="c", owner="o", composition=_composition())
    t1 = store.iter_tenant_blueprints("t1")
    t2 = store.iter_tenant_blueprints("t2")
    assert {b.name for b in t1} == {"a", "b"}
    assert all(b.tenant_id == "t1" for b in t1)
    assert {b.name for b in t2} == {"c"}
    assert store.iter_tenant_blueprints("t3") == []


def _approve_v1(store, tenant, bid, *, author):
    submit_version_for_approval(store, tenant_id=tenant, blueprint_id=bid, version=1, submitted_by=author)
    approve_version(store, tenant_id=tenant, blueprint_id=bid, version=1, approver="reviewer")


def test_seed_lookup_is_tenant_scoped():
    store = InMemoryBlueprintStore()
    seed_blueprints_from_archetypes(store, tenant_id="t1")
    seed_blueprints_from_archetypes(store, tenant_id="t2")
    t1_dev = find_blueprint_by_seed(store, "t1", "developer")
    t2_dev = find_blueprint_by_seed(store, "t2", "developer")
    assert t1_dev is not None and t1_dev.tenant_id == "t1"
    assert t2_dev is not None and t2_dev.tenant_id == "t2"
    # a seed only present for one tenant does not resolve for the other
    assert find_blueprint_by_seed(store, "t3", "developer") is None


def test_owner_index_is_tenant_isolated():
    # The tenant-scoped listing keeps owner-index results correct with zero
    # cross-tenant leakage: t1's index never attributes t2's agents/blueprints.
    store = InMemoryBlueprintStore()
    bp1, _ = create_blueprint(
        store, tenant_id="t1", name="a", owner="alice",
        composition=BlueprintComposition(agents=["planner"], tools=["repo_read"]), created_by="author",
    )
    _approve_v1(store, "t1", bp1.blueprint_id, author="author")
    bp2, _ = create_blueprint(
        store, tenant_id="t2", name="b", owner="bob",
        composition=BlueprintComposition(agents=["ranker"], tools=["repo_read"]), created_by="author",
    )
    _approve_v1(store, "t2", bp2.blueprint_id, author="author")
    index_t1 = build_agent_owner_index(store, "t1")
    assert index_t1 == {"planner": ("alice", bp1.blueprint_id)}
    assert "ranker" not in index_t1  # t2's agent never leaks into t1's index
