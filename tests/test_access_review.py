"""Tests for scheduled access-review / recertification campaigns (issue #2921).

Covers the campaign lifecycle (create -> items -> decide -> complete), overdue
detection, the audit event emitted per decision, evidence export (reference-only,
no secret values), tenant isolation, and the non-secret API surface under
``/v1/identities/access-reviews``.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.access_review import (
    DECISION_ATTEST,
    DECISION_FLAG,
    DECISION_REVOKE,
    STATUS_COMPLETED,
    STATUS_IN_PROGRESS,
    STATUS_OPEN,
    STATUS_OVERDUE,
    InMemoryAccessReviewStore,
    SQLiteAccessReviewStore,
    create_campaign,
    create_campaign_from_discovery,
    export_evidence,
    record_decision,
    refresh_campaign_status,
    set_access_review_store,
)

NOW = datetime(2026, 6, 18, 12, 0, 0, tzinfo=timezone.utc)

_DISCOVERED = [
    {
        "identity_id": "0oa1",
        "name": "billing-svc",
        "provider": "okta",
        "identity_type": "service_account",
        "owner": "finance",
        "scopes": ["read_invoices", "admin"],
    },
    {"identity_id": "sp-2", "name": "ci-deployer", "provider": "entra", "scopes": ["deploy"]},
]


@pytest.fixture()
def store():
    s = InMemoryAccessReviewStore()
    set_access_review_store(s)
    yield s
    set_access_review_store(None)


# ── Store + lifecycle ──────────────────────────────────────────────────────────


def test_create_campaign_enumerates_one_item_per_subject(store):
    campaign, items = create_campaign_from_discovery(
        store, tenant_id="t1", name="Q2 recert", discovered=_DISCOVERED, created_by="alice", now=NOW
    )
    assert campaign.status == STATUS_OPEN
    assert campaign.item_count == 2
    assert campaign.decided_count == 0
    assert {i.subject_name for i in items} == {"billing-svc", "ci-deployer"}
    # Admin scope flags the subject as privileged; "deploy" does not.
    by_name = {i.subject_name: i for i in items}
    assert by_name["billing-svc"].privileged is True
    assert by_name["ci-deployer"].privileged is False
    # Reference-only permission labels are carried, no secret material.
    assert by_name["billing-svc"].permissions == ["read_invoices", "admin"]


def test_create_campaign_sets_due_date(store):
    campaign, _ = create_campaign_from_discovery(store, tenant_id="t1", name="recert", discovered=_DISCOVERED, due_days=7, now=NOW)
    assert campaign.due_at == (NOW + timedelta(days=7)).isoformat()


def test_lifecycle_create_decide_complete(store):
    campaign, items = create_campaign_from_discovery(store, tenant_id="t1", name="recert", discovered=_DISCOVERED, now=NOW)
    # First decision moves the campaign to in_progress.
    _, c1 = record_decision(store, tenant_id="t1", item_id=items[0].item_id, decision=DECISION_ATTEST, decided_by="alice")
    assert c1.status == STATUS_IN_PROGRESS
    assert c1.decided_count == 1
    # Deciding the last item completes it.
    _, c2 = record_decision(store, tenant_id="t1", item_id=items[1].item_id, decision=DECISION_REVOKE, decided_by="alice")
    assert c2.status == STATUS_COMPLETED
    assert c2.decided_count == 2
    assert c2.completed_at


def test_decision_persists_reviewer_and_note(store):
    _, items = create_campaign_from_discovery(store, tenant_id="t1", name="recert", discovered=_DISCOVERED, now=NOW)
    item, _ = record_decision(
        store, tenant_id="t1", item_id=items[0].item_id, decision=DECISION_FLAG, decided_by="bob", note="needs owner review"
    )
    assert item.decision == DECISION_FLAG
    assert item.decided_by == "bob"
    assert item.decision_note == "needs owner review"
    assert item.decided_at


def test_invalid_decision_raises(store):
    _, items = create_campaign_from_discovery(store, tenant_id="t1", name="recert", discovered=_DISCOVERED, now=NOW)
    with pytest.raises(ValueError):
        record_decision(store, tenant_id="t1", item_id=items[0].item_id, decision="approve")


def test_decision_on_unknown_item_returns_none(store):
    create_campaign_from_discovery(store, tenant_id="t1", name="recert", discovered=_DISCOVERED, now=NOW)
    assert record_decision(store, tenant_id="t1", item_id="missing", decision=DECISION_ATTEST) is None


def test_overdue_detection(store):
    past = datetime(2026, 1, 1, tzinfo=timezone.utc)
    campaign, _ = create_campaign(
        store, tenant_id="t1", name="old", subjects=[{"subject_id": "x", "subject_name": "x"}], due_days=1, now=past
    )
    assert campaign.status == STATUS_OPEN
    refreshed = refresh_campaign_status(store, tenant_id="t1", campaign_id=campaign.campaign_id, now=NOW)
    assert refreshed is not None
    assert refreshed.status == STATUS_OVERDUE


def test_completed_campaign_is_never_overdue(store):
    past = datetime(2026, 1, 1, tzinfo=timezone.utc)
    campaign, items = create_campaign(
        store, tenant_id="t1", name="old", subjects=[{"subject_id": "x", "subject_name": "x"}], due_days=1, now=past
    )
    record_decision(store, tenant_id="t1", item_id=items[0].item_id, decision=DECISION_ATTEST, now=past)
    refreshed = refresh_campaign_status(store, tenant_id="t1", campaign_id=campaign.campaign_id, now=NOW)
    assert refreshed is not None
    assert refreshed.status == STATUS_COMPLETED


def test_evidence_export_is_reference_only(store):
    campaign, items = create_campaign_from_discovery(store, tenant_id="t1", name="recert", discovered=_DISCOVERED, now=NOW)
    record_decision(store, tenant_id="t1", item_id=items[0].item_id, decision=DECISION_REVOKE, decided_by="alice")
    record_decision(store, tenant_id="t1", item_id=items[1].item_id, decision=DECISION_ATTEST, decided_by="alice")
    bundle = export_evidence(store, tenant_id="t1", campaign_id=campaign.campaign_id, now=NOW)
    assert bundle is not None
    assert bundle["secret_values_included"] is False
    assert bundle["campaign"]["status"] == STATUS_COMPLETED
    assert bundle["decision_counts"][DECISION_REVOKE] == 1
    assert bundle["decision_counts"][DECISION_ATTEST] == 1
    assert "billing-svc" in bundle["revoke_recommended"]


def test_tenant_isolation_on_store(store):
    campaign, items = create_campaign_from_discovery(store, tenant_id="t1", name="recert", discovered=_DISCOVERED, now=NOW)
    # Wrong tenant cannot read the campaign or its items.
    assert store.get_campaign(campaign.campaign_id, "t2") is None
    assert store.get_item(items[0].item_id, "t2") is None
    assert store.list_campaigns("t2") == []
    # A decision scoped to the wrong tenant is a no-op (item not found).
    assert record_decision(store, tenant_id="t2", item_id=items[0].item_id, decision=DECISION_ATTEST) is None


def test_sqlite_store_round_trip(tmp_path):
    db = str(tmp_path / "ar.db")
    s = SQLiteAccessReviewStore(db)
    campaign, items = create_campaign_from_discovery(s, tenant_id="t1", name="recert", discovered=_DISCOVERED, now=NOW)
    record_decision(s, tenant_id="t1", item_id=items[0].item_id, decision=DECISION_ATTEST, decided_by="alice")
    # Re-open a fresh store against the same DB to confirm persistence.
    s2 = SQLiteAccessReviewStore(db)
    reloaded = s2.get_campaign(campaign.campaign_id, "t1")
    assert reloaded is not None
    assert reloaded.decided_count == 1
    items2 = s2.list_items(campaign.campaign_id, "t1")
    assert len(items2) == 2
    assert s2.get_campaign(campaign.campaign_id, "t2") is None


# ── API surface ────────────────────────────────────────────────────────────────


@pytest.fixture()
def client(store, monkeypatch):
    monkeypatch.setenv("AGENT_BOM_ALLOW_UNAUTHENTICATED_API", "1")
    from agent_bom.api.server import app

    return TestClient(app)


def test_api_create_list_get_decide_evidence(client):
    created = client.post(
        "/v1/identities/access-reviews",
        json={
            "name": "API recert",
            "subjects": [
                {"subject_id": "okta:s1", "subject_name": "svc1", "permissions": ["admin"], "privileged": True},
                {"subject_id": "entra:s2", "subject_name": "svc2", "permissions": ["read"]},
            ],
        },
    )
    assert created.status_code == 201, created.text
    payload = created.json()
    assert payload["campaign"]["item_count"] == 2
    cid = payload["campaign"]["campaign_id"]
    item_ids = [i["item_id"] for i in payload["items"]]

    assert client.get("/v1/identities/access-reviews").json()["count"] == 1
    assert client.get(f"/v1/identities/access-reviews/{cid}").json()["campaign"]["status"] == STATUS_OPEN

    d1 = client.post(
        f"/v1/identities/access-reviews/{cid}/items/{item_ids[0]}/decision",
        json={"decision": "revoke_recommended", "note": "unused 90d"},
    )
    assert d1.status_code == 200, d1.text
    assert d1.json()["campaign"]["status"] == STATUS_IN_PROGRESS

    d2 = client.post(
        f"/v1/identities/access-reviews/{cid}/items/{item_ids[1]}/decision",
        json={"decision": "attest"},
    )
    assert d2.json()["campaign"]["status"] == STATUS_COMPLETED

    ev = client.get(f"/v1/identities/access-reviews/{cid}/evidence").json()
    assert ev["secret_values_included"] is False
    assert ev["campaign"]["status"] == STATUS_COMPLETED
    assert "svc1" in ev["revoke_recommended"]


def test_api_create_requires_name(client):
    assert client.post("/v1/identities/access-reviews", json={"subjects": []}).status_code == 400


def test_api_invalid_decision_400(client):
    created = client.post(
        "/v1/identities/access-reviews",
        json={"name": "r", "subjects": [{"subject_id": "a", "subject_name": "a"}]},
    ).json()
    cid = created["campaign"]["campaign_id"]
    iid = created["items"][0]["item_id"]
    assert client.post(f"/v1/identities/access-reviews/{cid}/items/{iid}/decision", json={"decision": "x"}).status_code == 400


def test_api_unknown_campaign_404(client):
    assert client.get("/v1/identities/access-reviews/missing").status_code == 404
    assert client.get("/v1/identities/access-reviews/missing/evidence").status_code == 404


def test_api_decision_emits_audit_event(client):
    from agent_bom.api.audit_log import InMemoryAuditLog, set_audit_log

    audit = InMemoryAuditLog()
    set_audit_log(audit)
    try:
        created = client.post(
            "/v1/identities/access-reviews",
            json={"name": "r", "subjects": [{"subject_id": "a", "subject_name": "a"}]},
        ).json()
        cid = created["campaign"]["campaign_id"]
        iid = created["items"][0]["item_id"]
        client.post(f"/v1/identities/access-reviews/{cid}/items/{iid}/decision", json={"decision": "attest"})
        actions = {e.action for e in audit.list_entries(limit=100)}
        assert "identity.access_review_created" in actions
        assert "identity.access_review_decided" in actions
        # Audit chain stays intact (no tampered entries).
        verified, tampered = audit.verify_integrity(limit=100)
        assert tampered == 0
        assert verified >= 2
    finally:
        set_audit_log(InMemoryAuditLog())


def test_api_does_not_collide_with_single_identity_lookup(client):
    # The static access-reviews routes must take precedence over /v1/identities/{id}.
    assert client.get("/v1/identities/nonexistent").status_code == 404
    assert client.get("/v1/identities/access-reviews").status_code == 200
