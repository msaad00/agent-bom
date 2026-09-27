"""Immutable lifecycle references across restart, retirement, tenants and races."""

from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timedelta, timezone

import pytest
from fastapi import FastAPI
from starlette.testclient import TestClient

from agent_bom.api.lifecycle_store import LifecycleConflictError, SQLiteLifecycleStore
from agent_bom.evidence.lifecycle import RegisterDeployment, RegisterInstance, RegisterRun, composition_digest
from agent_bom.evidence.scan_agent_bom import build_scan_agent_bom


def scan():
    return {
        "generated_at": "2026-09-26T12:00:00Z",
        "scan_id": "scan-one",
        "agents": [
            {"name": "same", "canonical_id": agent, "stable_id": agent, "agent_type": "custom", "mcp_servers": []}
            for agent in ("agent-a", "agent-b")
        ],
    }


def document(tenant="t", agent="agent-a", result=None):
    return build_scan_agent_bom(result or scan(), agent_id=agent, tenant_id=tenant)


@pytest.fixture
def store(tmp_path):
    value = SQLiteLifecycleStore(str(tmp_path / "lifecycle.db"))
    yield value
    value.close()


def seed(store, tenant="t", agent="agent-a"):
    snapshot = store.capture(tenant, document(tenant, agent), "operator")
    deployment = store.deployment(
        tenant, RegisterDeployment(deployment_id="dep", agent_id=agent, snapshot_id=snapshot.record_id, version="1"), "operator"
    )
    instance = store.instance(
        tenant, RegisterInstance(instance_id="instance", deployment_id="dep", identity_id="identity"), "operator", identity_agent_id=agent
    )
    return snapshot, deployment, instance


def test_run_pins_snapshot_and_survives_retirement_and_restart(store, tmp_path):
    snapshot, _, _ = seed(store)
    run = store.run("t", RegisterRun(run_id="run", instance_id="instance", conversation_id="conversation"), "operator")
    assert run.snapshot_id == snapshot.record_id
    assert run.identity_id == "identity"
    assert run.assurance == "operator_recorded"
    retired = store.retire("t", "instance", "instance", "operator")
    assert retired.retired_at is not None
    assert store.retire("t", "instance", "instance", "another") == retired
    with pytest.raises(LifecycleConflictError):
        store.run("t", RegisterRun(run_id="new", instance_id="instance"), "operator")
    reopened = SQLiteLifecycleStore(str(tmp_path / "lifecycle.db"))
    try:
        assert reopened.get("t", "run", "run") == run
        assert reopened.snapshot("t", snapshot.record_id) == document()
        assert reopened.get("t", "instance", "instance") == retired
    finally:
        reopened.close()


def test_same_ids_in_other_tenant_do_not_join(store):
    snapshot, _, _ = seed(store)
    assert store.get("other", "instance", "instance") is None
    assert store.snapshot("other", snapshot.record_id) is None
    assert store.history("other", "snapshot", "agent-a").items == []
    with pytest.raises(LifecycleConflictError):
        store.capture("other", document(), "operator")
    with pytest.raises(LifecycleConflictError):
        store.deployment(
            "other", RegisterDeployment(deployment_id="d", agent_id="agent-a", snapshot_id=snapshot.record_id, version="1"), "operator"
        )
    seed(store, "other", "agent-b")
    assert store.get("t", "deployment", "dep").agent_id == "agent-a"
    assert store.get("other", "deployment", "dep").agent_id == "agent-b"


def test_same_names_and_renames_preserve_exact_identity(store):
    first = store.capture("t", document(), "operator")
    second = store.capture("t", document(agent="agent-b"), "operator")
    assert first.record_id != second.record_id
    renamed = scan()
    renamed["agents"][0]["name"] = "renamed"
    changed = store.capture("t", document(result=renamed), "operator")
    assert changed.agent_id == first.agent_id
    assert changed.composition_digest == first.composition_digest
    assert store.snapshot("t", first.record_id).content.subject.name == "same"
    assert store.snapshot("t", changed.record_id).content.subject.name == "renamed"


def test_capture_is_idempotent_and_cannot_replace_envelope(store):
    original = document()
    first = store.capture("t", original, "operator")
    assert store.capture("t", original, "other") == first
    changed = original.model_copy(update={"generated_at": datetime.now(timezone.utc)})
    with pytest.raises(LifecycleConflictError):
        store.capture("t", changed, "operator")
    assert store.snapshot("t", original.snapshot_id) == original


def test_component_changes_and_evidence_refresh_are_separate(store):
    first = document()
    refreshed = scan()
    refreshed["generated_at"] = "2026-09-27T12:00:00Z"
    refreshed["scan_id"] = "scan-two"
    second = document(result=refreshed)
    assert first.snapshot_id != second.snapshot_id
    assert composition_digest(first) == composition_digest(second)
    refreshed["agents"][0]["mcp_servers"] = [
        {"surface": "container-image", "packages": [{"name": "p", "ecosystem": "pypi", "version": "1"}]}
    ]
    third = document(result=refreshed)
    assert composition_digest(second) != composition_digest(third)
    for doc in (first, second, third):
        store.capture("t", doc, "operator")
    page = store.history("t", "snapshot", "agent-a", limit=2)
    assert len(page.items) == 2 and page.next_offset == 2
    assert len(store.history("t", "snapshot", "agent-a", limit=2, offset=2).items) == 1


def test_immutable_deployment_and_wrong_snapshot_agent(store):
    snapshot, deployment, _ = seed(store)
    other = store.capture("t", document(agent="agent-b"), "operator")
    with pytest.raises(LifecycleConflictError):
        store.deployment(
            "t", RegisterDeployment(deployment_id="new", agent_id="agent-a", snapshot_id=other.record_id, version="1"), "operator"
        )
    with pytest.raises(LifecycleConflictError):
        store.deployment(
            "t", RegisterDeployment(deployment_id="dep", agent_id="agent-a", snapshot_id=snapshot.record_id, version="2"), "operator"
        )
    assert store.get("t", "deployment", "dep") == deployment


def test_expired_instance_and_retired_parent_block_new_runs(store):
    seed(store)
    with pytest.raises(LifecycleConflictError):
        store.instance(
            "t",
            RegisterInstance(
                instance_id="expired",
                deployment_id="dep",
                identity_id="identity",
                expires_at=datetime.now(timezone.utc) - timedelta(seconds=1),
            ),
            "operator",
            identity_agent_id="agent-a",
        )
    with pytest.raises(LifecycleConflictError):
        store.instance(
            "t", RegisterInstance(instance_id="wrong", deployment_id="dep", identity_id="identity"), "operator", identity_agent_id="agent-b"
        )
    store.retire("t", "agent", "agent-a", "operator")
    with pytest.raises(LifecycleConflictError):
        store.run("t", RegisterRun(run_id="run", instance_id="instance"), "operator")
    assert store.get("t", "instance", "instance") is not None
    assert store.capture("t", document(), "operator")  # historic evidence remains retainable
    assert store.get("t", "agent", "agent-a").retired_at is not None


def test_concurrent_conflicting_bindings_are_atomic(tmp_path):
    path = str(tmp_path / "shared.db")
    stores = [SQLiteLifecycleStore(path), SQLiteLifecycleStore(path)]
    snapshot, _, _ = seed(stores[0])

    def write(index):
        try:
            return (
                stores[index]
                .deployment(
                    "t",
                    RegisterDeployment(deployment_id="race", agent_id="agent-a", snapshot_id=snapshot.record_id, version=str(index)),
                    "operator",
                )
                .version
            )
        except LifecycleConflictError:
            return "conflict"

    try:
        with ThreadPoolExecutor(2) as pool:
            result = list(pool.map(write, (0, 1)))
        assert result.count("conflict") == 1
        assert stores[0].get("t", "deployment", "race").version in result
    finally:
        for item in stores:
            item.close()


@pytest.fixture
def client(monkeypatch, store):
    from agent_bom.api.agent_identity_store import InMemoryAgentIdentityStore, issue_identity
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.routes import agent_lifecycle
    from agent_bom.api.routes import scan as routes
    from agent_bom.api.store import InMemoryJobStore

    app = FastAPI()

    @app.middleware("http")
    async def auth(request, call_next):
        token = request.headers.get("authorization", "")
        if token in ("Bearer admin", "Bearer viewer", "Bearer other"):
            request.state.api_key_role = "viewer" if token == "Bearer viewer" else "admin"
            request.state.auth_method = "api_key"
            request.state.tenant_id = "other" if token == "Bearer other" else "t"
        return await call_next(request)

    jobs = InMemoryJobStore()
    jobs.put(
        ScanJob(
            job_id="scan", tenant_id="t", status=JobStatus.DONE, request=ScanRequest(), created_at="2026-09-26T12:00:00Z", result=scan()
        )
    )
    identities = InMemoryAgentIdentityStore()
    identity, _ = issue_identity(identities, agent_id="agent-a", tenant_id="t", role="agent", blueprint_id="", ttl_seconds=3600)
    monkeypatch.setattr(routes, "_get_store", lambda: jobs)
    monkeypatch.setattr(routes, "_jobs_get", lambda _: None)
    monkeypatch.setattr(agent_lifecycle, "get_lifecycle_store", lambda: store)
    monkeypatch.setattr(agent_lifecycle, "get_agent_identity_store", lambda: identities)
    monkeypatch.setattr(
        "agent_bom.api.middleware.get_auth_runtime_status", lambda: {"auth_required": True, "unauthenticated_allowed": False}
    )
    app.include_router(agent_lifecycle.router, prefix="/v1")
    return TestClient(app), identity, jobs


def test_api_auth_tenancy_registration_and_retained_export(client):
    api, identity, jobs = client
    base = "/v1/agent-lifecycle"
    admin = {"Authorization": "Bearer admin"}
    body = {"scan_id": "scan", "agent_id": "agent-a"}
    assert api.post(base + "/snapshots", json=body).status_code in (401, 403)
    assert api.post(base + "/snapshots", headers={"Authorization": "Bearer viewer"}, json=body).status_code == 403
    assert api.post(base + "/snapshots", headers={"Authorization": "Bearer other"}, json=body).status_code == 404
    captured = api.post(base + "/snapshots", headers=admin, json=body)
    assert captured.status_code == 200, captured.text
    snapshot = captured.json()["snapshot_id"]
    dep = {"deployment_id": "dep", "agent_id": "agent-a", "snapshot_id": snapshot, "version": "1"}
    assert api.post(base + "/deployments", headers=admin, json=dep).status_code == 200
    inst = {"instance_id": "instance", "deployment_id": "dep", "identity_id": identity.identity_id}
    assert api.post(base + "/instances", headers=admin, json=inst).status_code == 200
    run = api.post(base + "/runs", headers=admin, json={"run_id": "run", "instance_id": "instance"})
    assert run.status_code == 200 and run.json()["snapshot_id"] == snapshot
    identity.status = "revoked"
    assert api.post(base + "/runs", headers=admin, json={"run_id": "new", "instance_id": "instance"}).status_code == 409
    jobs.delete("scan", tenant_id="t")
    exported = api.get(base + "/snapshots/export", headers=admin, params={"snapshot_id": snapshot})
    assert exported.status_code == 200
    assert exported.json()["content"]["subject"]["identity_status"] == "observed"
    assert (
        api.get(base + "/snapshots/export", headers={"Authorization": "Bearer other"}, params={"snapshot_id": snapshot}).status_code == 404
    )
    assert api.delete(base + "/snapshots/export", headers=admin, params={"snapshot_id": snapshot}).status_code == 405


def test_api_refuses_unknown_fields_and_returns_generic_storage_error(client, monkeypatch):
    api, _, _ = client
    headers = {"Authorization": "Bearer admin"}
    url = "/v1/agent-lifecycle/snapshots"
    assert api.post(url, headers=headers, json={"scan_id": "scan", "agent_id": "agent-a", "tenant_id": "other"}).status_code == 422

    def fail():
        raise RuntimeError("private-connection-secret")

    monkeypatch.setattr("agent_bom.api.routes.agent_lifecycle.get_lifecycle_store", fail)
    response = api.post(url, headers=headers, json={"scan_id": "scan", "agent_id": "agent-a"})
    assert response.status_code == 503
    assert "private-connection-secret" not in response.text
