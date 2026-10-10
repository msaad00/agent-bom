"""Registry backend selection must never drop configured Postgres writes."""

import importlib

import pytest


@pytest.mark.parametrize(
    "module,getter,global_name,class_name",
    [
        ("webhook_store", "get_webhook_subscription_store", "_WEBHOOK_SUBSCRIPTION_STORE", "PostgresWebhookSubscriptionStore"),
        ("dataset_version_store", "get_dataset_version_store", "_DATASET_VERSION_STORE", "PostgresDatasetVersionStore"),
        ("evaluation_store", "get_evaluation_run_store", "_EVALUATION_RUN_STORE", "PostgresEvaluationRunStore"),
        ("drift_incident_store", "get_drift_incident_store", "_DRIFT_INCIDENT_STORE", "PostgresDriftIncidentStore"),
    ],
)
@pytest.mark.parametrize("variable", ["AGENT_BOM_DB", "AGENT_BOM_POSTGRES_URL"])
def test_registry_postgres_selection(monkeypatch, module, getter, global_name, class_name, variable):
    owner = importlib.import_module("agent_bom.api." + module)
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv(variable, "postgresql://fixture.invalid/registry")
    monkeypatch.setattr(owner, global_name, None)
    # Pool construction is intercepted, never connect to the fixture DSN.
    monkeypatch.setattr("agent_bom.api.postgres_common._get_pool", lambda: (_ for _ in ()).throw(RuntimeError("selected Postgres")))
    with pytest.raises(RuntimeError, match="selected Postgres"):
        getattr(owner, getter)()


@pytest.mark.parametrize("kind", ["dataset", "evaluation", "webhook", "drift"])
def test_registry_restricted_replicas_and_cross_tenant(kind):
    import os
    from dataclasses import replace
    from uuid import uuid4

    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.storage import registry_stores as stores
    from tests.test_postgres_job_evidence_revision import tenant_scope

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres")
    from psycopg.errors import InsufficientPrivilege

    tenant, other = "registry-" + uuid4().hex, "registry-" + uuid4().hex
    now = "2026-10-07T00:00:00Z"
    cases = {
        "dataset": (stores.PostgresDatasetVersionStore, stores.DatasetVersionRecord(tenant, "ds", "v1", now, "test"), ("ds", "v1")),
        "evaluation": (stores.PostgresEvaluationRunStore, stores.EvaluationRunRecord(tenant, "ev", now, now), ("ev",)),
        "webhook": (
            stores.PostgresWebhookSubscriptionStore,
            stores.WebhookSubscription("hook", tenant, "https://example.com", "test-secret", [], "active", "", now, now),
            ("hook",),
        ),
        "drift": (
            stores.PostgresDriftIncidentStore,
            stores.DriftIncident("drift", tenant, "blueprint", "drift_detected", 1, 1, 0, [], now, now),
            ("drift",),
        ),
    }
    cls, record, keys = cases[kind]
    pools = [_new_application_pool(min_size=1, max_size=2) for _ in range(2)]
    try:
        a, b = (cls(pool=pool) for pool in pools)

        def read(store, tenant_id):
            return store.get(*keys) if kind == "webhook" else store.get(tenant_id, *keys)

        with tenant_scope(tenant):
            a.put(record)
            assert read(b, tenant) == record
            with pytest.raises(InsufficientPrivilege):
                b.put(replace(record, tenant_id=other))
        with tenant_scope(other):
            assert read(b, tenant) is None
            b.put(replace(record, tenant_id=other))
            assert read(a, other).tenant_id == other
        with tenant_scope(tenant):
            assert read(cls(pool=pools[1]), tenant) == record
    finally:
        for pool in pools:
            pool.close()


def test_drift_concurrent_replicas_preserve_occurrences():
    import os
    from concurrent.futures import ThreadPoolExecutor
    from uuid import uuid4

    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.storage.registry_stores import DriftIncident, PostgresDriftIncidentStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres")

    tenant = "drift-" + uuid4().hex
    record = DriftIncident("same", tenant, "bp", "drift_detected", 1, 1, 0, [], "first", "last")
    pools = [_new_application_pool(min_size=1, max_size=2) for _ in range(2)]
    try:
        stores = [PostgresDriftIncidentStore(pool=pool) for pool in pools]

        def write(index):
            with tenant_scope(tenant):
                return stores[index % 2].upsert(record)

        with ThreadPoolExecutor(max_workers=4) as executor:
            list(executor.map(write, range(20)))
        with tenant_scope(tenant):
            assert stores[1].get(tenant, "same").occurrences == 20
            from dataclasses import replace

            changed = stores[0].upsert(replace(record, resolved=True, blueprint_id="other", drift_score=2))
            assert not changed.resolved and changed.blueprint_id == "bp" and changed.drift_score == 2
            resolved = stores[0].resolve(tenant, "same", by="reviewer", note="reviewed", at="done")
            assert resolved.resolved and resolved.resolution_note == "reviewed"
            assert stores[1].upsert(record).occurrences == 1
    finally:
        for pool in pools:
            pool.close()


@pytest.mark.parametrize("kind", ["mcp_observation", "issue_mapping", "skills_scan", "kspm_posture"])
def test_additional_registry_postgres_selection(monkeypatch, kind):
    from agent_bom.api import kspm_posture_store, skills_scan_store, stores

    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.setenv("AGENT_BOM_POSTGRES_URL", "postgresql://fixture.invalid/registry")
    monkeypatch.setattr("agent_bom.api.postgres_common._get_pool", lambda: (_ for _ in ()).throw(RuntimeError("selected Postgres")))
    if kind == "kspm_posture":
        monkeypatch.setattr(kspm_posture_store, "_default_store", None)
        getter = kspm_posture_store.get_kspm_posture_store
    elif kind == "skills_scan":
        monkeypatch.setattr(skills_scan_store, "_default_store", None)
        getter = skills_scan_store.get_skills_scan_store
    else:
        monkeypatch.setattr(stores, "_" + kind + "_store", None)
        getter = getattr(stores, "_get_" + kind + "_store")
    with pytest.raises(RuntimeError, match="selected Postgres|Configured Postgres Skills"):
        getter()


@pytest.mark.parametrize("kind", ["mcp", "skills", "kspm", "issues"])
def test_additional_registry_replica_isolation(kind):
    import os
    from uuid import uuid4

    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.storage import observation_registries as adapters
    from tests.test_postgres_job_evidence_revision import tenant_scope

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres")
    from psycopg.errors import InsufficientPrivilege

    tenant, other = ("registry-" + uuid4().hex for _ in range(2))
    cls = {
        "mcp": adapters.PostgresMCPObservationStore,
        "skills": adapters.PostgresSkillsScanStore,
        "kspm": adapters.PostgresKspmPostureStore,
        "issues": adapters.PostgresIssueMappingStore,
    }[kind]
    pools = [_new_application_pool(min_size=1, max_size=2) for _ in range(2)]
    try:
        a, b = (cls(pool=pool) for pool in pools)

        def write(store, target):
            if kind == "mcp":
                return store.put(
                    adapters.MCPObservation(tenant_id=target, observation_id="same", server_stable_id="server", server_name="test")
                )
            if kind == "skills":
                return store.put(adapters.SkillsScanRun(target, "same", "now", {"findings": 1}))
            if kind == "kspm":
                return store.put(adapters.KspmPostureRun(target, "same", "cluster", "now", {"findings": 1}))
            return store.put(
                tenant_id=target,
                target_kind="finding",
                target_id="same",
                provider="test",
                external_id="one",
                external_url="https://example.com",
            )

        def read(store, target):
            if kind == "mcp":
                return store.get(target, "same")
            if kind in {"skills", "kspm"}:
                return store.latest_for_tenant(target)
            return store.find(tenant_id=target, target_kind="finding", target_id="same", provider="test")

        with tenant_scope(tenant):
            write(a, tenant)
            assert read(b, tenant).tenant_id == tenant
            with pytest.raises(InsufficientPrivilege):
                write(b, other)
        with tenant_scope(other):
            assert read(b, tenant) is None
            write(b, other)
            assert read(a, other).tenant_id == other
        with tenant_scope(tenant):
            assert read(cls(pool=pools[1]), tenant).tenant_id == tenant
            if kind == "issues":
                original = read(a, tenant)
                assert write(b, tenant).mapping_id == original.mapping_id
                assert a.update_status(original.mapping_id, tenant_id=tenant, status="resolved").status == "resolved"
            if kind == "mcp":
                assert b.get_by_server_canonical_id(tenant, "server").observation_id == "same"
    finally:
        for pool in pools:
            pool.close()


@pytest.mark.parametrize(
    "owner_name,getter,global_name,adapter_module,adapter_name",
    [
        ("access_review", "get_access_review_store", "_ACCESS_REVIEW_STORE", "postgres_access_review", "PostgresAccessReviewStore"),
        ("compliance_hub_store", "get_compliance_hub_store", "_HUB_STORE", "postgres_compliance_hub", "PostgresComplianceHubStore"),
        (
            "export_schedule_store",
            "get_export_schedule_store",
            "_EXPORT_SCHEDULE_STORE",
            "storage.export_schedules",
            "PostgresExportScheduleStore",
        ),
        ("runtime_event_store", "get_runtime_event_store", "_RUNTIME_EVENT_STORE", "postgres_runtime_event", "PostgresRuntimeEventStore"),
        ("scan_snapshot_store", "get_scan_snapshot_store", "_default_store", "postgres_scan_snapshot", "PostgresScanSnapshotStore"),
    ],
)
@pytest.mark.parametrize("variable", ["AGENT_BOM_DB", "AGENT_BOM_POSTGRES_URL"])
def test_existing_postgres_adapter_factory(monkeypatch, owner_name, getter, global_name, adapter_module, adapter_name, variable):
    owner = importlib.import_module("agent_bom.api." + owner_name)
    adapter = importlib.import_module("agent_bom.api." + adapter_module)
    sentinel = object()
    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv(variable, "postgresql://fixture.invalid/registry")
    monkeypatch.setattr(owner, global_name, None)
    monkeypatch.setattr(adapter, adapter_name, lambda: sentinel)
    assert getattr(owner, getter)() is sentinel


def test_registry_bootstrap_matches_migration():
    from pathlib import Path

    from agent_bom.api.storage.registry_schema import registry_migration_ddl

    assert registry_migration_ddl() in Path("deploy/supabase/postgres/runtime-schema.sql").read_text()


def test_registry_tables_force_rls_and_reject_forged_bypass():
    import os
    from uuid import uuid4

    from agent_bom.api.postgres_common import _new_application_pool, _tenant_connection
    from agent_bom.api.storage.registry_schema import REGISTRY_TABLES
    from agent_bom.api.storage.registry_stores import DatasetVersionRecord, PostgresDatasetVersionStore
    from tests.test_postgres_job_evidence_revision import tenant_scope

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres")

    pool = _new_application_pool(min_size=1, max_size=2)
    tenant = "registry-" + uuid4().hex
    try:
        with pool.connection() as conn:
            flags = conn.execute("SELECT rolsuper,rolbypassrls FROM pg_roles WHERE rolname=current_user").fetchone()
            assert flags == (False, False)
            for table in REGISTRY_TABLES:
                assert conn.execute(
                    "SELECT relrowsecurity,relforcerowsecurity FROM pg_class WHERE oid=%s::regclass", (table,)
                ).fetchone() == (True, True)
        with tenant_scope(tenant):
            PostgresDatasetVersionStore(pool=pool).put(DatasetVersionRecord(tenant, "ds", "v", "now", "test"))
        with tenant_scope("another-" + uuid4().hex), _tenant_connection(pool) as conn:
            conn.execute("SELECT set_config('app.bypass_rls','1',true)")
            assert conn.execute("SELECT data FROM dataset_versions WHERE tenant_id=%s", (tenant,)).fetchone() is None
    finally:
        pool.close()


def test_existing_access_review_postgres_is_durable_and_tenant_scoped():
    import os
    from dataclasses import replace
    from uuid import uuid4

    from agent_bom.api.access_review import AccessReviewCampaign
    from agent_bom.api.postgres_access_review import PostgresAccessReviewStore
    from agent_bom.api.postgres_common import _new_application_pool
    from tests.test_postgres_job_evidence_revision import tenant_scope

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres")
    from psycopg.errors import InsufficientPrivilege

    tenant, other = ("review-" + uuid4().hex for _ in range(2))
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        a, b = PostgresAccessReviewStore(pool), PostgresAccessReviewStore(pool)
        record = AccessReviewCampaign(
            campaign_id="same", tenant_id=tenant, name="review", status="open", created_at="now", due_at="later", created_by="operator"
        )
        with tenant_scope(tenant):
            a.put_campaign(record)
            assert b.get_campaign("same", tenant) == record
            with pytest.raises(InsufficientPrivilege):
                a.put_campaign(replace(record, tenant_id=other))
        with tenant_scope(other):
            assert b.get_campaign("same", tenant) is None
        with tenant_scope(tenant):
            assert PostgresAccessReviewStore(pool).get_campaign("same", tenant) == record
    finally:
        pool.close()


@pytest.mark.parametrize("variable", ["AGENT_BOM_DB", "AGENT_BOM_POSTGRES_URL"])
def test_runtime_exception_factory_honors_postgres_alias(monkeypatch, variable):
    from agent_bom.api.exception_store import configured_exception_store

    monkeypatch.delenv("AGENT_BOM_DB", raising=False)
    monkeypatch.delenv("AGENT_BOM_POSTGRES_URL", raising=False)
    monkeypatch.setenv(variable, "postgresql://fixture.invalid/registry")
    sentinel = object()
    monkeypatch.setattr("agent_bom.api.postgres_store.PostgresExceptionStore", lambda: sentinel)
    assert configured_exception_store() is sentinel


def test_webhook_signing_secret_is_sealed_at_rest_on_postgres(monkeypatch):
    import os
    from uuid import uuid4

    from cryptography.fernet import Fernet

    from agent_bom.api import connection_crypto, postgres_common
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.storage import registry_stores as stores
    from tests.test_postgres_job_evidence_revision import tenant_scope

    if not os.environ.get("AGENT_BOM_POSTGRES_URL"):
        pytest.skip("requires restricted-role Postgres")
    monkeypatch.setenv("AGENT_BOM_CONNECTIONS_KEY", Fernet.generate_key().decode())
    monkeypatch.delenv("AGENT_BOM_CONNECTIONS_KEY_PROVIDER", raising=False)
    connection_crypto.reset_key_cache()
    tenant = "registry-" + uuid4().hex
    now = "2026-10-07T00:00:00Z"
    sealed = stores.WebhookSubscription("hook-sealed", tenant, "https://example.com", "whsec_pg_plain", [], "active", "", now, now)
    legacy = stores.WebhookSubscription("hook-legacy", tenant, "https://example.com", "whsec_pg_legacy", [], "active", "", now, now)
    pool = _new_application_pool(min_size=1, max_size=2)
    try:
        store = stores.PostgresWebhookSubscriptionStore(pool=pool)
        with tenant_scope(tenant):
            store.put(sealed)
            store._put_record(legacy)  # pre-encryption row shape
            with postgres_common._tenant_connection(pool) as conn:
                rows = conn.execute(
                    "SELECT subscription_id, data->>'signing_secret' FROM webhook_subscriptions WHERE tenant_id=%s", (tenant,)
                )
                raw = dict(rows.fetchall())
            assert raw["hook-sealed"].startswith("enc:v1:")
            assert "whsec_pg_plain" not in raw["hook-sealed"]
            assert raw["hook-legacy"] == "whsec_pg_legacy"
            assert store.get("hook-sealed").signing_secret == "whsec_pg_plain"
            assert store.get("hook-legacy").signing_secret == "whsec_pg_legacy"
            listed = {s.subscription_id: s.signing_secret for s in store.list(tenant)}
            assert listed == {"hook-sealed": "whsec_pg_plain", "hook-legacy": "whsec_pg_legacy"}
    finally:
        pool.close()
        connection_crypto.reset_key_cache()
