"""Pushed evidence replaces only the same explicitly identified target."""

import os
from uuid import uuid4

import pytest

from agent_bom.api.findings_current import current_scan_findings, scan_scope_key
from agent_bom.api.models import PushPayload, ScanRequest
from agent_bom.api.routes.observability import _normalize_pushed_report
from tests.api.test_scan_job_sla_history import (
    get_rows,
    job,
    scan_store,  # noqa: F401
)


def pushed(month, *, scope=None, empty=False, partial=False):
    row = job(month, findings=[] if empty else None)
    row.target = None
    row.request = ScanRequest()
    row.source_id = "one-host"
    row.result.update(pushed=True, target_scope=scope, scan_run={"outcome": "partial" if partial else "complete"})
    for finding in row.result["findings"]:
        finding.update(id=f"finding-{month}", canonical_id=f"finding-{month}")
    return row


@pytest.mark.parametrize("legacy", [False, True])
def test_tiny_push_cannot_remove_other_repositories(scan_store, legacy):  # noqa: F811
    first = pushed(6, scope=None if legacy else "v1:" + "a" * 64)
    second = pushed(7, scope=None if legacy else "v1:" + "b" * 64)
    tiny = pushed(8, scope=None if legacy else "v1:" + "c" * 64, empty=True)
    for row in (first, second, tiny):
        scan_store.put(row)
    assert {f["canonical_id"] for f in get_rows()} == {"finding-6", "finding-7"}


def test_complete_rescan_replaces_only_its_target(scan_store):  # noqa: F811
    for row in (pushed(6, scope="v1:" + "a" * 64), pushed(7, scope="v1:" + "b" * 64), pushed(8, scope="v1:" + "a" * 64, empty=True)):
        scan_store.put(row)
    assert {f["canonical_id"] for f in get_rows()} == {"finding-7"}


def test_partial_push_marks_only_its_own_prior_findings_unreconfirmed():
    rows = [
        pushed(6, scope="v1:" + "a" * 64),
        pushed(7, scope="v1:" + "b" * 64),
        pushed(8, scope="v1:" + "a" * 64, empty=True, partial=True),
    ]
    findings = current_scan_findings(rows, since=None, scan_id=None, iter_findings=lambda row: row.result["findings"])
    statuses = {f["canonical_id"]: f["observation_status"] for f in findings}
    assert statuses == {"finding-6": "unreconfirmed", "finding-7": "observed"}


def test_scope_still_separates_source_hosts():
    first, second = pushed(6, scope="v1:" + "a" * 64), pushed(7, scope="v1:" + "a" * 64)
    second.source_id = "other-host"
    assert scan_scope_key(first) != scan_scope_key(second)


def test_server_assigned_targets_keep_their_existing_scope():
    first, second = pushed(6), pushed(7)
    first.target, second.target = {"path": "repo-a"}, {"path": "repo-b"}
    assert scan_scope_key(first) != scan_scope_key(second)


def test_legacy_push_discloses_non_replacement_without_inventing_scan_failure():
    report = _normalize_pushed_report(PushPayload(source_id="one-host"), fallback_scan_id="legacy")
    assert report["replacement_scope_status"] == "unscoped"
    assert report["scan_run"]["outcome"] == "complete"
    assert any(i["code"] == "push_target_unscoped" and not i["affects_coverage"] for i in report["scan_run"]["issues"])


def test_push_http_route_preserves_targets_after_readback(scan_store):  # noqa: F811
    from starlette.testclient import TestClient

    from agent_bom.api.server import app
    from tests.auth_helpers import proxy_headers

    with TestClient(app) as client:
        client.headers.update(proxy_headers(role="analyst", tenant="history-tenant"))
        for row in (pushed(6, scope="v1:" + "a" * 64), pushed(7, scope="v1:" + "b" * 64), pushed(8, scope="v1:" + "c" * 64, empty=True)):
            response = client.post("/v1/results/push", json={**row.result, "source_id": row.source_id})
            assert response.status_code == 201, response.text
            assert response.json()["target_scope"] == row.result["target_scope"]
            assert response.json()["replacement_scope_status"] == "identified"
    assert {f["canonical_id"] for f in get_rows()} == {"finding-6", "finding-7"}


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires isolated live Postgres")
def test_postgres_pushed_targets_survive_reconnect_and_tenant_isolation():
    from agent_bom.api import postgres_common
    from agent_bom.api.postgres_job_store import PostgresJobStore

    tenant = f"push-scope-{uuid4().hex}"
    token = postgres_common.set_current_tenant(tenant)
    postgres_common.reset_pool()
    try:
        store = PostgresJobStore()
        with store._pool.connection() as connection:
            role = connection.execute("SELECT rolsuper, rolbypassrls FROM pg_roles WHERE rolname = current_user").fetchone()
            assert role == (False, False)
        rows = [pushed(6, scope="v1:" + "a" * 64), pushed(7, scope="v1:" + "b" * 64), pushed(8, scope="v1:" + "c" * 64, empty=True)]
        for row in rows:
            row.tenant_id = tenant
            store.put(row)
        store._pool.close()
        postgres_common.reset_pool()
        reconnected = PostgresJobStore()
        restored = reconnected.list_all(tenant_id=tenant)
        findings = current_scan_findings(restored, since=None, scan_id=None, iter_findings=lambda row: row.result["findings"])
        assert {f["canonical_id"] for f in findings} == {"finding-6", "finding-7"}
        assert reconnected.list_all(tenant_id="unrelated-tenant") == []
        with reconnected._pool.connection() as connection:
            connection.execute("SELECT set_config('app.tenant_id', 'unrelated-tenant', true)")
            assert connection.execute("SELECT count(*) FROM scan_jobs WHERE team_id = %s", (tenant,)).fetchone()[0] == 0
    finally:
        postgres_common.reset_pool()
        postgres_common.reset_current_tenant(token)
