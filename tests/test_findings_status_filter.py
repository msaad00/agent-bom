"""Lifecycle-status filter on the read path (open / resolved / all).

After a full-sync ingest resolves absent findings via reconcile, the read
surfaces used to still rank + count resolved rows as if live: /v1/findings had
no status filter and /v1/overview folded resolved rows into the exec headline.
The lifecycle ``status`` column (open|reopened|resolved) is now a first-class,
sargable filter on list_current_page + current_severity_breakdown across all
backends, defaulting to the live posture (open+reopened) on the API.
"""

from __future__ import annotations

import tempfile
from uuid import uuid4

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
    set_compliance_hub_store,
)
from agent_bom.api.finding_lifecycle import collect_present_canonical_ids
from agent_bom.api.server import app, set_job_store
from agent_bom.api.store import InMemoryJobStore
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers

_AUTH = proxy_headers(tenant="default")


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()
    set_job_store(InMemoryJobStore())
    set_compliance_hub_store(InMemoryComplianceHubStore())


def _reset_caches() -> None:
    from agent_bom.api import hub_overview_cache
    from agent_bom.api.findings_count_cache import invalidate_tenant
    from agent_bom.api.routes.overview import _reset_overview_cache

    invalidate_tenant("default")
    hub_overview_cache.invalidate_tenant("default")
    _reset_overview_cache()


def _seed_and_resolve(findings: list[dict], keep_open: list[dict], *, tenant: str = "default") -> SQLiteComplianceHubStore:
    tmp = tempfile.mkdtemp()
    store = SQLiteComplianceHubStore(f"{tmp}/status.db")
    store.add(tenant, findings)
    store.upsert_current_batch(tenant, findings, observed_at="2026-07-18T00:00:00Z", batch_id="b", source="test")
    present = collect_present_canonical_ids(keep_open, source="test")
    resolved = store.reconcile_current_absent(tenant, present_canonical_ids=present, observed_at="2026-07-18T06:00:00Z")
    assert resolved == len(findings) - len(keep_open), "reconcile did not resolve the expected absent rows"
    set_compliance_hub_store(store)
    set_job_store(InMemoryJobStore())
    _reset_caches()
    return store


def _mk(idx: int, sev: str) -> dict:
    return {
        "id": f"f-{idx:04d}",
        "severity": sev,
        "effective_reach_score": float(idx % 20),
        "provider": "aws" if idx % 2 == 0 else "gcp",
        "account_ref": "aws:1",
        "environment": "prod",
        "security_domain": "cspm",
        "origin": "bulk_ingest",
        "source": "test",
        "batch_id": "b",
    }


def test_default_findings_excludes_resolved() -> None:
    findings = [_mk(i, "high") for i in range(50)]
    keep_open = findings[:10]  # resolve 40
    _seed_and_resolve(findings, keep_open)
    client = TestClient(app)

    resp = client.get("/v1/findings?limit=1000", headers=_AUTH)
    assert resp.status_code == 200
    ids = {f["id"] for f in resp.json()["findings"]}
    assert ids == {f["id"] for f in keep_open}, "default view must show ONLY open findings"
    assert resp.json()["total"] == 10  # exact open COUNT on the non-scope path


def test_status_all_includes_resolved() -> None:
    findings = [_mk(i, "high") for i in range(50)]
    keep_open = findings[:10]
    _seed_and_resolve(findings, keep_open)
    client = TestClient(app)

    resp = client.get("/v1/findings?status=all&limit=1000", headers=_AUTH)
    assert resp.status_code == 200
    ids = {f["id"] for f in resp.json()["findings"]}
    assert ids == {f["id"] for f in findings}
    assert resp.json()["total"] == 50


def test_status_resolved_returns_only_resolved() -> None:
    findings = [_mk(i, "high") for i in range(50)]
    keep_open = findings[:10]
    _seed_and_resolve(findings, keep_open)
    client = TestClient(app)

    resp = client.get("/v1/findings?status=resolved&limit=1000", headers=_AUTH)
    assert resp.status_code == 200
    ids = {f["id"] for f in resp.json()["findings"]}
    assert ids == {f["id"] for f in findings[10:]}
    assert resp.json()["total"] == 40


def test_invalid_status_rejected_422() -> None:
    findings = [_mk(i, "high") for i in range(5)]
    _seed_and_resolve(findings, findings)  # resolve none
    client = TestClient(app)
    resp = client.get("/v1/findings?status=bogus", headers=_AUTH)
    assert resp.status_code == 422
    assert "status" in resp.text.lower()


def test_current_severity_breakdown_status_filter() -> None:
    tenant = f"bd-{uuid4().hex}"
    findings = [_mk(i, "critical") for i in range(30)]
    keep_open = findings[:5]  # resolve 25
    with tempfile.TemporaryDirectory() as tmp:
        store = SQLiteComplianceHubStore(f"{tmp}/bd.db")
        store.add(tenant, findings)
        store.upsert_current_batch(tenant, findings, observed_at="2026-07-18T00:00:00Z", batch_id="b", source="test")
        present = collect_present_canonical_ids(keep_open, source="test")
        store.reconcile_current_absent(tenant, present_canonical_ids=present, observed_at="2026-07-18T06:00:00Z")

        open_bd = store.current_severity_breakdown(tenant, origin="bulk_ingest", status="open")
        assert open_bd["critical"] == 5, "default/open breakdown must exclude resolved"
        resolved_bd = store.current_severity_breakdown(tenant, origin="bulk_ingest", status="resolved")
        assert resolved_bd["critical"] == 25
        all_bd = store.current_severity_breakdown(tenant, origin="bulk_ingest", status="all")
        assert all_bd["critical"] == 30
        # Legacy callers (no status kwarg) keep all-history behavior.
        legacy_bd = store.current_severity_breakdown(tenant, origin="bulk_ingest")
        assert legacy_bd["critical"] == 30


def test_overview_headline_reflects_open_only() -> None:
    # Scaled repro: 100 findings (all critical), resolve 97 -> the exec headline
    # must reflect only the 3 open, not 100, and the grade must move off "F".
    findings = [_mk(i, "critical") for i in range(100)]
    keep_open = findings[:3]
    _seed_and_resolve(findings, keep_open)
    client = TestClient(app)

    resp = client.get("/v1/overview", headers=_AUTH)
    assert resp.status_code == 200
    data = resp.json()
    assert data["headline"]["critical"] == 3, "resolved rows must NOT inflate the exec headline"
    # /v1/findings default and the headline must reconcile on the open-only basis.
    findings_resp = client.get("/v1/findings?limit=1000", headers=_AUTH)
    assert findings_resp.json()["total"] == 3


def test_status_and_scope_combined_no_dup_no_drop() -> None:
    # 200 findings across aws/gcp; resolve a subset of aws; page provider=aws +
    # status=open by cursor and prove 0-dup/0-drop still holds with BOTH filters.
    findings = [_mk(i, "high") for i in range(200)]
    aws = [f for f in findings if f["provider"] == "aws"]
    keep_open_aws = aws[:40]  # resolve the other 60 aws
    keep_open = keep_open_aws + [f for f in findings if f["provider"] == "gcp"]
    _seed_and_resolve(findings, keep_open)
    client = TestClient(app)

    seen: list[str] = []
    cursors: list[str | None] = []
    cursor: str | None = None
    for _ in range(500):
        url = "/v1/findings?provider=aws&status=open&limit=7"
        if cursor:
            url += f"&cursor={cursor}"
        resp = client.get(url, headers=_AUTH)
        assert resp.status_code == 200
        page = resp.json()["findings"]
        seen.extend(f["id"] for f in page)
        nxt = resp.json().get("next_cursor") or None
        cursors.append(nxt)
        if not nxt:
            break
        cursor = nxt

    assert len(seen) == len(set(seen)), "duplicate ids across status+scope pages"
    assert set(seen) == {f["id"] for f in keep_open_aws}, "status+scope union wrong (dropped/leaked)"
    assert cursors[-1] is None
    # No resolved aws row and no gcp row leaked in.
    resolved_aws_ids = {f["id"] for f in aws[40:]}
    assert not (set(seen) & resolved_aws_ids)
    assert not any(i for i in seen if i in {f["id"] for f in findings if f["provider"] == "gcp"})


def test_status_sql_predicate_single_source_of_truth() -> None:
    from agent_bom.api.compliance_hub_store import status_matches, status_sql_predicate

    # Default open = live posture (open + reopened).
    assert status_sql_predicate("open") == ("status IN (?, ?)", ["open", "reopened"])
    assert status_sql_predicate("open", placeholder="%s") == ("status IN (%s, %s)", ["open", "reopened"])
    assert status_sql_predicate("resolved") == ("status = ?", ["resolved"])
    assert status_sql_predicate("all") == ("", [])
    assert status_sql_predicate(None) == ("", [])  # legacy store callers: no predicate
    # In-memory mirror: a row with no lifecycle status is treated as open.
    assert status_matches({}, "open") is True
    assert status_matches({"status": "resolved"}, "open") is False
    assert status_matches({"status": "reopened"}, "open") is True
    assert status_matches({"status": "resolved"}, "resolved") is True
    assert status_matches({"status": "resolved"}, "all") is True
    assert status_matches({"status": "resolved"}, None) is True


class _RecordingPGCursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _RecordingPGConn:
    def __init__(self):
        self.calls: list[tuple[str, tuple]] = []

    def execute(self, sql, params=None):
        flat = " ".join(sql.split())
        self.calls.append((flat, tuple(params or ())))
        if "GROUP BY" in flat:
            # Two open (critical), simulating the post-filter GROUP BY result.
            return _RecordingPGCursor([("critical", 2)])
        return _RecordingPGCursor([])


def test_postgres_current_severity_breakdown_status_sql(monkeypatch) -> None:
    """The Postgres backend threads the sargable %s status predicate into the
    exec-headline GROUP BY (verified via generated SQL — no live DB)."""
    from contextlib import contextmanager

    import agent_bom.api.postgres_compliance_hub as pgmod
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    conn = _RecordingPGConn()

    @contextmanager
    def fake_tenant_connection(_pool):
        yield conn

    monkeypatch.setattr(pgmod, "_tenant_connection", fake_tenant_connection)
    store = object.__new__(PostgresComplianceHubStore)
    store._pool = object()

    out = store.current_severity_breakdown("t", origin="bulk_ingest", status="open")
    assert out["critical"] == 2
    group_calls = [(sql, params) for sql, params in conn.calls if "GROUP BY" in sql]
    assert group_calls, "no GROUP BY issued"
    sql, params = group_calls[0]
    assert "status IN (%s, %s)" in sql, "open breakdown must carry the sargable %s status predicate"
    assert "open" in params and "reopened" in params

    # status=all issues NO status predicate.
    conn.calls.clear()
    store.current_severity_breakdown("t", origin="bulk_ingest", status="all")
    all_sql = next(sql for sql, _ in conn.calls if "GROUP BY" in sql)
    assert "status" not in all_sql
