"""Read-path fixes for the compliance-hub / overview surface.

Covers four findings fixed in one coherent change:

- **P1b exec-headline honesty.** The overview / posture ``critical`` & ``high``
  now derive from the SAME source + semantics as ``/v1/findings``
  (current-state ``hub_findings_current``, bulk origin, default read-window), so
  a click-through reconciles exactly. A stale / retired finding that lingers
  forever in the append-only ledger (``compliance_hub_findings``) no longer
  inflates the exec headline.
- **P1a event-loop.** ``/v1/compliance/hub/posture`` offloads its synchronous
  store work off the loop under adaptive backpressure and sheds with ``429``;
  the framework count aggregates in SQL instead of pulling every row into
  Python.
- **Cross-tenant isolation** of the SQL framework count + current-state
  severity breakdown.
- **Empty estate** renders an honest zero headline (buckets sum to total).
- **P3 ordinal keyset** no longer dup/drops: cursor pagination over
  ``sort=ordinal`` is rejected explicitly rather than filtering by the wrong
  key.
"""

from __future__ import annotations

from datetime import datetime, timedelta, timezone

import pytest
from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import reset_compliance_hub_store
from agent_bom.api.server import app
from tests.auth_helpers import disable_trusted_proxy_env, enable_trusted_proxy_env, proxy_headers


def setup_module() -> None:
    enable_trusted_proxy_env()


def teardown_module() -> None:
    disable_trusted_proxy_env()


@pytest.fixture(autouse=True)
def _reset(monkeypatch):
    from agent_bom.api import hub_overview_cache
    from agent_bom.api.findings_count_cache import reset_findings_count_cache
    from agent_bom.api.routes import overview as overview_routes
    from agent_bom.api.server import set_job_store
    from agent_bom.api.store import InMemoryJobStore

    # Force fresh reads: no cached overview / severity / count between assertions.
    monkeypatch.setenv("AGENT_BOM_OVERVIEW_CACHE_TTL_SECONDS", "0")
    monkeypatch.setenv("AGENT_BOM_HUB_OVERVIEW_CACHE_TTL_SECONDS", "0")
    reset_compliance_hub_store()
    set_job_store(InMemoryJobStore())
    hub_overview_cache.reset_hub_overview_cache()
    overview_routes._reset_overview_cache()
    reset_findings_count_cache()
    yield
    reset_compliance_hub_store()
    set_job_store(InMemoryJobStore())
    hub_overview_cache.reset_hub_overview_cache()


def _client(tenant: str = "tenant-alpha", role: str = "admin") -> TestClient:
    client = TestClient(app)
    client.headers.update(proxy_headers(role=role, tenant=tenant))
    return client


def _now() -> datetime:
    return datetime.now(timezone.utc)


def _ingest(client: TestClient, findings: list[dict], *, observed_at: str | None = None, source: str = "connector") -> None:
    body: dict = {"findings": findings, "source": source}
    if observed_at is not None:
        body["observed_at"] = observed_at
    resp = client.post("/v1/findings/bulk", json=body)
    assert resp.status_code == 201, resp.text


def _findings_total(client: TestClient, severity: str) -> int:
    resp = client.get(f"/v1/findings?severity={severity}")
    assert resp.status_code == 200, resp.text
    return int(resp.json()["total"])


def _put_scan(*, scan_id: str, completed_at: datetime, result: dict) -> None:
    """Persist a completed scan without going through the asynchronous runner."""
    from agent_bom.api.models import JobStatus, ScanJob, ScanRequest
    from agent_bom.api.stores import _get_store

    stamp = completed_at.isoformat()
    _get_store().put(
        ScanJob(
            job_id=scan_id,
            tenant_id="tenant-alpha",
            status=JobStatus.DONE,
            created_at=stamp,
            completed_at=stamp,
            request=ScanRequest(),
            result=result,
        )
    )


# ═══════════════════════════════════════════════════════════════════════════
# P1b — exec headline reconciles with the /v1/findings drill-down
# ═══════════════════════════════════════════════════════════════════════════


class TestExecHeadlineReconciliation:
    def test_stale_scan_is_excluded_from_all_exec_severity_surfaces(self) -> None:
        """The default findings window also bounds scan-derived exec counts."""
        client = _client()
        _put_scan(
            scan_id="stale-scan",
            completed_at=_now() - timedelta(days=400),
            result={"findings": [{"id": "stale-critical", "severity": "critical"}]},
        )

        assert _findings_total(client, "critical") == 0
        assert client.get("/v1/overview").json()["headline"]["critical"] == 0
        assert client.get("/v1/posture/counts").json()["critical"] == 0

    def test_blast_radius_rescans_are_deduped_across_exec_surfaces(self) -> None:
        """Repeated evidence for one CVE/package is one current finding."""
        client = _client()
        blast = {
            "blast_radius": [
                {
                    "vulnerability_id": "CVE-2026-4106",
                    "package": "shared-lib@1.0.0",
                    "severity": "critical",
                    "risk_score": 9.8,
                }
            ]
        }
        _put_scan(scan_id="rescan-1", completed_at=_now() - timedelta(days=2), result=blast)
        _put_scan(scan_id="rescan-2", completed_at=_now() - timedelta(days=1), result=blast)

        assert _findings_total(client, "critical") == 1
        assert client.get("/v1/overview").json()["headline"]["critical"] == 1
        assert client.get("/v1/posture/counts").json()["critical"] == 1

    def test_overview_headline_equals_findings_drilldown_for_same_window(self) -> None:
        """overview critical/high == /v1/findings critical/high (reconcile invariant).

        Seeds recent findings PLUS a stale critical + stale high whose
        ``last_seen`` is well outside the default read-window. The append-only
        ledger keeps the stale rows forever, so the old ledger-based headline
        over-counted; the current-state windowed derivation must match the
        drill-down exactly.
        """
        client = _client()
        # Recent, in-window evidence.
        _ingest(
            client,
            [
                {"id": "c-1", "severity": "critical"},
                {"id": "c-2", "severity": "critical"},
                {"id": "h-1", "severity": "high"},
                {"id": "m-1", "severity": "medium"},
            ],
        )
        # Stale evidence — outside the default window, lingers in the ledger.
        stale = (_now() - timedelta(days=400)).isoformat()
        _ingest(
            client,
            [
                {"id": "c-stale", "severity": "critical"},
                {"id": "h-stale", "severity": "high"},
            ],
            observed_at=stale,
            source="stale-connector",
        )

        findings_critical = _findings_total(client, "critical")
        findings_high = _findings_total(client, "high")
        # Drill-down is windowed to the recent evidence only.
        assert findings_critical == 2
        assert findings_high == 1

        headline = client.get("/v1/overview").json()["headline"]
        counts = client.get("/v1/posture/counts").json()

        # The reconciliation invariant: click-through matches the headline.
        assert headline["critical"] == findings_critical
        assert headline["high"] == findings_high
        assert counts["critical"] == findings_critical
        assert counts["high"] == findings_high

    def test_retired_finding_does_not_inflate_exec_headline(self) -> None:
        """A resolved + aged finding never inflates the exec headline (#3961/#4009).

        The finding is resolved (reconciled absent) AND aged past the window, so
        it lives only in the append-only ledger. The exec headline must exclude
        it and reconcile with the (empty) drill-down.
        """
        client = _client()
        from agent_bom.api.compliance_hub_store import get_compliance_hub_store

        stale = (_now() - timedelta(days=400)).isoformat()
        _ingest(client, [{"id": "gone-crit", "severity": "critical"}], observed_at=stale, source="dead")
        # Retire it: reconcile it absent so its current-state status is resolved.
        get_compliance_hub_store().reconcile_current_absent(
            "tenant-alpha",
            present_canonical_ids=set(),
            observed_at=stale,
            scope_source="dead",
        )

        assert _findings_total(client, "critical") == 0
        headline = client.get("/v1/overview").json()["headline"]
        assert headline["critical"] == 0
        # The full-bucket exec counts still sum to total honestly.
        counts = client.get("/v1/posture/counts").json()
        assert counts["critical"] == 0
        assert counts["total"] == sum(counts[k] for k in ("critical", "high", "medium", "low", "unrated"))

    def test_empty_estate_headline_is_honest_zero(self) -> None:
        """Zero-finding tenant: no NaN, no implied pass, buckets sum to total."""
        client = _client()
        headline = client.get("/v1/overview").json()["headline"]
        assert headline["critical"] == 0 and headline["high"] == 0
        counts = client.get("/v1/posture/counts").json()
        for band in ("critical", "high", "medium", "low", "unrated", "total"):
            assert counts[band] == 0, counts
        assert counts["total"] == sum(counts[k] for k in ("critical", "high", "medium", "low", "unrated"))

    def test_headline_is_tenant_scoped(self) -> None:
        """Tenant B's exec headline never leaks tenant A's findings."""
        a = _client(tenant="tenant-a")
        b = _client(tenant="tenant-b")
        _ingest(a, [{"id": "a-crit", "severity": "critical"}])
        assert a.get("/v1/overview").json()["headline"]["critical"] == 1
        assert b.get("/v1/overview").json()["headline"]["critical"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# P1a — posture offload + SQL framework counts
# ═══════════════════════════════════════════════════════════════════════════


class TestPostureOffload:
    def test_posture_sheds_with_429_when_backpressure_opens(self, monkeypatch) -> None:
        """/v1/compliance/hub/posture offloads off the loop and sheds under load."""
        from agent_bom.api.routes import compliance as compliance_routes
        from agent_bom.backpressure import reset_backpressure_for_tests

        monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_COMPLIANCE_P99_MS", "1")
        monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_COMPLIANCE_MIN_SAMPLES", "1")
        monkeypatch.setenv("AGENT_BOM_BACKPRESSURE_COMPLIANCE_COOLDOWN_SECONDS", "30")
        reset_backpressure_for_tests()

        import time

        original = compliance_routes._get_hub_posture_impl

        def _slow(request):
            time.sleep(0.01)
            return original(request)

        monkeypatch.setattr(compliance_routes, "_get_hub_posture_impl", _slow)
        client = _client()
        try:
            statuses = {client.get("/v1/compliance/hub/posture").status_code for _ in range(6)}
        finally:
            reset_backpressure_for_tests()
        assert 429 in statuses, statuses

    def test_posture_returns_reconciled_shape(self) -> None:
        client = _client()
        _ingest(
            client,
            [{"id": "f-1", "severity": "high", "applicable_frameworks": ["soc2", "iso-27001"]}],
        )
        body = client.get("/v1/compliance/hub/posture").json()
        assert body["totals"]["hub"] == 1
        assert body["framework_counts"]["hub"].get("soc2") == 1
        assert body["framework_counts"]["hub"].get("iso-27001") == 1


# ═══════════════════════════════════════════════════════════════════════════
# Store layer — SQL framework counts + current-state severity breakdown
# ═══════════════════════════════════════════════════════════════════════════


def _seed_ledger(store, tenant: str, rows: list[dict]) -> None:
    store.add(tenant, rows)


def _seed_current(store, tenant: str, finding: dict, *, observed_at: str, source: str = "connector") -> None:
    store.upsert_current_batch(
        tenant,
        [finding],
        observed_at=observed_at,
        batch_id=f"b-{finding['id']}",
        source=source,
    )


@pytest.fixture(params=["memory", "sqlite"])
def store(request):
    from agent_bom.api.compliance_hub_store import InMemoryComplianceHubStore, SQLiteComplianceHubStore

    if request.param == "memory":
        return InMemoryComplianceHubStore()
    return SQLiteComplianceHubStore(":memory:")


class TestFrameworkSlugCountsSql:
    def test_counts_normalize_and_merge_aliases(self, store) -> None:
        """Underscore / alias slug variants collapse to one canonical count."""
        _seed_ledger(
            store,
            "t1",
            [
                {"id": "f1", "severity": "high", "applicable_frameworks": ["iso_27001", "soc2"]},
                {"id": "f2", "severity": "low", "applicable_frameworks": ["ISO-27001"]},
                {"id": "f3", "severity": "low", "applicable_frameworks": []},
            ],
        )
        counts = store.framework_slug_counts("t1")
        # ``iso_27001`` (underscore) and ``ISO-27001`` (case) fold to one slug.
        assert counts.get("iso-27001") == 2
        assert counts.get("soc2") == 1

    def test_framework_counts_are_tenant_scoped(self, store) -> None:
        _seed_ledger(store, "t1", [{"id": "f1", "severity": "high", "applicable_frameworks": ["soc2"]}])
        _seed_ledger(store, "t2", [{"id": "f2", "severity": "high", "applicable_frameworks": ["pci-dss"]}])
        assert store.framework_slug_counts("t1") == {"soc2": 1}
        assert store.framework_slug_counts("t2") == {"pci-dss": 1}


class TestCurrentSeverityBreakdown:
    def test_matches_list_current_page_count_by_construction(self, store) -> None:
        """The exec breakdown counts exactly what /v1/findings counts.

        Same table, same tenant/origin/window filters, so the per-severity sum
        equals ``list_current_page`` COUNT for each band.
        """
        now = _now()
        recent = (now - timedelta(days=1)).isoformat()
        stale = (now - timedelta(days=400)).isoformat()
        # bulk origin so both surfaces agree on origin scope.
        _seed_current(store, "t1", {"id": "r1", "severity": "critical", "origin": "bulk_ingest"}, observed_at=recent)
        _seed_current(store, "t1", {"id": "r2", "severity": "high", "origin": "bulk_ingest"}, observed_at=recent)
        _seed_current(store, "t1", {"id": "old", "severity": "critical", "origin": "bulk_ingest"}, observed_at=stale)

        from agent_bom.api import time_window

        since = time_window.window_since_iso(90, now=now)
        breakdown = store.current_severity_breakdown("t1", origin="bulk_ingest", since=since)
        # Drill-down COUNT for the same window.
        _rows, crit_total, _c = store.list_current_page("t1", limit=100, severity="critical", origin="bulk_ingest", since=since)
        assert breakdown["critical"] == crit_total == 1
        assert breakdown["high"] == 1

    def test_current_severity_breakdown_is_tenant_scoped(self, store) -> None:
        now = _now()
        recent = (now - timedelta(days=1)).isoformat()
        _seed_current(store, "t1", {"id": "a", "severity": "critical", "origin": "bulk_ingest"}, observed_at=recent)
        _seed_current(store, "t2", {"id": "b", "severity": "critical", "origin": "bulk_ingest"}, observed_at=recent)
        b1 = store.current_severity_breakdown("t1", origin="bulk_ingest", since=None)
        b2 = store.current_severity_breakdown("t2", origin="bulk_ingest", since=None)
        assert b1["critical"] == 1
        assert b2["critical"] == 1
        # No collision / leak across tenants.
        assert store.current_severity_breakdown("t3", origin="bulk_ingest", since=None)["critical"] == 0


# ═══════════════════════════════════════════════════════════════════════════
# P3 — ordinal keyset does not dup/drop
# ═══════════════════════════════════════════════════════════════════════════


class TestOrdinalKeyset:
    def test_ordinal_offset_walk_has_no_dup_or_drop(self, store) -> None:
        now = _now()
        recent = (now - timedelta(days=1)).isoformat()
        for i in range(6):
            _seed_current(store, "t1", {"id": f"f{i}", "severity": "high", "origin": "bulk_ingest"}, observed_at=recent)
        seen: list[str] = []
        offset = 0
        while True:
            rows, _total, _cursor = store.list_current_page("t1", limit=2, offset=offset, sort="ordinal")
            if not rows:
                break
            seen.extend(str(r.get("canonical_id") or r.get("id")) for r in rows)
            offset += 2
        assert len(seen) == len(set(seen)) == 6

    def test_ordinal_emits_no_cursor(self, store) -> None:
        """Ordinal paginates by offset only — no broken keyset cursor is handed out."""
        now = _now()
        recent = (now - timedelta(days=1)).isoformat()
        for i in range(4):
            _seed_current(store, "t1", {"id": f"f{i}", "severity": "high", "origin": "bulk_ingest"}, observed_at=recent)
        _rows, _total, cursor = store.list_current_page("t1", limit=2, sort="ordinal")
        assert not cursor

    def test_ordinal_cursor_is_rejected(self) -> None:
        from agent_bom.api.finding_cursor import decode_finding_cursor, encode_finding_cursor

        crafted = encode_finding_cursor(sort="ordinal", primary=0.0, last_seen="2026-01-01T00:00:00Z", canonical_id="x")
        with pytest.raises(ValueError):
            decode_finding_cursor(crafted, expected_sort="ordinal")
