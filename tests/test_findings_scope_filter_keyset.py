"""Store-internal scope-filtered keyset pagination for GET /v1/findings.

Regression coverage for the read-path defect where any scope filter
(``?provider=`` / ``?account=`` / ``?environment=`` / ``?domain=``) dropped out
of the batched keyset path into an unbounded whole-tenant materialization that
ignored ``cursor`` and never emitted ``next_cursor``. The scope filter now runs
INSIDE the store on pre-enrichment current rows, batched + keyset-paged, so a
million-row tenant returns a scoped page without loading the table and cursor
pagination continues correctly.
"""

from __future__ import annotations

import tempfile
from uuid import uuid4

from starlette.testclient import TestClient

from agent_bom.api.compliance_hub_store import (
    InMemoryComplianceHubStore,
    SQLiteComplianceHubStore,
    collect_scope_filtered_page,
    set_compliance_hub_store,
)
from agent_bom.api.finding_cursor import cursor_from_current_row
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


def _bulk_findings() -> list[dict]:
    """~300 bulk findings across two providers, ties on effective_reach so the
    keyset tiebreakers (last_seen, canonical_id) are exercised."""
    findings: list[dict] = []
    for idx in range(300):
        provider = "aws" if idx % 2 == 0 else "gcp"
        findings.append(
            {
                "id": f"bulk-{provider}-{idx:04d}",
                "title": f"Finding {idx}",
                "severity": "high" if idx % 3 else "medium",
                # Deliberate ties (idx % 50) to force keyset tiebreak walks.
                "effective_reach_score": float(idx % 50),
                "cvss_score": float(idx % 10),
                "provider": provider,
                "account_ref": f"{provider}:acct-{idx % 4}",
                "environment": "prod" if idx % 2 == 0 else "dev",
                "security_domain": "cspm",
                "origin": "bulk_ingest",
                "source": "test",
                "batch_id": "batch-scope-keyset",
            }
        )
    return findings


def _seed_sqlite_bulk(findings: list[dict]) -> SQLiteComplianceHubStore:
    tmp = tempfile.mkdtemp()
    store = SQLiteComplianceHubStore(f"{tmp}/scope_keyset.db")
    store.add("default", findings)
    store.upsert_current_batch(
        "default",
        findings,
        observed_at="2026-07-18T00:00:00Z",
        batch_id="batch-scope-keyset",
        source="test",
    )
    set_compliance_hub_store(store)
    set_job_store(InMemoryJobStore())  # no in-memory scan findings
    return store


def _drain(client: TestClient, query: str, *, limit: int) -> tuple[list[str], list[str | None]]:
    """Page ``query`` fully by cursor; return (ordered ids, per-page next_cursors)."""
    ids: list[str] = []
    cursors: list[str | None] = []
    cursor: str | None = None
    for _ in range(1000):  # generous guard against a non-terminating loop
        url = f"{query}&limit={limit}"
        if cursor:
            url = f"{url}&cursor={cursor}"
        resp = client.get(url, headers=_AUTH)
        assert resp.status_code == 200, resp.text
        body = resp.json()
        page_ids = [f["id"] for f in body["findings"]]
        ids.extend(page_ids)
        nxt = body.get("next_cursor") or None
        cursors.append(nxt)
        if not nxt:
            break
        cursor = nxt
    else:  # pragma: no cover - loop guard
        raise AssertionError("cursor pagination did not terminate")
    return ids, cursors


def test_provider_scope_cursor_pages_no_dup_no_drop() -> None:
    """(a) ?provider=aws paged by a small cursor page: 0 dup, 0 drop, union ==
    full aws subset, next_cursor emitted between pages and absent on the last."""
    findings = _bulk_findings()
    _seed_sqlite_bulk(findings)
    client = TestClient(app)

    expected_aws = {f["id"] for f in findings if f["provider"] == "aws"}
    assert len(expected_aws) == 150

    ids, cursors = _drain(client, "/v1/findings?provider=aws", limit=25)

    assert len(ids) == len(set(ids)), "duplicate ids across scope-filtered pages"
    assert set(ids) == expected_aws, "scope-filtered union != full aws subset (dropped/leaked rows)"
    assert cursors[-1] is None, "final page must not emit a next_cursor"
    assert all(c is not None for c in cursors[:-1]), "next_cursor must be emitted between pages"
    # No gcp row ever leaked into an aws-scoped page.
    assert not any(i.startswith("bulk-gcp") for i in ids)


def test_scope_cursor_order_matches_full_scan_reference() -> None:
    """(b) The paged filtered order equals an unfiltered full-scan reference
    restricted to the matching subset, and a single big page == the paged union.
    """
    findings = _bulk_findings()
    _seed_sqlite_bulk(findings)
    client = TestClient(app)

    paged_ids, _ = _drain(client, "/v1/findings?provider=aws", limit=25)

    # Single big page (whole subset in one request) must match the paged order.
    big = client.get("/v1/findings?provider=aws&limit=1000", headers=_AUTH)
    assert big.status_code == 200
    big_ids = [f["id"] for f in big.json()["findings"]]
    assert big_ids == paged_ids, "paged order diverges from single-page order"

    # Full-scan reference: unfiltered big page, then Python-filter to aws.
    ref = client.get("/v1/findings?limit=1000", headers=_AUTH)
    assert ref.status_code == 200
    ref_ids = [f["id"] for f in ref.json()["findings"] if f["id"].startswith("bulk-aws")]
    assert ref_ids == paged_ids, "keyset order not preserved vs full-scan reference"


def test_domain_lens_scope_cursor_pages() -> None:
    """(c) domain filter over the overlapping-lens set (repo dep CVE in
    {vuln, aspm}) paged by cursor."""
    findings: list[dict] = []
    for idx in range(120):
        kind = idx % 3
        base = {
            "effective_reach_score": float(idx % 20),
            "origin": "bulk_ingest",
            "source_batch": "batch-lens",
            "batch_id": "batch-lens",
        }
        if kind == 0:  # repo dependency CVE -> lens {vuln, aspm}
            findings.append(
                {
                    "id": f"repo-cve-{idx:04d}",
                    "severity": "high",
                    "security_domain": "vuln",
                    "source": "SBOM",
                    "finding_type": "CVE",
                    "cve_id": f"CVE-2025-{idx:04d}",
                    **base,
                }
            )
        elif kind == 1:  # SAST -> lens {aspm}
            findings.append(
                {
                    "id": f"sast-{idx:04d}",
                    "severity": "medium",
                    "security_domain": "aspm",
                    "source": "SAST",
                    "finding_type": "SAST",
                    **base,
                }
            )
        else:  # container image CVE -> lens {vuln} only
            findings.append(
                {
                    "id": f"img-cve-{idx:04d}",
                    "severity": "low",
                    "security_domain": "vuln",
                    "source": "CONTAINER",
                    "finding_type": "CVE",
                    "cve_id": f"CVE-2025-9{idx:03d}",
                    **base,
                }
            )
    _seed_sqlite_bulk(findings)
    client = TestClient(app)

    expected_aspm = {f["id"] for f in findings if f["id"].startswith(("repo-cve", "sast"))}
    ids, cursors = _drain(client, "/v1/findings?domain=aspm", limit=15)
    assert len(ids) == len(set(ids))
    assert set(ids) == expected_aspm
    assert cursors[-1] is None
    assert not any(i.startswith("img-cve") for i in ids)


def test_sqlite_list_current_page_scope_no_dup_no_drop() -> None:
    """Store-level unit: list_current_page(scope=...) 0-dup/0-drop + honest
    next_cursor, with total=None under a scope filter (approximate)."""
    tenant = f"scope-{uuid4().hex}"
    findings = []
    for idx in range(200):
        provider = "aws" if idx % 2 == 0 else "gcp"
        findings.append(
            {
                "id": f"f-{provider}-{idx:04d}",
                "severity": "high",
                "effective_reach_score": float(idx % 30),
                "provider": provider,
                "account_ref": f"{provider}:a",
                "environment": "prod",
                "security_domain": "cspm",
                "origin": "bulk_ingest",
                "source": "test",
                "batch_id": "b",
            }
        )
    with tempfile.TemporaryDirectory() as tmp:
        store = SQLiteComplianceHubStore(f"{tmp}/unit.db")
        store.add(tenant, findings)
        store.upsert_current_batch(tenant, findings, observed_at="2026-07-18T00:00:00Z", batch_id="b", source="test")

        seen: list[str] = []
        cursor = None
        pages = 0
        while True:
            rows, total, nxt = store.list_current_page(
                tenant, limit=17, origin="bulk_ingest", cursor=cursor, scope={"provider": "aws"}, include_total=False
            )
            assert total is None  # scope => no O(table) COUNT
            seen.extend(r["id"] for r in rows)
            pages += 1
            if not nxt:
                break
            cursor = nxt
            assert pages < 500
        expected = {f["id"] for f in findings if f["provider"] == "aws"}
        assert len(seen) == len(set(seen))
        assert set(seen) == expected


def test_collect_scope_filtered_page_helper_no_dup_no_drop() -> None:
    """The shared free-function helper: multi-batch fetch, predicate filter,
    0-dup/0-drop, next_cursor only while more matches remain."""
    # 40 rows; even index matches; batches of 7.
    rows = [
        {
            "canonical_id": f"c{idx:03d}",
            "effective_reach_score": float(40 - idx),  # strictly descending -> deterministic
            "last_seen": "2026-07-18T00:00:00Z",
            "match": idx % 2 == 0,
            "payload": {"id": f"r{idx:03d}", "match": idx % 2 == 0},
        }
        for idx in range(40)
    ]

    def make_fetch(batch_size: int):
        # Serve rows in keyset order, honoring the batch cursor by canonical_id.
        def fetch(cursor, limit):
            start = 0
            if cursor:
                # decode: our cursor's canonical_id is the last emitted row id
                from agent_bom.api.finding_cursor import decode_finding_cursor

                _, _, canon = decode_finding_cursor(cursor, expected_sort="effective_reach")
                start = next(i for i, r in enumerate(rows) if r["canonical_id"] == canon) + 1
            window = rows[start : start + batch_size + 1]
            more = len(window) > batch_size
            window = window[:batch_size]
            pairs = [(r, r["payload"]) for r in window]
            nxt = cursor_from_current_row(window[-1], sort="effective_reach") if more and window else None
            return pairs, nxt

        return fetch

    payloads, next_cursor = collect_scope_filtered_page(
        make_fetch(7),
        predicate=lambda p: p["match"],
        page_limit=5,
        start_cursor=None,
        sort="effective_reach",
        batch_size=7,
    )
    assert [p["id"] for p in payloads] == ["r000", "r002", "r004", "r006", "r008"]
    assert next_cursor is not None

    # Drain the whole matching stream and assert 0-dup/0-drop.
    seen: list[str] = []
    cursor = None
    for _ in range(100):
        page, nxt = collect_scope_filtered_page(
            make_fetch(7),
            predicate=lambda p: p["match"],
            page_limit=5,
            start_cursor=cursor,
            sort="effective_reach",
            batch_size=7,
        )
        seen.extend(p["id"] for p in page)
        if not nxt:
            break
        cursor = nxt
    expected = [f"r{idx:03d}" for idx in range(40) if idx % 2 == 0]
    assert seen == expected
    assert len(seen) == len(set(seen))


# --------------------------------------------------------------------------- #
# Focused Postgres backend coverage (no live DB): a fake connection returns
# fixture current-rows in keyset order, honoring the keyset WHERE + LIMIT the
# store issues, so the real PostgresComplianceHubStore._list_current_page_scoped
# code path (query build + keyset clause + batched collect loop + hydration +
# enrichment) is exercised. Proves 0-dup/0-drop + %s keyset SQL across batches.
# --------------------------------------------------------------------------- #


class _FakePGCursor:
    def __init__(self, rows):
        self._rows = rows

    def fetchone(self):
        return self._rows[0] if self._rows else None

    def fetchall(self):
        return self._rows


class _FakePGConn:
    """Faithful-enough stand-in: serves the SELECT over an ordered master list,
    honoring the keyset canonical_id param + LIMIT the store builds."""

    def __init__(self, master):
        self.master = master  # list of current-row dicts, keyset order
        self.select_calls: list[tuple[str, tuple]] = []

    def execute(self, sql, params=None):
        flat = " ".join(sql.split())
        if "information_schema.columns" in flat:
            return _FakePGCursor([])  # has_ledger_col -> False
        if "FROM hub_findings_current" in flat and flat.upper().startswith("SELECT CANONICAL_ID"):
            self.select_calls.append((flat, tuple(params or ())))
            params = list(params or ())
            fetch_limit = int(params[-1])
            has_keyset = "effective_reach_score <" in flat
            start = 0
            if has_keyset:
                canonical = params[-2]  # trailing keyset param is canonical_id
                start = next(i for i, r in enumerate(self.master) if r["canonical_id"] == canonical) + 1
            window = self.master[start : start + fetch_limit]
            return _FakePGCursor([self._as_tuple(r) for r in window])
        return _FakePGCursor([])

    @staticmethod
    def _as_tuple(r):
        # 13 columns (no ledger col): canonical_id..updated_at, payload
        return (
            r["canonical_id"],
            r["first_seen"],
            r["last_seen"],
            r["status"],
            r["severity"],
            r["severity_rank"],
            r["cvss_score"],
            r["effective_reach_score"],
            r["scan_count"],
            None,
            None,
            r["updated_at"],
            r["payload"],
        )


def test_postgres_list_current_page_scoped_no_dup_no_drop(monkeypatch) -> None:
    from contextlib import contextmanager

    import agent_bom.api.postgres_compliance_hub as pgmod
    from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

    # 500 rows, only every 20th is aws -> sparse matches force a multi-batch
    # keyset walk inside a single collect (200-row batch yields <page_limit aws).
    master = []
    for idx in range(500):
        provider = "aws" if idx % 20 == 0 else "gcp"
        master.append(
            {
                "canonical_id": f"c{idx:04d}",
                "first_seen": "2026-07-18T00:00:00Z",
                "last_seen": "2026-07-18T00:00:00Z",
                "status": "open",
                "severity": "high",
                "severity_rank": 4,
                "cvss_score": 7.0,
                # strictly descending -> deterministic keyset order
                "effective_reach_score": float(500 - idx),
                "scan_count": 1,
                "updated_at": "2026-07-18T00:00:00Z",
                "payload": {"id": f"pg-{idx:04d}", "provider": provider, "security_domain": "cspm"},
            }
        )

    conn = _FakePGConn(master)

    @contextmanager
    def fake_tenant_connection(_pool):
        yield conn

    monkeypatch.setattr(pgmod, "_tenant_connection", fake_tenant_connection)

    store = object.__new__(PostgresComplianceHubStore)  # bypass _init_tables
    store._pool = object()

    expected = {f"pg-{idx:04d}" for idx in range(500) if idx % 20 == 0}
    assert len(expected) == 25

    seen: list[str] = []
    cursor = None
    pages = 0
    while True:
        rows, total, nxt = store.list_current_page(
            "t-pg", limit=17, origin="bulk_ingest", cursor=cursor, scope={"provider": "aws"}, include_total=False
        )
        assert total is None  # scope => no O(table) COUNT
        seen.extend(r["id"] for r in rows)
        pages += 1
        if not nxt:
            break
        cursor = nxt
        assert pages < 100

    assert len(seen) == len(set(seen)), "duplicate ids across postgres scope pages"
    assert set(seen) == expected, "postgres scope filter dropped/leaked rows"

    # SQL assertions: %s-parameterized keyset clause was issued across batches,
    # and the batch LIMIT rode a bounded fetch (page_limit+... capped), never the
    # table. The first batch has no keyset; a later batch carries the keyset.
    assert any("effective_reach_score <" in sql and "%s" in sql for sql, _ in conn.select_calls), (
        "expected a %s-parameterized keyset clause in the batched SELECTs"
    )
    first_sql, first_params = conn.select_calls[0]
    assert "effective_reach_score <" not in first_sql  # first batch: no keyset
    assert int(first_params[-1]) == 201  # scope_filter_batch_size(17)=200 -> fetch 201
