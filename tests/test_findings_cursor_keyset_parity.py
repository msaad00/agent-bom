"""Findings cursor pages match one reference order on SQLite and Postgres.

The fixture ties every sort key: effective reach, CVSS and severity repeat,
``last_seen`` repeats across observation batches, and rows missing from the
ledger share the ordinal sentinel. Canonical ids mix case, punctuation and
non-ASCII so a locale collation would order the final tie-breaker differently
from code-point order. The reference order is computed in Python from the raw
columns, independent of the SQL under test, and every walk (cursor, offset
and scope-filtered) must reproduce it exactly with no duplicate and no gap.
"""

from __future__ import annotations

import os
from collections.abc import Iterator
from functools import cmp_to_key
from typing import Any
from uuid import uuid4

import pytest

from agent_bom.api.compliance_hub_store import SQLiteComplianceHubStore, _sqlite_current_order_clause
from agent_bom.api.finding_cursor import (
    decode_finding_cursor,
    encode_finding_cursor,
    finding_keyset,
    postgres_keyset_clause,
    sqlite_keyset_clause,
)
from agent_bom.api.postgres_common import reset_current_tenant, set_current_tenant

_SORTS = ("effective_reach", "cvss", "severity", "ordinal")
_ID_PREFIXES = ("f-", "F-", "f_", "F~", "f.")
_ID_SUFFIXES = ("a", "B", "Z", "é", "0", "~")
_LEDGERED = 24
_OBSERVED = ("2026-09-01T00:00:00Z", "2026-09-02T00:00:00Z", "2026-09-03T00:00:00Z")

# Opaque cursors minted by the pre-refactor encoder for this fixture. They must
# keep decoding and resuming the listing after the SQL generation changes.
_LEGACY_CURSORS = {
    "effective_reach": (
        "eyJjYW5vbmljYWxfaWQiOiJmLUIiLCJsYXN0X3NlZW4iOiIyMDI2LTA5LTAxVDAwOjAwOjAwWiIsInByaW1hcnkiOjUuMCwic29ydCI6ImVmZmVjdGl2ZV9yZWFjaCJ9",
        (5.0, "2026-09-01T00:00:00Z", "f-B"),
    ),
    "ordinal": (
        "eyJjYW5vbmljYWxfaWQiOiJmLkIiLCJsYXN0X3NlZW4iOiIyMDI2LTA5LTAxVDAwOjAwOjAwWiIsInByaW1hcnkiOjkyMjMzNzIwMzY4NTQ3NzU4MDcsInNvcnQiOiJvcmRpbmFsIn0",
        (9223372036854775807, "2026-09-01T00:00:00Z", "f.B"),
    ),
}


def _findings() -> list[dict[str, Any]]:
    rows = []
    for index, (prefix, suffix) in enumerate((p, s) for p in _ID_PREFIXES for s in _ID_SUFFIXES):
        rows.append(
            {
                "id": f"{prefix}{suffix}",
                "title": f"Finding {index}",
                "severity": ("high", "critical", "high")[index % 3],
                "cvss_score": (7.5, 9.8, 7.5, 0.0)[index % 4],
                "effective_reach_score": (5.0, 5.0, 2.5)[index % 3],
                "provider": "aws" if index % 2 == 0 else "gcp",
                "account_ref": "aws:acct-1" if index % 2 == 0 else "gcp:acct-1",
            }
        )
    return rows


@pytest.fixture(
    params=[
        "sqlite",
        pytest.param(
            "postgres",
            marks=pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private migrated Postgres"),
        ),
    ]
)
def hub(request: pytest.FixtureRequest, tmp_path) -> Iterator[tuple[Any, str, list[dict[str, Any]]]]:
    tenant = "cursor-parity-" + uuid4().hex
    token = set_current_tenant(tenant)
    pool = None
    try:
        if request.param == "sqlite":
            store: Any = SQLiteComplianceHubStore(str(tmp_path / "hub.db"))
        else:
            from agent_bom.api.postgres_common import _new_application_pool
            from agent_bom.api.postgres_compliance_hub import PostgresComplianceHubStore

            pool = _new_application_pool(min_size=1, max_size=2)
            store = PostgresComplianceHubStore(pool)
        findings = _findings()
        store.add(tenant, findings[:_LEDGERED])
        store.upsert_current_batch(tenant, findings, observed_at=_OBSERVED[0], batch_id="b0", source="test")
        store.upsert_current_batch(tenant, findings[::3], observed_at=_OBSERVED[1], batch_id="b1", source="test")
        store.upsert_current_batch(tenant, findings[::5], observed_at=_OBSERVED[2], batch_id="b2", source="test")
        yield store, tenant, _raw_rows(store, tenant, request.param, pool)
    finally:
        reset_current_tenant(token)
        if pool is not None:
            pool.close()


def _raw_rows(store: Any, tenant: str, engine: str, pool: Any) -> list[dict[str, Any]]:
    sql = (
        "SELECT canonical_id, first_seen, last_seen, effective_reach_score, cvss_score, severity_rank, ledger_ordinal, "
        "status FROM hub_findings_current WHERE tenant_id = ?"
    )
    if engine == "sqlite":
        fetched = store._conn.execute(sql, (tenant,)).fetchall()
    else:
        from agent_bom.api.storage.sql import PostgresBackend

        with PostgresBackend(pool).transaction(read_only=True) as tx:
            fetched = tx.execute(sql, (tenant,)).fetchall()
    keys = ("canonical_id", "first_seen", "last_seen", "effective_reach_score", "cvss_score", "severity_rank", "ledger_ordinal", "status")
    rows = [dict(zip(keys, row)) for row in fetched]
    assert len(rows) == len(_ID_PREFIXES) * len(_ID_SUFFIXES)
    return rows


def _key(row: dict[str, Any], sort: str) -> tuple[tuple[Any, bool], ...]:
    """Sort key as (value, descending) pairs, compared by code point."""
    if sort == "ordinal":
        return ((int(row["ledger_ordinal"]), False), (row["first_seen"], False), (row["canonical_id"], False))
    primary = {"effective_reach": "effective_reach_score", "cvss": "cvss_score", "severity": "severity_rank"}[sort]
    return ((float(row[primary]), True), (row["last_seen"], True), (row["canonical_id"], False))


def _reference(rows: list[dict[str, Any]], sort: str) -> list[str]:
    def compare(left: dict[str, Any], right: dict[str, Any]) -> int:
        for (a, descending), (b, _) in zip(_key(left, sort), _key(right, sort)):
            if a != b:
                return ((a > b) - (a < b)) * (-1 if descending else 1)
        return 0

    return [row["canonical_id"] for row in sorted(rows, key=cmp_to_key(compare))]


def _walk(store: Any, tenant: str, sort: str, page_size: int, *, cursor: str | None = None, **filters: Any) -> list[str]:
    seen: list[str] = []
    pages = 0
    while True:
        rows, _total, cursor = store.list_current_page(tenant, limit=page_size, sort=sort, cursor=cursor, include_total=False, **filters)
        assert len(rows) <= page_size
        seen.extend(str(row["canonical_id"]) for row in rows)
        pages += 1
        if cursor is None:
            return seen
        assert pages <= 100, "cursor did not advance"


def test_fixture_ties_every_sort_key(hub) -> None:
    _store, _tenant, rows = hub
    for sort in _SORTS:
        keys = [tuple(value for value, _ in _key(row, sort)) for row in rows]
        assert len({key[:1] for key in keys}) < len(rows), sort
        assert len({key[:2] for key in keys}) < len(rows), sort
        assert len(set(keys)) == len(rows), sort
    assert sum(1 for row in rows if int(row["ledger_ordinal"]) == 9223372036854775807) == len(rows) - _LEDGERED


@pytest.mark.parametrize("sort", _SORTS)
@pytest.mark.parametrize("page_size", [1, 4, 7, 100])
def test_cursor_walk_matches_reference_order(hub, sort: str, page_size: int) -> None:
    store, tenant, rows = hub
    expected = _reference(rows, sort)
    walked = _walk(store, tenant, sort, page_size)
    assert walked == expected
    assert len(set(walked)) == len(walked)


@pytest.mark.parametrize("sort", _SORTS)
def test_offset_pages_match_reference_order(hub, sort: str) -> None:
    store, tenant, rows = hub
    expected = _reference(rows, sort)
    for offset in (0, 5, 13, 29):
        page, total, _ = store.list_current_page(tenant, limit=6, offset=offset, sort=sort)
        assert total == len(rows)
        assert [row["canonical_id"] for row in page] == expected[offset : offset + 6]


@pytest.mark.parametrize("sort", _SORTS)
def test_scope_filtered_walk_matches_reference_order(hub, sort: str) -> None:
    store, tenant, rows = hub
    unpaged, _, _ = store.list_current_page(tenant, limit=1000, sort=sort, include_total=False, scope={"provider": "aws"})
    in_scope = {str(row["canonical_id"]) for row in unpaged}
    assert in_scope and len(in_scope) < len(rows)
    expected = [canonical for canonical in _reference(rows, sort) if canonical in in_scope]
    assert [row["canonical_id"] for row in unpaged] == expected
    assert _walk(store, tenant, sort, 4, scope={"provider": "aws"}) == expected


@pytest.mark.parametrize("sort", sorted(_LEGACY_CURSORS))
def test_pre_refactor_cursor_tokens_resume_the_listing(hub, sort: str) -> None:
    store, tenant, rows = hub
    token, position = _LEGACY_CURSORS[sort]
    assert decode_finding_cursor(token, expected_sort=sort) == position
    expected = _reference(rows, sort)
    cursor_row = next(row for row in rows if row["canonical_id"] == position[2])
    assert tuple(value for value, _ in _key(cursor_row, sort))[0] == position[0]
    resumed = _walk(store, tenant, sort, 5, cursor=token)
    assert resumed == [canonical for canonical in expected if _after(rows, canonical, position, sort)]
    assert resumed and len(resumed) < len(expected)


@pytest.mark.parametrize(
    ("sort", "index"),
    [
        ("effective_reach", "idx_hub_findings_current_tenant_reach"),
        ("cvss", "idx_hub_findings_current_tenant_cvss"),
        ("severity", "idx_hub_findings_current_tenant_severity"),
        ("ordinal", "idx_hub_findings_current_tenant_ordinal"),
    ],
)
def test_sqlite_cursor_page_seeks_the_sort_index_without_a_sort(tmp_path, sort: str, index: str) -> None:
    store = SQLiteComplianceHubStore(str(tmp_path / "plan.db"))
    cursor = encode_finding_cursor(sort=sort, primary=5, last_seen="2026-09-01T00:00:00Z", canonical_id="f-B")
    predicate, params = sqlite_keyset_clause(sort, cursor)
    plan = store._conn.execute(
        f"EXPLAIN QUERY PLAN SELECT canonical_id FROM hub_findings_current WHERE tenant_id = ?{predicate} "  # nosec B608
        f"{_sqlite_current_order_clause(sort)} LIMIT 51",
        ("tenant", *params),
    ).fetchall()
    detail = " | ".join(str(row[3]) for row in plan)
    assert index in detail, detail
    assert "TEMP B-TREE" not in detail.upper(), detail
    leading = "ledger_ordinal" if sort == "ordinal" else finding_keyset(sort).columns[0]
    assert f"{leading}>" in detail.replace(" ", "") or f"{leading}<" in detail.replace(" ", ""), detail


@pytest.mark.skipif(not os.environ.get("AGENT_BOM_POSTGRES_URL"), reason="requires private migrated Postgres")
@pytest.mark.parametrize(
    ("sort", "status", "index"),
    [
        ("effective_reach", None, "idx_hub_findings_current_tenant_reach_c"),
        ("effective_reach", "open", "idx_hub_findings_current_tenant_open_reach_c"),
        ("cvss", None, "idx_hub_findings_current_tenant_cvss_c"),
        ("severity", None, "idx_hub_findings_current_tenant_severity_c"),
        ("ordinal", None, "idx_hub_findings_current_tenant_ordinal_c"),
    ],
)
def test_postgres_collated_order_is_served_by_a_collated_index(sort: str, status: str | None, index: str) -> None:
    from agent_bom.api.compliance_hub_store import _postgres_current_order_clause
    from agent_bom.api.postgres_common import _new_application_pool
    from agent_bom.api.storage.sql import PostgresBackend

    cursor = encode_finding_cursor(sort=sort, primary=5, last_seen="2026-09-01T00:00:00Z", canonical_id="f-B")
    predicate, params = postgres_keyset_clause(sort, cursor)
    predicate = predicate.replace("%s", "?")
    where = "tenant_id = ?" + (" AND status IN ('open', 'reopened')" if status else "")
    tenant = "cursor-plan-" + uuid4().hex
    token = set_current_tenant(tenant)
    pool = _new_application_pool(min_size=1, max_size=1)
    try:
        with PostgresBackend(pool).transaction(read_only=True) as tx:
            # Sorting is priced out, so any Sort node means no index can serve the order.
            tx.execute("SET LOCAL enable_sort = off")
            plans = [
                "\n".join(
                    str(row[0])
                    for row in tx.execute(
                        f"EXPLAIN SELECT canonical_id FROM hub_findings_current WHERE {where}{extra} "  # nosec B608
                        f"{_postgres_current_order_clause(sort)} LIMIT 51",
                        (tenant, *extra_params),
                    ).fetchall()
                )
                for extra, extra_params in (("", ()), (predicate, params))
            ]
    finally:
        reset_current_tenant(token)
        pool.close()
    for plan in plans:
        assert index in plan, plan
        assert "Sort" not in plan, plan


def _after(rows: list[dict[str, Any]], canonical: str, position: tuple[Any, ...], sort: str) -> bool:
    row = next(row for row in rows if row["canonical_id"] == canonical)
    for (value, descending), bound in zip(_key(row, sort), position):
        if value != bound:
            return value < bound if descending else value > bound
    return False
