"""Snapshot-consistent current-finding reads shared by both SQL adapters."""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from typing import Any

from agent_bom.api.finding_cursor import cursor_from_current_row, sqlite_keyset_clause
from agent_bom.api.storage.finding_current import columns, hydrate_rows, parse_row
from agent_bom.api.storage.sql import Dialect, SqlBackend, SqlSession
from agent_bom.core.tenancy import require_explicit_tenant_id

Page = tuple[list[dict[str, Any]], int | None, str | None]


def has_ledger_column(tx: SqlSession, dialect: Dialect) -> bool:
    if dialect == "sqlite":
        return any(row[1] == "ledger_finding_id" for row in tx.execute("PRAGMA table_info(hub_findings_current)").fetchall())
    return bool(
        tx.execute(
            "SELECT 1 FROM information_schema.columns WHERE table_schema = current_schema() "
            "AND table_name = 'hub_findings_current' AND column_name = 'ledger_finding_id'"
        ).fetchone()
    )


def current_order(sort: str) -> str:
    # Preserve deployed index collations and existing opaque-cursor ordering.
    if sort == "ordinal":
        return "ledger_ordinal ASC, first_seen ASC, canonical_id ASC"
    column = {"cvss": "cvss_score", "severity": "severity_rank"}.get(sort, "effective_reach_score")
    return f"{column} DESC, last_seen DESC, canonical_id ASC"


def filters(
    tenant: str, *, since: str | None, origin: str | None, severity: str | None, scan_id: str | None, status: str | None
) -> tuple[list[str], list[Any]]:
    from agent_bom.api.compliance_hub_store import status_sql_predicate

    where = ["tenant_id = ?"]
    params: list[Any] = [tenant]
    for predicate, value in [
        ("last_seen >= ?", since or None),
        ("origin = ?", origin),
        ("severity != '' AND LOWER(severity) = ?", severity.lower() if severity is not None else None),
        ("scan_id = ? AND scan_id != ''", scan_id),
    ]:
        if value is not None:
            where.append(predicate)
            params.append(value)
    predicate, values = status_sql_predicate(status)
    if predicate:
        where.append(predicate)
        params.extend(values)
    return where, params


def fetch_page(
    tx: SqlSession,
    tenant: str,
    *,
    where: Sequence[str],
    params: Sequence[Any],
    sort: str,
    limit: int,
    offset: int,
    cursor: str | None,
    has_ledger: bool,
) -> tuple[list[dict[str, Any]], str | None]:
    predicates, values = list(where), list(params)
    if cursor:
        clause, extra = sqlite_keyset_clause(sort, cursor)
        predicates.append(clause.removeprefix(" AND "))
        values.extend(extra)
    predicate = " AND ".join(predicates)
    values.append(limit + 1)
    limit_sql = "LIMIT ?"
    if offset and not cursor:
        limit_sql += " OFFSET ?"
        values.append(offset)
    rows = tx.execute(
        f"SELECT {columns(has_ledger)} FROM hub_findings_current WHERE {predicate} ORDER BY {current_order(sort)} {limit_sql}",  # nosec B608
        values,
    ).fetchall()  # nosec B608
    parsed = [parse_row(row, has_ledger_col=has_ledger) for row in rows[:limit]]
    hydrated = hydrate_rows(tx, tenant, parsed)
    next_cursor = cursor_from_current_row(hydrated[-1], sort=sort) if len(rows) > limit and hydrated else None
    return hydrated, next_cursor


def scoped_page(
    tx: SqlSession,
    tenant: str,
    *,
    where: Sequence[str],
    params: Sequence[Any],
    sort: str,
    limit: int,
    cursor: str | None,
    has_ledger: bool,
    scope: Mapping[str, str],
    metadata: dict[str, Any] | None,
) -> Page:
    from agent_bom.api.compliance_hub_store import collect_scope_filtered_page, scope_filter_batch_size
    from agent_bom.api.finding_lifecycle import enriched_finding_payload
    from agent_bom.finding_scope import row_matches_scope

    def fetch(batch_cursor: str | None, batch_limit: int) -> tuple[list[tuple[dict[str, Any], dict[str, Any]]], str | None]:
        rows, next_cursor = fetch_page(
            tx, tenant, where=where, params=params, sort=sort, limit=batch_limit, offset=0, cursor=batch_cursor, has_ledger=has_ledger
        )
        return [(row, enriched_finding_payload(row)) for row in rows], next_cursor

    rows, next_cursor = collect_scope_filtered_page(
        fetch,
        predicate=lambda payload: row_matches_scope(payload, scope),
        page_limit=limit,
        start_cursor=cursor,
        sort=sort,
        batch_size=scope_filter_batch_size(limit),
        metadata=metadata,
    )
    return rows, None, next_cursor


class SqlCurrentFindingReads:
    def __init__(self, backend: SqlBackend) -> None:
        self._backend = backend

    def get(self, tenant_id: str, canonical_id: str) -> dict[str, Any] | None:
        tenant = require_explicit_tenant_id(tenant_id)
        with self._backend.transaction(read_only=True) as tx:
            has_ledger = has_ledger_column(tx, self._backend.dialect)
            row = tx.execute(
                f"SELECT {columns(has_ledger)} FROM hub_findings_current WHERE tenant_id = ? AND canonical_id = ?",  # nosec B608
                (tenant, canonical_id),
            ).fetchone()  # nosec B608
            return hydrate_rows(tx, tenant, [parse_row(row, has_ledger_col=has_ledger)])[0] if row else None

    def lookup(self, tenant_id: str, canonical_ids: Sequence[str], *, scan_id: str | None = None, origin: str | None = None) -> set[str]:
        tenant = require_explicit_tenant_id(tenant_id)
        found: set[str] = set()
        keys = list(dict.fromkeys(canonical_ids))
        with self._backend.transaction(read_only=True) as tx:
            for start in range(0, len(keys), 500):
                batch = keys[start : start + 500]
                predicate = "tenant_id = ? AND canonical_id IN (" + ",".join("?" for _ in batch) + ")"
                params: list[Any] = [tenant, *batch]
                for column, value in [("scan_id", scan_id), ("origin", origin)]:
                    if value is not None:
                        predicate += f" AND {column} = ?"
                        params.append(value)
                rows = tx.execute(f"SELECT canonical_id FROM hub_findings_current WHERE {predicate}", params).fetchall()  # nosec B608
                found.update(str(row[0]) for row in rows)
        return found

    def list_page(
        self,
        tenant_id: str,
        *,
        limit: int,
        offset: int = 0,
        sort: str = "effective_reach",
        severity: str | None = None,
        scan_id: str | None = None,
        origin: str | None = None,
        include_total: bool = True,
        cursor: str | None = None,
        since: str | None = None,
        scope: Mapping[str, str] | None = None,
        status: str | None = None,
        scope_metadata: dict[str, Any] | None = None,
    ) -> Page:
        from agent_bom.api.finding_lifecycle import enriched_finding_payload

        tenant = require_explicit_tenant_id(tenant_id)
        normalized = sort if sort in ("ordinal", "cvss", "severity", "effective_reach") else "effective_reach"
        where, params = filters(tenant, since=since, origin=origin, severity=severity, scan_id=scan_id, status=status)
        limit = max(0, int(limit))
        with self._backend.transaction(read_only=True) as tx:
            has_ledger = has_ledger_column(tx, self._backend.dialect)
            if scope:
                return scoped_page(
                    tx,
                    tenant,
                    where=where,
                    params=params,
                    sort=normalized,
                    limit=limit,
                    cursor=cursor,
                    has_ledger=has_ledger,
                    scope=scope,
                    metadata=scope_metadata,
                )
            total = None
            if include_total and not cursor:
                row = tx.execute("SELECT COUNT(*) FROM hub_findings_current WHERE " + " AND ".join(where), params).fetchone()  # nosec B608
                total = int(row[0]) if row else 0
            rows, next_cursor = fetch_page(
                tx,
                tenant,
                where=where,
                params=params,
                sort=normalized,
                limit=limit,
                offset=int(offset),
                cursor=cursor,
                has_ledger=has_ledger,
            )
            return [enriched_finding_payload(row) for row in rows], total, next_cursor
