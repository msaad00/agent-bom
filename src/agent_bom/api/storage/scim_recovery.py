"""Validate identity recovery as a complete, tenant-bound SCIM snapshot."""

from typing import Any

TABLES = {"scim_users", "scim_groups"}


def validate_source(records: list[tuple[str, Any, dict[str, Any]]], tables: list[str]) -> None:
    if not TABLES.intersection(tables):
        return
    if not TABLES.issubset(tables):
        raise ValueError("Select both SCIM user and group tables together")
    users = {(r.tenant_id, r.user_id): r for t, r, _ in records if t == "scim_users"}
    groups = {(r.tenant_id, r.group_id): r for t, r, _ in records if t == "scim_groups"}
    names: set[tuple[str, str]] = set()
    for user in users.values():
        identity = user.tenant_id, user.user_name
        if identity in names or any((user.tenant_id, g) not in groups for g in user.groups):
            raise ValueError("SCIM membership or user identity requires reconciliation")
        names.add(identity)
    for group in groups.values():
        for member in group.members:
            identity = group.tenant_id, member.get("value")
            if not isinstance(identity[1], str) or identity not in users and identity not in groups:
                raise ValueError("SCIM membership references an unselected identity")


def validate_target(conn: Any, records: list[tuple[str, Any, dict[str, Any]]]) -> int:
    expected: dict[tuple[str, str], set[str]] = {}
    for table, row, _ in records:
        if table in TABLES:
            for selected in TABLES:
                expected.setdefault((row.tenant_id, selected), set())
            expected[row.tenant_id, table].add(row.user_id if table == "scim_users" else row.group_id)
    conflicts = 0
    for (tenant, table), identities in expected.items():
        conn.execute("SELECT set_config('app.tenant_id',%s,true)", (tenant,))
        key = "user_id" if table == "scim_users" else "group_id"
        actual = {r[0] for r in conn.execute(f"SELECT {key} FROM {table} WHERE tenant_id=%s", (tenant,)).fetchall()}  # nosec B608 - table and key are fixed SCIM identifiers
        conflicts += actual != identities
    return conflicts
