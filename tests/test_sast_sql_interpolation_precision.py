"""Precision of the "SQL query is built through string interpolation" rule.

The shapes below are lifted from agent-bom's own source, where every one is a
reviewed, parameterized query: a reviewer suppression (``# nosec B608``),
interpolation of only bind-placeholder markers, or interpolation of a
module-level constant identifier. None carries attacker-controlled text into
the SQL, so none may be reported. Interpolating a parameter still must be.
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.ast_analyzer import analyze_project


def _sql_findings(tmp_path: Path, source: str) -> list:
    (tmp_path / "store.py").write_text(source, encoding="utf-8")
    result = analyze_project(tmp_path)
    return [finding for finding in result.flow_findings if finding.category == "sql_string_construction"]


FALSE_POSITIVE_SHAPES = {
    # scanners/package_scan.py: nosec on the assignment line of a tracked name.
    "nosec-on-assignment": (
        "def ecosystems(conn, names):\n"
        "    placeholders = load_markers(names)\n"
        '    query = f"SELECT DISTINCT ecosystem FROM affected WHERE ecosystem IN ({placeholders})"  # nosec B608\n'
        "    return conn.execute(query, names).fetchall()\n"
    ),
    # graph/build_workspace.py: nosec on an inner line of a multi-line call.
    "nosec-inside-multiline-call": (
        "def count(conn, table, tenant_id):\n"
        "    return conn.execute(\n"
        '        f"SELECT COUNT(*) FROM {table} WHERE tenant_id = ?",  # nosec B608 - static table\n'
        "        (tenant_id,),\n"
        "    ).fetchone()\n"
    ),
    # cpe_match.py / package_scan.py: only bind markers are interpolated.
    "placeholder-join": (
        "def lookup(conn, ids):\n"
        '    placeholders = ",".join("?" for _ in ids)\n'
        '    return conn.execute(f"SELECT * FROM cpe_matches WHERE product IN ({placeholders})", ids).fetchall()\n'
        "\n"
        "def lookup_pg(cur, ids):\n"
        '    marks = ", ".join(["%s"] * len(ids))\n'
        '    cur.execute(f"DELETE FROM t WHERE id IN ({marks})", ids)\n'
        "\n"
        "def lookup_marker(conn, tenant_id, sqlite):\n"
        '    marker = "?" if sqlite else "%s"\n'
        '    return conn.execute(f"SELECT 1 FROM nodes WHERE tenant_id = {marker}", (tenant_id,))\n'
    ),
    # intel_lookup.py / graph/adjacency_page.py: module-level column constants.
    "module-constant": (
        '_KEV_VULN_COLS = "v.id, v.summary, v.severity"\n'
        "\n"
        "def kev_rows(conn, cve_id):\n"
        '    return conn.execute(f"SELECT {_KEV_VULN_COLS} FROM vulns v WHERE v.id = ?", (cve_id,)).fetchall()\n'
    ),
}


@pytest.mark.parametrize("shape", sorted(FALSE_POSITIVE_SHAPES))
def test_reviewed_or_constant_sql_is_not_reported(tmp_path: Path, shape: str) -> None:
    assert _sql_findings(tmp_path, FALSE_POSITIVE_SHAPES[shape]) == []


def test_bare_nosec_also_suppresses(tmp_path: Path) -> None:
    source = 'def f(conn, user_id):\n    return conn.execute(f"SELECT * FROM users WHERE id = {user_id}")  # nosec\n'
    assert _sql_findings(tmp_path, source) == []


TRUE_POSITIVE_SHAPES = {
    "parameter-interpolated": (
        'def lookup(cursor, user_id):\n    query = f"SELECT * FROM users WHERE id = {user_id}"\n    return cursor.execute(query)\n'
    ),
    "nosec-for-a-different-rule": (
        'def lookup(cursor, user_id):\n    return cursor.execute(f"SELECT * FROM users WHERE id = {user_id}")  # nosec B101\n'
    ),
    "placeholder-name-mixed-with-input": (
        "def lookup(conn, ids, order):\n"
        '    placeholders = ",".join("?" for _ in ids)\n'
        '    return conn.execute(f"SELECT * FROM t WHERE id IN ({placeholders}) ORDER BY {order}", ids)\n'
    ),
    "lowercase-module-name-is-not-a-constant": (
        'table = "users"\n\ndef lookup(conn, user_id):\n    return conn.execute(f"SELECT * FROM {table} WHERE id = {user_id}")\n'
    ),
    "constant-shadowed-locally": ('_COLS = "id"\n\ndef lookup(conn, _COLS):\n    return conn.execute(f"SELECT {_COLS} FROM users")\n'),
    "placeholder-name-reassigned-to-input": (
        "def lookup(conn, ids, raw):\n"
        '    placeholders = ",".join("?" for _ in ids)\n'
        "    placeholders = raw\n"
        '    return conn.execute(f"SELECT * FROM t WHERE id IN ({placeholders})", ids)\n'
    ),
    "concatenation-with-input": ('def lookup(conn, name):\n    return conn.execute("SELECT * FROM t WHERE name = \'" + name + "\'")\n'),
}


@pytest.mark.parametrize("shape", sorted(TRUE_POSITIVE_SHAPES))
def test_interpolated_input_is_still_reported(tmp_path: Path, shape: str) -> None:
    findings = _sql_findings(tmp_path, TRUE_POSITIVE_SHAPES[shape])
    assert len(findings) == 1, findings
    assert findings[0].title == "SQL query is built through string interpolation"
