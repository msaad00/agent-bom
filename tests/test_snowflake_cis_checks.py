"""Snowflake CIS checks must handle boolean SHOW columns and real column names."""

from __future__ import annotations

from agent_bom.cloud.snowflake_cis_benchmark import _check_1_1, _check_1_2, _sf_truthy


class _FakeCursor:
    """Minimal cursor that returns canned (columns, rows) for any execute()."""

    def __init__(self, columns: list[str], rows: list[tuple]):
        self._cols = columns
        self._rows = rows
        self.description = [(c,) for c in columns]

    def execute(self, sql: str):  # noqa: D401
        return None

    def fetchall(self):
        return self._rows


def test_sf_truthy_handles_bool_str_none() -> None:
    assert _sf_truthy(True) is True
    assert _sf_truthy(False) is False
    assert _sf_truthy("true") is True
    assert _sf_truthy("FALSE") is False
    assert _sf_truthy(None) is False


def test_check_1_1_does_not_crash_on_boolean_columns() -> None:
    # ext_authn_duo comes back as a real bool (the bug: .lower() crashed on it).
    cur = _FakeCursor(
        ["name", "ext_authn_duo", "has_password", "disabled"],
        [("WSAAD", False, True, "false"), ("SECURE_USER", True, True, "false")],
    )
    res = _check_1_1(cur)
    assert res.status.value == "fail"
    assert "WSAAD" in res.evidence  # the no-MFA user is flagged
    assert "SECURE_USER" not in res.evidence  # MFA-enabled user is not


def test_check_1_1_all_mfa_passes() -> None:
    cur = _FakeCursor(
        ["name", "ext_authn_duo", "has_password", "disabled"],
        [("U1", True, True, False), ("U2", "true", "true", "false")],
    )
    assert _check_1_1(cur).status.value == "pass"


def test_check_1_2_uses_name_column() -> None:
    class _PolicyCursor:
        description = None
        rows: list[tuple] = []

        def execute(self, sql: str):
            if sql.startswith("SHOW PASSWORD"):
                self.description = [(column,) for column in ("database_name", "schema_name", "name")]
                self.rows = [("SECURITY", "POLICIES", "WEAK_POL")]
            else:
                self.description = [(column,) for column in ("property", "value")]
                self.rows = [("PASSWORD_MIN_LENGTH", 8)]

        def fetchall(self):
            return self.rows

    cur = _PolicyCursor()
    res = _check_1_2(cur)
    assert res.status.value == "fail"
    assert "WEAK_POL" in res.evidence
