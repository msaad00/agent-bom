"""Typed environment settings: parsing, validation, and the invalid-value rule."""

from __future__ import annotations

import logging
from pathlib import Path

import pytest

from agent_bom.core import settings
from agent_bom.core.settings import (
    SettingError,
    env_bool,
    env_duration,
    env_enum,
    env_first,
    env_flag,
    env_float,
    env_int,
    env_is_set,
    env_list,
    env_opt,
    env_path,
    env_raw,
    env_str,
)

NAME = "AGENT_BOM_TEST_SETTING"


@pytest.fixture(autouse=True)
def _clean(monkeypatch):
    monkeypatch.delenv(NAME, raising=False)
    settings.reset_warning_state()


@pytest.mark.parametrize("raw", [None, "", "   "])
def test_unset_and_blank_yield_defaults_for_every_type(monkeypatch, raw):
    if raw is not None:
        monkeypatch.setenv(NAME, raw)
    assert env_str(NAME, "d") == "d"
    assert env_opt(NAME) is None
    assert env_is_set(NAME) is False
    assert env_bool(NAME, True) is True
    assert env_flag(NAME) is False
    assert env_int(NAME, 7) == 7
    assert env_float(NAME, 1.5) == 1.5
    assert env_duration(NAME, 30.0) == 30.0
    assert env_enum(NAME, "a", {"a", "b"}) == "a"
    assert env_list(NAME, ("x",)) == ("x",)
    assert env_path(NAME) is None


def test_env_raw_is_unparsed(monkeypatch):
    assert env_raw(NAME) is None
    assert env_raw(NAME, "d") == "d"
    monkeypatch.setenv(NAME, "")
    assert env_raw(NAME, "d") == ""
    monkeypatch.setenv(NAME, "  v ")
    assert env_raw(NAME) == "  v "
    assert env_str(NAME) == "v"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [("1", True), ("TRUE", True), (" yes ", True), ("On", True), ("0", False), ("false", False), ("NO", False), ("off", False)],
)
def test_bool_accepts_documented_words(monkeypatch, raw, expected):
    monkeypatch.setenv(NAME, raw)
    assert env_bool(NAME, not expected) is expected
    assert env_flag(NAME) is expected


def test_invalid_bool_fails_fast_with_actionable_message(monkeypatch):
    monkeypatch.setenv(NAME, "maybe")
    with pytest.raises(SettingError) as exc:
        env_bool(NAME)
    assert NAME in str(exc.value)
    assert "'maybe'" in str(exc.value)
    assert "1/true/yes/on" in str(exc.value)
    assert isinstance(exc.value, ValueError)


def test_flag_keeps_historical_off_for_garbage_and_warns_once(monkeypatch, caplog):
    monkeypatch.setenv(NAME, "enabled")
    with caplog.at_level(logging.WARNING, logger="agent_bom.core.settings"):
        assert env_flag(NAME) is False
        assert env_flag(NAME) is False
    assert len([r for r in caplog.records if NAME in r.getMessage()]) == 1


@pytest.mark.parametrize(("raw", "expected"), [("42", 42), (" -3 ", -3), ("0", 0)])
def test_int_parses(monkeypatch, raw, expected):
    monkeypatch.setenv(NAME, raw)
    assert env_int(NAME, 1) == expected


@pytest.mark.parametrize("raw", ["4.2", "ten", "1e3"])
def test_int_rejects_non_integers(monkeypatch, raw):
    monkeypatch.setenv(NAME, raw)
    with pytest.raises(SettingError, match="an integer"):
        env_int(NAME, 1)
    assert env_int(NAME, 1, on_invalid="default") == 1


def test_int_range_is_inclusive_and_named(monkeypatch):
    monkeypatch.setenv(NAME, "10")
    assert env_int(NAME, 1, minimum=10, maximum=10) == 10
    with pytest.raises(SettingError, match="between 11 and 20"):
        env_int(NAME, 1, minimum=11, maximum=20)
    with pytest.raises(SettingError, match="<= 9"):
        env_int(NAME, 1, maximum=9)


@pytest.mark.parametrize("raw", ["nan", "inf", "x"])
def test_float_rejects_non_finite_and_garbage(monkeypatch, raw):
    monkeypatch.setenv(NAME, raw)
    with pytest.raises(SettingError):
        env_float(NAME, 1.0)


def test_float_parses_and_bounds(monkeypatch):
    monkeypatch.setenv(NAME, "0.25")
    assert env_float(NAME, 1.0, minimum=0.0, maximum=1.0) == 0.25
    with pytest.raises(SettingError, match=">= 0.5"):
        env_float(NAME, 1.0, minimum=0.5)


@pytest.mark.parametrize(
    ("raw", "seconds"),
    [("30", 30.0), ("30s", 30.0), ("5m", 300.0), ("2h", 7200.0), ("1d", 86400.0), ("250ms", 0.25), ("1.5H", 5400.0)],
)
def test_duration_units(monkeypatch, raw, seconds):
    monkeypatch.setenv(NAME, raw)
    assert env_duration(NAME, 1.0) == pytest.approx(seconds)


@pytest.mark.parametrize("raw", ["-5", "5 minutes", "m", "1w"])
def test_duration_rejects_unknown_forms(monkeypatch, raw):
    monkeypatch.setenv(NAME, raw)
    with pytest.raises(SettingError, match="duration"):
        env_duration(NAME, 1.0)


def test_enum_is_case_insensitive_and_lists_choices(monkeypatch):
    monkeypatch.setenv(NAME, "DOCKER")
    assert env_enum(NAME, "auto", {"auto", "docker"}) == "docker"
    monkeypatch.setenv(NAME, "lxc")
    with pytest.raises(SettingError, match="one of auto, docker"):
        env_enum(NAME, "auto", {"auto", "docker"})


def test_list_strips_and_drops_blanks(monkeypatch):
    monkeypatch.setenv(NAME, " a, ,b ,, c")
    assert env_list(NAME) == ("a", "b", "c")
    monkeypatch.setenv(NAME, "a:b")
    assert env_list(NAME, sep=":") == ("a", "b")
    monkeypatch.setenv(NAME, " , ")
    assert env_list(NAME, ("d",)) == ()


def test_path_expands_user(monkeypatch):
    monkeypatch.setenv(NAME, "~/x")
    assert env_path(NAME) == Path("~/x").expanduser()


def test_first_non_blank_wins(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_TEST_A", " ")
    monkeypatch.setenv("AGENT_BOM_TEST_B", "b")
    assert env_first("AGENT_BOM_TEST_A", "AGENT_BOM_TEST_B") == "b"
    assert env_first("AGENT_BOM_TEST_A", default="d") == "d"


def test_values_are_read_at_call_time(monkeypatch):
    monkeypatch.setenv(NAME, "1")
    assert env_int(NAME, 0) == 1
    monkeypatch.setenv(NAME, "2")
    assert env_int(NAME, 0) == 2


@pytest.mark.parametrize("secret_name", ["AGENT_BOM_SIEM_TOKEN", "AGENT_BOM_API_KEY", "MY_PASSWORD", "AGENT_BOM_CONNECTIONS_KEY"])
def test_errors_never_echo_secret_values(monkeypatch, secret_name):
    monkeypatch.setenv(secret_name, "hunter2-supersecret")
    with pytest.raises(SettingError) as exc:
        env_int(secret_name, 1)
    assert "hunter2" not in str(exc.value)
    assert "<redacted>" in str(exc.value)


def test_errors_truncate_and_neutralize_control_characters(monkeypatch):
    monkeypatch.setenv(NAME, "x" * 200 + "\x1b[31m")
    with pytest.raises(SettingError) as exc:
        env_int(NAME, 1)
    message = str(exc.value)
    assert "\x1b" not in message
    assert len(message) < 250
