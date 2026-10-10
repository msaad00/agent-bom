"""Local-path scan opt-in for the API scan jail."""

from __future__ import annotations

import pytest

from agent_bom.api.scan_path_jail import _api_local_scans_enabled

_PRIMARY = "AGENT_BOM_API_LOCAL_PATH_SCANS"
_LEGACY = "AGENT_BOM_ENABLE_LOCAL_PATH_SCANS"


@pytest.fixture(autouse=True)
def _clear_opt_in(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.delenv(_PRIMARY, raising=False)
    monkeypatch.delenv(_LEGACY, raising=False)


def test_local_path_scans_are_disabled_by_default() -> None:
    assert _api_local_scans_enabled() is False


@pytest.mark.parametrize("value", ["", "   "])
def test_blank_opt_in_is_unset_not_enabled(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(_PRIMARY, value)

    assert _api_local_scans_enabled() is False


def test_blank_primary_falls_through_to_legacy_name(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_PRIMARY, "")
    monkeypatch.setenv(_LEGACY, "enabled")

    assert _api_local_scans_enabled() is True


@pytest.mark.parametrize("value", ["0", "false", "No", "off", "disabled"])
def test_explicit_disable_values(monkeypatch: pytest.MonkeyPatch, value: str) -> None:
    monkeypatch.setenv(_PRIMARY, value)

    assert _api_local_scans_enabled() is False


def test_explicit_enable(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv(_PRIMARY, "enabled")

    assert _api_local_scans_enabled() is True
