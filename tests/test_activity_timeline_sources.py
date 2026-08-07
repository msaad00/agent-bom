"""Activity is the agent/MCP runtime story — Snowflake is one source of it.

``GET /v1/activity`` used to hard-fail with 400 when ``SNOWFLAKE_ACCOUNT`` was
unset. That made the entire Activity surface unreachable for the large majority
of deployments: a self-hosted install running agents and MCP servers has real
runtime activity to show, and was told to go configure a data warehouse first.

Every source now reports its own state, the same contract ``nhi_discover`` and
``cloud_inventory`` already use for optional providers. An unconfigured source
contributes zero events and a clear reason, is never silently dropped, and never
fails the request.
"""

from __future__ import annotations

import warnings

import pytest

warnings.filterwarnings("ignore")

_HEADERS: dict[str, str] = {}


@pytest.fixture()
def client(monkeypatch: pytest.MonkeyPatch):
    """An open API client, so these tests exercise the timeline and not auth."""
    monkeypatch.delenv("SNOWFLAKE_ACCOUNT", raising=False)
    from fastapi.testclient import TestClient

    from agent_bom.api.server import app, configure_api

    configure_api(api_key=None)
    return TestClient(app)


def _sources(payload: dict) -> dict[str, dict]:
    return {source["source"]: source for source in payload["sources"]}


def test_activity_succeeds_without_snowflake(client) -> None:
    """The regression: no Snowflake must not mean no Activity page."""
    response = client.get("/v1/activity?days=30", headers=_HEADERS)

    assert response.status_code == 200, response.text


def test_unconfigured_snowflake_is_reported_not_hidden(client) -> None:
    """A missing source must be visible, so an operator knows what to wire up.

    Silently omitting it would make an incomplete timeline look complete.
    """
    payload = client.get("/v1/activity?days=30", headers=_HEADERS).json()

    snowflake = _sources(payload)["snowflake"]
    assert snowflake["status"] == "not_configured"
    assert snowflake["event_count"] == 0
    assert "SNOWFLAKE_ACCOUNT" in snowflake["detail"]


def test_runtime_source_is_always_present(client) -> None:
    """The runtime store needs no external warehouse, so it is always consulted."""
    payload = client.get("/v1/activity?days=30", headers=_HEADERS).json()

    assert "runtime" in _sources(payload)


def test_empty_is_distinguishable_from_unconfigured(client) -> None:
    """ "Nothing happened" and "nothing is wired up" need different next steps.

    Collapsing them into one empty state is what makes a dashboard feel broken:
    the operator cannot tell whether to wait or to go connect something.
    """
    payload = client.get("/v1/activity?days=30", headers=_HEADERS).json()

    assert payload["status"] in {"active", "empty", "no_sources_configured"}
    statuses = {source["status"] for source in payload["sources"]}
    assert statuses <= {"active", "empty", "not_configured", "unavailable"}


def test_window_is_clamped_to_a_year(client) -> None:
    """An unbounded window would scan the whole store."""
    payload = client.get("/v1/activity?days=99999", headers=_HEADERS).json()

    assert payload["window_days"] == 365


def test_response_is_bounded(client) -> None:
    """A timeline must never return an unbounded event list."""
    payload = client.get("/v1/activity?days=365", headers=_HEADERS).json()

    assert len(payload["events"]) <= 500
    assert isinstance(payload["truncated"], bool)


def test_a_failing_source_degrades_to_a_status_instead_of_500(client, monkeypatch: pytest.MonkeyPatch) -> None:
    """One broken source must not take the whole timeline down.

    A runtime-store hiccup should mark that one source ``unavailable`` and still
    render everything healthy, rather than 500-ing the Activity page.
    """
    import agent_bom.api.runtime_event_store as store_module

    class _BrokenStore:
        def list_observations(self, *_args, **_kwargs):
            raise RuntimeError("runtime store unavailable")

    monkeypatch.setattr(store_module, "get_runtime_event_store", lambda: _BrokenStore())

    response = client.get("/v1/activity?days=30", headers=_HEADERS)

    assert response.status_code == 200, response.text
    runtime = _sources(response.json())["runtime"]
    assert runtime["status"] == "unavailable"
    assert runtime["event_count"] == 0
