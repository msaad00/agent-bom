"""Cover the half of the retention tool that mutates the public registry.

``test_dockerhub_tag_cleanup`` exercises the pure planner. These tests cover the
HTTP layer and ``main()`` ordering, where a defect deletes published release
images irreversibly.
"""

from __future__ import annotations

import io
import json
import urllib.error
from typing import Any

import pytest

from scripts import dockerhub_tag_cleanup as mod


class _Response(io.BytesIO):
    status = 200

    def __enter__(self) -> "_Response":
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


def _json_response(payload: dict[str, Any]) -> _Response:
    return _Response(json.dumps(payload).encode())


@pytest.fixture
def client(monkeypatch: pytest.MonkeyPatch) -> mod.DockerHubClient:
    monkeypatch.setattr(mod.urllib.request, "urlopen", lambda *a, **k: _json_response({"token": "t0ken"}))
    return mod.DockerHubClient("user", "pass")


def test_list_tags_follows_pagination(client: mod.DockerHubClient, monkeypatch: pytest.MonkeyPatch) -> None:
    pages = {
        "https://hub.docker.com/v2/repositories/ns/repo/tags/?page_size=100&ordering=-last_updated": {
            "results": [{"name": "0.2.0"}],
            "next": "https://hub.docker.com/v2/repositories/ns/repo/tags/?page=2",
        },
        "https://hub.docker.com/v2/repositories/ns/repo/tags/?page=2": {
            "results": [{"name": "0.1.0"}],
            "next": None,
        },
    }
    monkeypatch.setattr(mod.urllib.request, "urlopen", lambda req, **k: _json_response(pages[req.full_url]))

    assert client.list_tags("ns/repo") == ["0.2.0", "0.1.0"]


def test_list_tags_refuses_offsite_pagination_url(client: mod.DockerHubClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """A `next` pointing off-host must not receive the Docker Hub bearer token."""
    reached: list[str] = []

    def fake_urlopen(req: Any, **_: object) -> _Response:
        reached.append(req.full_url)
        if "attacker" in req.full_url:
            raise AssertionError(f"forwarded credentials to {req.full_url}")
        return _json_response({"results": [{"name": "0.1.0"}], "next": "https://attacker.example/steal"})

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="refusing to follow"):
        client.list_tags("ns/repo")
    assert not any("attacker" in url for url in reached)


def test_delete_tag_raises_on_server_error(client: mod.DockerHubClient, monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_urlopen(req: Any, **_: object) -> _Response:
        raise urllib.error.HTTPError(req.full_url, 500, "Server Error", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)

    with pytest.raises(RuntimeError, match="HTTP 500"):
        client.delete_tag("ns/repo", "0.1.0")


def test_delete_tag_treats_missing_tag_as_done(client: mod.DockerHubClient, monkeypatch: pytest.MonkeyPatch) -> None:
    """A tag that is already gone is the desired end state, not a failure."""

    def fake_urlopen(req: Any, **_: object) -> _Response:
        raise urllib.error.HTTPError(req.full_url, 404, "Not Found", {}, None)  # type: ignore[arg-type]

    monkeypatch.setattr(mod.urllib.request, "urlopen", fake_urlopen)

    client.delete_tag("ns/repo", "0.1.0")


def test_protected_tag_is_never_deleted() -> None:
    """The version a release just published must survive retention."""
    tags = ["latest", "0.98.3", *[f"0.9{n}.0" for n in range(0, 9)]]
    plan = mod.plan_cleanup("ns/repo", tags, keep_count=3, protect=("0.90.0",))

    assert "0.90.0" in plan.keep
    assert "0.90.0" not in plan.delete


def test_main_aborts_before_any_delete_when_count_mismatches(monkeypatch: pytest.MonkeyPatch) -> None:
    deleted: list[str] = []

    class Fake:
        def __init__(self, *a: object) -> None: ...

        def list_tags(self, repository: str) -> list[str]:
            return ["latest", "0.3.0", "0.2.0", "0.1.0"]

        def delete_tag(self, repository: str, tag: str) -> None:
            deleted.append(tag)

    monkeypatch.setattr(mod, "DockerHubClient", Fake)
    monkeypatch.setenv("DOCKERHUB_USERNAME", "u")
    monkeypatch.setenv("DOCKERHUB_TOKEN", "t")

    rc = mod.main(["--repository", "ns/repo", "--keep-count", "2", "--expected-delete-count", "99"])

    assert rc == 1
    assert deleted == [], f"deleted despite the count guard: {deleted}"


def test_main_dry_run_never_deletes(monkeypatch: pytest.MonkeyPatch) -> None:
    deleted: list[str] = []

    class Fake:
        def __init__(self, *a: object) -> None: ...

        def list_tags(self, repository: str) -> list[str]:
            return ["latest", "0.3.0", "0.2.0", "0.1.0"]

        def delete_tag(self, repository: str, tag: str) -> None:
            deleted.append(tag)

    monkeypatch.setattr(mod, "DockerHubClient", Fake)
    monkeypatch.setenv("DOCKERHUB_USERNAME", "u")
    monkeypatch.setenv("DOCKERHUB_TOKEN", "t")

    rc = mod.main(["--repository", "ns/repo", "--keep-count", "2", "--dry-run"])

    assert rc == 0
    assert deleted == []
