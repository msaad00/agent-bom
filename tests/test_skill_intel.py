"""Regression tests for skill threat-intel feed loading."""

from __future__ import annotations

import json
from collections.abc import Iterable

import pytest

from agent_bom.skill_bundles import build_skill_bundle
from agent_bom.skill_intel import (
    ThreatIntelStatus,
    _load_document,
    _read_remote_json_bytes,
    lookup_bundle_threat_intel,
)


class _FakeResponse:
    def __init__(self, chunks: Iterable[bytes], *, content_type: str = "application/json") -> None:
        self._chunks = list(chunks)
        self.headers = {"content-type": content_type}

    def __enter__(self) -> _FakeResponse:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def raise_for_status(self) -> None:
        return None

    def iter_bytes(self) -> Iterable[bytes]:
        return iter(self._chunks)


class _FakeClient:
    chunks: list[bytes] = [b'{"entries": []}']
    content_type = "application/json"

    def __init__(self, **_kwargs: object) -> None:
        return None

    def __enter__(self) -> _FakeClient:
        return self

    def __exit__(self, *args: object) -> None:
        return None

    def stream(self, *_args: object, **_kwargs: object) -> _FakeResponse:
        return _FakeResponse(self.chunks, content_type=self.content_type)


def test_remote_skill_intel_rejects_http_without_fetching(tmp_path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("# Skill\n\nStay read-only.\n")
    bundle = build_skill_bundle(skill_file)

    result = lookup_bundle_threat_intel(bundle, "http://user:secret@example.com/feed.json?token=abc")

    assert result is not None
    assert result.status == ThreatIntelStatus.UNAVAILABLE
    assert result.provider == "example.com"
    assert result.detail is not None
    assert "remote feed rejected" in result.detail
    assert "secret" not in result.detail
    assert "token=abc" not in result.detail


def test_remote_skill_intel_rejects_private_hosts_without_fetching(tmp_path):
    skill_file = tmp_path / "SKILL.md"
    skill_file.write_text("# Skill\n\nStay read-only.\n")
    bundle = build_skill_bundle(skill_file)

    result = lookup_bundle_threat_intel(bundle, "https://127.0.0.1/feed.json")

    assert result is not None
    assert result.status == ThreatIntelStatus.UNAVAILABLE
    assert result.detail is not None
    assert "remote feed rejected" in result.detail


def test_remote_skill_intel_requires_json_content_type(monkeypatch):
    monkeypatch.setattr("agent_bom.skill_intel.validate_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("agent_bom.skill_intel.httpx.Client", _FakeClient)
    _FakeClient.content_type = "text/html"
    _FakeClient.chunks = [b"<html></html>"]

    with pytest.raises(ValueError, match="JSON content"):
        _read_remote_json_bytes("https://example.com/feed.json")


def test_remote_skill_intel_enforces_max_size(monkeypatch):
    monkeypatch.setattr("agent_bom.skill_intel.validate_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("agent_bom.skill_intel.httpx.Client", _FakeClient)
    _FakeClient.content_type = "application/json"
    _FakeClient.chunks = [b"{" + (b'"a":' + b'"b"' * 600_000) + b"}"]

    with pytest.raises(ValueError, match="maximum size"):
        _read_remote_json_bytes("https://example.com/feed.json")


def test_remote_skill_intel_loads_https_json(monkeypatch):
    monkeypatch.setattr("agent_bom.skill_intel.validate_url", lambda *_args, **_kwargs: None)
    monkeypatch.setattr("agent_bom.skill_intel.httpx.Client", _FakeClient)
    _FakeClient.content_type = "application/vnd.agent-bom+json"
    _FakeClient.chunks = [json.dumps({"provider": "fixture-feed", "entries": []}).encode()]

    assert _load_document("https://example.com/feed.json") == {
        "provider": "fixture-feed",
        "entries": [],
    }
