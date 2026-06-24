"""Auto-derive the Azure subscription from the signed-in credential.

When ``AZURE_SUBSCRIPTION_ID`` is unset, the inventory should resolve the
subscription from the credential's own ARM token (e.g. after ``az login``) so a
single-subscription tenant connects with zero extra configuration. These tests
stub the token + the read-only ARM subscriptions REST call — no network.
"""

from __future__ import annotations

import io
import json
from typing import Any

from agent_bom.cloud import azure_inventory


class _FakeToken:
    token = "fake-arm-token"


class _FakeCredential:
    def get_token(self, *_scopes: str, **_kwargs: Any) -> _FakeToken:
        return _FakeToken()


def _fake_arm_response(subs: list[dict[str, Any]]):
    body = json.dumps({"value": subs}).encode("utf-8")

    class _Resp(io.BytesIO):
        def __enter__(self) -> "_Resp":
            return self

        def __exit__(self, *_a: Any) -> None:
            return None

    return _Resp(body)


def test_derive_single_subscription(monkeypatch) -> None:
    subs = [{"subscriptionId": "sub-aaa", "state": "Enabled", "displayName": "prod"}]
    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_k: _fake_arm_response(subs))
    sub, note = azure_inventory._derive_default_subscription(_FakeCredential())
    assert sub == "sub-aaa"
    assert note == ""  # single sub → no "pin one" nudge


def test_derive_prefers_enabled_and_notes_multiple(monkeypatch) -> None:
    subs = [
        {"subscriptionId": "sub-disabled", "state": "Disabled"},
        {"subscriptionId": "sub-1", "state": "Enabled"},
        {"subscriptionId": "sub-2", "state": "Enabled"},
    ]
    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_k: _fake_arm_response(subs))
    sub, note = azure_inventory._derive_default_subscription(_FakeCredential())
    assert sub == "sub-1"  # first enabled, disabled skipped
    assert "Set AZURE_SUBSCRIPTION_ID to pin one" in note
    assert "of 2 visible" in note


def test_derive_no_subscriptions_returns_empty(monkeypatch) -> None:
    monkeypatch.setattr("urllib.request.urlopen", lambda *_a, **_k: _fake_arm_response([]))
    sub, note = azure_inventory._derive_default_subscription(_FakeCredential())
    assert sub == ""
    assert "No Azure subscriptions" in note


def test_derive_token_failure_degrades_to_warning() -> None:
    class _BadCredential:
        def get_token(self, *_s: str, **_k: Any):
            raise RuntimeError("token boom")

    sub, note = azure_inventory._derive_default_subscription(_BadCredential())
    assert sub == ""
    assert note  # sanitized warning, never raises
