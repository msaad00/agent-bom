"""GCP service-account impersonation (keyless least-privilege connection).

When AGENT_BOM_GCP_IMPERSONATE_SA is set and no explicit credential is passed,
the connector wraps ambient ADC in impersonated credentials for that SA, so
every discovery runs as a read-only role — the recommended path where SA keys
are org-disabled. Stubs google.auth + impersonated_credentials (no network).
"""

from __future__ import annotations

import sys
import types
from typing import Any

import pytest

from agent_bom.cloud import gcp_inventory


@pytest.fixture
def _stub_google_auth(monkeypatch):
    auth_mod = types.ModuleType("google.auth")
    imp_mod = types.ModuleType("google.auth.impersonated_credentials")

    class _Impersonated:
        def __init__(self, *, source_credentials: Any, target_principal: str, target_scopes: list[str]) -> None:
            self.target_principal = target_principal
            self.target_scopes = target_scopes

    imp_mod.Credentials = _Impersonated  # type: ignore[attr-defined]
    auth_mod.default = lambda *a, **k: (object(), "proj")  # type: ignore[attr-defined]

    google_mod = sys.modules.get("google") or types.ModuleType("google")
    monkeypatch.setitem(sys.modules, "google", google_mod)
    monkeypatch.setattr(google_mod, "auth", auth_mod, raising=False)
    monkeypatch.setitem(sys.modules, "google.auth", auth_mod)
    monkeypatch.setitem(sys.modules, "google.auth.impersonated_credentials", imp_mod)
    return _Impersonated


def test_impersonates_when_env_set(monkeypatch, _stub_google_auth):
    monkeypatch.setenv("AGENT_BOM_GCP_IMPERSONATE_SA", "abom-scanner@proj.iam.gserviceaccount.com")
    warns: list[str] = []
    creds = gcp_inventory._resolve_impersonation(None, warns)
    assert isinstance(creds, _stub_google_auth)
    assert creds.target_principal == "abom-scanner@proj.iam.gserviceaccount.com"
    assert warns == []


def test_no_impersonation_when_env_unset(monkeypatch):
    monkeypatch.delenv("AGENT_BOM_GCP_IMPERSONATE_SA", raising=False)
    assert gcp_inventory._resolve_impersonation(None, []) is None


def test_explicit_credentials_take_precedence(monkeypatch):
    monkeypatch.setenv("AGENT_BOM_GCP_IMPERSONATE_SA", "x@proj.iam.gserviceaccount.com")
    sentinel = object()
    assert gcp_inventory._resolve_impersonation(sentinel, []) is sentinel


def test_impersonation_failure_degrades_to_warning(monkeypatch, _stub_google_auth):
    monkeypatch.setenv("AGENT_BOM_GCP_IMPERSONATE_SA", "abom-scanner@proj.iam.gserviceaccount.com")
    sys.modules["google.auth"].default = lambda *a, **k: (_ for _ in ()).throw(RuntimeError("ADC boom"))  # type: ignore
    warns: list[str] = []
    assert gcp_inventory._resolve_impersonation(None, warns) is None
    assert warns and "impersonation" in warns[0].lower()
