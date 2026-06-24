"""Auto-derive the GCP project from Application Default Credentials.

When GOOGLE_CLOUD_PROJECT is unset, the inventory should resolve the project
from ADC (a service-account key's project_id, gcloud config, or the metadata
server) so a key/ADC connection needs zero extra config. Stubs google.auth.
"""

from __future__ import annotations

import sys
import types
from typing import Any

from agent_bom.cloud import gcp_inventory


def _stub_google_auth(monkeypatch, *, project: Any, raises: bool = False) -> None:
    mod = types.ModuleType("google.auth")

    def _default(*_a: Any, **_k: Any):
        if raises:
            raise RuntimeError("ADC boom")
        return (object(), project)

    mod.default = _default  # type: ignore[attr-defined]
    monkeypatch.setitem(sys.modules, "google.auth", mod)


def test_derive_project_from_adc(monkeypatch) -> None:
    _stub_google_auth(monkeypatch, project="my-proj-123")
    proj, note = gcp_inventory._derive_default_project()
    assert proj == "my-proj-123"
    assert note == ""


def test_derive_no_project_in_adc(monkeypatch) -> None:
    _stub_google_auth(monkeypatch, project=None)
    proj, note = gcp_inventory._derive_default_project()
    assert proj == ""
    assert "Application Default Credentials" in note


def test_derive_adc_error_degrades_to_warning(monkeypatch) -> None:
    _stub_google_auth(monkeypatch, project=None, raises=True)
    proj, note = gcp_inventory._derive_default_project()
    assert proj == ""
    assert note  # sanitized, never raises
