"""Routes that spend the control plane's own cloud identity are privileged.

``/v1/cloud/{provider}/cis-benchmark`` does not use a tenant's stored
connection. It runs against whatever ambient credentials the control-plane
process itself holds — an instance role, an assumed role, a mounted profile.
Two consequences follow:

* it must be an explicit operator opt-in, not on by default, and
* it must require admin, because "analyst in any tenant" is not the same
  trust level as "may spend the platform's own identity".

The caller must also not choose which host profile to spend. Selecting the
credential is operator configuration, not request input.
"""

from __future__ import annotations

from typing import Any
from unittest.mock import patch

import pytest
from starlette.testclient import TestClient

from agent_bom.api.server import app


@pytest.fixture
def client() -> Any:
    return TestClient(app)


def test_cis_benchmark_is_disabled_unless_an_operator_enables_it(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Default install must not spend ambient credentials on request."""
    monkeypatch.delenv("AGENT_BOM_CLOUD_CIS_BENCHMARK", raising=False)

    response = client.get("/v1/cloud/aws/cis-benchmark")

    assert response.status_code == 200
    body = response.json()
    assert body["status"] == "disabled"
    # Carries ``error`` too so headless callers degrade like any other envelope.
    assert "AGENT_BOM_CLOUD_CIS_BENCHMARK" in body["error"]


def test_disabled_benchmark_never_invokes_a_provider(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """The guard must short-circuit before any SDK call."""
    monkeypatch.delenv("AGENT_BOM_CLOUD_CIS_BENCHMARK", raising=False)

    with patch("agent_bom.api.routes.cloud._run_cis_benchmark") as runner:
        client.get("/v1/cloud/aws/cis-benchmark")

    runner.assert_not_called()


def test_enabled_benchmark_rejects_a_caller_supplied_profile(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Which host credential to spend is operator config, not request input."""
    monkeypatch.setenv("AGENT_BOM_CLOUD_CIS_BENCHMARK", "1")

    response = client.get("/v1/cloud/aws/cis-benchmark?profile=production")

    assert response.status_code == 400
    assert "profile" in response.json()["detail"].lower()


def test_enabled_benchmark_still_runs_without_a_profile(client: Any, monkeypatch: pytest.MonkeyPatch) -> None:
    """Enabling the flag must leave the normal path working."""
    monkeypatch.setenv("AGENT_BOM_CLOUD_CIS_BENCHMARK", "1")

    with patch("agent_bom.api.routes.cloud._run_cis_benchmark", return_value={"status": "ok"}) as runner:
        response = client.get("/v1/cloud/aws/cis-benchmark")

    assert response.status_code == 200
    runner.assert_called_once()


def test_benchmark_requires_admin_not_analyst() -> None:
    """Analyst-in-any-tenant is the wrong bar for the platform's own identity."""
    from agent_bom.api.routes import cloud

    assert cloud._CIS_DEP is not cloud._SCAN_DEP, "CIS benchmark must not share the analyst-level scan dependency"


def test_inventory_keeps_its_own_per_provider_opt_in(client: Any) -> None:
    """The inventory surface is unchanged: still analyst-level, still env-gated."""
    from agent_bom.api.routes import cloud

    response = client.get("/v1/cloud/aws/inventory")

    assert response.status_code == 200
    assert response.json()["status"] == "disabled"
    # Unlike the benchmark, inventory returns non-secret counts and keeps the
    # scan-level dependency it already had.
    assert cloud._SCAN_DEP is not cloud._CIS_DEP
