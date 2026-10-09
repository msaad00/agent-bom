"""Rendered scaling limits must activate shared-state runtime safeguards."""

from __future__ import annotations

import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

CHART = Path(__file__).resolve().parents[1] / "deploy/helm/agent-bom"
pytestmark = pytest.mark.skipif(shutil.which("helm") is None, reason="helm not installed")


def _render(workload: dict, *, component: str = "api") -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["helm", "template", "replica-safety", str(CHART), "--values", "-"],
        input=yaml.safe_dump(
            {
                "controlPlane": {
                    "enabled": True,
                    "postgresSecrets": {
                        "enabled": True,
                        "appSecretRef": {"name": "test-db"},
                        "maintenanceSecretRef": {"name": "test-maintenance"},
                        "adminSecretRef": {"name": "test-admin"},
                    },
                    component: workload,
                },
                "pdb": {"enabled": True},
            }
        ),
        text=True,
        capture_output=True,
        check=False,
    )


def _objects(result: subprocess.CompletedProcess[str]) -> list[dict]:
    assert result.returncode == 0, result.stderr
    return [doc for doc in yaml.safe_load_all(result.stdout) if doc]


def _api_env(objects: list[dict]) -> dict[str, str]:
    api = next(doc for doc in objects if doc["kind"] == "Deployment" and doc["metadata"]["name"] == "agent-bom-api")
    return {entry["name"]: entry["value"] for entry in api["spec"]["template"]["spec"]["containers"][0]["env"] if "value" in entry}


@pytest.mark.parametrize(
    ("replicas", "enabled", "minimum", "maximum", "keda", "fallback", "expected"),
    [
        (1, False, 2, 6, False, 2, 1),
        (3, False, 2, 6, False, 2, 3),
        (1, True, 1, 6, False, 2, 6),
        (9, True, 1, 6, False, 2, 9),
        (1, True, 1, 12, True, 2, 12),
        (1, True, 1, 6, True, 8, 8),
        (0, True, 0, 4, True, 2, 4),
    ],
)
def test_api_guards_use_every_configured_replica_source(replicas, enabled, minimum, maximum, keda, fallback, expected):
    objects = _objects(
        _render(
            {
                "replicas": replicas,
                "autoscaling": {
                    "enabled": enabled,
                    "minReplicas": minimum,
                    "maxReplicas": maximum,
                    "keda": {
                        "enabled": keda,
                        "fallback": {"replicas": fallback},
                        "prometheus": {"serverAddress": "http://prometheus.monitoring.svc:9090"},
                    },
                },
            }
        )
    )
    assert _api_env(objects)["AGENT_BOM_CONTROL_PLANE_REPLICAS"] == str(expected)


@pytest.mark.parametrize("component", ["api", "ui"])
@pytest.mark.parametrize("autoscaling", [False, True])
def test_disruption_budget_accounts_for_autoscaling_from_one(component, autoscaling):
    objects = _objects(
        _render({"replicas": 1, "autoscaling": {"enabled": autoscaling, "minReplicas": 1, "maxReplicas": 3}}, component=component)
    )
    budgets = [doc for doc in objects if doc["kind"] == "PodDisruptionBudget" and doc["metadata"]["name"] == f"agent-bom-{component}"]
    assert bool(budgets) is autoscaling


def test_api_replica_guard_cannot_be_shadowed_by_extra_env():
    result = _render({"replicas": 3, "env": [{"name": "AGENT_BOM_CONTROL_PLANE_REPLICAS", "value": "1"}]})
    assert result.returncode != 0
    assert "cannot override AGENT_BOM_CONTROL_PLANE_REPLICAS" in result.stderr


def test_scale_out_requires_a_shared_browser_signing_key(monkeypatch):
    from agent_bom.api import browser_session, secret_source

    env = _api_env(_objects(_render({"replicas": 1, "autoscaling": {"enabled": True, "minReplicas": 1, "maxReplicas": 6}})))
    monkeypatch.setenv("AGENT_BOM_CONTROL_PLANE_REPLICAS", env["AGENT_BOM_CONTROL_PLANE_REPLICAS"])
    monkeypatch.delenv("AGENT_BOM_REQUIRE_BROWSER_SESSION_SIGNING_KEY", raising=False)
    monkeypatch.setattr(secret_source, "resolve_secret", lambda *args, **kwargs: "")
    with pytest.raises(browser_session.BrowserSessionError, match="required for clustered"):
        browser_session.create_browser_session_token(
            subject="operator",
            role="viewer",
            tenant_id="test",
            auth_method="api_key",
            max_age_seconds=60,
        )
