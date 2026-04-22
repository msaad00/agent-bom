from __future__ import annotations

import base64
import json

from starlette.testclient import TestClient

from agent_bom.sidecar_injector import SidecarInjectorSettings, create_sidecar_injector_app


def _decode_patch(response) -> list[dict]:
    body = response.json()
    patch = body["response"]["patch"]
    return json.loads(base64.b64decode(patch))


def _settings(audit_events: list[dict]) -> SidecarInjectorSettings:
    def _audit(action: str, actor: str = "system", resource: str = "", **details: object) -> None:
        audit_events.append({"action": action, "actor": actor, "resource": resource, "details": details})

    return SidecarInjectorSettings(
        proxy_image="agentbom/agent-bom:0.81.0",
        control_plane_url="http://agent-bom-api.agent-bom.svc.cluster.local:8422",
        control_plane_token_secret_name="agent-bom-proxy-auth",
        audit_logger=_audit,
    )


def test_sidecar_injector_mutates_pod_with_proxy_container():
    audit_events: list[dict] = []
    client = TestClient(create_sidecar_injector_app(_settings(audit_events)))
    payload = {
        "request": {
            "uid": "req-1",
            "operation": "CREATE",
            "kind": {"kind": "Pod"},
            "namespace": "agent-bom",
            "object": {
                "metadata": {
                    "name": "mcp-pod",
                    "labels": {"agent-bom.io/proxy": "true", "agent-bom.io/tenant": "tenant-a"},
                },
                "spec": {
                    "containers": [{"name": "app", "image": "example.com/mcp:1"}],
                },
            },
        }
    }
    response = client.post("/mutate", json=payload)
    assert response.status_code == 200
    patch = _decode_patch(response)
    sidecar = next(item["value"] for item in patch if item["path"] == "/spec/containers/-")
    assert sidecar["name"] == "agent-bom-proxy"
    assert "--url" in sidecar["args"]
    assert "http://127.0.0.1:3000" in sidecar["args"]
    assert any(item["path"] == "/metadata/annotations/agent-bom.io~1proxy-injected" for item in patch)
    assert audit_events[0]["details"]["tenant_id"] == "tenant-a"


def test_sidecar_injector_honors_explicit_mcp_url():
    audit_events: list[dict] = []
    client = TestClient(create_sidecar_injector_app(_settings(audit_events)))
    payload = {
        "request": {
            "uid": "req-2",
            "operation": "CREATE",
            "kind": {"kind": "Pod"},
            "namespace": "agent-bom",
            "object": {
                "metadata": {
                    "generateName": "mcp-pod-",
                    "annotations": {"agent-bom.io/mcp-url": "http://127.0.0.1:9090/sse"},
                },
                "spec": {"containers": [{"name": "app", "image": "example.com/mcp:1"}]},
            },
        }
    }
    response = client.post("/mutate", json=payload)
    patch = _decode_patch(response)
    sidecar = next(item["value"] for item in patch if item["path"] == "/spec/containers/-")
    assert "http://127.0.0.1:9090/sse" in sidecar["args"]


def test_sidecar_injector_skips_existing_sidecar_or_opt_out():
    audit_events: list[dict] = []
    client = TestClient(create_sidecar_injector_app(_settings(audit_events)))
    payload = {
        "request": {
            "uid": "req-3",
            "operation": "CREATE",
            "kind": {"kind": "Pod"},
            "namespace": "agent-bom",
            "object": {
                "metadata": {
                    "name": "mcp-pod",
                    "labels": {"agent-bom.io/proxy": "false"},
                },
                "spec": {
                    "containers": [
                        {"name": "app", "image": "example.com/mcp:1"},
                        {"name": "agent-bom-proxy", "image": "agentbom/agent-bom:0.81.0"},
                    ]
                },
            },
        }
    }
    response = client.post("/mutate", json=payload)
    assert response.status_code == 200
    body = response.json()
    assert "patch" not in body["response"]
    assert audit_events == []
