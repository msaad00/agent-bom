"""Tests for Kubernetes MCP server discovery (#307).

Tests cover:
- discover_k8s_mcp_servers() returns None when kubectl not on PATH
- Pods with MCP labels are detected
- Pods with MCP image name patterns are detected
- Pods with MCP_ environment variables are detected
- Pods without MCP signals are skipped
- MCP CRDs (mcpservers.mcp.io) are discovered when present
- CRD query failure (not installed) does not crash function
- Exposed ports trigger SSE transport + URL generation
- All namespaces mode (-A flag)
- Custom kubectl context is passed through
- discover_all() with include_k8s_mcp=False skips K8s (default)
- discover_all() with include_k8s_mcp=True invokes discover_k8s_mcp_servers
"""

from __future__ import annotations

import json
from unittest.mock import MagicMock, patch

from agent_bom.discovery import discover_k8s_mcp_servers
from agent_bom.models import AgentType, TransportType

# ─── Helpers ──────────────────────────────────────────────────────────────────


def _pod(name: str, namespace: str = "default", labels: dict | None = None, containers: list | None = None) -> dict:
    return {
        "metadata": {
            "name": name,
            "namespace": namespace,
            "labels": labels or {},
            "annotations": {},
        },
        "spec": {"containers": containers or [{"name": "mcp", "image": "mcp-server:latest", "env": [], "ports": []}]},
    }


def _crd_item(name: str, namespace: str = "default", url: str = "") -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": {"url": url, "command": "mcp-server"},
    }


def _kubectl_response(items: list) -> str:
    return json.dumps({"apiVersion": "v1", "items": items})


# ─── kubectl not available ─────────────────────────────────────────────────────


def test_returns_none_when_kubectl_missing():
    with patch("agent_bom.discovery.shutil.which", return_value=None):
        result = discover_k8s_mcp_servers()
    assert result is None


# ─── Pod label detection ───────────────────────────────────────────────────────


def test_detects_pod_with_mcp_server_label():
    pod = _pod("mcp-pod", labels={"mcp.server": "true"})
    pods_resp = _kubectl_response([pod])
    crd_resp = _kubectl_response([])  # no CRDs

    call_count = {"n": 0}

    def _fake_run(cmd, **kwargs):
        call_count["n"] += 1
        r = MagicMock()
        r.returncode = 0
        r.stdout = pods_resp if "pods" in cmd else crd_resp
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            agent = discover_k8s_mcp_servers()

    assert agent is not None
    assert len(agent.mcp_servers) == 1
    assert agent.source == "kubernetes"
    assert agent.agent_type == AgentType.CUSTOM


def test_detects_pod_with_mcp_image_name():
    container = {"name": "server", "image": "ghcr.io/org/mcp-server:v1", "env": [], "ports": []}
    pod = _pod("img-pod", labels={}, containers=[container])
    pods_resp = _kubectl_response([pod])
    crd_resp = _kubectl_response([])

    def _fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        r.stdout = pods_resp if "pods" in cmd else crd_resp
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            agent = discover_k8s_mcp_servers()

    assert agent is not None
    assert any("img-pod" in s.name for s in agent.mcp_servers)


def test_detects_pod_with_mcp_env_var():
    container = {
        "name": "server",
        "image": "myapp:latest",
        "env": [{"name": "MCP_PORT", "value": "8000"}],
        "ports": [],
    }
    pod = _pod("env-pod", labels={}, containers=[container])
    pods_resp = _kubectl_response([pod])
    crd_resp = _kubectl_response([])

    def _fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        r.stdout = pods_resp if "pods" in cmd else crd_resp
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            agent = discover_k8s_mcp_servers()

    assert agent is not None
    assert any("env-pod" in s.name for s in agent.mcp_servers)


def test_skips_pod_without_mcp_signals():
    container = {"name": "web", "image": "nginx:latest", "env": [], "ports": []}
    pod = _pod("nginx-pod", labels={"app": "frontend"}, containers=[container])
    pods_resp = _kubectl_response([pod])
    crd_resp = _kubectl_response([])

    def _fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        r.stdout = pods_resp if "pods" in cmd else crd_resp
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            agent = discover_k8s_mcp_servers()

    assert agent is None


def test_returns_none_when_no_mcp_pods_or_crds():
    pods_resp = _kubectl_response([])
    crd_resp = _kubectl_response([])

    def _fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        r.stdout = pods_resp if "pods" in cmd else crd_resp
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            agent = discover_k8s_mcp_servers()

    assert agent is None


# ─── Ports → SSE transport ─────────────────────────────────────────────────────


def test_exposed_port_sets_sse_transport():
    container = {
        "name": "mcp",
        "image": "mcp-server:latest",
        "env": [],
        "ports": [{"containerPort": 9090}],
    }
    pod = _pod("port-pod", labels={"mcp.server": "true"}, containers=[container])
    pods_resp = _kubectl_response([pod])
    crd_resp = _kubectl_response([])

    def _fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        r.stdout = pods_resp if "pods" in cmd else crd_resp
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            agent = discover_k8s_mcp_servers()

    assert agent is not None
    srv = agent.mcp_servers[0]
    assert srv.transport == TransportType.SSE
    assert "9090" in srv.url


def test_no_ports_sets_stdio_transport():
    container = {"name": "mcp", "image": "mcp-server:latest", "env": [], "ports": []}
    pod = _pod("no-port", labels={"mcp.server": "true"}, containers=[container])
    pods_resp = _kubectl_response([pod])
    crd_resp = _kubectl_response([])

    def _fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        r.stdout = pods_resp if "pods" in cmd else crd_resp
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            agent = discover_k8s_mcp_servers()

    assert agent is not None
    assert agent.mcp_servers[0].transport == TransportType.STDIO


# ─── CRD discovery ────────────────────────────────────────────────────────────


def test_discovers_mcp_crd():
    pods_resp = _kubectl_response([])
    crd_item = _crd_item("my-mcp-server", namespace="production", url="http://mcp.production.svc:8080")
    crd_resp = _kubectl_response([crd_item])

    def _fake_run(cmd, **kwargs):
        r = MagicMock()
        r.returncode = 0
        r.stdout = pods_resp if "pods" in cmd else crd_resp
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            agent = discover_k8s_mcp_servers()

    assert agent is not None
    assert any("my-mcp-server" in s.name for s in agent.mcp_servers)
    srv = next(s for s in agent.mcp_servers if "my-mcp-server" in s.name)
    assert srv.transport == TransportType.SSE
    assert srv.url == "http://mcp.production.svc:8080"


def test_crd_failure_does_not_crash():
    """CRD query returning non-zero doesn't crash — graceful degradation."""
    pod = _pod("mcp-pod", labels={"mcp.server": "true"})
    pods_resp = _kubectl_response([pod])

    call_n = {"n": 0}

    def _fake_run(cmd, **kwargs):
        call_n["n"] += 1
        r = MagicMock()
        if "pods" in cmd:
            r.returncode = 0
            r.stdout = pods_resp
        else:
            r.returncode = 1  # CRD not installed
            r.stdout = ""
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            agent = discover_k8s_mcp_servers()

    # Should still return pod-level results
    assert agent is not None
    assert len(agent.mcp_servers) == 1


# ─── Namespace / context flags ────────────────────────────────────────────────


def test_all_namespaces_flag_passes_dash_a():
    captured = []

    def _fake_run(cmd, **kwargs):
        captured.append(cmd)
        r = MagicMock()
        r.returncode = 0
        r.stdout = _kubectl_response([])
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            discover_k8s_mcp_servers(all_namespaces=True)

    pod_cmd = next(c for c in captured if "pods" in c)
    assert "-A" in pod_cmd


def test_custom_namespace_is_used():
    captured = []

    def _fake_run(cmd, **kwargs):
        captured.append(cmd)
        r = MagicMock()
        r.returncode = 0
        r.stdout = _kubectl_response([])
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            discover_k8s_mcp_servers(namespace="production")

    pod_cmd = next(c for c in captured if "pods" in c)
    assert "-n" in pod_cmd
    assert "production" in pod_cmd


def test_custom_context_is_passed():
    captured = []

    def _fake_run(cmd, **kwargs):
        captured.append(cmd)
        r = MagicMock()
        r.returncode = 0
        r.stdout = _kubectl_response([])
        return r

    with patch("agent_bom.discovery.shutil.which", return_value="/usr/bin/kubectl"):
        with patch("agent_bom.discovery.subprocess.run", side_effect=_fake_run):
            discover_k8s_mcp_servers(context="my-cluster")

    for cmd in captured:
        assert "--context" in cmd
        assert "my-cluster" in cmd


# ─── discover_all() integration ───────────────────────────────────────────────

_DISCOVER_ALL_PATCHES = {
    "agent_bom.discovery.discover_global_configs": [],
    "agent_bom.discovery.discover_project_configs": [],
    "agent_bom.discovery.discover_compose_mcp_servers": None,
    "agent_bom.discovery.discover_docker_mcp": None,
    "agent_bom.discovery.detect_installed_agents": [],
}


def test_discover_all_skips_k8s_by_default():
    from contextlib import ExitStack

    from agent_bom.discovery import discover_all

    with ExitStack() as stack:
        mock_k8s = stack.enter_context(patch("agent_bom.discovery.discover_k8s_mcp_servers"))
        for target, rv in _DISCOVER_ALL_PATCHES.items():
            stack.enter_context(patch(target, return_value=rv))
        discover_all()

    mock_k8s.assert_not_called()


def test_discover_all_calls_k8s_when_flagged():
    from contextlib import ExitStack

    from agent_bom.discovery import discover_all

    with ExitStack() as stack:
        mock_k8s = stack.enter_context(patch("agent_bom.discovery.discover_k8s_mcp_servers", return_value=None))
        for target, rv in _DISCOVER_ALL_PATCHES.items():
            stack.enter_context(patch(target, return_value=rv))
        discover_all(include_k8s_mcp=True, k8s_namespace="prod", k8s_all_namespaces=False, k8s_context=None)

    mock_k8s.assert_called_once_with(namespace="prod", all_namespaces=False, context=None)
