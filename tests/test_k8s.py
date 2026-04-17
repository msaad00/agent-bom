"""Direct unit tests for agent_bom.k8s module.

Covers discover_images() and list_namespaces() with mock kubectl.
"""

from __future__ import annotations

import json
import shutil
import subprocess

import pytest

from agent_bom.k8s import K8sDiscoveryError, _kubectl_available, discover_images, list_namespaces, scan_live_cluster_posture

# ─── _kubectl_available ──────────────────────────────────────────────────────


def test_kubectl_available_found(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/local/bin/kubectl" if cmd == "kubectl" else None)
    assert _kubectl_available() is True


def test_kubectl_available_not_found(monkeypatch):
    monkeypatch.setattr(shutil, "which", lambda _: None)
    assert _kubectl_available() is False


# ─── discover_images ─────────────────────────────────────────────────────────


def _mock_kubectl(monkeypatch, pods_json, returncode=0, stderr=""):
    """Helper: mock shutil.which + subprocess.run for kubectl calls."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)
    captured_cmds = []

    def fake_run(cmd, **kwargs):
        captured_cmds.append(list(cmd))

        class R:
            pass

        r = R()
        r.returncode = returncode
        r.stdout = json.dumps(pods_json) if isinstance(pods_json, dict) else pods_json
        r.stderr = stderr
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)
    return captured_cmds


def test_discover_images_label_selector(monkeypatch):
    """discover_images passes -l flag for label selector."""
    pods = {"items": []}
    cmds = _mock_kubectl(monkeypatch, pods)
    discover_images(label_selector="app=web")
    assert "-l" in cmds[0]
    assert "app=web" in cmds[0]


def test_discover_images_context(monkeypatch):
    """discover_images passes --context flag."""
    pods = {"items": []}
    cmds = _mock_kubectl(monkeypatch, pods)
    discover_images(context="staging-cluster")
    assert "--context" in cmds[0]
    assert "staging-cluster" in cmds[0]


def test_discover_images_timeout(monkeypatch):
    """discover_images raises K8sDiscoveryError on timeout."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, kwargs.get("timeout", 60))

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(K8sDiscoveryError, match="timed out"):
        discover_images()


def test_discover_images_invalid_json(monkeypatch):
    """discover_images raises K8sDiscoveryError for invalid JSON output."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stdout = "not valid json{{"
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(K8sDiscoveryError, match="invalid JSON"):
        discover_images()


def test_discover_images_ephemeral_containers(monkeypatch):
    """discover_images extracts images from ephemeralContainers."""
    pods = {
        "items": [
            {
                "metadata": {"name": "debug-pod", "namespace": "default"},
                "spec": {
                    "containers": [{"name": "app", "image": "myapp:v1"}],
                    "ephemeralContainers": [{"name": "debugger", "image": "busybox:debug"}],
                },
            }
        ]
    }
    _mock_kubectl(monkeypatch, pods)
    records = discover_images()
    images = [r[0] for r in records]
    assert "myapp:v1" in images
    assert "busybox:debug" in images


def test_discover_images_empty_items(monkeypatch):
    """discover_images returns empty list when no pods exist."""
    _mock_kubectl(monkeypatch, {"items": []})
    assert discover_images() == []


def test_discover_images_deduplication(monkeypatch):
    """Same image from multiple pods is only returned once."""
    pods = {
        "items": [
            {
                "metadata": {"name": "pod-a", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "shared:v1"}]},
            },
            {
                "metadata": {"name": "pod-b", "namespace": "default"},
                "spec": {"containers": [{"name": "app", "image": "shared:v1"}]},
            },
        ]
    }
    _mock_kubectl(monkeypatch, pods)
    records = discover_images()
    images = [r[0] for r in records]
    assert images.count("shared:v1") == 1
    assert records[0][1] == "pod-a"  # attributed to first pod


def test_discover_images_missing_metadata(monkeypatch):
    """discover_images handles pods with missing metadata gracefully."""
    pods = {
        "items": [
            {
                "spec": {"containers": [{"name": "app", "image": "myapp:v1"}]},
            }
        ]
    }
    _mock_kubectl(monkeypatch, pods)
    records = discover_images()
    assert len(records) == 1
    assert records[0][0] == "myapp:v1"
    assert records[0][1] == "unknown"  # defaults to "unknown" when metadata missing


def test_discover_images_namespace_flag(monkeypatch):
    """discover_images passes -n namespace when not all_namespaces."""
    cmds = _mock_kubectl(monkeypatch, {"items": []})
    discover_images(namespace="production")
    assert "-n" in cmds[0]
    assert "production" in cmds[0]


def test_discover_images_multiple_container_types(monkeypatch):
    """discover_images extracts from containers, initContainers, and ephemeralContainers."""
    pods = {
        "items": [
            {
                "metadata": {"name": "full-pod", "namespace": "default"},
                "spec": {
                    "containers": [{"name": "main", "image": "app:v1"}],
                    "initContainers": [{"name": "init", "image": "init:v1"}],
                    "ephemeralContainers": [{"name": "debug", "image": "debug:v1"}],
                },
            }
        ]
    }
    _mock_kubectl(monkeypatch, pods)
    records = discover_images()
    images = {r[0] for r in records}
    assert images == {"app:v1", "init:v1", "debug:v1"}


# ─── list_namespaces ─────────────────────────────────────────────────────────


def test_list_namespaces_no_kubectl(monkeypatch):
    """list_namespaces raises K8sDiscoveryError when kubectl is missing."""
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(K8sDiscoveryError, match="kubectl"):
        list_namespaces()


def test_list_namespaces_valid(monkeypatch):
    """list_namespaces parses namespace names from kubectl JSON."""
    ns_data = {
        "items": [
            {"metadata": {"name": "default"}},
            {"metadata": {"name": "kube-system"}},
            {"metadata": {"name": "production"}},
        ]
    }
    _mock_kubectl(monkeypatch, ns_data)
    result = list_namespaces()
    assert result == ["default", "kube-system", "production"]


def test_list_namespaces_with_context(monkeypatch):
    """list_namespaces passes --context flag."""
    cmds = _mock_kubectl(monkeypatch, {"items": []})
    list_namespaces(context="my-cluster")
    assert "--context" in cmds[0]
    assert "my-cluster" in cmds[0]


def test_list_namespaces_kubectl_error(monkeypatch):
    """list_namespaces raises K8sDiscoveryError on non-zero exit."""
    _mock_kubectl(monkeypatch, "", returncode=1, stderr="connection refused")
    with pytest.raises(K8sDiscoveryError):
        list_namespaces()


def test_list_namespaces_timeout(monkeypatch):
    """list_namespaces raises K8sDiscoveryError on timeout."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    def fake_run(cmd, **kwargs):
        raise subprocess.TimeoutExpired(cmd, 30)

    monkeypatch.setattr(subprocess, "run", fake_run)
    with pytest.raises(K8sDiscoveryError):
        list_namespaces()


def test_list_namespaces_invalid_json(monkeypatch):
    """list_namespaces returns empty list on invalid JSON."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    def fake_run(cmd, **kwargs):
        class R:
            returncode = 0
            stdout = "not json"
            stderr = ""

        return R()

    monkeypatch.setattr(subprocess, "run", fake_run)
    result = list_namespaces()
    assert result == []


def test_list_namespaces_empty(monkeypatch):
    """list_namespaces returns empty list when no namespaces exist."""
    _mock_kubectl(monkeypatch, {"items": []})
    assert list_namespaces() == []


def test_scan_live_cluster_posture_finds_runtime_gaps(monkeypatch):
    """Live cluster posture scan reports runtime RBAC, pod health, and network gaps."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    payloads = {
        ("get", "pods"): {
            "items": [
                {
                    "metadata": {"name": "api", "namespace": "prod"},
                    "spec": {"automountServiceAccountToken": True},
                    "status": {
                        "phase": "CrashLoopBackOff",
                        "containerStatuses": [
                            {
                                "name": "api",
                                "ready": False,
                                "state": {"waiting": {"reason": "CrashLoopBackOff"}},
                            }
                        ],
                    },
                }
            ]
        },
        ("get", "networkpolicies"): {"items": []},
        ("get", "clusterrolebindings"): {
            "items": [
                {
                    "metadata": {"name": "admin-binding"},
                    "roleRef": {"name": "cluster-admin"},
                    "subjects": [{"kind": "ServiceAccount", "namespace": "prod", "name": "default"}],
                }
            ]
        },
    }

    def fake_run(cmd, **kwargs):
        class R:
            pass

        r = R()
        r.returncode = 0
        r.stderr = ""
        key = tuple(cmd[1:3])
        r.stdout = json.dumps(payloads[key])
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)

    findings = scan_live_cluster_posture(namespace="prod")
    rule_ids = {finding.rule_id for finding in findings}
    assert {"K8S-LIVE-001", "K8S-LIVE-002", "K8S-LIVE-003", "K8S-LIVE-004", "K8S-LIVE-005", "K8S-LIVE-006"} <= rule_ids


def test_scan_live_cluster_posture_clean_cluster(monkeypatch):
    """Live cluster posture scan returns no findings for a healthy constrained cluster."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    payloads = {
        ("get", "pods"): {
            "items": [
                {
                    "metadata": {"name": "api", "namespace": "prod"},
                    "spec": {"automountServiceAccountToken": False},
                    "status": {
                        "phase": "Running",
                        "containerStatuses": [{"name": "api", "ready": True, "state": {"running": {}}}],
                    },
                }
            ]
        },
        ("get", "networkpolicies"): {"items": [{"metadata": {"name": "default-deny", "namespace": "prod"}}]},
        ("get", "clusterrolebindings"): {"items": []},
    }

    def fake_run(cmd, **kwargs):
        class R:
            pass

        r = R()
        r.returncode = 0
        r.stderr = ""
        key = tuple(cmd[1:3])
        r.stdout = json.dumps(payloads[key])
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)

    assert scan_live_cluster_posture(namespace="prod") == []
