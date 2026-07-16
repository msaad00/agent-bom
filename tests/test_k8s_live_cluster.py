"""Unit tests for live Kubernetes cluster security checks.

Covers the three read-only check families added to ``agent_bom.k8s``:

* PodSecurity against *running* workloads (``evaluate_pod_security``)
* namespace / RBAC audit (``evaluate_rbac``)
* node / kubelet CIS configuration (``evaluate_kubelet_config``)

All checks operate on already-parsed cluster objects (fixture dicts modelled on
``kubectl get ... -o json`` / kubelet ``configz`` payloads) so no live cluster
is required.  The kubectl transport is exercised separately in ``test_k8s.py``.
"""

from __future__ import annotations

import shutil
import subprocess

import pytest

from agent_bom.k8s import (
    K8sDiscoveryError,
    evaluate_kubelet_config,
    evaluate_pod_security,
    evaluate_rbac,
    scan_live_cluster_posture,
)

# ─── PodSecurity (running workloads) ─────────────────────────────────────────


def _pod(spec: dict, name: str = "app", namespace: str = "prod") -> dict:
    return {
        "metadata": {"name": name, "namespace": namespace},
        "spec": spec,
        "status": {"phase": "Running"},
    }


def test_pod_security_privileged_container():
    pods = {
        "items": [
            _pod(
                {
                    "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "c", "securityContext": {"privileged": True}}],
                }
            )
        ]
    }
    findings = evaluate_pod_security(pods)
    by_id = {f.rule_id: f for f in findings}
    assert "K8S-LIVE-007" in by_id
    assert by_id["K8S-LIVE-007"].severity == "critical"
    assert by_id["K8S-LIVE-007"].category == "kubernetes-live"
    assert "CIS-K8s-5.2.1" in by_id["K8S-LIVE-007"].compliance


def test_pod_security_host_namespaces_and_hostpath():
    pods = {
        "items": [
            _pod(
                {
                    "hostNetwork": True,
                    "hostPID": True,
                    "hostIPC": True,
                    "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "hp", "hostPath": {"path": "/etc"}}],
                    "containers": [{"name": "c", "securityContext": {"readOnlyRootFilesystem": True}}],
                }
            )
        ]
    }
    ids = {f.rule_id for f in evaluate_pod_security(pods)}
    assert "K8S-LIVE-008" in ids  # hostNetwork
    assert "K8S-LIVE-009" in ids  # hostPID / hostIPC
    assert "K8S-LIVE-010" in ids  # hostPath


def test_pod_security_run_as_root_and_priv_escalation_and_caps():
    pods = {
        "items": [
            _pod(
                {
                    "securityContext": {"seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [
                        {
                            "name": "c",
                            "securityContext": {
                                "runAsUser": 0,
                                "allowPrivilegeEscalation": True,
                                "capabilities": {"add": ["SYS_ADMIN"]},
                            },
                        }
                    ],
                }
            )
        ]
    }
    ids = {f.rule_id for f in evaluate_pod_security(pods)}
    assert "K8S-LIVE-011" in ids  # runAsUser 0
    assert "K8S-LIVE-012" in ids  # allowPrivilegeEscalation
    assert "K8S-LIVE-013" in ids  # dangerous capability


def test_pod_security_missing_pod_security_context():
    pods = {"items": [_pod({"containers": [{"name": "c", "securityContext": {"readOnlyRootFilesystem": True}}]})]}
    ids = {f.rule_id for f in evaluate_pod_security(pods)}
    assert "K8S-LIVE-014" in ids


def test_pod_security_hardened_pod_clean():
    """A hardened running pod yields no PodSecurity findings."""
    pods = {
        "items": [
            _pod(
                {
                    "hostNetwork": False,
                    "hostPID": False,
                    "hostIPC": False,
                    "securityContext": {"runAsNonRoot": True, "seccompProfile": {"type": "RuntimeDefault"}},
                    "volumes": [{"name": "data", "emptyDir": {}}],
                    "containers": [
                        {
                            "name": "c",
                            "securityContext": {
                                "privileged": False,
                                "runAsNonRoot": True,
                                "allowPrivilegeEscalation": False,
                                "readOnlyRootFilesystem": True,
                                "capabilities": {"drop": ["ALL"]},
                            },
                        }
                    ],
                }
            )
        ]
    }
    assert evaluate_pod_security(pods) == []


def test_pod_security_skips_non_running_pods():
    """PodSecurity is a runtime posture check — only running pods are evaluated."""
    pods = {
        "items": [
            {
                "metadata": {"name": "old", "namespace": "prod"},
                "spec": {"containers": [{"name": "c", "securityContext": {"privileged": True}}]},
                "status": {"phase": "Succeeded"},
            }
        ]
    }
    assert evaluate_pod_security(pods) == []


# ─── RBAC / namespace audit ──────────────────────────────────────────────────


def test_rbac_cluster_admin_binding():
    crb = {
        "items": [
            {
                "metadata": {"name": "admin-binding"},
                "roleRef": {"name": "cluster-admin"},
                "subjects": [{"kind": "ServiceAccount", "namespace": "prod", "name": "default"}],
            }
        ]
    }
    findings = evaluate_rbac({"items": []}, {"items": []}, crb)
    by_id = {f.rule_id: f for f in findings}
    assert "K8S-LIVE-006" in by_id
    assert by_id["K8S-LIVE-006"].severity == "critical"


def test_rbac_wildcard_cluster_role():
    cluster_roles = {
        "items": [
            {
                "metadata": {"name": "app-superuser"},
                "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}],
            }
        ]
    }
    findings = evaluate_rbac(cluster_roles, {"items": []}, {"items": []})
    by_id = {f.rule_id: f for f in findings}
    assert "K8S-LIVE-015" in by_id
    assert by_id["K8S-LIVE-015"].severity == "high"
    assert "CIS-K8s-5.1.3" in by_id["K8S-LIVE-015"].compliance


def test_rbac_wildcard_namespaced_role():
    roles = {
        "items": [
            {
                "metadata": {"name": "ns-superuser", "namespace": "prod"},
                "rules": [{"apiGroups": [""], "resources": ["secrets"], "verbs": ["*"]}],
            }
        ]
    }
    ids = {f.rule_id for f in evaluate_rbac({"items": []}, roles, {"items": []})}
    assert "K8S-LIVE-016" in ids


def test_rbac_ignores_builtin_system_roles():
    """Built-in cluster-admin and system: roles are expected wildcards — not flagged."""
    cluster_roles = {
        "items": [
            {"metadata": {"name": "cluster-admin"}, "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
            {"metadata": {"name": "system:controller:x"}, "rules": [{"apiGroups": ["*"], "resources": ["*"], "verbs": ["*"]}]},
        ]
    }
    ids = {f.rule_id for f in evaluate_rbac(cluster_roles, {"items": []}, {"items": []})}
    assert "K8S-LIVE-015" not in ids


def test_rbac_least_privilege_role_clean():
    cluster_roles = {
        "items": [
            {
                "metadata": {"name": "reader"},
                "rules": [{"apiGroups": [""], "resources": ["pods"], "verbs": ["get", "list", "watch"]}],
            }
        ]
    }
    assert evaluate_rbac(cluster_roles, {"items": []}, {"items": []}) == []


# ─── Node / kubelet configuration (kube-bench-style CIS) ──────────────────────


def test_kubelet_anonymous_auth_and_always_allow():
    cfg = {
        "authentication": {"anonymous": {"enabled": True}},
        "authorization": {"mode": "AlwaysAllow"},
        "readOnlyPort": 10255,
    }
    findings = evaluate_kubelet_config("node-1", cfg)
    by_id = {f.rule_id: f for f in findings}
    assert by_id["K8S-LIVE-020"].severity == "critical"  # anonymous-auth
    assert "CIS-K8s-4.2.1" in by_id["K8S-LIVE-020"].compliance
    assert by_id["K8S-LIVE-021"].severity == "critical"  # AlwaysAllow
    assert "K8S-LIVE-022" in by_id  # read-only port
    assert by_id["K8S-LIVE-020"].file_path == "k8s://node/node-1"


def test_kubelet_weak_hardening_flags():
    cfg = {
        "authentication": {"anonymous": {"enabled": False}},
        "authorization": {"mode": "Webhook"},
        "readOnlyPort": 0,
        "streamingConnectionIdleTimeout": "0",
        "protectKernelDefaults": False,
        "makeIPTablesUtilChains": False,
        "rotateCertificates": False,
    }
    ids = {f.rule_id for f in evaluate_kubelet_config("node-1", cfg)}
    assert "K8S-LIVE-023" in ids  # streaming idle timeout disabled
    assert "K8S-LIVE-024" in ids  # protectKernelDefaults
    assert "K8S-LIVE-025" in ids  # makeIPTablesUtilChains
    assert "K8S-LIVE-026" in ids  # rotateCertificates
    # Hardened auth/authz/read-only-port must NOT be flagged.
    assert "K8S-LIVE-020" not in ids
    assert "K8S-LIVE-021" not in ids
    assert "K8S-LIVE-022" not in ids


def test_kubelet_hardened_config_clean():
    cfg = {
        "authentication": {"anonymous": {"enabled": False}},
        "authorization": {"mode": "Webhook"},
        "readOnlyPort": 0,
        "streamingConnectionIdleTimeout": "4h0m0s",
        "protectKernelDefaults": True,
        "makeIPTablesUtilChains": True,
        "rotateCertificates": True,
    }
    assert evaluate_kubelet_config("node-1", cfg) == []


# ─── Honest no-cluster / unreachable handling ────────────────────────────────


def test_scan_live_cluster_no_kubectl(monkeypatch):
    """No kubectl on PATH → honest error, never a fake clean pass."""
    monkeypatch.setattr(shutil, "which", lambda _: None)
    with pytest.raises(K8sDiscoveryError):
        scan_live_cluster_posture(namespace="prod")


def test_scan_live_cluster_kubelet_unreachable_skips_not_fails(monkeypatch):
    """A managed cluster that blocks the kubelet configz proxy must skip node
    checks honestly (no finding fabricated, scan still completes) rather than
    crash or emit a false pass."""
    monkeypatch.setattr(shutil, "which", lambda cmd: "/usr/bin/" + cmd)

    import json

    payloads = {
        ("get", "pods"): {"items": []},
        ("get", "networkpolicies"): {"items": []},
        ("get", "clusterrolebindings"): {"items": []},
        ("get", "clusterroles"): {"items": []},
        ("get", "roles"): {"items": []},
        ("get", "nodes"): {"items": [{"metadata": {"name": "node-1"}}]},
    }

    def fake_run(cmd, **kwargs):
        class R:
            pass

        r = R()
        r.stderr = ""
        key = tuple(cmd[1:3])
        if key == ("get", "--raw"):
            # kubelet configz blocked (managed control plane)
            r.returncode = 1
            r.stdout = ""
            r.stderr = "Error from server (Forbidden): nodes proxy is forbidden"
            return r
        r.returncode = 0
        r.stdout = json.dumps(payloads[key])
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Must not raise; kubelet checks are simply skipped.
    findings = scan_live_cluster_posture(namespace="prod")
    assert all(not f.rule_id.startswith("K8S-LIVE-02") for f in findings)
