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
    CollectorState,
    K8sDiscoveryError,
    K8sPostureStatus,
    evaluate_kubelet_config,
    evaluate_pod_security,
    evaluate_rbac,
    scan_live_cluster_posture,
    scan_live_cluster_posture_with_evidence,
)
from agent_bom.k8s_transport import K8sReadResult, K8sTransportError

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


def test_pod_security_pod_level_root_inherited_by_container():
    # Regression: root is set at the POD level; the container has a
    # securityContext but does not override runAsUser/runAsNonRoot, so it
    # inherits root. Container-only evaluation missed this (false-negative).
    pods = {
        "items": [
            _pod(
                {
                    "securityContext": {"runAsUser": 0, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "c", "securityContext": {"readOnlyRootFilesystem": True}}],
                }
            )
        ]
    }
    ids = {f.rule_id for f in evaluate_pod_security(pods)}
    assert "K8S-LIVE-011" in ids


def test_pod_security_pod_level_run_as_non_root_false_inherited():
    pods = {
        "items": [
            _pod(
                {
                    "securityContext": {"runAsNonRoot": False, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "c", "securityContext": {"readOnlyRootFilesystem": True}}],
                }
            )
        ]
    }
    ids = {f.rule_id for f in evaluate_pod_security(pods)}
    assert "K8S-LIVE-011" in ids


def test_pod_security_container_overrides_pod_level_root():
    # Pod sets root, but the container explicitly runs as a non-root uid: the
    # container override wins, so no root finding.
    pods = {
        "items": [
            _pod(
                {
                    "securityContext": {"runAsUser": 0, "seccompProfile": {"type": "RuntimeDefault"}},
                    "containers": [{"name": "c", "securityContext": {"runAsUser": 1000, "runAsNonRoot": True}}],
                }
            )
        ]
    }
    ids = {f.rule_id for f in evaluate_pod_security(pods)}
    assert "K8S-LIVE-011" not in ids


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


def test_scan_live_cluster_does_not_request_configz_by_default(monkeypatch):
    """The compatibility scan does not request opt-in node config evidence."""
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
        assert key != ("get", "--raw")
        r.returncode = 0
        r.stdout = json.dumps(payloads[key])
        return r

    monkeypatch.setattr(subprocess, "run", fake_run)

    # Must not raise; kubelet checks are simply skipped.
    findings = scan_live_cluster_posture(namespace="prod")
    assert all(not f.rule_id.startswith("K8S-LIVE-02") for f in findings)


class _FixtureTransport:
    name = "fixture"

    def __init__(self, payloads: dict[str, dict], errors: dict[str, K8sTransportError] | None = None) -> None:
        self.payloads = payloads
        self.errors = errors or {}
        self.get_paths: list[tuple[str, int, str]] = []

    def list_resource(self, resource: str, *, namespace: str | None = None, all_namespaces: bool = False):
        del namespace, all_namespaces
        if resource in self.errors:
            raise self.errors[resource]
        data = self.payloads.get(resource, {"items": []})
        return K8sReadResult(data=data, object_count=len(data.get("items", [])), pages=1, truncated=False)

    def get_kubelet_json(self, host: str, port: int, path: str, *, timeout: int | None = None):
        del timeout
        self.get_paths.append((host, port, path))
        if "configz" in self.errors:
            raise self.errors["configz"]
        return self.payloads.get("configz", {})

    def close(self) -> None:
        return None


def _foundation_payloads() -> dict[str, dict]:
    return {
        "pods": {
            "items": [
                _pod(
                    {
                        "automountServiceAccountToken": False,
                        "securityContext": {"runAsNonRoot": True},
                        "containers": [{"name": "c", "securityContext": {"privileged": True}}],
                    }
                )
            ]
        },
        "networkpolicies": {"items": []},
        "clusterrolebindings": {"items": []},
        "clusterroles": {"items": []},
        "roles": {"items": []},
        "nodes": {
            "items": [
                {
                    "metadata": {"name": "node-a"},
                    "status": {
                        "addresses": [{"type": "InternalIP", "address": "10.0.0.10"}],
                        "daemonEndpoints": {"kubeletEndpoint": {"Port": 10250}},
                    },
                }
            ]
        },
    }


def test_posture_evidence_isolates_forbidden_collector_without_false_network_policy_finding() -> None:
    transport = _FixtureTransport(
        _foundation_payloads(),
        errors={"networkpolicies": K8sTransportError("forbidden", status_code=403)},
    )

    result = scan_live_cluster_posture_with_evidence(namespace="prod", transport=transport)

    evidence = {item.collector_id: item for item in result.collectors}
    assert result.status is K8sPostureStatus.PARTIAL
    assert evidence["pods"].state is CollectorState.EXECUTED
    assert evidence["networkpolicies"].state is CollectorState.UNEVALUABLE
    assert "K8S-LIVE-007" in {finding.rule_id for finding in result.findings}
    assert "K8S-LIVE-005" not in {finding.rule_id for finding in result.findings}


def test_kubelet_configz_is_opt_in_and_skipped_without_proxy_access() -> None:
    transport = _FixtureTransport(_foundation_payloads())

    result = scan_live_cluster_posture_with_evidence(namespace="prod", transport=transport)

    evidence = {item.collector_id: item for item in result.collectors}
    assert evidence["kubelet_configz"].state is CollectorState.SKIPPED
    assert result.status is K8sPostureStatus.COMPLETE
    assert transport.get_paths == []


def test_kubelet_configz_forbidden_is_unevaluable_not_clean() -> None:
    transport = _FixtureTransport(
        _foundation_payloads(),
        errors={"configz": K8sTransportError("forbidden", status_code=403)},
    )

    result = scan_live_cluster_posture_with_evidence(
        namespace="prod",
        transport=transport,
        enable_nodes_configz=True,
    )

    evidence = {item.collector_id: item for item in result.collectors}
    assert evidence["kubelet_configz"].state is CollectorState.UNEVALUABLE
    assert result.status is K8sPostureStatus.PARTIAL
    assert transport.get_paths == [("10.0.0.10", 10250, "/configz")]
    assert all(not finding.rule_id.startswith("K8S-LIVE-02") for finding in result.findings)


def test_kubelet_configz_success_is_executed_evidence() -> None:
    payloads = _foundation_payloads()
    payloads["configz"] = {
        "kubeletconfig": {
            "authentication": {"anonymous": {"enabled": False}},
            "authorization": {"mode": "Webhook"},
            "readOnlyPort": 0,
        }
    }
    transport = _FixtureTransport(payloads)

    result = scan_live_cluster_posture_with_evidence(
        namespace="prod",
        transport=transport,
        enable_nodes_configz=True,
    )

    evidence = {item.collector_id: item for item in result.collectors}
    assert evidence["kubelet_configz"].state is CollectorState.EXECUTED
    assert evidence["kubelet_configz"].object_count == 1
    assert result.status is K8sPostureStatus.COMPLETE


def test_kubelet_configz_rejects_external_node_metadata_without_requesting_it() -> None:
    payloads = _foundation_payloads()
    payloads["nodes"]["items"][0]["status"]["addresses"] = [
        {"type": "ExternalIP", "address": "8.8.8.8"},
    ]
    transport = _FixtureTransport(payloads)

    result = scan_live_cluster_posture_with_evidence(
        namespace="prod",
        transport=transport,
        enable_nodes_configz=True,
    )

    evidence = {item.collector_id: item for item in result.collectors}
    assert evidence["kubelet_configz"].state is CollectorState.UNEVALUABLE
    assert result.status is K8sPostureStatus.PARTIAL
    assert transport.get_paths == []


def test_kubelet_configz_caps_node_fanout(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.k8s as k8s_module

    payloads = _foundation_payloads()
    second_node = {
        "metadata": {"name": "node-b"},
        "status": {
            "addresses": [{"type": "InternalIP", "address": "10.0.0.11"}],
            "daemonEndpoints": {"kubeletEndpoint": {"Port": 10250}},
        },
    }
    payloads["nodes"]["items"].append(second_node)
    payloads["configz"] = {"kubeletconfig": {"readOnlyPort": 0}}
    transport = _FixtureTransport(payloads)
    monkeypatch.setattr(k8s_module, "MAX_CONFIGZ_NODES", 1)

    result = scan_live_cluster_posture_with_evidence(
        namespace="prod",
        transport=transport,
        enable_nodes_configz=True,
    )

    evidence = {item.collector_id: item for item in result.collectors}
    assert evidence["kubelet_configz"].truncated is True
    assert evidence["kubelet_configz"].object_count == 1
    assert result.status is K8sPostureStatus.PARTIAL
    assert transport.get_paths == [("10.0.0.10", 10250, "/configz")]


def test_kubelet_configz_honors_overall_deadline(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.k8s as k8s_module

    payloads = _foundation_payloads()
    transport = _FixtureTransport(payloads)
    readings = iter((100.0, 161.0))
    monkeypatch.setattr(k8s_module, "monotonic", lambda: next(readings))
    monkeypatch.setattr(k8s_module, "MAX_CONFIGZ_BUDGET_SECONDS", 60)

    result = scan_live_cluster_posture_with_evidence(
        namespace="prod",
        transport=transport,
        enable_nodes_configz=True,
    )

    evidence = {item.collector_id: item for item in result.collectors}
    assert evidence["kubelet_configz"].truncated is True
    assert evidence["kubelet_configz"].object_count == 0
    assert result.status is K8sPostureStatus.PARTIAL
    assert transport.get_paths == []


def test_posture_evidence_records_failed_collectors_without_raising() -> None:
    errors = {
        resource: K8sTransportError("connection failed")
        for resource in ("pods", "networkpolicies", "clusterrolebindings", "clusterroles", "roles", "nodes")
    }

    result = scan_live_cluster_posture_with_evidence(transport=_FixtureTransport({}, errors=errors))

    assert result.status is K8sPostureStatus.FAILED
    assert {item.state for item in result.collectors if item.collector_id != "kubelet_configz"} == {CollectorState.FAILED}


def test_posture_evidence_normalizes_invalid_in_cluster_port(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setenv("KUBERNETES_SERVICE_HOST", "10.0.0.1")
    monkeypatch.setenv("KUBERNETES_SERVICE_PORT", "0")

    result = scan_live_cluster_posture_with_evidence()

    assert result.status is K8sPostureStatus.FAILED
    assert result.transport == "unavailable"
    assert {item.state for item in result.collectors if item.collector_id != "kubelet_configz"} == {CollectorState.FAILED}
    assert {item.message for item in result.collectors if item.collector_id != "kubelet_configz"} == {"Invalid Kubernetes service port"}


def test_compatibility_wrapper_fails_closed_on_partial_evidence(monkeypatch: pytest.MonkeyPatch) -> None:
    import agent_bom.k8s as k8s_module

    transport = _FixtureTransport(
        _foundation_payloads(),
        errors={"networkpolicies": K8sTransportError("forbidden", status_code=403)},
    )
    monkeypatch.setattr(k8s_module, "select_k8s_transport", lambda **_kwargs: transport)

    with pytest.raises(K8sDiscoveryError, match="forbidden"):
        scan_live_cluster_posture(namespace="prod")
