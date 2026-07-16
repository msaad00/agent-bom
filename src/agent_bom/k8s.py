"""Kubernetes live-cluster helpers.

Runs ``kubectl get pods`` to list running containers, then returns their image
references so the caller can pass them to ``image.scan_image()`` for package
extraction.

Usage from cli.py::

    from agent_bom.k8s import discover_images, K8sDiscoveryError
    images = discover_images(namespace="default", context="my-cluster")
    for image_ref, pod_name, container_name in images:
        packages, strategy = scan_image(image_ref)
"""

from __future__ import annotations

import json
import shutil
import subprocess
from typing import Optional

from agent_bom.iac.models import IaCFinding


class K8sDiscoveryError(Exception):
    """Raised when kubectl discovery fails."""


def _kubectl_available() -> bool:
    return shutil.which("kubectl") is not None


ImageRecord = tuple[str, str, str]  # (image_ref, pod_name, container_name)


def _run_kubectl_json(args: list[str], *, context: Optional[str] = None, timeout: int = 60) -> dict:
    """Run kubectl and parse JSON output."""
    if not _kubectl_available():
        raise K8sDiscoveryError(
            "'kubectl' not found on PATH. Install kubectl and ensure it is configured with access to the target cluster."
        )

    cmd = ["kubectl", *args]
    if context:
        cmd += ["--context", context]

    try:
        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except FileNotFoundError:
        raise K8sDiscoveryError("kubectl not found")
    except subprocess.TimeoutExpired:
        raise K8sDiscoveryError("kubectl timed out — check cluster connectivity")

    if result.returncode != 0:
        stderr = result.stderr.strip()
        raise K8sDiscoveryError(f"kubectl exited {result.returncode}: {stderr[:300]}")

    try:
        return json.loads(result.stdout)
    except json.JSONDecodeError as exc:
        raise K8sDiscoveryError(f"kubectl produced invalid JSON: {exc}")


def discover_images(
    namespace: str = "default",
    all_namespaces: bool = False,
    context: Optional[str] = None,
    label_selector: Optional[str] = None,
) -> list[ImageRecord]:
    """Discover container images running in a Kubernetes cluster.

    Uses ``kubectl get pods`` with ``-o json`` output.

    Args:
        namespace: Kubernetes namespace to query (ignored when ``all_namespaces=True``).
        all_namespaces: Query all namespaces (``kubectl get pods -A``).
        context: kubectl context to use (uses current context if ``None``).
        label_selector: Label selector string, e.g. ``"app=myapp"``.

    Returns:
        List of ``(image_ref, pod_name, container_name)`` tuples.
        Deduplication is applied — the same image reference is only returned once,
        attributed to the first pod/container where it was seen.

    Raises:
        K8sDiscoveryError: If kubectl is not available or the API call fails.
    """
    cmd = ["get", "pods", "-o", "json"]

    if all_namespaces:
        cmd.append("-A")
    else:
        cmd += ["-n", namespace]

    if label_selector:
        cmd += ["-l", label_selector]

    data = _run_kubectl_json(cmd, context=context, timeout=60)

    records: list[ImageRecord] = []
    seen_images: set[str] = set()

    for pod in data.get("items", []):
        pod_name = pod.get("metadata", {}).get("name", "unknown")
        pod_ns = pod.get("metadata", {}).get("namespace", namespace)
        qualified_pod = f"{pod_ns}/{pod_name}" if all_namespaces else pod_name

        # Prefer spec.containers; also check initContainers and ephemeralContainers
        container_lists = [
            pod.get("spec", {}).get("containers", []),
            pod.get("spec", {}).get("initContainers", []),
            pod.get("spec", {}).get("ephemeralContainers", []),
        ]

        for container_list in container_lists:
            for container in container_list:
                image_ref = container.get("image", "").strip()
                container_name = container.get("name", "unknown")
                if image_ref and image_ref not in seen_images:
                    seen_images.add(image_ref)
                    records.append((image_ref, qualified_pod, container_name))

    return records


def list_namespaces(context: Optional[str] = None) -> list[str]:
    """Return the list of namespaces in the cluster.

    Useful for ``--k8s --all-namespaces`` mode UI feedback.

    Raises:
        K8sDiscoveryError: If kubectl is not available or the call fails.
    """
    try:
        data = _run_kubectl_json(["get", "namespaces", "-o", "json"], context=context, timeout=30)
        return [item["metadata"]["name"] for item in data.get("items", [])]
    except K8sDiscoveryError as exc:
        if "invalid JSON" in str(exc):
            return []
        raise
    except KeyError:
        return []


# Capabilities whose runtime presence materially widens the host attack surface.
_DANGEROUS_CAPABILITIES = frozenset({"NET_RAW", "NET_ADMIN", "SYS_ADMIN", "SYS_PTRACE", "SYS_MODULE", "ALL"})

# Durations that mean "no idle timeout" for the kubelet streaming connection.
_ZERO_DURATIONS = frozenset({"0", "0s", "0m", "0h", "0m0s", "0h0m0s"})


def _pod_containers(spec: dict) -> list[dict]:
    """Return all container specs (containers + initContainers) from a pod spec."""
    containers = spec.get("containers", []) or []
    init_containers = spec.get("initContainers", []) or []
    return [c for c in list(containers) + list(init_containers) if isinstance(c, dict)]


def evaluate_pod_security(pods: dict, default_namespace: str = "default") -> list[IaCFinding]:
    """Evaluate PodSecurity posture across *running* workloads.

    Operates on a parsed ``kubectl get pods -o json`` payload. Only pods in the
    ``Running`` phase are evaluated — this is a runtime posture check, not a
    manifest lint, so pending/terminated pods are ignored. Findings mirror the
    severities and CIS/NIST mappings of the static manifest scanner
    (:mod:`agent_bom.iac.kubernetes`).
    """
    findings: list[IaCFinding] = []
    for pod in pods.get("items", []) or []:
        if not isinstance(pod, dict):
            continue
        if (pod.get("status", {}) or {}).get("phase") != "Running":
            continue
        metadata = pod.get("metadata", {}) or {}
        name = metadata.get("name", "unknown")
        ns = metadata.get("namespace", default_namespace)
        pod_ref = f"k8s://{ns}/{name}"
        spec = pod.get("spec", {}) or {}

        if spec.get("hostNetwork") is True:
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-008",
                    severity="high",
                    title="Running pod uses host network",
                    message=(
                        f"Pod '{ns}/{name}' is running with hostNetwork: true. It shares the node's "
                        "network namespace, allowing traffic sniffing and NetworkPolicy bypass."
                    ),
                    file_path=pod_ref,
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.2.4", "NIST-CM-7"],
                )
            )
        if spec.get("hostPID") is True or spec.get("hostIPC") is True:
            shared = ", ".join(k for k in ("hostPID", "hostIPC") if spec.get(k) is True)
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-009",
                    severity="high",
                    title="Running pod shares host process/IPC namespace",
                    message=(
                        f"Pod '{ns}/{name}' is running with {shared}: true. Sharing the host PID/IPC "
                        "namespace enables container escape and cross-process attacks."
                    ),
                    file_path=pod_ref,
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.2.2", "NIST-CM-7"],
                )
            )
        for vol in spec.get("volumes", []) or []:
            if isinstance(vol, dict) and vol.get("hostPath"):
                host_path = (vol.get("hostPath") or {}).get("path", "unknown")
                findings.append(
                    IaCFinding(
                        rule_id="K8S-LIVE-010",
                        severity="high",
                        title="Running pod mounts a host path",
                        message=(
                            f"Pod '{ns}/{name}' mounts host path '{host_path}' via volume "
                            f"'{vol.get('name', 'unknown')}'. hostPath mounts break container isolation "
                            "and can expose or tamper with node files."
                        ),
                        file_path=pod_ref,
                        line_number=1,
                        category="kubernetes-live",
                        compliance=["CIS-K8s-5.2.12", "NIST-SC-7"],
                    )
                )
                break

        for container in _pod_containers(spec):
            cname = container.get("name", "unnamed")
            sec_ctx = container.get("securityContext", {}) or {}

            if sec_ctx.get("privileged") is True:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-LIVE-007",
                        severity="critical",
                        title="Running privileged container",
                        message=(
                            f"Container '{cname}' in pod '{ns}/{name}' is running in privileged mode, "
                            "granting full host access. Remove privileged: true from the workload."
                        ),
                        file_path=pod_ref,
                        line_number=1,
                        category="kubernetes-live",
                        compliance=["CIS-K8s-5.2.1", "NIST-AC-6"],
                        attack_techniques=["T1611"],
                    )
                )
            if sec_ctx.get("runAsUser") == 0 or sec_ctx.get("runAsNonRoot") is False:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-LIVE-011",
                        severity="high",
                        title="Running container executes as root",
                        message=(
                            f"Container '{cname}' in pod '{ns}/{name}' is running as root "
                            "(runAsUser: 0 or runAsNonRoot: false). Run as a non-root user to limit "
                            "exploit impact."
                        ),
                        file_path=pod_ref,
                        line_number=1,
                        category="kubernetes-live",
                        compliance=["CIS-K8s-5.2.6", "NIST-AC-6"],
                    )
                )
            if sec_ctx.get("allowPrivilegeEscalation") is True:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-LIVE-012",
                        severity="high",
                        title="Running container allows privilege escalation",
                        message=(
                            f"Container '{cname}' in pod '{ns}/{name}' allows privilege escalation. "
                            "Set allowPrivilegeEscalation: false to block setuid-based escalation."
                        ),
                        file_path=pod_ref,
                        line_number=1,
                        category="kubernetes-live",
                        compliance=["CIS-K8s-5.2.5", "NIST-AC-6"],
                    )
                )
            add_caps = (sec_ctx.get("capabilities", {}) or {}).get("add", []) or []
            dangerous = sorted({c.upper() for c in add_caps if isinstance(c, str)} & _DANGEROUS_CAPABILITIES)
            if dangerous:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-LIVE-013",
                        severity="critical",
                        title="Running container adds dangerous capabilities",
                        message=(
                            f"Container '{cname}' in pod '{ns}/{name}' adds capabilities {dangerous}. "
                            "Drop ALL capabilities and add back only what the workload needs."
                        ),
                        file_path=pod_ref,
                        line_number=1,
                        category="kubernetes-live",
                        compliance=["CIS-K8s-5.2.8", "NIST-AC-6"],
                    )
                )

        if not spec.get("securityContext"):
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-014",
                    severity="medium",
                    title="Running pod has no securityContext",
                    message=(
                        f"Pod '{ns}/{name}' is running without a pod-level securityContext. Set "
                        "runAsNonRoot, fsGroup, and seccompProfile to enforce a hardened baseline."
                    ),
                    file_path=pod_ref,
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.2.6", "NIST-AC-6"],
                )
            )

    return findings


def _rule_has_wildcard(rule: dict) -> bool:
    """Return True if an RBAC policy rule grants wildcard verbs or resources."""
    verbs = rule.get("verbs", []) or []
    resources = rule.get("resources", []) or []
    return "*" in verbs or "*" in resources


def _is_builtin_role(name: str) -> bool:
    """Built-in roles (cluster-admin, system:*) are expected wildcards."""
    return name == "cluster-admin" or name == "admin" or name.startswith("system:")


def evaluate_rbac(
    cluster_roles: dict,
    roles: dict,
    cluster_role_bindings: dict,
    default_namespace: str = "default",
) -> list[IaCFinding]:
    """Audit live RBAC for over-broad grants.

    Flags ClusterRoleBindings to ``cluster-admin`` and user-defined
    Cluster/Roles that grant wildcard verbs or resources. Built-in
    ``cluster-admin`` and ``system:*`` roles are intentionally skipped — their
    wildcards are expected and cannot be tightened.
    """
    findings: list[IaCFinding] = []

    for binding in cluster_role_bindings.get("items", []) or []:
        if not isinstance(binding, dict):
            continue
        role_ref = binding.get("roleRef", {}) or {}
        if role_ref.get("name") != "cluster-admin":
            continue
        metadata = binding.get("metadata", {}) or {}
        subjects = binding.get("subjects", []) or []
        subject_names = (
            ", ".join(
                f"{s.get('kind', 'Subject')}:{s.get('namespace', '')}/{s.get('name', 'unknown')}".strip("/")
                for s in subjects
                if isinstance(s, dict)
            )
            or "unknown subject"
        )
        binding_name = metadata.get("name", "unknown")
        findings.append(
            IaCFinding(
                rule_id="K8S-LIVE-006",
                severity="critical",
                title="Live cluster-admin RBAC binding detected",
                message=(
                    f"ClusterRoleBinding '{binding_name}' grants cluster-admin to {subject_names}. "
                    "Review live RBAC drift and replace with least-privilege bindings."
                ),
                file_path=f"k8s://clusterrolebinding/{binding_name}",
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-5.1.1", "NIST-AC-6"],
            )
        )

    for role in cluster_roles.get("items", []) or []:
        if not isinstance(role, dict):
            continue
        name = (role.get("metadata", {}) or {}).get("name", "unknown")
        if _is_builtin_role(name):
            continue
        if any(_rule_has_wildcard(r) for r in (role.get("rules", []) or []) if isinstance(r, dict)):
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-015",
                    severity="high",
                    title="ClusterRole grants wildcard permissions",
                    message=(
                        f"ClusterRole '{name}' grants wildcard (*) verbs or resources. Wildcard grants "
                        "violate least-privilege — enumerate the specific verbs/resources required."
                    ),
                    file_path=f"k8s://clusterrole/{name}",
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.1.3", "NIST-AC-6"],
                )
            )

    for role in roles.get("items", []) or []:
        if not isinstance(role, dict):
            continue
        metadata = role.get("metadata", {}) or {}
        name = metadata.get("name", "unknown")
        ns = metadata.get("namespace", default_namespace)
        if name.startswith("system:"):
            continue
        if any(_rule_has_wildcard(r) for r in (role.get("rules", []) or []) if isinstance(r, dict)):
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-016",
                    severity="high",
                    title="Role grants wildcard permissions",
                    message=(
                        f"Role '{ns}/{name}' grants wildcard (*) verbs or resources. Wildcard grants "
                        "violate least-privilege — enumerate the specific verbs/resources required."
                    ),
                    file_path=f"k8s://role/{ns}/{name}",
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.1.3", "NIST-AC-6"],
                )
            )

    return findings


def evaluate_kubelet_config(node_name: str, kubelet_config: dict) -> list[IaCFinding]:
    """Evaluate a node's kubelet configuration against CIS Benchmark section 4.2.

    ``kubelet_config`` is the resolved KubeletConfiguration (v1beta1) as returned
    by the read-only ``/api/v1/nodes/<node>/proxy/configz`` endpoint (the
    ``kubeletconfig`` object). Only fields present in the resolved config are
    evaluated; absent optional fields are not fabricated into a pass or fail.
    """
    findings: list[IaCFinding] = []
    node_ref = f"k8s://node/{node_name}"

    anonymous = (kubelet_config.get("authentication", {}) or {}).get("anonymous", {}) or {}
    if anonymous.get("enabled") is True:
        findings.append(
            IaCFinding(
                rule_id="K8S-LIVE-020",
                severity="critical",
                title="Kubelet allows anonymous authentication",
                message=(
                    f"Kubelet on node '{node_name}' has authentication.anonymous.enabled: true. "
                    "Anonymous requests to the kubelet API can read pod data and exec into containers. "
                    "Set --anonymous-auth=false."
                ),
                file_path=node_ref,
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-4.2.1", "NIST-AC-6"],
            )
        )

    if (kubelet_config.get("authorization", {}) or {}).get("mode") == "AlwaysAllow":
        findings.append(
            IaCFinding(
                rule_id="K8S-LIVE-021",
                severity="critical",
                title="Kubelet authorization mode is AlwaysAllow",
                message=(
                    f"Kubelet on node '{node_name}' uses authorization.mode: AlwaysAllow, which grants "
                    "every authenticated request. Set --authorization-mode=Webhook."
                ),
                file_path=node_ref,
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-4.2.2", "NIST-AC-6"],
            )
        )

    read_only_port = kubelet_config.get("readOnlyPort")
    if isinstance(read_only_port, int) and read_only_port != 0:
        findings.append(
            IaCFinding(
                rule_id="K8S-LIVE-022",
                severity="high",
                title="Kubelet read-only port is enabled",
                message=(
                    f"Kubelet on node '{node_name}' exposes readOnlyPort {read_only_port}. This "
                    "unauthenticated port leaks pod and node metadata. Set --read-only-port=0."
                ),
                file_path=node_ref,
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-4.2.4", "NIST-AC-6"],
            )
        )

    idle_timeout = str(kubelet_config.get("streamingConnectionIdleTimeout", "")).strip().lower()
    if idle_timeout in _ZERO_DURATIONS:
        findings.append(
            IaCFinding(
                rule_id="K8S-LIVE-023",
                severity="medium",
                title="Kubelet streaming connections never time out",
                message=(
                    f"Kubelet on node '{node_name}' sets streamingConnectionIdleTimeout to 0 (disabled). "
                    "Idle exec/attach/port-forward streams are held open indefinitely. Set a non-zero "
                    "timeout (e.g. 4h)."
                ),
                file_path=node_ref,
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-4.2.5", "NIST-AC-12"],
            )
        )

    if kubelet_config.get("protectKernelDefaults") is False:
        findings.append(
            IaCFinding(
                rule_id="K8S-LIVE-024",
                severity="medium",
                title="Kubelet does not protect kernel defaults",
                message=(
                    f"Kubelet on node '{node_name}' has protectKernelDefaults: false, so it may overwrite "
                    "hardened kernel sysctls. Set --protect-kernel-defaults=true."
                ),
                file_path=node_ref,
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-4.2.6", "NIST-CM-6"],
            )
        )

    if kubelet_config.get("makeIPTablesUtilChains") is False:
        findings.append(
            IaCFinding(
                rule_id="K8S-LIVE-025",
                severity="low",
                title="Kubelet does not manage iptables util chains",
                message=(
                    f"Kubelet on node '{node_name}' has makeIPTablesUtilChains: false. Enable it so the "
                    "kubelet maintains the iptables rules that back NetworkPolicy enforcement."
                ),
                file_path=node_ref,
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-4.2.7", "NIST-SC-7"],
            )
        )

    if kubelet_config.get("rotateCertificates") is False:
        findings.append(
            IaCFinding(
                rule_id="K8S-LIVE-026",
                severity="medium",
                title="Kubelet client certificate rotation is disabled",
                message=(
                    f"Kubelet on node '{node_name}' has rotateCertificates: false. Long-lived client "
                    "certificates widen the credential-theft window. Set --rotate-certificates=true."
                ),
                file_path=node_ref,
                line_number=1,
                category="kubernetes-live",
                compliance=["CIS-K8s-4.2.10", "NIST-IA-5"],
            )
        )

    return findings


def _fetch_kubelet_config(node_name: str, context: Optional[str]) -> Optional[dict]:
    """Fetch a node's resolved kubelet config via the read-only configz proxy.

    Returns the ``kubeletconfig`` object, or ``None`` when the endpoint is
    unreachable (managed control planes commonly forbid the node proxy). A
    blocked endpoint is an honest skip — never a fabricated pass.
    """
    raw_path = f"/api/v1/nodes/{node_name}/proxy/configz"
    try:
        data = _run_kubectl_json(["get", "--raw", raw_path], context=context, timeout=30)
    except K8sDiscoveryError:
        return None
    if not isinstance(data, dict):
        return None
    config = data.get("kubeletconfig")
    return config if isinstance(config, dict) else None


def scan_live_cluster_posture(
    namespace: str = "default",
    all_namespaces: bool = False,
    context: Optional[str] = None,
) -> list[IaCFinding]:
    """Inspect runtime Kubernetes posture through the live API via kubectl.

    This complements manifest scanning. It does not attempt full policy
    evaluation across the cluster; it inspects live workload, RBAC, namespace,
    and node/kubelet state that static manifests cannot prove. All access is
    read-only (``kubectl get`` / read-only ``--raw`` GETs); the scan never
    mutates or execs into the cluster.

    Check families
    --------------
    * Runtime workload health — K8S-LIVE-001..004
    * Namespace NetworkPolicy coverage — K8S-LIVE-005
    * RBAC / namespace audit — K8S-LIVE-006, 015, 016
    * PodSecurity on running workloads — K8S-LIVE-007..014
    * Node / kubelet CIS configuration — K8S-LIVE-020..026 (skipped honestly
      when the kubelet configz proxy is forbidden on managed control planes)
    """
    ns_args = ["-A"] if all_namespaces else ["-n", namespace]
    findings: list[IaCFinding] = []

    pods = _run_kubectl_json(["get", "pods", *ns_args, "-o", "json"], context=context, timeout=60)
    network_policies = _run_kubectl_json(["get", "networkpolicies", *ns_args, "-o", "json"], context=context, timeout=30)
    cluster_role_bindings = _run_kubectl_json(["get", "clusterrolebindings", "-o", "json"], context=context, timeout=30)
    cluster_roles = _run_kubectl_json(["get", "clusterroles", "-o", "json"], context=context, timeout=30)
    roles = _run_kubectl_json(["get", "roles", *ns_args, "-o", "json"], context=context, timeout=30)
    nodes = _run_kubectl_json(["get", "nodes", "-o", "json"], context=context, timeout=30)

    policy_namespaces = {
        item.get("metadata", {}).get("namespace", namespace)
        for item in network_policies.get("items", [])
        if item.get("metadata", {}).get("namespace")
    }
    namespaces_with_pods: set[str] = set()

    for pod in pods.get("items", []):
        metadata = pod.get("metadata", {})
        pod_name = metadata.get("name", "unknown")
        pod_ns = metadata.get("namespace", namespace)
        namespaces_with_pods.add(pod_ns)
        pod_ref = f"k8s://{pod_ns}/{pod_name}"
        spec = pod.get("spec", {}) or {}
        status = pod.get("status", {}) or {}
        phase = status.get("phase", "Unknown")

        if phase != "Running":
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-001",
                    severity="medium",
                    title="Live pod not running",
                    message=(
                        f"Pod '{pod_ns}/{pod_name}' is currently in phase '{phase}'. "
                        "Investigate runtime drift, crash loops, or image/config rollout health."
                    ),
                    file_path=pod_ref,
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.7.4", "NIST-SI-4"],
                )
            )

        container_statuses = status.get("containerStatuses", []) or []
        for container_status in container_statuses:
            waiting = (container_status.get("state", {}) or {}).get("waiting", {}) or {}
            if waiting.get("reason") == "CrashLoopBackOff":
                findings.append(
                    IaCFinding(
                        rule_id="K8S-LIVE-002",
                        severity="high",
                        title="Live pod is crash looping",
                        message=(
                            f"Pod '{pod_ns}/{pod_name}' container '{container_status.get('name', 'unknown')}' "
                            "is in CrashLoopBackOff. Runtime drift or bad rollout is already impacting availability."
                        ),
                        file_path=pod_ref,
                        line_number=1,
                        category="kubernetes-live",
                        compliance=["CIS-K8s-5.7.4", "NIST-SI-4"],
                    )
                )
            if not container_status.get("ready", False):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-LIVE-003",
                        severity="medium",
                        title="Live pod container not ready",
                        message=(
                            f"Pod '{pod_ns}/{pod_name}' container '{container_status.get('name', 'unknown')}' "
                            "is not ready. Live readiness drift may bypass assumptions in static manifests."
                        ),
                        file_path=pod_ref,
                        line_number=1,
                        category="kubernetes-live",
                        compliance=["CIS-K8s-5.7.4", "NIST-SI-4"],
                    )
                )

        if spec.get("automountServiceAccountToken", True):
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-004",
                    severity="medium",
                    title="Live pod mounts service-account token",
                    message=(
                        f"Pod '{pod_ns}/{pod_name}' is running with service-account token auto-mount enabled. "
                        "Disable token mounting unless the workload needs Kubernetes API access."
                    ),
                    file_path=pod_ref,
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.1.6", "NIST-AC-6"],
                )
            )

    for ns in sorted(namespaces_with_pods):
        if ns not in policy_namespaces:
            findings.append(
                IaCFinding(
                    rule_id="K8S-LIVE-005",
                    severity="high",
                    title="Namespace lacks live NetworkPolicy coverage",
                    message=(
                        f"Namespace '{ns}' has running pods but no live NetworkPolicy objects. "
                        "This is a runtime posture gap even if manifests exist elsewhere in Git."
                    ),
                    file_path=f"k8s://namespace/{ns}",
                    line_number=1,
                    category="kubernetes-live",
                    compliance=["CIS-K8s-5.3.2", "NIST-SC-7"],
                )
            )

    # PodSecurity on running workloads (K8S-LIVE-007..014).
    findings.extend(evaluate_pod_security(pods, default_namespace=namespace))

    # RBAC / namespace audit (K8S-LIVE-006, 015, 016).
    findings.extend(evaluate_rbac(cluster_roles, roles, cluster_role_bindings, default_namespace=namespace))

    # Node / kubelet CIS configuration (K8S-LIVE-020..026). The configz proxy is
    # commonly forbidden on managed control planes — skip those nodes honestly
    # instead of fabricating a pass.
    for node in nodes.get("items", []) or []:
        node_name = (node.get("metadata", {}) or {}).get("name")
        if not node_name:
            continue
        kubelet_config = _fetch_kubelet_config(node_name, context)
        if kubelet_config is not None:
            findings.extend(evaluate_kubelet_config(node_name, kubelet_config))

    return findings
