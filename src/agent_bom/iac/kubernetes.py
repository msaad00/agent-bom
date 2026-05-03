"""Kubernetes manifest misconfiguration scanner.

Scans YAML manifests for common security misconfigurations using
``yaml.safe_load``.  Handles multi-document YAML (``---`` separators).
No external tools required.

Rules
-----
K8S-001  privileged: true in securityContext
K8S-002  hostNetwork: true
K8S-003  hostPID: true or hostIPC: true
K8S-004  No resource limits (missing resources.limits)
K8S-005  runAsUser: 0 or runAsNonRoot: false
K8S-006  Missing readOnlyRootFilesystem: true
K8S-007  Secrets in env values (not secretKeyRef)
K8S-008  Using default namespace
K8S-009  allowPrivilegeEscalation: true
K8S-010  Missing automountServiceAccountToken: false
K8S-011  Container image uses :latest tag
K8S-012  No NetworkPolicy defined
K8S-013  No securityContext at pod level
K8S-014  hostPath volume mount
K8S-015  Writable /etc or /var mount
K8S-016  Container port 22 exposed (SSH)
K8S-017  No PodDisruptionBudget for Deployment
K8S-018  Capability NET_RAW or SYS_ADMIN added
K8S-019  emptyDir without sizeLimit
K8S-020  Service type LoadBalancer without annotation
K8S-021  Missing PodDisruptionBudget for Deployments
K8S-022  Container without liveness probe
K8S-023  Container without readiness probe
K8S-024  ServiceAccount with automountServiceAccountToken: true
K8S-025  ClusterRoleBinding with cluster-admin role
K8S-026  Pod with hostPort specified
K8S-027  Container with writable /var/run/docker.sock mount
K8S-028  NetworkPolicy missing egress rules
K8S-029  Container image from untrusted registry
K8S-030  Deployment without PodAntiAffinity (single point of failure)
K8S-031  Missing seccompProfile
K8S-032  Container with NET_ADMIN capability
K8S-033  Pod with shareProcessNamespace: true
K8S-034  GPU container with privileged mode or allowPrivilegeEscalation (GPU escape pattern)
K8S-035  hostPath volume mounting /dev/nvidia or /proc/driver/nvidia (direct device exposure)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from agent_bom.iac.models import IaCFinding

# Secret-like env variable name patterns
_SECRET_NAME_RE = re.compile(
    r"(?:API[_\-]?KEY|PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE[_\-]?KEY|"
    r"ACCESS[_\-]?KEY|AUTH|BEARER|DB_PASS)",
    re.IGNORECASE,
)

# Workload kinds that have a pod spec
_WORKLOAD_KINDS = frozenset(
    {
        "Pod",
        "Deployment",
        "DaemonSet",
        "StatefulSet",
        "ReplicaSet",
        "Job",
        "CronJob",
    }
)

# Trusted container image registries (K8S-029)
_TRUSTED_REGISTRIES = frozenset(
    {
        "docker.io",
        "gcr.io",
        "ghcr.io",
        "registry.k8s.io",
        "quay.io",
        "mcr.microsoft.com",
        "public.ecr.aws",
        "nvcr.io",
    }
)


def _get_pod_spec(doc: dict[str, Any]) -> dict[str, Any] | None:
    """Extract the pod spec from a workload resource."""
    kind = doc.get("kind", "")
    if kind == "Pod":
        return doc.get("spec", {})
    if kind == "CronJob":
        return doc.get("spec", {}).get("jobTemplate", {}).get("spec", {}).get("template", {}).get("spec", {})
    if kind in _WORKLOAD_KINDS:
        return doc.get("spec", {}).get("template", {}).get("spec", {})
    return None


def _find_line(content: str, key: str, value: Any, start_line: int = 1) -> int:
    """Best-effort line number search for a key-value pair in YAML text."""
    if isinstance(value, bool):
        val_str = "true" if value else "false"
    elif isinstance(value, int):
        val_str = str(value)
    else:
        val_str = str(value)
    pattern = rf"{re.escape(key)}\s*:\s*{re.escape(val_str)}"
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(pattern, line):
            return i
    return start_line


def _find_key_line(content: str, key: str, start_line: int = 1) -> int:
    """Best-effort line number search for a key in YAML text."""
    for i, line in enumerate(content.splitlines(), 1):
        if re.search(rf"\b{re.escape(key)}\s*:", line):
            return i
    return start_line


def _is_trusted_registry(image: str) -> bool:
    """Return True if the container image is from a trusted registry."""
    # Images without a '/' are Docker Hub library images (e.g. "nginx:1.25")
    if "/" not in image:
        return True
    # Images like "library/nginx" or "myuser/myimage" are Docker Hub
    registry = image.split("/")[0]
    # A registry hostname must contain a '.' or ':'
    if "." not in registry and ":" not in registry:
        return True  # Docker Hub user/image
    return registry in _TRUSTED_REGISTRIES


def scan_k8s_manifest(file_path: str | Path) -> list[IaCFinding]:
    """Scan a single Kubernetes YAML manifest for misconfigurations.

    Parameters
    ----------
    file_path:
        Path to a Kubernetes YAML manifest.

    Returns
    -------
    list[IaCFinding]
        Detected misconfigurations.
    """
    path = Path(file_path)
    if not path.is_file():
        return []

    content = path.read_text(encoding="utf-8", errors="replace")
    rel_path = str(path)
    findings: list[IaCFinding] = []

    try:
        docs = list(yaml.safe_load_all(content))
    except yaml.YAMLError:
        return []

    for doc in docs:
        if not isinstance(doc, dict):
            continue

        kind = doc.get("kind", "")
        metadata = doc.get("metadata", {}) or {}
        name = metadata.get("name", kind)

        # ── Non-workload resource checks ──────────────────────────────

        # K8S-024: ServiceAccount with automountServiceAccountToken: true
        if kind == "ServiceAccount":
            if doc.get("automountServiceAccountToken") is True:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-024",
                        severity="medium",
                        title="ServiceAccount auto-mounts token",
                        message=(
                            f"ServiceAccount '{name}' sets automountServiceAccountToken: true. "
                            "Set to false and only mount tokens in pods that need API access."
                        ),
                        file_path=rel_path,
                        line_number=_find_line(content, "automountServiceAccountToken", True),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.1.6", "NIST-AC-6"],
                    )
                )

        # K8S-025: ClusterRoleBinding with cluster-admin role
        if kind == "ClusterRoleBinding":
            role_ref = doc.get("roleRef", {}) or {}
            if role_ref.get("name") == "cluster-admin":
                findings.append(
                    IaCFinding(
                        rule_id="K8S-025",
                        severity="critical",
                        title="ClusterRoleBinding grants cluster-admin",
                        message=(
                            f"ClusterRoleBinding '{name}' binds to the cluster-admin role. "
                            "This grants full cluster access. Use least-privilege roles instead."
                        ),
                        file_path=rel_path,
                        line_number=_find_key_line(content, "cluster-admin"),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.1.1", "NIST-AC-6"],
                    )
                )

        # K8S-028: NetworkPolicy missing egress rules
        if kind == "NetworkPolicy":
            spec = doc.get("spec", {}) or {}
            policy_types = spec.get("policyTypes", []) or []
            if "Egress" not in policy_types or not spec.get("egress"):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-028",
                        severity="medium",
                        title="NetworkPolicy missing egress rules",
                        message=(
                            f"NetworkPolicy '{name}' does not define egress rules. "
                            "Without egress rules, pods can reach any external endpoint. "
                            "Add egress rules to restrict outbound traffic."
                        ),
                        file_path=rel_path,
                        line_number=_find_key_line(content, "spec"),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.3.2", "NIST-SC-7"],
                    )
                )

        # ── Workload resource checks ─────────────────────────────────

        if kind not in _WORKLOAD_KINDS:
            continue

        pod_spec = _get_pod_spec(doc)
        if not pod_spec:
            continue

        namespace = metadata.get("namespace", "")

        # K8S-002: hostNetwork
        if pod_spec.get("hostNetwork") is True:
            findings.append(
                IaCFinding(
                    rule_id="K8S-002",
                    severity="high",
                    title="hostNetwork enabled",
                    message=(
                        f"Resource '{name}' uses hostNetwork: true. "
                        "This shares the host's network namespace, allowing "
                        "traffic sniffing and bypass of network policies."
                    ),
                    file_path=rel_path,
                    line_number=_find_line(content, "hostNetwork", True),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.4", "NIST-CM-7"],
                )
            )

        # K8S-003: hostPID / hostIPC
        for host_key in ("hostPID", "hostIPC"):
            if pod_spec.get(host_key) is True:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-003",
                        severity="high",
                        title=f"{host_key} enabled",
                        message=(
                            f"Resource '{name}' uses {host_key}: true. "
                            "Sharing the host PID/IPC namespace allows container "
                            "escape and cross-process attacks."
                        ),
                        file_path=rel_path,
                        line_number=_find_line(content, host_key, True),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.2.2", "NIST-CM-7"],
                    )
                )

        # K8S-008: default namespace
        if namespace == "default" or (not namespace and kind != "Pod"):
            findings.append(
                IaCFinding(
                    rule_id="K8S-008",
                    severity="medium",
                    title="Using default namespace",
                    message=(f"Resource '{name}' uses the default namespace. Use dedicated namespaces for workload isolation and RBAC."),
                    file_path=rel_path,
                    line_number=_find_key_line(content, "namespace", 1),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.7.1", "NIST-AC-4"],
                )
            )

        # K8S-010: automountServiceAccountToken
        if pod_spec.get("automountServiceAccountToken") is not False:
            findings.append(
                IaCFinding(
                    rule_id="K8S-010",
                    severity="medium",
                    title="Service account token auto-mounted",
                    message=(
                        f"Resource '{name}' does not set automountServiceAccountToken: false. "
                        "The default service account token is mounted into every pod, "
                        "enabling lateral movement if compromised."
                    ),
                    file_path=rel_path,
                    line_number=_find_key_line(content, "spec"),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.1.6", "NIST-AC-6"],
                )
            )

        # K8S-033: shareProcessNamespace: true
        if pod_spec.get("shareProcessNamespace") is True:
            findings.append(
                IaCFinding(
                    rule_id="K8S-033",
                    severity="medium",
                    title="shareProcessNamespace enabled",
                    message=(
                        f"Resource '{name}' sets shareProcessNamespace: true. "
                        "All containers in the pod share the same PID namespace, "
                        "allowing them to signal each other's processes. "
                        "Only enable when explicitly required."
                    ),
                    file_path=rel_path,
                    line_number=_find_line(content, "shareProcessNamespace", True),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.2", "NIST-CM-7"],
                )
            )

        # K8S-030: Deployment without PodAntiAffinity
        if kind == "Deployment":
            affinity = pod_spec.get("affinity", {}) or {}
            if not affinity.get("podAntiAffinity"):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-030",
                        severity="low",
                        title="Deployment without PodAntiAffinity",
                        message=(
                            f"Deployment '{name}' does not define podAntiAffinity. "
                            "Without anti-affinity, all replicas may be scheduled on the same node, "
                            "creating a single point of failure."
                        ),
                        file_path=rel_path,
                        line_number=_find_key_line(content, "spec"),
                        category="kubernetes",
                        compliance=["NIST-CP-10"],
                    )
                )

        # Per-container checks
        containers = pod_spec.get("containers", []) or []
        init_containers = pod_spec.get("initContainers", []) or []
        for container in containers + init_containers:
            if not isinstance(container, dict):
                continue

            cname = container.get("name", "unnamed")
            sec_ctx = container.get("securityContext", {}) or {}

            # K8S-001: privileged
            if sec_ctx.get("privileged") is True:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-001",
                        severity="critical",
                        title="Privileged container",
                        message=(
                            f"Container '{cname}' in '{name}' runs in privileged mode. "
                            "This gives the container full host access. "
                            "Remove privileged: true unless absolutely required."
                        ),
                        file_path=rel_path,
                        line_number=_find_line(content, "privileged", True),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.2.1", "NIST-AC-6"],
                    )
                )

            # K8S-005: runAsUser: 0 or runAsNonRoot: false
            if sec_ctx.get("runAsUser") == 0:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-005",
                        severity="high",
                        title="Container runs as root (UID 0)",
                        message=(
                            f"Container '{cname}' in '{name}' runs as root (runAsUser: 0). Use a non-root user to limit exploit impact."
                        ),
                        file_path=rel_path,
                        line_number=_find_line(content, "runAsUser", 0),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.2.6", "NIST-AC-6"],
                    )
                )
            if sec_ctx.get("runAsNonRoot") is False:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-005",
                        severity="high",
                        title="runAsNonRoot explicitly disabled",
                        message=(
                            f"Container '{cname}' in '{name}' sets runAsNonRoot: false. "
                            "Enable runAsNonRoot: true and specify a non-root runAsUser."
                        ),
                        file_path=rel_path,
                        line_number=_find_line(content, "runAsNonRoot", False),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.2.6", "NIST-AC-6"],
                    )
                )

            # K8S-006: readOnlyRootFilesystem
            if not sec_ctx.get("readOnlyRootFilesystem"):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-006",
                        severity="high",
                        title="Writable root filesystem",
                        message=(
                            f"Container '{cname}' in '{name}' does not set "
                            "readOnlyRootFilesystem: true. A read-only root filesystem "
                            "prevents attackers from writing malicious binaries."
                        ),
                        file_path=rel_path,
                        line_number=_find_key_line(content, cname),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.2.4", "NIST-CM-6"],
                    )
                )

            # K8S-009: allowPrivilegeEscalation
            if sec_ctx.get("allowPrivilegeEscalation") is True:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-009",
                        severity="high",
                        title="Privilege escalation allowed",
                        message=(
                            f"Container '{cname}' in '{name}' allows privilege escalation. "
                            "Set allowPrivilegeEscalation: false to prevent "
                            "child processes from gaining more privileges."
                        ),
                        file_path=rel_path,
                        line_number=_find_line(content, "allowPrivilegeEscalation", True),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.2.5", "NIST-AC-6"],
                    )
                )

            # K8S-004: resource limits
            resources = container.get("resources", {}) or {}
            if not resources.get("limits"):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-004",
                        severity="medium",
                        title="No resource limits",
                        message=(
                            f"Container '{cname}' in '{name}' has no resource limits. "
                            "Set CPU and memory limits to prevent resource exhaustion "
                            "and noisy-neighbor issues."
                        ),
                        file_path=rel_path,
                        line_number=_find_key_line(content, cname),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.4.1", "NIST-SC-6"],
                    )
                )

            # K8S-007: Secrets in env values (not using secretKeyRef)
            env_list = container.get("env", []) or []
            for env_var in env_list:
                if not isinstance(env_var, dict):
                    continue
                env_name = env_var.get("name", "")
                env_value = env_var.get("value")
                # If it has a plain 'value' (not valueFrom/secretKeyRef) and name looks secret
                if env_value is not None and _SECRET_NAME_RE.search(env_name):
                    findings.append(
                        IaCFinding(
                            rule_id="K8S-007",
                            severity="critical",
                            title="Secret in plain env value",
                            message=(
                                f"Container '{cname}' in '{name}' has env var '{env_name}' "
                                "with a hardcoded value instead of secretKeyRef. "
                                "Use Kubernetes Secrets with valueFrom.secretKeyRef."
                            ),
                            file_path=rel_path,
                            line_number=_find_key_line(content, env_name),
                            category="kubernetes",
                            compliance=["CIS-K8s-5.4.1", "NIST-IA-5"],
                        )
                    )

            # K8S-011: Container image uses :latest
            image = container.get("image", "")
            if image and (":" not in image or image.endswith(":latest")):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-011",
                        severity="medium",
                        title="Container image uses :latest tag",
                        message=f"Container '{cname}' uses image '{image}' without a pinned tag. Pin to a specific version.",
                        file_path=rel_path,
                        line_number=_find_key_line(content, image),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.5.1", "NIST-CM-6"],
                    )
                )

            # K8S-016: Container port 22 exposed
            for port in container.get("ports", []) or []:
                if isinstance(port, dict) and port.get("containerPort") == 22:
                    findings.append(
                        IaCFinding(
                            rule_id="K8S-016",
                            severity="high",
                            title="Container port 22 exposed (SSH)",
                            message=f"Container '{cname}' exposes port 22 (SSH). Use kubectl exec instead of SSH access.",
                            file_path=rel_path,
                            line_number=_find_key_line(content, "22"),
                            category="kubernetes",
                            compliance=["CIS-K8s-5.1.3", "NIST-CM-7"],
                        )
                    )

            # K8S-018: Dangerous capabilities added
            sec_ctx = container.get("securityContext", {}) or {}
            caps = sec_ctx.get("capabilities", {}) or {}
            add_caps = caps.get("add", []) or []
            dangerous = {"NET_RAW", "SYS_ADMIN", "SYS_PTRACE", "ALL"}
            for cap in add_caps:
                if cap.upper() in dangerous:
                    findings.append(
                        IaCFinding(
                            rule_id="K8S-018",
                            severity="critical",
                            title=f"Dangerous capability {cap} added",
                            message=f"Container '{cname}' adds capability {cap}. Drop all capabilities and add only required ones.",
                            file_path=rel_path,
                            line_number=_find_key_line(content, cap),
                            category="kubernetes",
                            compliance=["CIS-K8s-5.2.8", "NIST-AC-6"],
                        )
                    )

            # K8S-022: Container without liveness probe
            if not container.get("livenessProbe"):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-022",
                        severity="medium",
                        title="Container without liveness probe",
                        message=(
                            f"Container '{cname}' in '{name}' has no livenessProbe. "
                            "Without a liveness probe, Kubernetes cannot detect and restart "
                            "deadlocked or unresponsive containers."
                        ),
                        file_path=rel_path,
                        line_number=_find_key_line(content, cname),
                        category="kubernetes",
                        compliance=["NIST-SI-13"],
                    )
                )

            # K8S-023: Container without readiness probe
            if not container.get("readinessProbe"):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-023",
                        severity="medium",
                        title="Container without readiness probe",
                        message=(
                            f"Container '{cname}' in '{name}' has no readinessProbe. "
                            "Without a readiness probe, traffic is sent to pods before "
                            "they are ready to serve requests."
                        ),
                        file_path=rel_path,
                        line_number=_find_key_line(content, cname),
                        category="kubernetes",
                        compliance=["NIST-SI-13"],
                    )
                )

            # K8S-026: Pod with hostPort specified
            for port in container.get("ports", []) or []:
                if isinstance(port, dict) and port.get("hostPort"):
                    findings.append(
                        IaCFinding(
                            rule_id="K8S-026",
                            severity="medium",
                            title="Container uses hostPort",
                            message=(
                                f"Container '{cname}' in '{name}' specifies hostPort {port['hostPort']}. "
                                "hostPort ties the pod to a specific node and limits scheduling. "
                                "Use a Service or Ingress instead."
                            ),
                            file_path=rel_path,
                            line_number=_find_key_line(content, "hostPort"),
                            category="kubernetes",
                            compliance=["CIS-K8s-5.2.13", "NIST-CM-7"],
                        )
                    )

            # K8S-027: Container with writable /var/run/docker.sock mount
            vol_mounts = container.get("volumeMounts", []) or []
            for vm in vol_mounts:
                if isinstance(vm, dict) and vm.get("mountPath") == "/var/run/docker.sock":
                    read_only = vm.get("readOnly", False)
                    if not read_only:
                        findings.append(
                            IaCFinding(
                                rule_id="K8S-027",
                                severity="critical",
                                title="Writable Docker socket mount",
                                message=(
                                    f"Container '{cname}' in '{name}' mounts /var/run/docker.sock "
                                    "without readOnly: true. This allows full Docker daemon access "
                                    "and container escape. Remove the mount or set readOnly: true."
                                ),
                                file_path=rel_path,
                                line_number=_find_key_line(content, "docker.sock"),
                                category="kubernetes",
                                compliance=["CIS-K8s-5.2.12", "NIST-AC-6"],
                            )
                        )

            # K8S-029: Container image from untrusted registry
            image = container.get("image", "")
            if image and not _is_trusted_registry(image):
                findings.append(
                    IaCFinding(
                        rule_id="K8S-029",
                        severity="high",
                        title="Container image from untrusted registry",
                        message=(
                            f"Container '{cname}' in '{name}' uses image '{image}' "
                            "from an untrusted registry. Use images from trusted registries "
                            "(Docker Hub, GCR, GHCR, Quay, ECR, MCR, NVCR, registry.k8s.io)."
                        ),
                        file_path=rel_path,
                        line_number=_find_key_line(content, image),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.5.1", "NIST-CM-11"],
                    )
                )

            # K8S-031: Missing seccompProfile
            sec_profile = sec_ctx.get("seccompProfile")
            pod_sec_ctx = pod_spec.get("securityContext", {}) or {}
            pod_seccomp = pod_sec_ctx.get("seccompProfile")
            if not sec_profile and not pod_seccomp:
                findings.append(
                    IaCFinding(
                        rule_id="K8S-031",
                        severity="medium",
                        title="Missing seccompProfile",
                        message=(
                            f"Container '{cname}' in '{name}' has no seccompProfile set "
                            "at container or pod level. Set seccompProfile.type to "
                            "RuntimeDefault or Localhost to restrict syscalls."
                        ),
                        file_path=rel_path,
                        line_number=_find_key_line(content, cname),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.7.2", "NIST-CM-6"],
                    )
                )

            # K8S-032: Container with NET_ADMIN capability
            for cap in add_caps:
                if cap.upper() == "NET_ADMIN":
                    findings.append(
                        IaCFinding(
                            rule_id="K8S-032",
                            severity="high",
                            title="NET_ADMIN capability added",
                            message=(
                                f"Container '{cname}' in '{name}' adds NET_ADMIN capability. "
                                "This allows network configuration changes including iptables "
                                "manipulation. Remove unless explicitly required."
                            ),
                            file_path=rel_path,
                            line_number=_find_key_line(content, "NET_ADMIN"),
                            category="kubernetes",
                            compliance=["CIS-K8s-5.2.8", "NIST-AC-6"],
                        )
                    )

            # K8S-034: GPU container with privileged mode or allowPrivilegeEscalation
            # A container requesting nvidia.com/gpu resources combined with privileged: true
            # or allowPrivilegeEscalation: true creates a GPU-assisted container escape path.
            resource_requests = (container.get("resources", {}) or {}).get("requests", {}) or {}
            resource_limits = (container.get("resources", {}) or {}).get("limits", {}) or {}
            has_gpu_resource = any(
                k in ("nvidia.com/gpu", "amd.com/gpu", "gpu.intel.com/i915", "gpu.intel.com/xe")
                for k in list(resource_requests) + list(resource_limits)
            )
            if has_gpu_resource:
                is_privileged = sec_ctx.get("privileged") is True
                allows_escalation = sec_ctx.get("allowPrivilegeEscalation") is True
                if is_privileged or allows_escalation:
                    escalation_flag = "privileged: true" if is_privileged else "allowPrivilegeEscalation: true"
                    findings.append(
                        IaCFinding(
                            rule_id="K8S-034",
                            severity="critical",
                            title="GPU container with privilege escalation",
                            message=(
                                f"Container '{cname}' in '{name}' requests GPU resources and sets "
                                f"{escalation_flag}. A privileged GPU container can access all GPU "
                                "device files on the host, enabling full host escape. "
                                "Remove privilege escalation from GPU workloads."
                            ),
                            file_path=rel_path,
                            line_number=_find_line(content, "privileged", True)
                            if is_privileged
                            else _find_line(content, "allowPrivilegeEscalation", True),
                            category="kubernetes",
                            compliance=["CIS-K8s-5.2.1", "NIST-AC-6", "NIST-SI-3"],
                            attack_techniques=["T1611"],
                        )
                    )

        # K8S-019: emptyDir without sizeLimit / K8S-014: hostPath
        volumes = pod_spec.get("volumes", []) or []
        for vol in volumes:
            if not isinstance(vol, dict):
                continue
            empty_dir = vol.get("emptyDir")
            if empty_dir is not None and not (isinstance(empty_dir, dict) and empty_dir.get("sizeLimit")):
                vol_name = vol.get("name", "unknown")
                findings.append(
                    IaCFinding(
                        rule_id="K8S-019",
                        severity="low",
                        title=f"emptyDir '{vol_name}' without sizeLimit",
                        message=f"Volume '{vol_name}' uses emptyDir without sizeLimit. Set sizeLimit to prevent disk exhaustion.",
                        file_path=rel_path,
                        line_number=_find_key_line(content, vol_name),
                        category="kubernetes",
                        compliance=["NIST-SC-6"],
                    )
                )
            if vol.get("hostPath"):
                vol_name = vol.get("name", "unknown")
                findings.append(
                    IaCFinding(
                        rule_id="K8S-014",
                        severity="high",
                        title=f"hostPath volume mount '{vol_name}'",
                        message=f"Volume '{vol_name}' mounts a host path. This breaks container isolation. Use PVCs instead.",
                        file_path=rel_path,
                        line_number=_find_key_line(content, vol_name),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.2.12", "NIST-SC-7"],
                    )
                )
                # K8S-035: hostPath mounting NVIDIA device files exposes the GPU driver directly
                host_path_value = (vol.get("hostPath") or {}).get("path", "")
                if any(host_path_value.startswith(p) for p in ("/dev/nvidia", "/proc/driver/nvidia")):
                    findings.append(
                        IaCFinding(
                            rule_id="K8S-035",
                            severity="critical",
                            title=f"hostPath mounts NVIDIA device file '{host_path_value}'",
                            message=(
                                f"Volume '{vol_name}' in '{name}' mounts '{host_path_value}' "
                                "directly from the host. Exposing NVIDIA device files bypasses "
                                "container isolation and grants raw GPU hardware access. "
                                "Use the NVIDIA device plugin instead of hostPath mounts."
                            ),
                            file_path=rel_path,
                            line_number=_find_key_line(content, vol_name),
                            category="kubernetes",
                            compliance=["CIS-K8s-5.2.12", "NIST-AC-6", "NIST-SI-3"],
                            attack_techniques=["T1611"],
                        )
                    )

        # K8S-013: No securityContext at pod level
        if not pod_spec.get("securityContext"):
            findings.append(
                IaCFinding(
                    rule_id="K8S-013",
                    severity="medium",
                    title="No securityContext at pod level",
                    message=f"Pod '{name}' has no pod-level securityContext. Set runAsNonRoot, fsGroup, and seccompProfile.",
                    file_path=rel_path,
                    line_number=_find_key_line(content, "spec"),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.6", "NIST-AC-6"],
                )
            )

    # ── Cross-document checks ───────────────────────────────────────────

    # K8S-021: Missing PodDisruptionBudget for Deployments
    # Collect Deployment names and PDB matchLabels from the same manifest
    deployment_names: set[str] = set()
    pdb_selectors: set[str] = set()
    for doc in docs:
        if not isinstance(doc, dict):
            continue
        dk = doc.get("kind", "")
        dm = doc.get("metadata", {}) or {}
        if dk == "Deployment":
            deployment_names.add(dm.get("name", ""))
        if dk == "PodDisruptionBudget":
            selector = doc.get("spec", {}).get("selector", {}) or {}
            match_labels = selector.get("matchLabels", {}) or {}
            # Track the app label value as a proxy for deployment name
            for _lbl_key, lbl_val in match_labels.items():
                pdb_selectors.add(lbl_val)

    for dep_name in deployment_names:
        if dep_name and dep_name not in pdb_selectors:
            findings.append(
                IaCFinding(
                    rule_id="K8S-021",
                    severity="low",
                    title=f"No PodDisruptionBudget for Deployment '{dep_name}'",
                    message=(
                        f"Deployment '{dep_name}' has no matching PodDisruptionBudget "
                        "in the same manifest. A PDB ensures minimum availability "
                        "during voluntary disruptions like node drains."
                    ),
                    file_path=rel_path,
                    line_number=_find_key_line(content, dep_name),
                    category="kubernetes",
                    compliance=["NIST-CP-10"],
                )
            )

    return findings
