"""Kubernetes manifest rules evaluated per container and init container."""

from __future__ import annotations

import re

from agent_bom.iac.kubernetes_common import K8sContainer, find_key_line, find_line
from agent_bom.iac.models import IaCFinding

# Secret-like env variable name patterns
_SECRET_NAME_RE = re.compile(
    r"(?:API[_\-]?KEY|PASSWORD|SECRET|TOKEN|CREDENTIAL|PRIVATE[_\-]?KEY|"
    r"ACCESS[_\-]?KEY|AUTH|BEARER|DB_PASS)",
    re.IGNORECASE,
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


def k8s_001(c: K8sContainer) -> list[IaCFinding]:
    """K8S-001: privileged."""
    cname, sec_ctx, name, content, rel_path = c.cname, c.sec_ctx, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                line_number=find_line(content, "privileged", True),
                category="kubernetes",
                compliance=["CIS-K8s-5.2.1", "NIST-AC-6"],
            )
        )
    return findings


def k8s_005(c: K8sContainer) -> list[IaCFinding]:
    """K8S-005: runAsUser: 0 or runAsNonRoot: false."""
    cname, sec_ctx, name, content, rel_path = c.cname, c.sec_ctx, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
    if sec_ctx.get("runAsUser") == 0:
        findings.append(
            IaCFinding(
                rule_id="K8S-005",
                severity="high",
                title="Container runs as root (UID 0)",
                message=(f"Container '{cname}' in '{name}' runs as root (runAsUser: 0). Use a non-root user to limit exploit impact."),
                file_path=rel_path,
                line_number=find_line(content, "runAsUser", 0),
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
                    f"Container '{cname}' in '{name}' sets runAsNonRoot: false. Enable runAsNonRoot: true and specify a non-root runAsUser."
                ),
                file_path=rel_path,
                line_number=find_line(content, "runAsNonRoot", False),
                category="kubernetes",
                compliance=["CIS-K8s-5.2.6", "NIST-AC-6"],
            )
        )
    return findings


def k8s_006(c: K8sContainer) -> list[IaCFinding]:
    """K8S-006: readOnlyRootFilesystem."""
    cname, sec_ctx, name, content, rel_path = c.cname, c.sec_ctx, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                line_number=find_key_line(content, cname),
                category="kubernetes",
                compliance=["CIS-K8s-5.2.4", "NIST-CM-6"],
            )
        )
    return findings


def k8s_009(c: K8sContainer) -> list[IaCFinding]:
    """K8S-009: allowPrivilegeEscalation."""
    cname, sec_ctx, name, content, rel_path = c.cname, c.sec_ctx, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                line_number=find_line(content, "allowPrivilegeEscalation", True),
                category="kubernetes",
                compliance=["CIS-K8s-5.2.5", "NIST-AC-6"],
            )
        )
    return findings


def k8s_004(c: K8sContainer) -> list[IaCFinding]:
    """K8S-004: resource limits."""
    container, cname, name, content, rel_path = c.container, c.cname, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                line_number=find_key_line(content, cname),
                category="kubernetes",
                compliance=["CIS-K8s-5.4.1", "NIST-SC-6"],
            )
        )
    return findings


def k8s_007(c: K8sContainer) -> list[IaCFinding]:
    """K8S-007: Secrets in env values (not using secretKeyRef)."""
    container, cname, name, content, rel_path = c.container, c.cname, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                    line_number=find_key_line(content, env_name),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.4.1", "NIST-IA-5"],
                )
            )
    return findings


def k8s_011(c: K8sContainer) -> list[IaCFinding]:
    """K8S-011: Container image uses :latest."""
    container, cname, content, rel_path = c.container, c.cname, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
    image = container.get("image", "")
    if image and (":" not in image or image.endswith(":latest")):
        findings.append(
            IaCFinding(
                rule_id="K8S-011",
                severity="medium",
                title="Container image uses :latest tag",
                message=f"Container '{cname}' uses image '{image}' without a pinned tag. Pin to a specific version.",
                file_path=rel_path,
                line_number=find_key_line(content, image),
                category="kubernetes",
                compliance=["CIS-K8s-5.5.1", "NIST-CM-6"],
            )
        )
    return findings


def k8s_016(c: K8sContainer) -> list[IaCFinding]:
    """K8S-016: Container port 22 exposed."""
    container, cname, content, rel_path = c.container, c.cname, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
    for port in container.get("ports", []) or []:
        if isinstance(port, dict) and port.get("containerPort") == 22:
            findings.append(
                IaCFinding(
                    rule_id="K8S-016",
                    severity="high",
                    title="Container port 22 exposed (SSH)",
                    message=f"Container '{cname}' exposes port 22 (SSH). Use kubectl exec instead of SSH access.",
                    file_path=rel_path,
                    line_number=find_key_line(content, "22"),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.1.3", "NIST-CM-7"],
                )
            )
    return findings


def k8s_018(c: K8sContainer) -> list[IaCFinding]:
    """K8S-018: Dangerous capabilities added."""
    container, cname, content, rel_path = c.container, c.cname, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                    line_number=find_key_line(content, cap),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.8", "NIST-AC-6"],
                )
            )
    return findings


def k8s_022(c: K8sContainer) -> list[IaCFinding]:
    """K8S-022: Container without liveness probe."""
    container, cname, name, content, rel_path = c.container, c.cname, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                line_number=find_key_line(content, cname),
                category="kubernetes",
                compliance=["NIST-SI-13"],
            )
        )
    return findings


def k8s_023(c: K8sContainer) -> list[IaCFinding]:
    """K8S-023: Container without readiness probe."""
    container, cname, name, content, rel_path = c.container, c.cname, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                line_number=find_key_line(content, cname),
                category="kubernetes",
                compliance=["NIST-SI-13"],
            )
        )
    return findings


def k8s_026(c: K8sContainer) -> list[IaCFinding]:
    """K8S-026: Pod with hostPort specified."""
    container, cname, name, content, rel_path = c.container, c.cname, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                    line_number=find_key_line(content, "hostPort"),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.13", "NIST-CM-7"],
                )
            )
    return findings


def k8s_027(c: K8sContainer) -> list[IaCFinding]:
    """K8S-027: Container with writable /var/run/docker.sock mount."""
    container, cname, name, content, rel_path = c.container, c.cname, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                        line_number=find_key_line(content, "docker.sock"),
                        category="kubernetes",
                        compliance=["CIS-K8s-5.2.12", "NIST-AC-6"],
                    )
                )
    return findings


def k8s_029(c: K8sContainer) -> list[IaCFinding]:
    """K8S-029: Container image from untrusted registry."""
    container, cname, name, content, rel_path = c.container, c.cname, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
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
                line_number=find_key_line(content, image),
                category="kubernetes",
                compliance=["CIS-K8s-5.5.1", "NIST-CM-11"],
            )
        )
    return findings


def k8s_031(c: K8sContainer) -> list[IaCFinding]:
    """K8S-031: Missing seccompProfile."""
    cname, sec_ctx, name, pod_spec, content, rel_path = (
        c.cname,
        c.sec_ctx,
        c.workload.name,
        c.workload.pod_spec,
        c.workload.content,
        c.workload.rel_path,
    )
    findings: list[IaCFinding] = []
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
                line_number=find_key_line(content, cname),
                category="kubernetes",
                compliance=["CIS-K8s-5.7.2", "NIST-CM-6"],
            )
        )
    return findings


def k8s_032(c: K8sContainer) -> list[IaCFinding]:
    """K8S-032: Container with NET_ADMIN capability."""
    cname, sec_ctx, name, content, rel_path = c.cname, c.sec_ctx, c.workload.name, c.workload.content, c.workload.rel_path
    findings: list[IaCFinding] = []
    caps = sec_ctx.get("capabilities", {}) or {}
    add_caps = caps.get("add", []) or []
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
                    line_number=find_key_line(content, "NET_ADMIN"),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.8", "NIST-AC-6"],
                )
            )
    return findings


def k8s_034(c: K8sContainer) -> list[IaCFinding]:
    """K8S-034: GPU container with privileged mode or allowPrivilegeEscalation."""
    container, cname, sec_ctx, name, content, rel_path = (
        c.container,
        c.cname,
        c.sec_ctx,
        c.workload.name,
        c.workload.content,
        c.workload.rel_path,
    )
    findings: list[IaCFinding] = []
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
                    line_number=find_line(content, "privileged", True)
                    if is_privileged
                    else find_line(content, "allowPrivilegeEscalation", True),
                    category="kubernetes",
                    compliance=["CIS-K8s-5.2.1", "NIST-AC-6", "NIST-SI-3"],
                    attack_techniques=["T1611"],
                )
            )
    return findings
