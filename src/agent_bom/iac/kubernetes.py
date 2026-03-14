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
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml

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
        if kind not in _WORKLOAD_KINDS:
            continue

        pod_spec = _get_pod_spec(doc)
        if not pod_spec:
            continue

        metadata = doc.get("metadata", {}) or {}
        namespace = metadata.get("namespace", "")
        name = metadata.get("name", kind)

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

    return findings
