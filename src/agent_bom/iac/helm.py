"""Helm chart misconfiguration scanner.

Scans ``Chart.yaml`` and ``values.yaml`` for common security misconfigurations
using ``yaml.safe_load``.  No external tools required.

Rules
-----
HELM-001  Chart.yaml uses apiVersion: v1 (deprecated Helm 2 format)
HELM-002  Chart.yaml missing appVersion field
HELM-003  values.yaml has hardcoded secret values (password/token/secret/key/credential/auth)
HELM-004  values.yaml has image tag set to "latest" (unpinned mutable tag)
HELM-005  values.yaml has service.type: NodePort (exposes on all node IPs/ports)
HELM-006  values.yaml has networkPolicy.enabled: false (disables network isolation)
HELM-007  values.yaml has rbac.create: false or serviceAccount.create: false
HELM-008  Ingress without TLS configuration
HELM-009  Service with externalTrafficPolicy: Cluster (source IP lost)
HELM-010  PersistentVolumeClaim without storageClassName
HELM-011  Container resources without memory limits
HELM-012  Missing podSecurityContext
HELM-013  Values with default admin password
HELM-014  Missing livenessProbe in templates
HELM-015  Deployment replicas set to 1 (no HA)
"""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

import yaml  # type: ignore[import-untyped]

from agent_bom.iac.models import IaCFinding

# Secret-like field name patterns for values.yaml
_SECRET_FIELD_RE = re.compile(
    r"(?:password|token|secret|key|credential|auth)",
    re.IGNORECASE,
)

# Placeholder values that should NOT be flagged
_PLACEHOLDER_VALUES = frozenset(
    {
        "",
        "changeme",
        "CHANGEME",
        "replace",
        "placeholder",
        "TODO",
    }
)

_PLACEHOLDER_PREFIX_RE = re.compile(r"^your[-_]", re.IGNORECASE)
# Helm/Jinja template expressions — resolved at deploy time, never hardcoded secrets
_TEMPLATE_VAR_RE = re.compile(r"\{\{.*?\}\}", re.DOTALL)


def _find_line(content: str, key: str, value: Any, start_line: int = 1) -> int:
    """Best-effort line number search for a key-value pair in YAML text."""
    if isinstance(value, bool):
        val_str = "true" if value else "false"
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


def _is_placeholder(value: str) -> bool:
    """Return True if the value is a known non-secret placeholder."""
    if value in _PLACEHOLDER_VALUES:
        return True
    if _PLACEHOLDER_PREFIX_RE.match(value):
        return True
    # Helm/Jinja template expressions ({{ .Values.* }}) are resolved at deploy time
    if _TEMPLATE_VAR_RE.search(value):
        return True
    return False


def _walk_secret_fields(obj: Any, content: str, file_path: str, findings: list[IaCFinding]) -> None:
    """Recursively walk a parsed YAML object and flag secret-like fields with real values."""
    if isinstance(obj, dict):
        for k, v in obj.items():
            if isinstance(k, str) and _SECRET_FIELD_RE.search(k):
                if isinstance(v, str) and v and not _is_placeholder(v):
                    findings.append(
                        IaCFinding(
                            rule_id="HELM-003",
                            severity="critical",
                            title=f"Hardcoded secret in values.yaml: '{k}'",
                            message=(
                                f"Field '{k}' in values.yaml contains a hardcoded secret value. "
                                "Use environment variable substitution, a Secrets Store CSI driver, "
                                "or reference a Kubernetes Secret instead of hardcoding credentials."
                            ),
                            file_path=file_path,
                            line_number=_find_key_line(content, k),
                            category="helm",
                            compliance=["CIS-K8s-5.4.1", "NIST-IA-5"],
                        )
                    )
            # Recurse into nested structures regardless
            if isinstance(v, (dict, list)):
                _walk_secret_fields(v, content, file_path, findings)
    elif isinstance(obj, list):
        for item in obj:
            if isinstance(item, (dict, list)):
                _walk_secret_fields(item, content, file_path, findings)


def scan_chart_yaml(file_path: str | Path) -> list[IaCFinding]:
    """Scan a Helm ``Chart.yaml`` file for misconfigurations.

    Parameters
    ----------
    file_path:
        Path to a ``Chart.yaml`` file.

    Returns
    -------
    list[IaCFinding]
        Detected misconfigurations.
    """
    path = Path(file_path)
    if not path.is_file():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rel_path = str(path)
    findings: list[IaCFinding] = []

    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return []

    if not isinstance(doc, dict):
        return []

    # HELM-001: deprecated apiVersion: v1
    api_version = doc.get("apiVersion")
    if api_version == "v1":
        findings.append(
            IaCFinding(
                rule_id="HELM-001",
                severity="high",
                title="Deprecated Helm 2 apiVersion in Chart.yaml",
                message=(
                    "Chart.yaml uses 'apiVersion: v1' which is the deprecated Helm 2 format. "
                    "Upgrade to 'apiVersion: v2' to use Helm 3 features and avoid compatibility issues."
                ),
                file_path=rel_path,
                line_number=_find_line(content, "apiVersion", "v1"),
                category="helm",
                compliance=["CIS-K8s-5.1.1", "NIST-CM-6"],
            )
        )

    # HELM-002: missing appVersion
    if "appVersion" not in doc:
        findings.append(
            IaCFinding(
                rule_id="HELM-002",
                severity="low",
                title="Missing appVersion in Chart.yaml",
                message=(
                    "Chart.yaml does not define 'appVersion'. "
                    "Set appVersion to track the upstream application version being deployed, "
                    "improving release auditing and traceability."
                ),
                file_path=rel_path,
                line_number=1,
                category="helm",
                compliance=["NIST-CM-8"],
            )
        )

    return findings


def scan_values_yaml(file_path: str | Path) -> list[IaCFinding]:
    """Scan a Helm ``values.yaml`` (or ``values-*.yaml``) file for misconfigurations.

    Parameters
    ----------
    file_path:
        Path to a Helm values file.

    Returns
    -------
    list[IaCFinding]
        Detected misconfigurations.
    """
    path = Path(file_path)
    if not path.is_file():
        return []

    try:
        content = path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        return []

    rel_path = str(path)
    findings: list[IaCFinding] = []

    try:
        doc = yaml.safe_load(content)
    except yaml.YAMLError:
        return []

    if not isinstance(doc, dict):
        return []

    # HELM-003: hardcoded secrets (recursive walk)
    _walk_secret_fields(doc, content, rel_path, findings)

    # HELM-004: image tag set to "latest"
    image_section = doc.get("image")
    if isinstance(image_section, dict):
        tag = image_section.get("tag")
        if tag == "latest":
            findings.append(
                IaCFinding(
                    rule_id="HELM-004",
                    severity="medium",
                    title="Image tag set to 'latest' in values.yaml",
                    message=(
                        "values.yaml sets image.tag to 'latest'. The latest tag is mutable and can "
                        "cause unexpected version changes on re-deploy. Pin to a specific immutable digest or version tag."
                    ),
                    file_path=rel_path,
                    line_number=_find_line(content, "tag", "latest"),
                    category="helm",
                    compliance=["CIS-K8s-5.5.1", "NIST-CM-6"],
                )
            )

    # HELM-005: service.type: NodePort
    service_section = doc.get("service")
    if isinstance(service_section, dict):
        svc_type = service_section.get("type")
        if svc_type == "NodePort":
            findings.append(
                IaCFinding(
                    rule_id="HELM-005",
                    severity="medium",
                    title="service.type set to NodePort",
                    message=(
                        "values.yaml sets service.type to 'NodePort'. NodePort exposes the service "
                        "on all node IPs on a static port, increasing the attack surface. "
                        "Use ClusterIP with an Ingress controller or LoadBalancer instead."
                    ),
                    file_path=rel_path,
                    line_number=_find_line(content, "type", "NodePort"),
                    category="helm",
                    compliance=["CIS-K8s-5.3.1", "NIST-SC-7"],
                )
            )

    # HELM-006: networkPolicy.enabled: false
    network_policy = doc.get("networkPolicy")
    if isinstance(network_policy, dict):
        if network_policy.get("enabled") is False:
            findings.append(
                IaCFinding(
                    rule_id="HELM-006",
                    severity="medium",
                    title="networkPolicy.enabled set to false",
                    message=(
                        "values.yaml explicitly disables NetworkPolicy (networkPolicy.enabled: false). "
                        "Enable NetworkPolicy to enforce network isolation and restrict pod-to-pod traffic."
                    ),
                    file_path=rel_path,
                    line_number=_find_line(content, "enabled", False),
                    category="helm",
                    compliance=["CIS-K8s-5.3.2", "NIST-SC-7"],
                )
            )

    # HELM-007: rbac.create: false or serviceAccount.create: false
    rbac_section = doc.get("rbac")
    if isinstance(rbac_section, dict):
        if rbac_section.get("create") is False:
            findings.append(
                IaCFinding(
                    rule_id="HELM-007",
                    severity="medium",
                    title="rbac.create set to false",
                    message=(
                        "values.yaml sets rbac.create to false. Disabling RBAC resource creation "
                        "may leave the workload relying on overly permissive pre-existing roles. "
                        "Enable RBAC to enforce least-privilege access control."
                    ),
                    file_path=rel_path,
                    line_number=_find_line(content, "create", False),
                    category="helm",
                    compliance=["CIS-K8s-5.1.5", "NIST-AC-6"],
                )
            )

    service_account = doc.get("serviceAccount")
    if isinstance(service_account, dict):
        if service_account.get("create") is False:
            findings.append(
                IaCFinding(
                    rule_id="HELM-007",
                    severity="medium",
                    title="serviceAccount.create set to false",
                    message=(
                        "values.yaml sets serviceAccount.create to false. Disabling service account "
                        "creation may reuse the default service account, which is often over-privileged. "
                        "Create a dedicated service account with only the required permissions."
                    ),
                    file_path=rel_path,
                    line_number=_find_line(content, "create", False),
                    category="helm",
                    compliance=["CIS-K8s-5.1.6", "NIST-AC-6"],
                )
            )

    # HELM-008: Ingress without TLS configuration
    ingress_section = doc.get("ingress")
    if isinstance(ingress_section, dict):
        if ingress_section.get("enabled") is not False and not ingress_section.get("tls"):
            findings.append(
                IaCFinding(
                    rule_id="HELM-008",
                    severity="high",
                    title="Ingress without TLS configuration",
                    message=(
                        "values.yaml defines an ingress without TLS configuration. "
                        "Traffic will be served over plain HTTP, exposing data in transit. "
                        "Configure ingress.tls with a certificate secret."
                    ),
                    file_path=rel_path,
                    line_number=_find_key_line(content, "ingress"),
                    category="helm",
                    compliance=["CIS-K8s-5.4.1", "NIST-SC-8"],
                )
            )

    # HELM-009: Service with externalTrafficPolicy: Cluster
    if isinstance(service_section, dict):
        if service_section.get("externalTrafficPolicy") == "Cluster":
            findings.append(
                IaCFinding(
                    rule_id="HELM-009",
                    severity="low",
                    title="Service externalTrafficPolicy set to Cluster",
                    message=(
                        "values.yaml sets service.externalTrafficPolicy to 'Cluster'. "
                        "This causes source IP to be lost via SNAT. Set to 'Local' to "
                        "preserve client source IP for auditing and network policy enforcement."
                    ),
                    file_path=rel_path,
                    line_number=_find_line(content, "externalTrafficPolicy", "Cluster"),
                    category="helm",
                    compliance=["NIST-AU-3"],
                )
            )

    # HELM-010: PersistentVolumeClaim without storageClassName
    persistence_section = doc.get("persistence")
    if isinstance(persistence_section, dict):
        if persistence_section.get("enabled") is not False and not persistence_section.get("storageClassName"):
            findings.append(
                IaCFinding(
                    rule_id="HELM-010",
                    severity="low",
                    title="PersistentVolumeClaim without storageClassName",
                    message=(
                        "values.yaml defines persistence without an explicit storageClassName. "
                        "The default storage class may not meet performance or encryption "
                        "requirements. Specify storageClassName explicitly."
                    ),
                    file_path=rel_path,
                    line_number=_find_key_line(content, "persistence"),
                    category="helm",
                    compliance=["NIST-SC-28"],
                )
            )

    # HELM-011: Container resources without memory limits
    resources_section = doc.get("resources")
    if isinstance(resources_section, dict):
        limits = resources_section.get("limits")
        if not isinstance(limits, dict) or not limits.get("memory"):
            findings.append(
                IaCFinding(
                    rule_id="HELM-011",
                    severity="medium",
                    title="Container resources without memory limits",
                    message=(
                        "values.yaml defines resources without memory limits. "
                        "Without memory limits, a container can consume all node memory "
                        "and cause OOM kills on other workloads. Set resources.limits.memory."
                    ),
                    file_path=rel_path,
                    line_number=_find_key_line(content, "resources"),
                    category="helm",
                    compliance=["CIS-K8s-5.4.1", "NIST-SC-6"],
                )
            )

    # HELM-012: Missing podSecurityContext
    if not doc.get("podSecurityContext"):
        findings.append(
            IaCFinding(
                rule_id="HELM-012",
                severity="medium",
                title="Missing podSecurityContext in values.yaml",
                message=(
                    "values.yaml does not define podSecurityContext. "
                    "Set podSecurityContext with runAsNonRoot: true, fsGroup, and "
                    "seccompProfile to enforce pod-level security defaults."
                ),
                file_path=rel_path,
                line_number=1,
                category="helm",
                compliance=["CIS-K8s-5.2.6", "NIST-AC-6"],
            )
        )

    # HELM-013: Values with default admin password
    _admin_pw_keys = {"adminPassword", "admin_password", "adminPass", "admin_pass"}
    for admin_key in _admin_pw_keys:
        admin_val = doc.get(admin_key)
        if isinstance(admin_val, str) and admin_val and not _is_placeholder(admin_val):
            findings.append(
                IaCFinding(
                    rule_id="HELM-013",
                    severity="critical",
                    title=f"Default admin password in values.yaml: '{admin_key}'",
                    message=(
                        f"values.yaml sets '{admin_key}' to a non-placeholder value. "
                        "Default admin passwords are a common attack vector. "
                        "Use a Kubernetes Secret or external secret manager instead."
                    ),
                    file_path=rel_path,
                    line_number=_find_key_line(content, admin_key),
                    category="helm",
                    compliance=["CIS-K8s-5.4.1", "NIST-IA-5"],
                )
            )

    # HELM-014: Missing livenessProbe in templates
    if not doc.get("livenessProbe"):
        findings.append(
            IaCFinding(
                rule_id="HELM-014",
                severity="medium",
                title="Missing livenessProbe in values.yaml",
                message=(
                    "values.yaml does not define livenessProbe defaults. "
                    "Without a liveness probe, Kubernetes cannot detect and restart "
                    "deadlocked containers. Define livenessProbe with httpGet or tcpSocket."
                ),
                file_path=rel_path,
                line_number=1,
                category="helm",
                compliance=["NIST-SI-13"],
            )
        )

    # HELM-015: Deployment replicas set to 1 (no HA)
    replicas = doc.get("replicaCount")
    if replicas is None:
        replicas = doc.get("replicas")
    if isinstance(replicas, int) and replicas == 1:
        findings.append(
            IaCFinding(
                rule_id="HELM-015",
                severity="low",
                title="Deployment replicas set to 1",
                message=(
                    "values.yaml sets replicaCount/replicas to 1. "
                    "A single replica provides no high availability. "
                    "Set replicas >= 2 for production workloads to ensure uptime."
                ),
                file_path=rel_path,
                line_number=_find_key_line(content, "replicaCount") if doc.get("replicaCount") else _find_key_line(content, "replicas"),
                category="helm",
                compliance=["NIST-CP-10"],
            )
        )

    return findings
