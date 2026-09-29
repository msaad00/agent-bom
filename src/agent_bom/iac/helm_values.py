"""Helm ``values.yaml`` rule checks.

Each ``helm_NNN`` function evaluates one rule against a parsed values file and
returns its findings. ``scan_values_yaml`` runs them in ``HELM_VALUES_RULES``
order.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from agent_bom.iac.helm_common import _find_key_line, _find_line, _is_placeholder, _walk_secret_fields
from agent_bom.iac.models import IaCFinding


@dataclass(frozen=True)
class HelmValues:
    """A parsed values file as the rule checks see it."""

    doc: dict[str, Any]
    content: str
    rel_path: str


def helm_003(v: HelmValues) -> list[IaCFinding]:
    """HELM-003: hardcoded secrets (recursive walk)."""
    findings: list[IaCFinding] = []
    _walk_secret_fields(v.doc, v.content, v.rel_path, findings)
    return findings


def helm_004(v: HelmValues) -> list[IaCFinding]:
    """HELM-004: image tag set to "latest"."""
    findings: list[IaCFinding] = []
    image_section = v.doc.get("image")
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
                    file_path=v.rel_path,
                    line_number=_find_line(v.content, "tag", "latest"),
                    category="helm",
                    compliance=["CIS-K8s-5.5.1", "NIST-CM-6"],
                )
            )
    return findings


def helm_005(v: HelmValues) -> list[IaCFinding]:
    """HELM-005: service.type: NodePort."""
    findings: list[IaCFinding] = []
    service_section = v.doc.get("service")
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
                    file_path=v.rel_path,
                    line_number=_find_line(v.content, "type", "NodePort"),
                    category="helm",
                    compliance=["CIS-K8s-5.3.1", "NIST-SC-7"],
                )
            )
    return findings


def helm_006(v: HelmValues) -> list[IaCFinding]:
    """HELM-006: networkPolicy.enabled: false."""
    findings: list[IaCFinding] = []
    network_policy = v.doc.get("networkPolicy")
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
                    file_path=v.rel_path,
                    line_number=_find_line(v.content, "enabled", False),
                    category="helm",
                    compliance=["CIS-K8s-5.3.2", "NIST-SC-7"],
                )
            )
    return findings


def helm_007(v: HelmValues) -> list[IaCFinding]:
    """HELM-007: rbac.create: false or serviceAccount.create: false."""
    findings: list[IaCFinding] = []
    rbac_section = v.doc.get("rbac")
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
                    file_path=v.rel_path,
                    line_number=_find_line(v.content, "create", False),
                    category="helm",
                    compliance=["CIS-K8s-5.1.5", "NIST-AC-6"],
                )
            )

    service_account = v.doc.get("serviceAccount")
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
                    file_path=v.rel_path,
                    line_number=_find_line(v.content, "create", False),
                    category="helm",
                    compliance=["CIS-K8s-5.1.6", "NIST-AC-6"],
                )
            )
    return findings


def helm_008(v: HelmValues) -> list[IaCFinding]:
    """HELM-008: Ingress without TLS configuration."""
    findings: list[IaCFinding] = []
    ingress_section = v.doc.get("ingress")
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
                    file_path=v.rel_path,
                    line_number=_find_key_line(v.content, "ingress"),
                    category="helm",
                    compliance=["CIS-K8s-5.4.1", "NIST-SC-8"],
                )
            )
    return findings


def helm_009(v: HelmValues) -> list[IaCFinding]:
    """HELM-009: Service with externalTrafficPolicy: Cluster."""
    findings: list[IaCFinding] = []
    service_section = v.doc.get("service")
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
                    file_path=v.rel_path,
                    line_number=_find_line(v.content, "externalTrafficPolicy", "Cluster"),
                    category="helm",
                    compliance=["NIST-AU-3"],
                )
            )
    return findings


def helm_010(v: HelmValues) -> list[IaCFinding]:
    """HELM-010: PersistentVolumeClaim without storageClassName."""
    findings: list[IaCFinding] = []
    persistence_section = v.doc.get("persistence")
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
                    file_path=v.rel_path,
                    line_number=_find_key_line(v.content, "persistence"),
                    category="helm",
                    compliance=["NIST-SC-28"],
                )
            )
    return findings


def helm_011(v: HelmValues) -> list[IaCFinding]:
    """HELM-011: Container resources without memory limits."""
    findings: list[IaCFinding] = []
    resources_section = v.doc.get("resources")
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
                    file_path=v.rel_path,
                    line_number=_find_key_line(v.content, "resources"),
                    category="helm",
                    compliance=["CIS-K8s-5.4.1", "NIST-SC-6"],
                )
            )
    return findings


def helm_012(v: HelmValues) -> list[IaCFinding]:
    """HELM-012: Missing podSecurityContext."""
    findings: list[IaCFinding] = []
    if not v.doc.get("podSecurityContext"):
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
                file_path=v.rel_path,
                line_number=1,
                category="helm",
                compliance=["CIS-K8s-5.2.6", "NIST-AC-6"],
            )
        )
    return findings


def helm_013(v: HelmValues) -> list[IaCFinding]:
    """HELM-013: Values with default admin password."""
    findings: list[IaCFinding] = []
    _admin_pw_keys = {"adminPassword", "admin_password", "adminPass", "admin_pass"}
    for admin_key in _admin_pw_keys:
        admin_val = v.doc.get(admin_key)
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
                    file_path=v.rel_path,
                    line_number=_find_key_line(v.content, admin_key),
                    category="helm",
                    compliance=["CIS-K8s-5.4.1", "NIST-IA-5"],
                )
            )
    return findings


def helm_014(v: HelmValues) -> list[IaCFinding]:
    """HELM-014: Missing livenessProbe in templates."""
    findings: list[IaCFinding] = []
    if not v.doc.get("livenessProbe"):
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
                file_path=v.rel_path,
                line_number=1,
                category="helm",
                compliance=["NIST-SI-13"],
            )
        )
    return findings


def helm_015(v: HelmValues) -> list[IaCFinding]:
    """HELM-015: Deployment replicas set to 1 (no HA)."""
    findings: list[IaCFinding] = []
    replicas = v.doc.get("replicaCount")
    if replicas is None:
        replicas = v.doc.get("replicas")
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
                file_path=v.rel_path,
                line_number=(
                    _find_key_line(v.content, "replicaCount") if v.doc.get("replicaCount") else _find_key_line(v.content, "replicas")
                ),
                category="helm",
                compliance=["NIST-CP-10"],
            )
        )
    return findings


HELM_VALUES_RULES: tuple[Callable[[HelmValues], list[IaCFinding]], ...] = (
    helm_003,
    helm_004,
    helm_005,
    helm_006,
    helm_007,
    helm_008,
    helm_009,
    helm_010,
    helm_011,
    helm_012,
    helm_013,
    helm_014,
    helm_015,
)
