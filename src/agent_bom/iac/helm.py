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

from pathlib import Path

import yaml  # type: ignore[import-untyped]

from agent_bom.iac.helm_common import (
    _PLACEHOLDER_PREFIX_RE,
    _PLACEHOLDER_VALUES,
    _SECRET_FIELD_RE,
    _SECRET_REFERENCE_FIELD_RE,
    _TEMPLATE_VAR_RE,
    _find_key_line,
    _find_line,
    _is_placeholder,
    _is_secret_reference_field,
    _walk_secret_fields,
)
from agent_bom.iac.helm_values import HELM_VALUES_RULES, HelmValues
from agent_bom.iac.models import IaCFinding

__all__ = [
    "_PLACEHOLDER_PREFIX_RE",
    "_PLACEHOLDER_VALUES",
    "_SECRET_FIELD_RE",
    "_SECRET_REFERENCE_FIELD_RE",
    "_TEMPLATE_VAR_RE",
    "_find_key_line",
    "_find_line",
    "_is_placeholder",
    "_is_secret_reference_field",
    "_walk_secret_fields",
    "scan_chart_yaml",
    "scan_values_yaml",
]


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

    values = HelmValues(doc=doc, content=content, rel_path=rel_path)
    for check in HELM_VALUES_RULES:
        findings.extend(check(values))

    return findings
