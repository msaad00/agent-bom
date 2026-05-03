"""IaC misconfiguration scanning — Dockerfile, Kubernetes, Terraform, CloudFormation, Helm.

Coordinator module that discovers and scans IaC files across all supported
formats.  Each scanner is regex/YAML-based with zero external dependencies.

Rules are aligned with cloud provider official documentation and best practices
(AWS Well-Architected, CIS Benchmarks) and mapped to applicable compliance
frameworks (NIST, CIS-AWS, SOC 2) where relevant.

Usage::

    from agent_bom.iac import scan_iac_directory

    findings = scan_iac_directory("/path/to/project")
"""

from __future__ import annotations

import re
from pathlib import Path

from agent_bom.iac.cloudformation import _is_cloudformation, scan_cloudformation
from agent_bom.iac.dockerfile import scan_dockerfile
from agent_bom.iac.helm import scan_chart_yaml, scan_values_yaml
from agent_bom.iac.kubernetes import scan_k8s_manifest
from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security import scan_terraform_security

__all__ = [
    "scan_iac_directory",
    "scan_chart_yaml",
    "scan_values_yaml",
]

# Dockerfile filename patterns
_DOCKERFILE_NAMES = frozenset(
    {
        "Dockerfile",
        "dockerfile",
        "Dockerfile.dev",
        "Dockerfile.prod",
        "Dockerfile.ci",
        "Dockerfile.test",
    }
)

# K8s manifest filename suffixes + directory hints
_K8S_DIRS = frozenset({"k8s", "kubernetes", "deploy", "manifests", "helm"})

# Helm Chart.yaml names (case-insensitive)
_CHART_YAML_NAMES = frozenset({"Chart.yaml", "chart.yaml"})

# values.yaml / values-*.yaml pattern
_VALUES_YAML_RE = re.compile(r"^values(?:-[a-zA-Z0-9_-]+)?\.ya?ml$")


def _is_chart_yaml(path: Path) -> bool:
    """Check if a file is a Helm Chart.yaml."""
    return path.name in _CHART_YAML_NAMES


def _is_values_yaml(path: Path) -> bool:
    """Check if a file is a Helm values file (values.yaml or values-*.yaml)."""
    return bool(_VALUES_YAML_RE.match(path.name))


def _is_dockerfile(path: Path) -> bool:
    """Check if a file looks like a Dockerfile."""
    name = path.name
    if name in _DOCKERFILE_NAMES:
        return True
    if name.startswith("Dockerfile"):
        return True
    return False


def _is_k8s_manifest(path: Path) -> bool:
    """Check if a YAML file might be a Kubernetes manifest (heuristic)."""
    if path.suffix not in (".yaml", ".yml"):
        return False
    # Check directory hints
    for parent in path.parents:
        if parent.name.lower() in _K8S_DIRS:
            return True
    # Check file content for K8s markers
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2000]
        return "apiVersion:" in head and "kind:" in head
    except OSError:
        return False


def scan_iac_directory(root: str | Path) -> list[IaCFinding]:
    """Scan a directory tree for IaC misconfigurations across all supported formats.

    Discovers Dockerfiles, Kubernetes YAML manifests, Terraform ``.tf``
    files, and CloudFormation templates, then runs the appropriate scanner
    on each.

    Parameters
    ----------
    root:
        Root directory to scan recursively.

    Returns
    -------
    list[IaCFinding]
        All findings from all scanners, sorted by severity then file path.
    """
    root_path = Path(root).expanduser().resolve()
    if not root_path.is_dir():
        return []

    findings: list[IaCFinding] = []
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    # Walk the directory tree
    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        # Skip hidden dirs / common non-IaC
        if any(part.startswith(".") for part in path.relative_to(root_path).parts):
            continue
        if "node_modules" in path.parts or "__pycache__" in path.parts:
            continue

        if _is_chart_yaml(path):
            findings.extend(scan_chart_yaml(path))
        elif _is_values_yaml(path):
            findings.extend(scan_values_yaml(path))
        elif _is_dockerfile(path):
            findings.extend(scan_dockerfile(path))
        elif path.suffix == ".tf":
            findings.extend(scan_terraform_security(path))
            from agent_bom.iac.terraform_ai import scan_terraform_ai

            findings.extend(scan_terraform_ai(path))
        elif _is_k8s_manifest(path):
            # K8s check before CloudFormation — both match .yaml/.yml but
            # K8s markers (apiVersion + kind) are more specific than "Resources:"
            findings.extend(scan_k8s_manifest(path))
        elif _is_cloudformation(path):
            findings.extend(scan_cloudformation(path))

    # Enrich with MITRE ATT&CK technique IDs
    from agent_bom.iac.atlas_mapping import get_atlas_techniques
    from agent_bom.iac.attack_mapping import get_attack_techniques

    for finding in findings:
        if not finding.attack_techniques:
            finding.attack_techniques = get_attack_techniques(finding.rule_id)
        if not finding.atlas_techniques:
            finding.atlas_techniques = get_atlas_techniques(finding.rule_id, message=finding.message)

    # Sort: critical first, then by file path
    findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line_number))
    return findings
