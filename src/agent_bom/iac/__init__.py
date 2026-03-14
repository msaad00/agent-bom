"""IaC misconfiguration scanning — Dockerfile, Kubernetes, Terraform security.

Coordinator module that discovers and scans IaC files across all supported
formats.  Each scanner is regex/YAML-based with zero external dependencies.

Usage::

    from agent_bom.iac import scan_iac_directory

    findings = scan_iac_directory("/path/to/project")
"""

from __future__ import annotations

from pathlib import Path

from agent_bom.iac.dockerfile import scan_dockerfile
from agent_bom.iac.kubernetes import scan_k8s_manifest
from agent_bom.iac.models import IaCFinding
from agent_bom.iac.terraform_security import scan_terraform_security

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

    Discovers Dockerfiles, Kubernetes YAML manifests, and Terraform ``.tf``
    files, then runs the appropriate scanner on each.

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

        if _is_dockerfile(path):
            findings.extend(scan_dockerfile(path))
        elif path.suffix == ".tf":
            findings.extend(scan_terraform_security(path))
        elif _is_k8s_manifest(path):
            findings.extend(scan_k8s_manifest(path))

    # Sort: critical first, then by file path
    findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line_number))
    return findings
