"""IaC misconfiguration scanning — Dockerfile, Kubernetes, Terraform, CloudFormation, Helm, DCM.

Coordinator module that discovers and scans IaC files across all supported
formats.  Each scanner is regex/YAML-based with zero external dependencies.

Rules are aligned with cloud provider official documentation and best practices
(AWS Well-Architected, CIS Benchmarks) and mapped to applicable compliance
frameworks (NIST, CIS-AWS, SOC 2) where relevant.

Usage (legacy — returns findings list only)::

    from agent_bom.iac import scan_iac_directory
    findings = scan_iac_directory("/path/to/project")

Usage (context-aware — returns findings + per-scanner verdicts)::

    from agent_bom.iac import scan_iac_with_context
    from agent_bom.iac.models import ScanContext

    ctx = ScanContext(deployment_mode="native-app")
    result = scan_iac_with_context("/path/to/project", ctx)
    # result.findings  — same content as scan_iac_directory
    # result.verdicts  — per-scanner: ran / not-applicable / disabled
"""

from __future__ import annotations

import re
from collections import defaultdict
from pathlib import Path

from agent_bom.iac.cloudformation import _is_cloudformation, scan_cloudformation
from agent_bom.iac.dcm import is_dcm_migration, scan_dcm_migration
from agent_bom.iac.dockerfile import scan_dockerfile
from agent_bom.iac.helm import scan_chart_yaml, scan_values_yaml
from agent_bom.iac.kubernetes import scan_k8s_manifest
from agent_bom.iac.models import IaCFinding, ScanContext, ScannerVerdict, ScanResult
from agent_bom.iac.terraform_security import scan_terraform_security

_DCM_AVAILABLE = True  # dcm.py is on main (#2222 merged)

__all__ = [
    "scan_iac_directory",
    "scan_iac_with_context",
    "scan_chart_yaml",
    "scan_values_yaml",
    "scan_dcm_migration",
    "ScanContext",
    "ScanResult",
    "ScannerVerdict",
]

# Canonical scanner IDs — order determines dispatch priority in the walk.
# Add new scanners here; the verdict table always has one entry per ID.
_SCANNER_IDS: tuple[str, ...] = (
    "helm",
    "dockerfile",
    "terraform",
    "dcm",
    "kubernetes",
    "cloudformation",
)

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
    return path.name in _CHART_YAML_NAMES


def _is_values_yaml(path: Path) -> bool:
    return bool(_VALUES_YAML_RE.match(path.name))


def _is_dockerfile(path: Path) -> bool:
    name = path.name
    if name in _DOCKERFILE_NAMES:
        return True
    if name.startswith("Dockerfile"):
        return True
    return False


def _is_k8s_manifest(path: Path) -> bool:
    if path.suffix not in (".yaml", ".yml"):
        return False
    for parent in path.parents:
        if parent.name.lower() in _K8S_DIRS:
            return True
    try:
        head = path.read_text(encoding="utf-8", errors="replace")[:2000]
        return "apiVersion:" in head and "kind:" in head
    except OSError:
        return False


def scan_iac_with_context(
    root: str | Path,
    context: ScanContext | None = None,
) -> ScanResult:
    """Scan a directory tree for IaC misconfigurations, returning findings and
    a per-scanner capability verdict table.

    Two orthogonal gates are applied for each scanner on every file:

    1. **Authorization** — ``context.enabled_scanners`` acts as an allowlist.
       ``None`` (default) means all scanners are unlocked.  A non-empty
       frozenset locks out any scanner whose ID is absent; those scanners
       emit a ``"disabled"`` verdict and are never dispatched.

    2. **Applicability** — tracked by counting files matched per scanner during
       the single directory walk.  Zero matches → ``"not-applicable"``; one or
       more → ``"ran"``.  This is the expected status for scanners whose file
       types don't exist in the scanned tree (e.g. Dockerfile scanner on a
       pure-Terraform repo, or any bare-metal scanner inside a Snowflake Native
       App deployment where there are simply no host-level files to inspect).

    Parameters
    ----------
    root:
        Root directory to scan recursively.
    context:
        Optional deployment and authorization context.  Defaults to
        ``ScanContext(deployment_mode="standalone")`` with all scanners
        unlocked.

    Returns
    -------
    ScanResult
        ``findings`` is identical in content to ``scan_iac_directory``.
        ``verdicts`` has one ``ScannerVerdict`` per known scanner ID.
    """
    ctx = context or ScanContext()
    root_path = Path(root).expanduser().resolve()

    if not root_path.is_dir():
        early_verdicts: list[ScannerVerdict] = [
            ScannerVerdict(
                scanner_id=sid,
                status="disabled" if (ctx.enabled_scanners is not None and sid not in ctx.enabled_scanners) else "not-applicable",
                files_scanned=0,
                reason="scan root does not exist or is not a directory",
            )
            for sid in _SCANNER_IDS
        ]
        return ScanResult(findings=[], verdicts=early_verdicts)

    # Gate 1: build the disabled set up-front so the walk loop is O(1) per file.
    if ctx.enabled_scanners is not None:
        disabled: frozenset[str] = frozenset(sid for sid in _SCANNER_IDS if sid not in ctx.enabled_scanners)
    else:
        disabled = frozenset()

    findings: list[IaCFinding] = []
    files_matched: dict[str, int] = defaultdict(int)
    severity_order = {"critical": 0, "high": 1, "medium": 2, "low": 3}

    for path in sorted(root_path.rglob("*")):
        if not path.is_file():
            continue
        if any(part.startswith(".") for part in path.relative_to(root_path).parts):
            continue
        if "node_modules" in path.parts or "__pycache__" in path.parts:
            continue

        # Dispatch in priority order: more specific checks first.
        if _is_chart_yaml(path) or _is_values_yaml(path):
            if "helm" not in disabled:
                files_matched["helm"] += 1
                if _is_chart_yaml(path):
                    findings.extend(scan_chart_yaml(path))
                else:
                    findings.extend(scan_values_yaml(path))
            else:
                files_matched.setdefault("helm", 0)
        elif _is_dockerfile(path):
            if "dockerfile" not in disabled:
                files_matched["dockerfile"] += 1
                findings.extend(scan_dockerfile(path))
        elif path.suffix == ".tf":
            if "terraform" not in disabled:
                files_matched["terraform"] += 1
                findings.extend(scan_terraform_security(path))
                from agent_bom.iac.terraform_ai import scan_terraform_ai

                findings.extend(scan_terraform_ai(path))
        elif is_dcm_migration(path):
            # DCM before generic .sql / K8s so V<seq>__name.sql is never
            # misclassified. Snowflake Native App's own DCM project
            # (deploy/snowflake/native-app/dcm/) self-tests via this path.
            if "dcm" not in disabled:
                files_matched["dcm"] += 1
                findings.extend(scan_dcm_migration(path))
        elif _is_k8s_manifest(path):
            # K8s before CloudFormation — both match .yaml/.yml but K8s
            # markers (apiVersion + kind) are more specific than "Resources:".
            if "kubernetes" not in disabled:
                files_matched["kubernetes"] += 1
                findings.extend(scan_k8s_manifest(path))
        elif _is_cloudformation(path):
            if "cloudformation" not in disabled:
                files_matched["cloudformation"] += 1
                findings.extend(scan_cloudformation(path))

    # Enrich with MITRE ATT&CK and MITRE ATLAS technique IDs
    from agent_bom.iac.atlas_mapping import get_atlas_techniques
    from agent_bom.iac.attack_mapping import get_attack_techniques

    for finding in findings:
        if not finding.attack_techniques:
            finding.attack_techniques = get_attack_techniques(finding.rule_id)
        if not finding.atlas_techniques:
            finding.atlas_techniques = get_atlas_techniques(finding.rule_id, message=finding.message)

    findings.sort(key=lambda f: (severity_order.get(f.severity, 9), f.file_path, f.line_number))

    # Build verdict table — one entry per canonical scanner ID.
    verdicts: list[ScannerVerdict] = []
    for sid in _SCANNER_IDS:
        if sid in disabled:
            verdicts.append(
                ScannerVerdict(
                    scanner_id=sid,
                    status="disabled",
                    files_scanned=0,
                    reason=f"locked out by deployment context ({ctx.deployment_mode})",
                )
            )
        elif files_matched.get(sid, 0) > 0:
            verdicts.append(
                ScannerVerdict(
                    scanner_id=sid,
                    status="ran",
                    files_scanned=files_matched[sid],
                )
            )
        else:
            verdicts.append(
                ScannerVerdict(
                    scanner_id=sid,
                    status="not-applicable",
                    files_scanned=0,
                    reason="no matching files found in scan root",
                )
            )

    return ScanResult(findings=findings, verdicts=verdicts)


def scan_iac_directory(root: str | Path) -> list[IaCFinding]:
    """Scan a directory tree for IaC misconfigurations across all supported formats.

    Legacy entry point — returns findings list only.  New callers should
    prefer ``scan_iac_with_context`` which also returns per-scanner verdicts.

    Parameters
    ----------
    root:
        Root directory to scan recursively.

    Returns
    -------
    list[IaCFinding]
        All findings from all scanners, sorted by severity then file path.
    """
    return scan_iac_with_context(root).findings
