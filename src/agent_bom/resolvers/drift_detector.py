"""Version drift detection: declared vs installed vs running.

Compares package versions across three tiers:
  1. Declared — what lockfiles/manifests say
  2. Installed — what ``pip list`` / ``npm ls`` / ``go list`` report
  3. Running — what the live process actually loaded (future)

Version mismatches are flagged as ``VersionDrift`` findings with severity
based on the magnitude of the gap and whether the installed version is
older (potentially vulnerable) or newer (potentially untested).
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field

from agent_bom.models import Package

logger = logging.getLogger(__name__)


@dataclass
class VersionDrift:
    """A version mismatch between declared and installed versions."""

    package_name: str
    ecosystem: str
    declared_version: str | None
    installed_version: str | None
    drift_type: str  # "version_mismatch", "undeclared", "missing"
    severity: str  # "critical", "high", "medium", "low", "info"
    detail: str

    def to_dict(self) -> dict:
        return {
            "package": self.package_name,
            "ecosystem": self.ecosystem,
            "declared_version": self.declared_version,
            "installed_version": self.installed_version,
            "drift_type": self.drift_type,
            "severity": self.severity,
            "detail": self.detail,
        }


@dataclass
class DriftReport:
    """Aggregated drift findings for a single scan context."""

    drifts: list[VersionDrift] = field(default_factory=list)
    declared_count: int = 0
    installed_count: int = 0
    match_count: int = 0

    @property
    def drift_count(self) -> int:
        return len(self.drifts)

    @property
    def has_critical(self) -> bool:
        return any(d.severity == "critical" for d in self.drifts)

    def to_dict(self) -> dict:
        return {
            "declared_count": self.declared_count,
            "installed_count": self.installed_count,
            "match_count": self.match_count,
            "drift_count": self.drift_count,
            "has_critical": self.has_critical,
            "drifts": [d.to_dict() for d in self.drifts],
        }


def detect_drift(
    declared_packages: list[Package],
    installed_versions: dict[str, str],
    ecosystem: str,
) -> DriftReport:
    """Compare declared packages against installed versions.

    Args:
        declared_packages: Packages parsed from lockfiles/manifests.
        installed_versions: {name: version} from runtime resolver.
        ecosystem: Ecosystem identifier (npm, pypi, go, etc.).

    Returns:
        DriftReport with all mismatches and summary statistics.
    """
    report = DriftReport()

    # Normalize names for comparison
    declared_map: dict[str, Package] = {}
    for pkg in declared_packages:
        if pkg.ecosystem == ecosystem:
            norm_name = _normalize_name(pkg.name, ecosystem)
            declared_map[norm_name] = pkg

    installed_norm: dict[str, str] = {}
    for name, ver in installed_versions.items():
        norm_name = _normalize_name(name, ecosystem)
        installed_norm[norm_name] = ver

    report.declared_count = len(declared_map)
    report.installed_count = len(installed_norm)

    # Check declared packages against installed
    for norm_name, pkg in declared_map.items():
        if norm_name in installed_norm:
            installed_ver = installed_norm[norm_name]
            if _versions_match(pkg.version, installed_ver):
                report.match_count += 1
            else:
                severity = _assess_drift_severity(pkg.version, installed_ver)
                report.drifts.append(
                    VersionDrift(
                        package_name=pkg.name,
                        ecosystem=ecosystem,
                        declared_version=pkg.version,
                        installed_version=installed_ver,
                        drift_type="version_mismatch",
                        severity=severity,
                        detail=f"Declared {pkg.version} but installed {installed_ver}",
                    )
                )
        else:
            # Declared but not installed — missing dependency
            report.drifts.append(
                VersionDrift(
                    package_name=pkg.name,
                    ecosystem=ecosystem,
                    declared_version=pkg.version,
                    installed_version=None,
                    drift_type="missing",
                    severity="high",
                    detail=f"Declared {pkg.version} but not found in installed packages",
                )
            )

    # Check for undeclared installed packages (only direct deps matter)
    declared_names = set(declared_map.keys())
    for norm_name, installed_ver in installed_norm.items():
        if norm_name not in declared_names:
            report.drifts.append(
                VersionDrift(
                    package_name=norm_name,
                    ecosystem=ecosystem,
                    declared_version=None,
                    installed_version=installed_ver,
                    drift_type="undeclared",
                    severity="medium",
                    detail=f"Installed {installed_ver} but not declared in manifest",
                )
            )

    return report


def _normalize_name(name: str, ecosystem: str) -> str:
    """Normalize package name for cross-source comparison."""
    if ecosystem in ("pypi", "pip"):
        # PEP 503: normalize to lowercase, replace hyphens/underscores/dots
        return name.lower().replace("-", "_").replace(".", "_")
    # npm, go, cargo: case-sensitive, use as-is
    return name


def _versions_match(declared: str, installed: str) -> bool:
    """Check if two version strings are equivalent."""
    if declared == installed:
        return True
    # Strip common prefixes/suffixes
    d = declared.lstrip("v=^~>< ")
    i = installed.lstrip("v=^~>< ")
    return d == i


def _assess_drift_severity(declared: str, installed: str) -> str:
    """Assess severity of a version mismatch.

    - Major version difference → critical (breaking change risk)
    - Minor version difference → high (feature/security gap)
    - Patch version difference → medium (likely bug/security fix)
    - Pre-release / build metadata only → low
    """
    d_parts = _parse_version_parts(declared)
    i_parts = _parse_version_parts(installed)

    if d_parts is None or i_parts is None:
        return "medium"  # Can't compare — assume moderate risk

    d_major, d_minor, d_patch = d_parts
    i_major, i_minor, i_patch = i_parts

    if d_major != i_major:
        return "critical"
    if d_minor != i_minor:
        return "high"
    if d_patch != i_patch:
        return "medium"
    return "low"


def _parse_version_parts(version: str) -> tuple[int, int, int] | None:
    """Extract major.minor.patch from a version string."""
    import re

    clean = version.lstrip("v=^~>< ")
    m = re.match(r"^(\d+)(?:\.(\d+))?(?:\.(\d+))?", clean)
    if not m:
        return None
    major = int(m.group(1))
    minor = int(m.group(2)) if m.group(2) else 0
    patch = int(m.group(3)) if m.group(3) else 0
    return (major, minor, patch)
