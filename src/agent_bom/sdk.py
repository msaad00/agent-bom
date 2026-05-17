"""Public Python API for embedding agent-bom in other tools.

This module is intentionally thin: it exposes stable Python functions while
delegating to the same scanner, inventory, and history primitives used by the
CLI and MCP surfaces. It is not a second scan implementation.
"""

from __future__ import annotations

import asyncio
import io
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

from agent_bom.ecosystems import SUPPORTED_PACKAGE_ECOSYSTEM_SET
from agent_bom.finding import Asset, Finding
from agent_bom.mcp_server_runtime import validate_ecosystem
from agent_bom.models import AIBOMReport, Package


class AgentBomSDKError(RuntimeError):
    """Raised when the public Python API cannot complete a requested operation."""


@dataclass(frozen=True)
class PackageCheckResult:
    """Typed result returned by :func:`check` and :func:`async_check`."""

    package: str
    version: str
    ecosystem: str
    status: str
    vulnerabilities: int
    details: list[dict[str, Any]] = field(default_factory=list)
    message: str = ""

    @property
    def is_clean(self) -> bool:
        return self.status == "clean"

    def to_dict(self) -> dict[str, Any]:
        return {
            "package": self.package,
            "version": self.version,
            "ecosystem": self.ecosystem,
            "status": self.status,
            "vulnerabilities": self.vulnerabilities,
            "details": self.details,
            "message": self.message,
        }


@dataclass(frozen=True)
class InventoryResult:
    """Typed inventory wrapper returned by :func:`inventory`."""

    data: dict[str, Any]
    agent_count: int
    server_count: int
    package_count: int

    def to_dict(self) -> dict[str, Any]:
        return {
            "data": self.data,
            "agent_count": self.agent_count,
            "server_count": self.server_count,
            "package_count": self.package_count,
        }


@dataclass(frozen=True)
class DiffResult:
    """Typed report diff wrapper returned by :func:`diff`."""

    data: dict[str, Any]

    @property
    def summary(self) -> dict[str, Any]:
        summary = self.data.get("summary", {})
        return summary if isinstance(summary, dict) else {}

    @property
    def new_findings(self) -> int:
        return int(self.summary.get("new_findings", 0) or 0)

    def to_dict(self) -> dict[str, Any]:
        return self.data


def scan(
    *,
    config_path: str | Path | None = None,
    project: str | Path | None = None,
    demo: bool = False,
    offline: bool = False,
    enrich: bool = False,
    compliance: bool = False,
    transitive: bool = False,
    max_depth: int = 3,
    blast_radius_depth: int = 2,
) -> AIBOMReport:
    """Run the standard local scan pipeline and return a typed report.

    ``project`` and ``config_path`` both point at a local project/config scope.
    The name ``config_path`` is kept for MCP/API users who are already familiar
    with that argument; internally this delegates to the same simple scan runner
    used by CLI commands.
    """

    if project is not None and config_path is not None and Path(project).expanduser() != Path(config_path).expanduser():
        raise ValueError("project and config_path refer to different scan scopes")

    from rich.console import Console

    from agent_bom.cli._scan_runner import ScanConfig, run_default_scan

    output = io.StringIO()
    console = Console(file=output, force_terminal=False, no_color=True, width=120)
    scan_scope = project if project is not None else config_path
    result = run_default_scan(
        ScanConfig(
            project=str(scan_scope) if scan_scope is not None else None,
            demo=demo,
            offline=offline,
            enrich=enrich,
            compliance=compliance,
            resolve_transitive=transitive,
            max_depth=max_depth,
            blast_radius_depth=blast_radius_depth,
            quiet=True,
        ),
        console,
    )
    if result.report is None:
        raise AgentBomSDKError("scan completed without a report")
    return result.report


def _parse_package_spec(spec: str) -> tuple[str, str]:
    cleaned = spec.strip()
    if not cleaned:
        raise ValueError("package must not be empty")
    if "@" in cleaned and not cleaned.startswith("@"):
        name, version = cleaned.rsplit("@", 1)
    elif cleaned.startswith("@") and cleaned.count("@") > 1:
        last_at = cleaned.rindex("@")
        name, version = cleaned[:last_at], cleaned[last_at + 1 :]
    elif "==" in cleaned:
        name, version = cleaned.split("==", 1)
    else:
        name, version = cleaned, "latest"
    name = name.strip()
    version = version.strip() or "latest"
    if not name:
        raise ValueError("package name must not be empty")
    return name, version


def _vulnerability_details(pkg: Package) -> list[dict[str, Any]]:
    return [
        {
            "id": vuln.id,
            "severity": vuln.severity.value,
            "cvss_score": vuln.cvss_score,
            "fixed_version": vuln.fixed_version,
            "summary": vuln.summary or "",
            "compliance_tags": vuln.compliance_tags,
        }
        for vuln in pkg.vulnerabilities
    ]


async def async_check(package: str, *, ecosystem: str = "npm", offline: bool = False) -> PackageCheckResult:
    """Check one package spec and return a typed vulnerability result."""

    eco = validate_ecosystem(ecosystem, SUPPORTED_PACKAGE_ECOSYSTEM_SET)
    name, version = _parse_package_spec(package)
    if eco in {"deb", "apk", "rpm"} and version in {"", "latest"}:
        raise ValueError(f"explicit version required for {eco} packages")

    from agent_bom.scanners import ScanOptions, scan_packages

    pkg = Package(name=name, version=version, ecosystem=eco)
    await scan_packages([pkg], options=ScanOptions(offline=offline))
    details = _vulnerability_details(pkg)
    status = "vulnerable" if details else "clean"
    return PackageCheckResult(
        package=pkg.name,
        version=pkg.version,
        ecosystem=eco,
        status=status,
        vulnerabilities=len(details),
        details=details,
        message=f"No known vulnerabilities in {pkg.name}@{pkg.version}" if status == "clean" else "",
    )


def check(package: str, *, ecosystem: str = "npm", offline: bool = False) -> PackageCheckResult:
    """Synchronous wrapper around :func:`async_check`.

    Async applications should call :func:`async_check` directly to avoid nesting
    event loops.
    """

    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(async_check(package, ecosystem=ecosystem, offline=offline))
    raise AgentBomSDKError("check() cannot run inside an active event loop; use async_check() instead")


def inventory(source: str | Path) -> InventoryResult:
    """Load a JSON/CSV/NDJSON inventory artifact and return typed counts."""

    from agent_bom.inventory import load_inventory

    data = load_inventory(str(source))
    agents = data.get("agents", [])
    agent_count = len(agents) if isinstance(agents, list) else 0
    server_count = 0
    package_count = 0
    if isinstance(agents, list):
        for agent in agents:
            servers = agent.get("mcp_servers", []) if isinstance(agent, dict) else []
            if not isinstance(servers, list):
                continue
            server_count += len(servers)
            for server in servers:
                packages = server.get("packages", []) if isinstance(server, dict) else []
                if isinstance(packages, list):
                    package_count += len(packages)
    return InventoryResult(
        data=data,
        agent_count=agent_count,
        server_count=server_count,
        package_count=package_count,
    )


def _coerce_report_input(value: str | Path | Mapping[str, Any]) -> dict[str, Any]:
    if isinstance(value, Mapping):
        return dict(value)
    from agent_bom.history import load_report_or_sbom

    return load_report_or_sbom(Path(value))


def diff(baseline: str | Path | Mapping[str, Any], current: str | Path | Mapping[str, Any]) -> DiffResult:
    """Diff two agent-bom reports or SBOM documents."""

    from agent_bom.history import diff_reports

    return DiffResult(diff_reports(_coerce_report_input(baseline), _coerce_report_input(current)))


__all__ = [
    "AIBOMReport",
    "AgentBomSDKError",
    "Asset",
    "DiffResult",
    "Finding",
    "InventoryResult",
    "PackageCheckResult",
    "async_check",
    "check",
    "diff",
    "inventory",
    "scan",
]
