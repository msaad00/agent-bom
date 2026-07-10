"""Extra discovery passes for shallow-cloned public repositories.

Static surface inventory is owned by ``agent_bom.repo_auto_detect`` — see
``REPO_STATIC_SURFACES`` and ``repo_static_surface_catalog()`` for the
canonical list shared with CLI ``--project`` / ``--repo`` auto-detect.
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface

_WEAK_CRYPTO_PATTERNS: list[tuple[str, re.Pattern[str], str]] = [
    ("MD5 hash", re.compile(r"\bhashlib\.md5\b|\bMD5\.new\b|\bmd5\s*\(", re.IGNORECASE), "medium"),
    ("SHA-1 hash", re.compile(r"\bhashlib\.sha1\b|\bSHA1\.new\b|\bsha1\s*\(", re.IGNORECASE), "medium"),
    ("DES cipher", re.compile(r"\bDES\.new\b|\bDES3\.new\b|Cipher\.getInstance\s*\(\s*[\"']DES", re.IGNORECASE), "high"),
    ("RC4 cipher", re.compile(r"\bARC4\.new\b|\bRC4\b|\bArcfour\b", re.IGNORECASE), "high"),
    ("Insecure SSL/TLS protocol", re.compile(r"ssl\.PROTOCOL_(?:SSLv2|SSLv23|TLSv1(?:\s|,|\)|$))"), "high"),
    ("ECB block mode", re.compile(r"modes\.ECB\b|/ECB/|MODE_ECB\b", re.IGNORECASE), "medium"),
]

_WEAK_CRYPTO_EXTENSIONS = frozenset({".py", ".js", ".ts", ".jsx", ".tsx", ".go", ".rs", ".java", ".rb", ".php", ".cs"})
_WEAK_CRYPTO_SKIP_DIRS = frozenset(
    {
        ".git",
        "node_modules",
        "__pycache__",
        ".venv",
        "venv",
        "dist",
        "build",
        "site-packages",
        "tests",
        "test",
        "testing",
        "fixtures",
    }
)
_MAX_WEAK_CRYPTO_FILES = 5000


@dataclass
class RepoTreeScanResult:
    skill_audit_data: dict[str, Any] | None = None
    iac_findings_data: dict[str, Any] | None = None
    ai_inventory_data: dict[str, Any] | None = None
    sast_data: dict[str, Any] | None = None


@dataclass
class WeakCryptoFinding:
    file_path: str
    line_number: int
    rule_id: str
    title: str
    severity: str
    message: str

    def to_dict(self) -> dict[str, Any]:
        return {
            "file_path": self.file_path,
            "line_number": self.line_number,
            "rule_id": self.rule_id,
            "title": self.title,
            "severity": self.severity,
            "message": self.message,
            "cwe_ids": ["CWE-327"],
        }


@dataclass
class WeakCryptoScanResult:
    findings: list[WeakCryptoFinding] = field(default_factory=list)
    files_scanned: int = 0

    @property
    def total(self) -> int:
        return len(self.findings)

    def to_dict(self) -> dict[str, Any]:
        return {
            "findings": [finding.to_dict() for finding in self.findings],
            "files_scanned": self.files_scanned,
            "total": self.total,
        }


def _scan_weak_crypto(project: Path) -> WeakCryptoScanResult:
    result = WeakCryptoScanResult()
    if not project.is_dir():
        return result

    file_count = 0
    for file_path in sorted(project.rglob("*")):
        if not file_path.is_file():
            continue
        if any(part in _WEAK_CRYPTO_SKIP_DIRS for part in file_path.parts):
            continue
        if file_path.name.startswith("test_") or file_path.name.endswith("_test.py"):
            continue
        if file_path.suffix.lower() not in _WEAK_CRYPTO_EXTENSIONS:
            continue
        if file_count >= _MAX_WEAK_CRYPTO_FILES:
            break
        file_count += 1

        try:
            lines = file_path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            continue

        rel_path = str(file_path.relative_to(project))
        for line_num, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#") or stripped.startswith("//"):
                continue
            for title, pattern, severity in _WEAK_CRYPTO_PATTERNS:
                if pattern.search(line):
                    result.findings.append(
                        WeakCryptoFinding(
                            file_path=rel_path,
                            line_number=line_num,
                            rule_id=f"CRYPTO-{title.upper().replace(' ', '-')}",
                            title=title,
                            severity=severity,
                            message=f"Potential use of weak or deprecated cryptography: {title}",
                        )
                    )
                    break

    result.files_scanned = file_count
    return result


def scan_cloned_repo_tree(
    cloned_path: str,
    *,
    agents: list[Agent],
    warnings: list[str],
    update_progress: Callable[[str], None] | None = None,
) -> RepoTreeScanResult:
    """Run static discovery passes on a cloned repository root.

    Surfaces mirror CLI ``--repo`` auto-detect where applicable. Canonical
    inventory: ``agent_bom.repo_auto_detect.repo_static_surface_summary()``.
    """
    root = Path(cloned_path)
    result = RepoTreeScanResult()
    ai_inventory: dict[str, Any] = {}

    from agent_bom.parsers.skill_audit import audit_skill_result
    from agent_bom.parsers.skills import discover_skill_files, scan_skill_files

    skill_files = discover_skill_files(root)
    if skill_files:
        if update_progress is not None:
            update_progress(f"Scanning {len(skill_files)} skill/instruction file(s)")
        skill_result = scan_skill_files(skill_files)
        if skill_result.servers or skill_result.packages or skill_result.credential_env_vars:
            skill_provenance = {
                "source_type": "skill_invoked_pull",
                "observed_via": ["skill_invoked_pull"],
                "source": "skill-files",
                "collector": "skill_scanner",
                "confidence": "high",
            }
            if skill_result.servers:
                for server in skill_result.servers:
                    for pkg in getattr(server, "packages", []) or []:
                        if getattr(pkg, "discovery_provenance", None) is None:
                            pkg.discovery_provenance = skill_provenance
                agents.append(
                    Agent(
                        name="skill-files",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(skill_files[0]),
                        mcp_servers=skill_result.servers,
                        source="skill-files",
                        discovery_provenance=skill_provenance,
                    )
                )
            if skill_result.packages:
                for pkg in skill_result.packages:
                    if getattr(pkg, "discovery_provenance", None) is None:
                        pkg.discovery_provenance = skill_provenance
                agents.append(
                    Agent(
                        name="skill-packages",
                        agent_type=AgentType.CUSTOM,
                        config_path=", ".join(str(path) for path in skill_files[:3]),
                        mcp_servers=[MCPServer(name="skill-packages", command="(from skill files)", packages=skill_result.packages)],
                        source="skill-files",
                        discovery_provenance=skill_provenance,
                    )
                )
            if skill_result.credential_env_vars:
                warnings.append(
                    f"{len(skill_result.credential_env_vars)} credential env var(s) referenced in skill/instruction files"
                )
            skill_audit = audit_skill_result(skill_result)
            result.skill_audit_data = {
                "findings": [
                    {
                        "severity": finding.severity,
                        "category": finding.category,
                        "title": finding.title,
                        "detail": finding.detail,
                        "source_file": finding.source_file,
                        "package": finding.package,
                        "server": finding.server,
                        "recommendation": finding.recommendation,
                        "context": finding.context,
                    }
                    for finding in skill_audit.findings
                ],
                "packages_checked": skill_audit.packages_checked,
                "servers_checked": skill_audit.servers_checked,
                "credentials_checked": skill_audit.credentials_checked,
                "passed": skill_audit.passed,
            }

    from agent_bom.iac import scan_iac_with_context
    from agent_bom.iac.models import ScanContext as IaCContext

    if update_progress is not None:
        update_progress("Scanning IaC and cloud config files")
    iac_result = scan_iac_with_context(root, IaCContext(deployment_mode="standalone"))
    if iac_result.findings:
        result.iac_findings_data = {
            "total": len(iac_result.findings),
            "findings": [
                {
                    "rule_id": finding.rule_id,
                    "severity": finding.severity,
                    "title": finding.title,
                    "message": finding.message,
                    "file_path": finding.file_path,
                    "line_number": finding.line_number,
                    "category": finding.category,
                    "compliance": finding.compliance,
                    "attack_techniques": finding.attack_techniques,
                    "remediation": finding.remediation,
                }
                for finding in iac_result.findings
            ],
        }

    from agent_bom.parsers import scan_project_directory, summarize_project_inventory

    if update_progress is not None:
        update_progress("Parsing lockfiles and dependency manifests (uv.lock, requirements.txt, …)")
    dir_map = scan_project_directory(root, warnings=warnings)
    if dir_map:
        inventory = summarize_project_inventory(root, dir_map)
        ai_inventory["dependency_inventory"] = inventory
        dep_provenance = {
            "source_type": "repo_lockfile",
            "observed_via": ["repo_lockfile"],
            "source": "repo-lockfiles",
            "collector": "manifest_parser",
            "confidence": "high",
        }
        for directory, packages in sorted(dir_map.items(), key=lambda item: str(item[0])):
            rel_path = "." if directory.resolve() == root.resolve() else str(directory.relative_to(root))
            label = "root" if rel_path == "." else rel_path
            for pkg in packages:
                if getattr(pkg, "discovery_provenance", None) is None:
                    pkg.discovery_provenance = dep_provenance
            server = MCPServer(name=f"repo-deps:{label}", surface=ServerSurface.FILESYSTEM, packages=packages)
            agents.append(
                Agent(
                    name=f"repo-deps:{label}",
                    agent_type=AgentType.CUSTOM,
                    config_path=str(directory),
                    mcp_servers=[server],
                    source="repo-lockfiles",
                    discovery_provenance=dep_provenance,
                )
            )
        if update_progress is not None:
            update_progress(
                f"Parsed {inventory.get('package_count', 0)} package(s) from {inventory.get('manifest_directories', 0)} manifest director"
                f"{'y' if inventory.get('manifest_directories') == 1 else 'ies'}"
            )

    from agent_bom.secret_scanner import scan_secrets

    if update_progress is not None:
        update_progress("Scanning for hardcoded secrets and credentials")
    secret_result = scan_secrets(root)
    if secret_result.total > 0:
        ai_inventory["secrets"] = secret_result.to_dict()
        warnings.append(f"{secret_result.total} hardcoded secret(s) or credential pattern(s) found in repository files")

    if update_progress is not None:
        update_progress("Scanning for weak or deprecated cryptography")
    weak_crypto_result = _scan_weak_crypto(root)
    if weak_crypto_result.total > 0:
        ai_inventory["weak_crypto"] = weak_crypto_result.to_dict()
        warnings.append(f"{weak_crypto_result.total} weak-crypto pattern(s) found in repository source files")

    # AI SDK / observability inventory (LangChain, LangGraph, Langfuse, …) —
    # mirrors CLI --project/--repo auto-enable when a Python agent surface exists.
    from agent_bom.repo_auto_detect import project_has_python_agent_surface

    if project_has_python_agent_surface(root):
        try:
            from agent_bom.ai_components import scan_source
            from agent_bom.models import Package

            if update_progress is not None:
                update_progress("Scanning for AI SDK / observability imports")
            manifest_pkgs: set[str] = set()
            for agent in agents:
                for server in agent.mcp_servers:
                    for pkg in server.packages:
                        manifest_pkgs.add(pkg.name)
            ai_report = scan_source(str(root), manifest_packages=manifest_pkgs)
            ai_inventory.update(
                {
                    "total_components": ai_report.total,
                    "shadow_ai_count": len(ai_report.shadow_ai),
                    "deprecated_models_count": len(ai_report.deprecated_models),
                    "api_keys_count": len(ai_report.api_keys),
                    "unique_sdks": sorted(ai_report.unique_sdks),
                    "unique_models": sorted(ai_report.unique_models),
                    "files_scanned": ai_report.files_scanned,
                    "framework_agents": list(ai_report.framework_agents),
                    "components": [
                        {
                            "type": c.component_type.value,
                            "name": "[REDACTED]" if c.component_type.value == "api_key" else c.name,
                            "language": c.language,
                            "file": c.file_path,
                            "line": c.line_number,
                            "severity": c.severity.value,
                            "is_shadow": c.is_shadow,
                            "package": c.package_name,
                            "ecosystem": c.ecosystem,
                            "description": c.description,
                            "deprecated_replacement": c.deprecated_replacement,
                        }
                        for c in ai_report.components
                    ],
                }
            )
            ai_packages: list[Package] = []
            seen_pkgs: set[str] = set()
            for comp in ai_report.components:
                if comp.package_name and comp.ecosystem:
                    pkg_key = f"{comp.ecosystem}:{comp.package_name}"
                    if pkg_key not in seen_pkgs:
                        seen_pkgs.add(pkg_key)
                        ai_packages.append(
                            Package(name=comp.package_name, version="latest", ecosystem=comp.ecosystem)
                        )
            if ai_packages:
                ai_provenance = {
                    "source_type": "ai_inventory",
                    "observed_via": ["ai_inventory"],
                    "source": "ai-inventory",
                    "collector": "ai_component_scanner",
                    "confidence": "medium",
                }
                for pkg in ai_packages:
                    if getattr(pkg, "discovery_provenance", None) is None:
                        pkg.discovery_provenance = ai_provenance
                agents.append(
                    Agent(
                        name="ai-inventory",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(root),
                        source="ai-inventory",
                        discovery_provenance=ai_provenance,
                        mcp_servers=[
                            MCPServer(
                                name="ai-inventory",
                                surface=ServerSurface.AI_INVENTORY,
                                packages=ai_packages,
                            )
                        ],
                    )
                )
            if ai_report.total:
                warnings.append(
                    f"{ai_report.total} AI component(s) inventoried "
                    f"({len(ai_report.unique_sdks)} SDK(s), {len(ai_report.framework_agents)} framework agent(s))"
                )
        except Exception:
            pass  # AI inventory must not block repo scans

    if ai_inventory:
        result.ai_inventory_data = ai_inventory

    from agent_bom.jupyter import scan_jupyter_notebooks

    if update_progress is not None:
        update_progress("Scanning Jupyter notebooks (.ipynb) for AI libraries and credentials")
    jupyter_agents, jupyter_warnings = scan_jupyter_notebooks(root)
    if jupyter_agents:
        agents.extend(jupyter_agents)
        if update_progress is not None:
            update_progress(f"Found {len(jupyter_agents)} notebook(s) with AI library usage")
    warnings.extend(jupyter_warnings)

    try:
        from agent_bom.sast import SASTScanError, scan_code

        if update_progress is not None:
            update_progress("Running SAST (Semgrep) when available on control plane")
        sast_packages, sast_result = scan_code(str(root))
        if sast_result.total_findings > 0:
            result.sast_data = sast_result.to_dict()
            if sast_packages:
                sast_provenance = {
                    "source_type": "repo_sast",
                    "observed_via": ["repo_sast"],
                    "source": "sast",
                    "collector": "semgrep",
                    "confidence": "high",
                }
                for pkg in sast_packages:
                    if getattr(pkg, "discovery_provenance", None) is None:
                        pkg.discovery_provenance = sast_provenance
                agents.append(
                    Agent(
                        name="repo-sast",
                        agent_type=AgentType.CUSTOM,
                        config_path=str(root),
                        mcp_servers=[
                            MCPServer(
                                name=f"sast:{root.name}",
                                surface=ServerSurface.SAST,
                                packages=sast_packages,
                            )
                        ],
                        source="sast",
                        discovery_provenance=sast_provenance,
                    )
                )
    except SASTScanError:
        pass  # Semgrep not installed — optional on control plane
    except Exception:
        pass  # SAST must not block repo scans

    return result
