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

from agent_bom.evidence.scan_run import ScanIssue
from agent_bom.models import Agent, AgentType, MCPServer, ServerSurface
from agent_bom.traversal import iter_discovery_files

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
    codeowners: dict[str, str] = field(default_factory=dict)
    scan_issues: list[ScanIssue] = field(default_factory=list)


def scan_path_secrets(roots: list[Path] | list[str], *, offline: bool) -> tuple[dict[str, Any], list[ScanIssue]]:
    """Run the CLI's secret scan over each API-submitted root and merge the results.

    One root keeps the scanner's root-relative paths, exactly as ``scan -p``
    reports them. Several roots prefix each path with its root's name so a
    finding still says which submitted tree it came from. Offline scans make
    no live credential-validation calls, matching the CLI.
    """
    from agent_bom.secret_scanner import SecretScanResult, scan_secrets

    merged = SecretScanResult()
    resolved = [Path(root) for root in roots]
    for root in resolved:
        part = scan_secrets(root, aws_live_validation=False) if offline else scan_secrets(root)
        if len(resolved) > 1:
            for finding in part.findings:
                finding.file_path = f"{root.name}/{finding.file_path}"
        merged.findings.extend(part.findings)
        merged.files_scanned += part.files_scanned
        merged.ignored_paths += part.ignored_paths
        merged.pruned_directories += part.pruned_directories
        merged.warnings.extend(part.warnings)
    issues = [
        ScanIssue(
            code="scanner_coverage_gap",
            stage="scanning",
            source="secret-scan",
            message=f"Secret scan incomplete: {warning}",
            affects_coverage=True,
        )
        for warning in merged.warnings
    ]
    return merged.to_dict(), issues


def secret_scan_warning(block: dict[str, Any], *, location: str) -> str:
    """Describe scanner categories without classifying PII as credentials."""
    categories = block.get("by_category", {})
    pii = categories.get("pii", 0)
    secrets = categories.get("credential", 0) + categories.get("secret", 0)
    parts = []
    if secrets:
        parts.append(f"{secrets} secret or credential pattern(s)")
    if pii:
        parts.append(f"{pii} PII pattern(s)")
    return f"{' and '.join(parts) or str(block['total']) + ' finding(s)'} found in {location} files"


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
    for file_path in sorted(iter_discovery_files(project, extra_skip_dirs=_WEAK_CRYPTO_SKIP_DIRS)):
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


def _provenance(source_type: str, source: str, collector: str, confidence: str) -> dict[str, Any]:
    return {"source_type": source_type, "observed_via": [source_type], "source": source, "collector": collector, "confidence": confidence}


def _stamp_provenance(packages: Any, provenance: dict[str, Any]) -> None:
    for pkg in packages:
        if getattr(pkg, "discovery_provenance", None) is None:
            pkg.discovery_provenance = provenance


def _append_skill_agents(skill_result: Any, skill_files: list[Path], agents: list[Agent]) -> None:
    skill_provenance = _provenance("skill_invoked_pull", "skill-files", "skill_scanner", "high")
    if skill_result.servers:
        for server in skill_result.servers:
            _stamp_provenance(getattr(server, "packages", []) or [], skill_provenance)
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
        _stamp_provenance(skill_result.packages, skill_provenance)
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


def _skill_audit_payload(skill_audit: Any) -> dict[str, Any]:
    return {
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


def _scan_skill_stage(
    root: Path, result: RepoTreeScanResult, agents: list[Agent], warnings: list[str], update_progress: Callable[[str], None] | None
) -> None:
    from agent_bom.parsers.skill_audit import audit_skill_result
    from agent_bom.parsers.skills import discover_skill_files, scan_skill_files

    skill_files = discover_skill_files(root)
    if not skill_files:
        return
    if update_progress is not None:
        update_progress(f"Scanning {len(skill_files)} skill/instruction file(s)")
    skill_result = scan_skill_files(skill_files)
    # A successfully read instruction file is itself an auditable security
    # surface. Behavioral risks live in ``raw_content`` and must not be
    # gated on whether inventory extraction happened to find a package,
    # server, or credential reference — a pure prompt-injection or
    # credential-exfiltration file has none of those. The CLI copy of this
    # gate was removed in #4568; this is the same fix for the hosted
    # ``POST /v1/scans`` repo-URL job and the MCP ``scan`` tool.
    if not skill_result.source_files:
        return
    _append_skill_agents(skill_result, skill_files, agents)
    if skill_result.credential_env_vars:
        warnings.append(f"{len(skill_result.credential_env_vars)} credential env var(s) referenced in skill/instruction files")
    skill_audit = audit_skill_result(skill_result)
    result.skill_audit_data = _skill_audit_payload(skill_audit)


def _scan_iac_stage(root: Path, result: RepoTreeScanResult, update_progress: Callable[[str], None] | None) -> None:
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


def _append_dependency_agents(root: Path, dir_map: dict[Any, Any], agents: list[Agent]) -> None:
    dep_provenance = _provenance("repo_lockfile", "repo-lockfiles", "manifest_parser", "high")
    for directory, packages in sorted(dir_map.items(), key=lambda item: str(item[0])):
        rel_path = "." if directory.resolve() == root.resolve() else str(directory.relative_to(root))
        label = "root" if rel_path == "." else rel_path
        _stamp_provenance(packages, dep_provenance)
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


def _scan_dependency_stage(
    root: Path, ai_inventory: dict[str, Any], agents: list[Agent], warnings: list[str], update_progress: Callable[[str], None] | None
) -> None:
    from agent_bom.parsers import scan_project_directory, summarize_project_inventory

    if update_progress is not None:
        update_progress("Parsing lockfiles and dependency manifests (uv.lock, requirements.txt, …)")
    dir_map = scan_project_directory(root, warnings=warnings)
    if not dir_map:
        return
    inventory = summarize_project_inventory(root, dir_map)
    ai_inventory["dependency_inventory"] = inventory
    _append_dependency_agents(root, dir_map, agents)
    if update_progress is not None:
        update_progress(
            f"Parsed {inventory.get('package_count', 0)} package(s) from {inventory.get('manifest_directories', 0)} manifest director"
            f"{'y' if inventory.get('manifest_directories') == 1 else 'ies'}"
        )


def _scan_secrets_stage(
    root: Path,
    result: RepoTreeScanResult,
    ai_inventory: dict[str, Any],
    warnings: list[str],
    update_progress: Callable[[str], None] | None,
    offline: bool,
) -> None:
    if update_progress is not None:
        update_progress("Scanning for secrets, credentials, and PII")
    secrets_block, secret_issues = scan_path_secrets([root], offline=offline)
    # A zero-finding result still records whether discovery actually covered
    # the requested tree. Preserve it through both API report assembly paths.
    ai_inventory["secrets"] = secrets_block
    result.scan_issues.extend(secret_issues)
    if secrets_block["total"] > 0:
        warnings.append(secret_scan_warning(secrets_block, location="repository"))


def _scan_weak_crypto_stage(
    root: Path, ai_inventory: dict[str, Any], warnings: list[str], update_progress: Callable[[str], None] | None
) -> None:
    if update_progress is not None:
        update_progress("Scanning for weak or deprecated cryptography")
    weak_crypto_result = _scan_weak_crypto(root)
    if weak_crypto_result.total > 0:
        ai_inventory["weak_crypto"] = weak_crypto_result.to_dict()
        warnings.append(f"{weak_crypto_result.total} weak-crypto pattern(s) found in repository source files")


def _ai_report_summary(ai_report: Any) -> dict[str, Any]:
    return {
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


def _append_ai_inventory_agent(root: Path, ai_report: Any, agents: list[Agent], package_cls: Any) -> None:
    ai_packages: list[Any] = []
    seen_pkgs: set[str] = set()
    for comp in ai_report.components:
        if comp.package_name and comp.ecosystem:
            pkg_key = f"{comp.ecosystem}:{comp.package_name}"
            if pkg_key not in seen_pkgs:
                seen_pkgs.add(pkg_key)
                ai_packages.append(package_cls(name=comp.package_name, version="latest", ecosystem=comp.ecosystem))
    if not ai_packages:
        return
    ai_provenance = _provenance("ai_inventory", "ai-inventory", "ai_component_scanner", "medium")
    _stamp_provenance(ai_packages, ai_provenance)
    agents.append(
        Agent(
            name="ai-inventory",
            agent_type=AgentType.CUSTOM,
            config_path=str(root),
            source="ai-inventory",
            discovery_provenance=ai_provenance,
            mcp_servers=[MCPServer(name="ai-inventory", surface=ServerSurface.AI_INVENTORY, packages=ai_packages)],
        )
    )


def _scan_ai_inventory_stage(
    root: Path, ai_inventory: dict[str, Any], agents: list[Agent], warnings: list[str], update_progress: Callable[[str], None] | None
) -> None:
    # AI SDK / observability inventory (LangChain, LangGraph, Langfuse, …) —
    # mirrors CLI --project/--repo auto-enable when a Python agent surface exists.
    from agent_bom.repo_auto_detect import project_has_python_agent_surface

    if not project_has_python_agent_surface(root):
        return
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
        ai_inventory.update(_ai_report_summary(ai_report))
        _append_ai_inventory_agent(root, ai_report, agents, Package)
        if ai_report.total:
            warnings.append(
                f"{ai_report.total} AI component(s) inventoried "
                f"({len(ai_report.unique_sdks)} SDK(s), {len(ai_report.framework_agents)} framework agent(s))"
            )
    except Exception:
        pass  # AI inventory must not block repo scans


def _scan_ast_stage(root: Path, ai_inventory: dict[str, Any], update_progress: Callable[[str], None] | None) -> None:
    try:
        from agent_bom.ast_analyzer import analyze_project, project_has_analyzable_sources

        if project_has_analyzable_sources(root):
            if update_progress is not None:
                update_progress("Analyzing source-defined tools and sensitive data flows")
            ast_result = analyze_project(root)
            ai_inventory["ast_analysis"] = ast_result.to_dict()
    except Exception:
        pass  # Native AST analysis is additive and must not block repo scans.


def _scan_jupyter_stage(root: Path, agents: list[Agent], warnings: list[str], update_progress: Callable[[str], None] | None) -> None:
    from agent_bom.jupyter import scan_jupyter_notebooks

    if update_progress is not None:
        update_progress("Scanning Jupyter notebooks (.ipynb) for AI libraries and credentials")
    jupyter_agents, jupyter_warnings = scan_jupyter_notebooks(root)
    if jupyter_agents:
        agents.extend(jupyter_agents)
        if update_progress is not None:
            update_progress(f"Found {len(jupyter_agents)} notebook(s) with AI library usage")
    warnings.extend(jupyter_warnings)


def _append_sast_agent(root: Path, sast_packages: Any, agents: list[Agent]) -> None:
    sast_provenance = _provenance("repo_sast", "sast", "semgrep", "high")
    _stamp_provenance(sast_packages, sast_provenance)
    agents.append(
        Agent(
            name="repo-sast",
            agent_type=AgentType.CUSTOM,
            config_path=str(root),
            mcp_servers=[MCPServer(name=f"sast:{root.name}", surface=ServerSurface.SAST, packages=sast_packages)],
            source="sast",
            discovery_provenance=sast_provenance,
        )
    )


def _sast_scan_error_data(exc: Any, sast_result_cls: Any) -> tuple[dict[str, Any], str]:
    from agent_bom.security import sanitize_error

    known_reason_codes = {
        "invalid_semgrep_output",
        "offline_no_local_config",
        "offline_remote_config",
        "scan_failed",
        "semgrep_failed",
        "semgrep_unavailable",
    }
    reason_code = exc.reason_code if exc.reason_code in known_reason_codes else "scan_failed"
    detail_by_reason = {
        "offline_remote_config": "SAST skipped because offline mode disallows registry-backed rules.",
        "offline_no_local_config": "SAST skipped because offline mode found no local rule configuration.",
        "semgrep_unavailable": "SAST skipped because Semgrep is unavailable on the control plane.",
    }
    status_detail = detail_by_reason.get(reason_code)
    if status_detail is None:
        status_detail = sanitize_error(exc, generic=True)
    data = sast_result_cls(
        execution_status=exc.execution_status,
        status_reason=reason_code,
        status_detail=status_detail,
    ).to_dict()
    return data, reason_code


def _scan_sast_stage(
    root: Path,
    result: RepoTreeScanResult,
    agents: list[Agent],
    warnings: list[str],
    update_progress: Callable[[str], None] | None,
    offline: bool,
) -> None:
    try:
        from agent_bom.sast import SASTResult, SASTScanError, scan_code

        if update_progress is not None:
            update_progress("Running SAST (Semgrep) when available on control plane")
        sast_packages, sast_result = scan_code(str(root), offline=offline)
        result.sast_data = sast_result.to_dict()
        if sast_result.total_findings > 0:
            if sast_packages:
                _append_sast_agent(root, sast_packages, agents)
    except SASTScanError as exc:
        result.sast_data, reason_code = _sast_scan_error_data(exc, SASTResult)
        warnings.append(f"SAST {exc.execution_status.value}: {reason_code}")
    except Exception as exc:  # noqa: BLE001 — repo scans preserve a typed, sanitized partial result
        from agent_bom.sast import SASTExecutionStatus, SASTResult
        from agent_bom.security import sanitize_error

        result.sast_data = SASTResult(
            execution_status=SASTExecutionStatus.FAILED,
            status_reason="unexpected_failure",
            status_detail=sanitize_error(exc, generic=True),
        ).to_dict()
        warnings.append("SAST failed: unexpected_failure")


def scan_cloned_repo_tree(
    cloned_path: str,
    *,
    agents: list[Agent],
    warnings: list[str],
    update_progress: Callable[[str], None] | None = None,
    offline: bool = False,
) -> RepoTreeScanResult:
    """Run static discovery passes on a cloned repository root.

    Surfaces mirror CLI ``--repo`` auto-detect where applicable. Canonical
    inventory: ``agent_bom.repo_auto_detect.repo_static_surface_summary()``.
    """
    root = Path(cloned_path)
    result = RepoTreeScanResult()
    from agent_bom.repo_auto_detect import load_codeowners

    result.codeowners = load_codeowners(root)
    ai_inventory: dict[str, Any] = {}

    _scan_skill_stage(root, result, agents, warnings, update_progress)
    _scan_iac_stage(root, result, update_progress)
    _scan_dependency_stage(root, ai_inventory, agents, warnings, update_progress)
    _scan_secrets_stage(root, result, ai_inventory, warnings, update_progress, offline)
    _scan_weak_crypto_stage(root, ai_inventory, warnings, update_progress)
    _scan_ai_inventory_stage(root, ai_inventory, agents, warnings, update_progress)
    _scan_ast_stage(root, ai_inventory, update_progress)

    if ai_inventory:
        result.ai_inventory_data = ai_inventory

    _scan_jupyter_stage(root, agents, warnings, update_progress)
    _scan_sast_stage(root, result, agents, warnings, update_progress, offline)
    return result
