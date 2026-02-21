"""Security auditor for skill file scan results.

Cross-references extracted packages and MCP servers against the bundled
MCP registry to detect typosquatting, unverified servers, shell access,
excessive credentials, and external URL data-exfiltration risks.
"""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from difflib import SequenceMatcher
from pathlib import Path

from agent_bom.models import TransportType
from agent_bom.parsers.skills import SkillScanResult

logger = logging.getLogger(__name__)

# ── Registry loader ──────────────────────────────────────────────────────────


def _load_registry() -> dict:
    """Load the bundled MCP registry keyed by package name."""
    registry_path = Path(__file__).parent.parent / "mcp_registry.json"
    if not registry_path.exists():
        return {}
    try:
        data = json.loads(registry_path.read_text())
        servers = data.get("servers", {})
        # Handle both dict-keyed and list-based registry formats
        if isinstance(servers, dict):
            return servers
        # If it were a list, key by package name
        return {entry["package"]: entry for entry in servers}
    except Exception:
        return {}


# ── Data structures ──────────────────────────────────────────────────────────


@dataclass
class SkillFinding:
    """A single security finding from the skill audit."""

    severity: str  # "critical" | "high" | "medium" | "low"
    category: str  # typosquat | unverified_server | excessive_permissions | shell_access | unknown_package | dangerous_tool | external_url
    title: str
    detail: str
    source_file: str
    package: str | None = None
    server: str | None = None
    recommendation: str = ""


@dataclass
class SkillAuditResult:
    """Aggregated result of the skill security audit."""

    findings: list[SkillFinding] = field(default_factory=list)
    packages_checked: int = 0
    servers_checked: int = 0
    credentials_checked: int = 0
    passed: bool = True  # no critical/high findings


# ── Shell / dangerous keywords ───────────────────────────────────────────────

_SHELL_COMMANDS = {"sh", "bash", "cmd", "powershell", "zsh"}

_DANGEROUS_ARG_KEYWORDS = {
    "--allow-exec", "exec", "shell", "--dangerous", "--yolo",
}

_DANGEROUS_SERVER_NAME_KEYWORDS = {"exec", "shell", "terminal", "command"}

# ── Main audit function ─────────────────────────────────────────────────────


def audit_skill_result(result: SkillScanResult) -> SkillAuditResult:
    """Run all security checks against a parsed skill scan result.

    Checks performed:
      1. Typosquat detection (HIGH)
      2. Unverified MCP server (MEDIUM)
      3. Unknown package (LOW)
      4. Shell/exec access (HIGH)
      5. Dangerous server names (HIGH)
      6. Excessive credential exposure (MEDIUM)
      7. External URL / data exfiltration (MEDIUM)
    """
    registry = _load_registry()
    audit = SkillAuditResult()
    source_file = result.source_files[0] if result.source_files else "unknown"

    # ── 1-3: Package checks ──────────────────────────────────────────────
    audit.packages_checked = len(result.packages)

    registry_names = list(registry.keys())

    for pkg in result.packages:
        _check_package(pkg, registry, registry_names, source_file, audit)

    # ── 4-5, 7: Server checks ───────────────────────────────────────────
    audit.servers_checked = len(result.servers)

    for srv in result.servers:
        _check_server(srv, registry, source_file, audit)

    # ── 6: Credential checks ────────────────────────────────────────────
    audit.credentials_checked = len(result.credential_env_vars)

    if len(result.credential_env_vars) >= 8:
        audit.findings.append(SkillFinding(
            severity="medium",
            category="excessive_permissions",
            title="Excessive credential exposure across skill files",
            detail=(
                f"{len(result.credential_env_vars)} credential env vars detected: "
                f"{', '.join(result.credential_env_vars[:10])}"
                f"{'...' if len(result.credential_env_vars) > 10 else ''}"
            ),
            source_file=source_file,
            recommendation="Reduce the number of credentials or scope them to individual servers.",
        ))

    # Also check per-server credential density
    for srv in result.servers:
        env_count = len(srv.env)
        if env_count >= 5:
            audit.findings.append(SkillFinding(
                severity="medium",
                category="excessive_permissions",
                title=f"Server '{srv.name}' has {env_count} env vars configured",
                detail=(
                    f"MCP server '{srv.name}' has {env_count} environment variables, "
                    "which may indicate over-provisioned access."
                ),
                source_file=source_file,
                server=srv.name,
                recommendation="Review env vars and remove any that are not strictly required.",
            ))

    # ── Final pass/fail ──────────────────────────────────────────────────
    audit.passed = not any(
        f.severity in ("critical", "high") for f in audit.findings
    )

    return audit


# ── Per-package checks ───────────────────────────────────────────────────────


def _check_package(
    pkg,
    registry: dict,
    registry_names: list[str],
    source_file: str,
    audit: SkillAuditResult,
) -> None:
    """Run checks 1-3 against a single package."""
    name = pkg.name

    # Exact match in registry — nothing to flag for typosquat/unknown
    if name in registry:
        return

    # Check for typosquat (fuzzy match)
    best_ratio = 0.0
    best_match = ""
    for reg_name in registry_names:
        ratio = SequenceMatcher(None, name.lower(), reg_name.lower()).ratio()
        if ratio > best_ratio:
            best_ratio = ratio
            best_match = reg_name

    if best_ratio >= 0.80:
        # Close but not exact — possible typosquat
        audit.findings.append(SkillFinding(
            severity="high",
            category="typosquat",
            title=f"Possible typosquat: '{name}'",
            detail=(
                f"Package '{name}' is {best_ratio:.0%} similar to known registry "
                f"entry '{best_match}'. This could be a typosquat attack."
            ),
            source_file=source_file,
            package=name,
            recommendation=f"Verify the package name. Did you mean '{best_match}'?",
        ))
    else:
        # No close match at all — unknown package
        audit.findings.append(SkillFinding(
            severity="low",
            category="unknown_package",
            title=f"Unknown package: '{name}'",
            detail=(
                f"Package '{name}' was not found in the MCP registry and has no "
                "close fuzzy match. It may be legitimate but cannot be verified."
            ),
            source_file=source_file,
            package=name,
            recommendation="Verify the package source and maintainer before trusting it.",
        ))


# ── Per-server checks ───────────────────────────────────────────────────────


def _check_server(
    srv,
    registry: dict,
    source_file: str,
    audit: SkillAuditResult,
) -> None:
    """Run checks 2, 4-5, and 7 against a single MCP server."""
    # ── Check 4: Shell/exec access via command ───────────────────────────
    cmd_base = srv.command.rsplit("/", 1)[-1].lower() if srv.command else ""
    if cmd_base in _SHELL_COMMANDS:
        audit.findings.append(SkillFinding(
            severity="high",
            category="shell_access",
            title=f"Shell access via server '{srv.name}'",
            detail=(
                f"Server '{srv.name}' uses shell command '{srv.command}', "
                "which grants arbitrary code execution."
            ),
            source_file=source_file,
            server=srv.name,
            recommendation="Avoid using raw shell commands. Use a purpose-built MCP server instead.",
        ))

    # ── Check 4b: Shell/exec access via args ─────────────────────────────
    args_lower = [a.lower() for a in srv.args]
    matched_args = [
        a for a in args_lower
        if any(kw in a for kw in _DANGEROUS_ARG_KEYWORDS)
    ]
    if matched_args:
        audit.findings.append(SkillFinding(
            severity="high",
            category="shell_access",
            title=f"Dangerous arguments on server '{srv.name}'",
            detail=(
                f"Server '{srv.name}' has arguments containing dangerous keywords: "
                f"{', '.join(matched_args)}"
            ),
            source_file=source_file,
            server=srv.name,
            recommendation="Remove dangerous flags or use a sandboxed execution environment.",
        ))

    # ── Check 5: Dangerous server name ───────────────────────────────────
    name_lower = srv.name.lower()
    matched_name_keywords = [
        kw for kw in _DANGEROUS_SERVER_NAME_KEYWORDS if kw in name_lower
    ]
    if matched_name_keywords:
        audit.findings.append(SkillFinding(
            severity="high",
            category="shell_access",
            title=f"Server name suggests dangerous capabilities: '{srv.name}'",
            detail=(
                f"Server name '{srv.name}' contains keywords suggesting "
                f"execution capabilities: {', '.join(matched_name_keywords)}"
            ),
            source_file=source_file,
            server=srv.name,
            recommendation="Review the server's actual capabilities and restrict if possible.",
        ))

    # ── Check 2: Unverified MCP server ───────────────────────────────────
    matched_entry = _match_server_to_registry(srv, registry)
    if matched_entry is None:
        audit.findings.append(SkillFinding(
            severity="medium",
            category="unverified_server",
            title=f"MCP server not found in registry: '{srv.name}'",
            detail=(
                f"Server '{srv.name}' (command: '{srv.command}') does not match "
                "any entry in the MCP registry."
            ),
            source_file=source_file,
            server=srv.name,
            recommendation="Verify the server source and add it to the registry if trustworthy.",
        ))
    elif not matched_entry.get("verified", False):
        audit.findings.append(SkillFinding(
            severity="medium",
            category="unverified_server",
            title=f"Unverified MCP server: '{srv.name}'",
            detail=(
                f"Server '{srv.name}' matches registry entry "
                f"'{matched_entry.get('package', '?')}' but is marked as unverified."
            ),
            source_file=source_file,
            server=srv.name,
            recommendation="Review the server source code before trusting it in production.",
        ))

    # ── Check 7: External URL ────────────────────────────────────────────
    if srv.transport in (TransportType.SSE, TransportType.STREAMABLE_HTTP) and srv.url:
        url_lower = srv.url.lower()
        is_local = any(
            local in url_lower
            for local in ("localhost", "127.0.0.1", "[::1]", "0.0.0.0")
        )
        if not is_local:
            audit.findings.append(SkillFinding(
                severity="medium",
                category="external_url",
                title=f"External URL on server '{srv.name}'",
                detail=(
                    f"Server '{srv.name}' connects to external URL '{srv.url}'. "
                    "Data sent to this server may leave your network."
                ),
                source_file=source_file,
                server=srv.name,
                recommendation="Ensure the remote endpoint is trusted and traffic is encrypted.",
            ))


def _match_server_to_registry(srv, registry: dict) -> dict | None:
    """Try to match an MCP server to a registry entry.

    Matches on command_patterns or package name appearing in the server's
    command or args.
    """
    candidates = [srv.name, srv.command] + srv.args

    for _pkg_name, entry in registry.items():
        patterns = entry.get("command_patterns", [entry.get("package", "")])
        pkg_name = entry.get("package", "")
        for candidate in candidates:
            if not candidate:
                continue
            # Check command_patterns
            for pattern in patterns:
                if pattern and pattern in candidate:
                    return entry
            # Check package name
            if pkg_name and pkg_name in candidate:
                return entry
    return None
