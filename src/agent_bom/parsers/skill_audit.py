"""Security auditor for skill file scan results.

Cross-references extracted packages and MCP servers against the bundled
MCP registry to detect typosquatting, unverified servers, shell access,
excessive credentials, and external URL data-exfiltration risks.

Packages not in the MCP registry are dynamically verified against
PyPI/npm before flagging as unknown (reduces false positives).
"""

from __future__ import annotations

import asyncio
import json
import logging
import re
from difflib import SequenceMatcher
from pathlib import Path
from typing import Optional

from agent_bom.models import TransportType
from agent_bom.parsers.skill_audit_behavior import (
    _DANGEROUS_ARG_KEYWORDS,
    _DANGEROUS_SERVER_NAME_KEYWORDS,
    _SHELL_COMMANDS,
    _scan_behavioral_risks,
    _scan_js_ts_semantic_risks,
    _scan_python_ast_risks,
    _summarize_behavioral_findings,
)
from agent_bom.parsers.skill_audit_types import SkillAuditResult, SkillFinding
from agent_bom.parsers.skills import SkillMetadata, SkillScanResult
from agent_bom.security import sanitize_url

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


# ── Dynamic package verification ─────────────────────────────────────────────

NPM_REGISTRY = "https://registry.npmjs.org"
PYPI_API = "https://pypi.org/pypi"


async def _verify_package_exists(name: str, ecosystem: str) -> Optional[bool]:
    """Check if a package exists on its ecosystem registry.

    Returns True if found, False if confirmed not-found, None on error.
    """
    from agent_bom.http_client import create_client, request_with_retry

    if ecosystem == "pypi":
        url = f"{PYPI_API}/{name}/json"
    elif ecosystem == "npm":
        encoded = name.replace("/", "%2F")
        url = f"{NPM_REGISTRY}/{encoded}/latest"
    else:
        return None

    try:
        async with create_client(timeout=5.0) as client:
            resp = await request_with_retry(client, "GET", url, max_retries=1)
            if resp is None:
                return None
            return resp.status_code == 200
    except Exception:
        return None


async def _batch_verify_packages(
    packages: list[tuple[str, str]],
) -> dict[str, bool]:
    """Verify multiple (name, ecosystem) pairs concurrently.

    Returns ``{name: True/False}``. Packages that error default to True
    (fail-open — don't flag if we can't verify).
    """
    if not packages:
        return {}

    results: dict[str, bool] = {}
    sem = asyncio.Semaphore(20)

    async def _check(name: str, eco: str) -> None:
        async with sem:
            found = await _verify_package_exists(name, eco)
            # fail-open: treat network errors as "exists" to avoid false flags
            results[name] = found if found is not None else True

    await asyncio.gather(*[_check(n, e) for n, e in packages])
    return results


def _batch_verify_packages_sync(
    packages: list[tuple[str, str]],
) -> dict[str, bool]:
    """Sync wrapper for ``_batch_verify_packages``."""
    return asyncio.run(_batch_verify_packages(packages))


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

    # Batch-verify packages not in the MCP registry against PyPI/npm
    unregistered = [(pkg.name, pkg.ecosystem) for pkg in result.packages if pkg.name not in registry]
    verified: dict[str, bool] = {}
    if unregistered:
        try:
            verified = _batch_verify_packages_sync(unregistered)
        except Exception:
            logger.debug("Package verification failed, falling back to registry-only")

    for pkg in result.packages:
        _check_package(pkg, registry, registry_names, source_file, audit, verified)

    # ── 4-5, 7: Server checks ───────────────────────────────────────────
    audit.servers_checked = len(result.servers)

    for srv in result.servers:
        _check_server(srv, registry, source_file, audit)

    # ── 6: Credential checks ────────────────────────────────────────────
    audit.credentials_checked = len(result.credential_env_vars)

    if len(result.credential_env_vars) >= 8:
        audit.findings.append(
            SkillFinding(
                severity="medium",
                category="excessive_permissions",
                title="Excessive credential exposure across skill files",
                detail=(
                    f"{len(result.credential_env_vars)} credential env vars referenced "
                    f"across skill files: "
                    f"{', '.join(result.credential_env_vars[:10])}"
                    f"{'...' if len(result.credential_env_vars) > 10 else ''}"
                ),
                source_file=source_file,
                recommendation="Reduce the number of credentials or scope them to individual servers.",
                context="env_reference",
            )
        )

    # Also check per-server credential density
    for srv in result.servers:
        env_count = len(srv.env)
        if env_count >= 5:
            audit.findings.append(
                SkillFinding(
                    severity="medium",
                    category="excessive_permissions",
                    title=f"Server '{srv.name}' has {env_count} env vars configured",
                    detail=(
                        f"MCP server config '{srv.name}' (from JSON block in {source_file}) "
                        f"has {env_count} environment variables, "
                        "which may indicate over-provisioned access."
                    ),
                    source_file=source_file,
                    server=srv.name,
                    recommendation="Review env vars and remove any that are not strictly required.",
                    context="config_block",
                )
            )

    # ── Behavioral risk patterns ────────────────────────────────────────
    if result.raw_content:
        behavioral_findings = _scan_behavioral_risks(result.raw_content)
        audit.findings.extend(behavioral_findings)
        audit.findings.extend(_scan_python_ast_risks(result.raw_content))
        audit.findings.extend(_scan_js_ts_semantic_risks(result.raw_content))

    # ── Metadata quality checks (SKILL.md frontmatter) ───────────────
    if result.metadata is not None:
        metadata_findings = _check_metadata_quality(result.metadata, result.raw_content, source_file)
        audit.findings.extend(metadata_findings)

    # ── Final pass/fail ──────────────────────────────────────────────────
    audit.behavioral_summary = _summarize_behavioral_findings(audit.findings)
    audit.passed = not any(f.severity in ("critical", "high") for f in audit.findings)

    return audit


# ── Per-package checks ───────────────────────────────────────────────────────


def _check_package(
    pkg,
    registry: dict,
    registry_names: list[str],
    source_file: str,
    audit: SkillAuditResult,
    verified: dict[str, bool] | None = None,
) -> None:
    """Run checks 1-3 against a single package.

    *verified* is a dict of ``{name: True/False}`` from dynamic PyPI/npm
    verification.  Packages verified as existing on their registry are
    silently skipped (not flagged as unknown).
    """
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
        audit.findings.append(
            SkillFinding(
                severity="high",
                category="typosquat",
                title=f"Possible typosquat: '{name}'",
                detail=(
                    f"Package '{name}' (extracted from a code block in {source_file}) "
                    f"is {best_ratio:.0%} similar to known registry entry '{best_match}'. "
                    "This could be a typosquat attack."
                ),
                source_file=source_file,
                package=name,
                recommendation=f"Verify the package name. Did you mean '{best_match}'?",
                context="code_block",
            )
        )
    else:
        # Dynamically verified as a real package on PyPI/npm — skip
        if verified and verified.get(name):
            return

        # Not in registry AND not found on PyPI/npm — flag as unknown
        audit.findings.append(
            SkillFinding(
                severity="low",
                category="unknown_package",
                title=f"Unknown package: '{name}'",
                detail=(
                    f"Package '{name}' (extracted from a code block in {source_file}) "
                    "was not found in the MCP registry or on "
                    f"{'PyPI' if pkg.ecosystem == 'pypi' else 'npm'}. "
                    "It may be a typo or a private package."
                ),
                source_file=source_file,
                package=name,
                recommendation="Verify the package source and maintainer before trusting it.",
                context="code_block",
            )
        )


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
        audit.findings.append(
            SkillFinding(
                severity="high",
                category="shell_access",
                title=f"Shell access via server '{srv.name}'",
                detail=(
                    f"MCP server config '{srv.name}' (from JSON block in {source_file}) "
                    f"uses shell command '{srv.command}', "
                    "which grants arbitrary code execution."
                ),
                source_file=source_file,
                server=srv.name,
                recommendation="Avoid using raw shell commands. Use a purpose-built MCP server instead.",
                context="config_block",
            )
        )

    # ── Check 4b: Shell/exec access via args ─────────────────────────────
    args_lower = [a.lower() for a in srv.args]
    matched_args = [a for a in args_lower if any(kw in a for kw in _DANGEROUS_ARG_KEYWORDS)]
    if matched_args:
        audit.findings.append(
            SkillFinding(
                severity="high",
                category="shell_access",
                title=f"Dangerous arguments on server '{srv.name}'",
                detail=(
                    f"MCP server config '{srv.name}' (from JSON block in {source_file}) "
                    f"has arguments containing dangerous keywords: "
                    f"{', '.join(matched_args)}"
                ),
                source_file=source_file,
                server=srv.name,
                recommendation="Remove dangerous flags or use a sandboxed execution environment.",
                context="config_block",
            )
        )

    # ── Check 5: Dangerous server name ───────────────────────────────────
    name_lower = srv.name.lower()
    matched_name_keywords = [kw for kw in _DANGEROUS_SERVER_NAME_KEYWORDS if kw in name_lower]
    if matched_name_keywords:
        audit.findings.append(
            SkillFinding(
                severity="high",
                category="shell_access",
                title=f"Server name suggests dangerous capabilities: '{srv.name}'",
                detail=(
                    f"MCP server '{srv.name}' (from JSON block in {source_file}) "
                    f"has a name containing keywords suggesting "
                    f"execution capabilities: {', '.join(matched_name_keywords)}"
                ),
                source_file=source_file,
                server=srv.name,
                recommendation="Review the server's actual capabilities and restrict if possible.",
                context="config_block",
            )
        )

    # ── Check 2: Unverified MCP server ───────────────────────────────────
    matched_entry = _match_server_to_registry(srv, registry)
    if matched_entry is None:
        audit.findings.append(
            SkillFinding(
                severity="medium",
                category="unverified_server",
                title=f"MCP server not found in registry: '{srv.name}'",
                detail=(
                    f"MCP server config '{srv.name}' (command: '{srv.command}') "
                    f"from {source_file} does not match any entry in the MCP registry."
                ),
                source_file=source_file,
                server=srv.name,
                recommendation="Verify the server source and add it to the registry if trustworthy.",
                context="config_block",
            )
        )
    elif not matched_entry.get("verified", False):
        audit.findings.append(
            SkillFinding(
                severity="medium",
                category="unverified_server",
                title=f"Unverified MCP server: '{srv.name}'",
                detail=(
                    f"MCP server config '{srv.name}' from {source_file} matches "
                    f"registry entry '{matched_entry.get('package', '?')}' but is "
                    "marked as unverified."
                ),
                source_file=source_file,
                server=srv.name,
                recommendation="Review the server source code before trusting it in production.",
                context="config_block",
            )
        )

    # ── Check 7: External URL ────────────────────────────────────────────
    if srv.transport in (TransportType.SSE, TransportType.STREAMABLE_HTTP) and srv.url:
        url_lower = srv.url.lower()
        is_local = any(
            local in url_lower
            for local in ("localhost", "127.0.0.1", "[::1]", "0.0.0.0")  # nosec B104 — checking URLs, not binding
        )
        if not is_local:
            audit.findings.append(
                SkillFinding(
                    severity="medium",
                    category="external_url",
                    title=f"External URL on server '{srv.name}'",
                    detail=(
                        f"MCP server config '{srv.name}' (from JSON block in {source_file}) "
                        f"connects to external URL '{sanitize_url(srv.url)}'. "
                        "Data sent to this server may leave your network."
                    ),
                    source_file=source_file,
                    server=srv.name,
                    recommendation="Ensure the remote endpoint is trusted and traffic is encrypted.",
                    context="config_block",
                )
            )


# ── Metadata quality checks ──────────────────────────────────────────────────

# Commands that imply runtime dependencies needing declaration
_RUNTIME_DEP_PATTERNS: dict[str, list[str]] = {
    "docker": [r"\bdocker\b", r"--image\b", r"\bcontainer\b"],
    "grype": [r"\bgrype\b", r"\bsyft\b"],
    "kubectl": [r"\bkubectl\b", r"\bk8s\b", r"\bkubernetes\b"],
    "terraform": [r"\bterraform\b", r"\btf\b"],
    "helm": [r"\bhelm\b"],
}

_REQUIRED_CAPABILITY_KEYS = {
    "read_findings",
    "read_inventory",
    "read_audit_log",
    "write_findings",
    "outbound_http",
    "shell_exec",
}


def _check_metadata_quality(
    meta: SkillMetadata,
    raw_content: dict[str, str],
    source_file: str,
) -> list[SkillFinding]:
    """Check SKILL.md metadata for completeness and transparency gaps.

    Modeled after OpenClaw's security assessment categories:
      - Purpose & Capability: source/homepage consistency
      - Install Mechanism: source verification, multiple install methods
      - Instruction Scope: undeclared runtime dependencies
      - Credentials: documented scope
    """

    findings: list[SkillFinding] = []

    # ── Missing source / homepage ─────────────────────────────────────
    if not meta.homepage and not meta.source:
        findings.append(
            SkillFinding(
                severity="medium",
                category="missing_source",
                title="No homepage or source URL in skill metadata",
                detail=(
                    f"Skill '{meta.name or 'unknown'}' in {source_file} has no homepage "
                    "or source URL in its frontmatter. Users cannot verify the publisher "
                    "or audit the source code."
                ),
                source_file=source_file,
                recommendation="Add 'homepage' and 'source' fields to the YAML frontmatter.",
                context="metadata",
            )
        )

    # ── Missing license ───────────────────────────────────────────────
    if not meta.license:
        findings.append(
            SkillFinding(
                severity="low",
                category="missing_license",
                title="No license declared in skill metadata",
                detail=(
                    f"Skill '{meta.name or 'unknown'}' in {source_file} does not declare "
                    "a license. This makes it unclear under what terms the skill can be used."
                ),
                source_file=source_file,
                recommendation="Add a 'license' field (e.g. 'Apache-2.0', 'MIT') to the frontmatter.",
                context="metadata",
            )
        )

    # ── Explicit skill capability boundary ───────────────────────────
    raw_frontmatter = meta.raw_frontmatter or ""
    has_capabilities = bool(re.search(r"^\s*(?:skill_)?capabilities:\s*$", raw_frontmatter, re.MULTILINE))
    if not has_capabilities:
        findings.append(
            SkillFinding(
                severity="low",
                category="missing_capability_declaration",
                title="No explicit skill capability declaration",
                detail=(
                    f"Skill '{meta.name or 'unknown'}' in {source_file} does not declare "
                    "an explicit capability map. Sandboxed runtimes and Snowflake Native "
                    "App deployments need declared read, write, network, and shell "
                    "boundaries before a skill can be safely invoked."
                ),
                source_file=source_file,
                recommendation=(
                    "Add a 'capabilities' or 'skill_capabilities' frontmatter block "
                    "covering read_findings, read_inventory, read_audit_log, "
                    "write_findings, outbound_http, and shell_exec."
                ),
                context="metadata",
            )
        )
    else:
        missing_keys = sorted(key for key in _REQUIRED_CAPABILITY_KEYS if not re.search(rf"^\s*{key}\s*:", raw_frontmatter, re.MULTILINE))
        if missing_keys:
            findings.append(
                SkillFinding(
                    severity="low",
                    category="incomplete_capability_declaration",
                    title="Incomplete skill capability declaration",
                    detail=(
                        f"Skill '{meta.name or 'unknown'}' in {source_file} declares "
                        "skill capabilities but omits: "
                        f"{', '.join(missing_keys)}. Missing keys make sandbox and "
                        "customer-controlled runtime policy generation ambiguous."
                    ),
                    source_file=source_file,
                    recommendation=(
                        "Declare every required capability key explicitly and use false instead of omitting a denied capability."
                    ),
                    context="metadata",
                )
            )

    # ── Undeclared runtime dependencies ───────────────────────────────
    all_text = " ".join(raw_content.values()).lower()
    declared_bins = set(b.lower() for b in meta.required_bins + meta.optional_bins)

    for dep_name, patterns in _RUNTIME_DEP_PATTERNS.items():
        if dep_name.lower() in declared_bins:
            continue
        for pat in patterns:
            if re.search(pat, all_text, re.IGNORECASE):
                findings.append(
                    SkillFinding(
                        severity="medium",
                        category="undeclared_dependency",
                        title=f"Undeclared runtime dependency: '{dep_name}'",
                        detail=(
                            f"Skill '{meta.name or 'unknown'}' in {source_file} references "
                            f"'{dep_name}' in its instructions but does not declare it "
                            "in required_bins or optional_bins. Users may encounter failures "
                            "if the binary is not installed."
                        ),
                        source_file=source_file,
                        recommendation=(
                            f"Add '{dep_name}' to 'optional_bins' (if optional) or "
                            "'requires.bins' (if required) in the frontmatter metadata."
                        ),
                        context="metadata",
                    )
                )
                break  # One finding per dep, not per pattern match

    # ── Single install method ─────────────────────────────────────────
    if len(meta.install_methods) == 1:
        findings.append(
            SkillFinding(
                severity="low",
                category="limited_install",
                title="Only one install method declared",
                detail=(
                    f"Skill '{meta.name or 'unknown'}' in {source_file} only provides "
                    f"'{meta.install_methods[0]}' as an install method. Offering "
                    "multiple install options (uv, pip, pipx) improves accessibility."
                ),
                source_file=source_file,
                recommendation="Add alternative install methods (pip, pipx) to the frontmatter.",
                context="metadata",
            )
        )

    # ── Read-only claims without source verification ──────────────────
    read_only_claimed = any("read-only" in text.lower() or "read only" in text.lower() for text in raw_content.values())
    if read_only_claimed and not meta.source and not meta.homepage:
        findings.append(
            SkillFinding(
                severity="medium",
                category="unverifiable_claim",
                title="Read-only claim without source verification",
                detail=(
                    f"Skill '{meta.name or 'unknown'}' in {source_file} claims read-only "
                    "behavior but provides no source URL for users to verify this claim. "
                    "Without access to the source code, read-only guarantees are runtime "
                    "assertions that cannot be audited."
                ),
                source_file=source_file,
                recommendation=("Add a 'source' URL to the frontmatter so users can audit the code and verify read-only behavior."),
                context="metadata",
            )
        )

    # ── Network endpoints not documented ──────────────────────────────
    # Check if skill content references API calls but doesn't have a
    # "network" or "endpoints" or "API" documentation section
    has_api_refs = bool(
        re.search(
            r"https?://(?:api\.|registry\.|services\.)",
            all_text,
        )
    )
    # Look for documentation sections about network/endpoints, not just API URLs
    has_network_docs = bool(
        re.search(
            r"(?:^|\n)#+\s+.*(?:network|endpoint|transparenc|api.+call)",
            all_text,
            re.IGNORECASE,
        )
    ) or bool(
        re.search(
            r"(?:network\s+endpoint|endpoint.+call|api.+(?:read-only|read only))",
            all_text,
            re.IGNORECASE,
        )
    )
    if has_api_refs and not has_network_docs:
        findings.append(
            SkillFinding(
                severity="medium",
                category="undocumented_network",
                title="API endpoints referenced but not documented",
                detail=(
                    f"Skill '{meta.name or 'unknown'}' in {source_file} references "
                    "external API URLs but does not document which network endpoints "
                    "are called or what data is transmitted."
                ),
                source_file=source_file,
                recommendation=(
                    "Add a 'Transparency' or 'Network endpoints' section documenting all external APIs called and what data is sent."
                ),
                context="metadata",
            )
        )

    return findings


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
