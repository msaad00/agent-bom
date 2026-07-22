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
from agent_bom.parsers.skill_audit_metadata import _check_metadata_quality
from agent_bom.parsers.skill_audit_types import SkillAuditResult, SkillFinding
from agent_bom.parsers.skills import SkillScanResult
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

    async def _check(name: str, eco: str) -> tuple[str, bool]:
        async with sem:
            found = await _verify_package_exists(name, eco)
            # fail-open: treat network errors as "exists" to avoid false flags
            return name, found if found is not None else True

    outcomes = await asyncio.gather(*[_check(n, e) for n, e in packages], return_exceptions=True)
    for package, outcome in zip(packages, outcomes, strict=False):
        name = package[0]
        if isinstance(outcome, BaseException):
            logger.debug("Package verify task failed for %s; fail-open as exists", name)
            results[name] = True
            continue
        results[outcome[0]] = outcome[1]
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
      8. MCP blocklist match on extracted servers (CRITICAL/HIGH)
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
    """Run checks 2, 4-5, 7, and 8 against a single MCP server."""
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

    # ── Check 8: MCP blocklist (skill-extracted servers) ───────────────
    try:
        from agent_bom.mcp_blocklist import match_mcp_server
    except Exception:  # pragma: no cover - import guard
        match_mcp_server = None  # type: ignore[assignment]
    if match_mcp_server is not None:
        for match in match_mcp_server(srv):
            detail_bits = [match.description or match.title]
            if match.matched_value:
                detail_bits.append(f"Matched value: {match.matched_value!r} ({match.match_type}).")
            detail_bits.append(f"Extracted from skill/instruction surface {source_file}.")
            audit.findings.append(
                SkillFinding(
                    severity=str(match.severity or "high").lower(),
                    category="mcp_blocklist",
                    title=match.title,
                    detail=" ".join(bit for bit in detail_bits if bit),
                    source_file=source_file,
                    server=srv.name,
                    package=match.package or None,
                    recommendation=(
                        "Remove or disable the matched MCP server until the blocklist entry is reviewed."
                        if match.default_recommendation == "block"
                        else "Review the matched MCP server against the blocklist entry before use."
                    ),
                    context="config_block",
                    evidence_source="external_registry",
                    confidence=str(match.confidence or "high"),
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


# ── Unified Finding stream ───────────────────────────────────────────────────


def _risk_score(severity: str) -> float:
    return {
        "critical": 9.0,
        "high": 7.5,
        "medium": 5.0,
        "low": 2.5,
    }.get(str(severity or "").lower(), 1.0)


def _finding_type_for_skill_category(category: str):
    """Map skill-audit categories onto the unified Finding taxonomy.

    Behavioral / package / server findings stay ``SKILL_RISK`` so the skill
    lane keeps a single rule id in SARIF/exports. Only curated MCP blocklist
    hits cross-walk to ``MCP_BLOCKLIST`` (same policy signal as MCP scan).
    """
    from agent_bom.finding import FindingType

    normalized = str(category or "").lower()
    if normalized == "mcp_blocklist":
        return FindingType.MCP_BLOCKLIST
    return FindingType.SKILL_RISK


def skill_audit_data_to_findings(skill_audit: dict) -> list:
    """Convert serialized skill-audit data into the unified Finding stream.

    Mirrors ``prompt_scan_data_to_findings`` so main-scan / API reports carry
    ``FindingType.SKILL_RISK`` (and MCP blocklist hits) instead of leaving
    skill results only in the ``skill_audit_data`` sidecar.
    """
    from agent_bom.finding import Asset, Finding, FindingSource

    if not isinstance(skill_audit, dict):
        return []

    unified = []
    for item in skill_audit.get("findings") or []:
        if not isinstance(item, dict):
            continue
        source_file = str(item.get("source_file") or "")
        category = str(item.get("category") or "skill_risk")
        severity = str(item.get("ai_adjusted_severity") or item.get("severity") or "unknown").lower()
        if severity == "false_positive":
            continue
        title = str(item.get("title") or "Skill security finding")
        asset_name = (
            str(item.get("server") or item.get("package") or "")
            or (Path(source_file).name if source_file else "skill")
        )
        asset_type = "mcp_server" if item.get("server") else ("package" if item.get("package") else "skill_file")
        identifier = item.get("server") or item.get("package") or source_file or None
        unified.append(
            Finding(
                finding_type=_finding_type_for_skill_category(category),
                source=FindingSource.SKILL,
                asset=Asset(
                    name=asset_name,
                    asset_type=asset_type,
                    identifier=str(identifier) if identifier else None,
                    location=source_file or None,
                ),
                severity=severity,
                title=title,
                description=str(item.get("detail") or title),
                remediation_guidance=str(item.get("recommendation") or "") or None,
                owasp_tags=["LLM01"] if "injection" in category or "prompt" in category else [],
                owasp_mcp_tags=["MCP04", "MCP07"] if category == "mcp_blocklist" else [],
                nist_ai_rmf_tags=["MAP-4.1", "MEASURE-2.6"],
                evidence={
                    "category": category,
                    "package": item.get("package"),
                    "server": item.get("server"),
                    "context": item.get("context"),
                    "confidence": item.get("confidence"),
                    "evidence_source": item.get("evidence_source"),
                    "source_line": item.get("source_line"),
                    "ai_detected": item.get("ai_detected"),
                    "scanner": "skill_audit",
                },
                risk_score=_risk_score(severity),
            )
        )
    return unified


def replace_skill_findings(report, skill_audit: dict | None) -> int:
    """Replace ``FindingSource.SKILL`` rows on *report* from serialized audit data.

    Returns the number of findings attached.
    """
    from agent_bom.finding import FindingSource

    if skill_audit is None:
        return 0
    existing = list(getattr(report, "findings", None) or [])
    retained = [finding for finding in existing if getattr(finding, "source", None) != FindingSource.SKILL]
    added = skill_audit_data_to_findings(skill_audit)
    report.findings = retained + added
    return len(added)
