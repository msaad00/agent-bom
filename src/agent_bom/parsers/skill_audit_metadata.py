"""Skill metadata quality checks for the skill security auditor.

Inspects SKILL.md frontmatter and content for completeness and transparency
gaps — missing source/homepage/license, absent capability declarations,
undeclared runtime dependencies, unverifiable read-only claims, and
undocumented network endpoints.

Split out of ``skill_audit.py`` (issue #1522) with no behavior change; the
public audit entrypoint continues to call :func:`_check_metadata_quality`.
"""

from __future__ import annotations

import re

from agent_bom.parsers.skill_audit_types import SkillFinding
from agent_bom.parsers.skills import SkillMetadata

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
