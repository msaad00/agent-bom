"""Interactive chat engine for agent-bom.

Provides a conversational interface to agent-bom capabilities using the
existing AI enrichment backends (Ollama, HuggingFace, litellm).  Users
can ask about their security posture, trigger scans, query compliance
status, and get remediation advice — all through natural language.

The chat engine maps user intents to existing agent-bom tools and formats
results conversationally.
"""

from __future__ import annotations

import asyncio
import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

from rich.console import Console
from rich.markdown import Markdown
from rich.panel import Panel
from rich.table import Table

logger = logging.getLogger(__name__)

# ─── Intent detection ────────────────────────────────────────────────────────

INTENT_KEYWORDS: dict[str, list[str]] = {
    "scan": ["scan", "discover", "find agents", "detect", "audit", "check my"],
    "check_package": ["check package", "check if", "vulnerable", "cve for", "vulnerabilities in"],
    "compliance": ["compliance", "compliant", "hipaa", "cmmc", "soc2", "soc 2", "iso 27001", "nist", "cis ", "owasp", "eu ai act", "framework"],
    "remediate": ["fix", "remediate", "patch", "upgrade", "how to fix", "resolve"],
    "blast_radius": ["blast radius", "impact", "affected", "exposure", "risk score"],
    "inventory": ["inventory", "list agents", "show agents", "what agents", "which agents", "servers"],
    "help": ["help", "what can you", "commands", "how do i", "what do you"],
    "status": ["status", "posture", "score", "grade", "how secure", "overview"],
}


def detect_intent(message: str) -> str:
    """Detect user intent from a natural language message."""
    msg = message.lower().strip()

    for intent, keywords in INTENT_KEYWORDS.items():
        for kw in keywords:
            if kw in msg:
                return intent

    return "general"


# ─── Chat context ────────────────────────────────────────────────────────────


@dataclass
class ChatContext:
    """Maintains conversation state across turns."""

    history: list[dict[str, str]] = field(default_factory=list)
    last_scan_result: Optional[dict[str, Any]] = None
    last_agents: Optional[list] = None
    last_blast_radii: Optional[list] = None
    console: Console = field(default_factory=lambda: Console())

    def add_message(self, role: str, content: str) -> None:
        self.history.append({"role": role, "content": content})
        # Keep last 20 messages to avoid context overflow
        if len(self.history) > 20:
            self.history = self.history[-20:]


# ─── Tool executors ──────────────────────────────────────────────────────────


async def _run_scan(ctx: ChatContext, console: Console) -> str:
    """Run agent discovery and vulnerability scan."""
    from agent_bom.discovery import discover_all
    from agent_bom.scanners import scan_agents

    console.print("\n[yellow]Discovering agents...[/yellow]")
    agents = discover_all()

    if not agents:
        return "No AI agents found on this system. Make sure you have Claude Desktop, Cursor, Windsurf, or other supported agents installed and configured."

    console.print(f"[green]Found {len(agents)} agent(s)[/green]")
    ctx.last_agents = agents

    total_servers = sum(len(a.mcp_servers) for a in agents)
    total_packages = sum(sum(len(s.packages) for s in a.mcp_servers) for a in agents)

    console.print(f"[dim]  {total_servers} MCP server(s), {total_packages} package(s)[/dim]")
    console.print("[yellow]Scanning for vulnerabilities...[/yellow]\n")

    blast_radii = await scan_agents(agents)
    ctx.last_blast_radii = blast_radii

    if not blast_radii:
        agent_names = ", ".join(a.name for a in agents)
        return f"**Scan complete.** Found {len(agents)} agent(s) ({agent_names}) with {total_servers} MCP server(s) and {total_packages} package(s). **No vulnerabilities detected** — your setup looks clean!"

    critical = sum(1 for br in blast_radii if br.vulnerability.severity.value == "critical")
    high = sum(1 for br in blast_radii if br.vulnerability.severity.value == "high")
    medium = sum(1 for br in blast_radii if br.vulnerability.severity.value == "medium")
    low = sum(1 for br in blast_radii if br.vulnerability.severity.value == "low")

    lines = [
        f"**Scan complete.** Found **{len(blast_radii)} vulnerabilities** across {len(agents)} agent(s).\n",
        "| Severity | Count |",
        "|----------|-------|",
    ]
    if critical:
        lines.append(f"| Critical | {critical} |")
    if high:
        lines.append(f"| High | {high} |")
    if medium:
        lines.append(f"| Medium | {medium} |")
    if low:
        lines.append(f"| Low | {low} |")

    # Top 5 findings
    top = sorted(blast_radii, key=lambda br: br.risk_score, reverse=True)[:5]
    lines.append("\n**Top findings:**")
    for br in top:
        lines.append(f"- **{br.vulnerability.id}** ({br.vulnerability.severity.value}) in `{br.package.name}@{br.package.version}` — risk score {br.risk_score:.1f}/10")

    if critical + high > 0:
        lines.append(f"\n> Use `fix` or `remediate` to get remediation steps for these findings.")

    return "\n".join(lines)


async def _run_check_package(ctx: ChatContext, message: str, console: Console) -> str:
    """Check a specific package for vulnerabilities."""
    from agent_bom.models import Package
    from agent_bom.scanners import query_osv_batch

    # Extract package spec from message
    words = message.split()
    pkg_spec = None
    for word in words:
        if "@" in word and not word.startswith("@"):
            pkg_spec = word
            break
        if any(c.isdigit() for c in word) and "." in word:
            # Looks like a version — check previous word
            idx = words.index(word)
            if idx > 0:
                pkg_spec = f"{words[idx - 1]}@{word}"
                break

    if not pkg_spec:
        # Try to find a package name
        for word in words:
            if word not in {"check", "package", "is", "vulnerable", "cve", "for", "vulnerabilities", "in", "the", "a"}:
                pkg_spec = word
                break

    if not pkg_spec:
        return "Please specify a package to check, e.g. `check lodash@4.17.20` or `is express vulnerable?`"

    if "@" in pkg_spec:
        name, version = pkg_spec.rsplit("@", 1)
    else:
        name, version = pkg_spec, "latest"

    # Detect ecosystem
    ecosystem = "npm"  # default
    if any(c in name for c in [".", "/"]) and not name.startswith("@"):
        ecosystem = "pypi"

    console.print(f"\n[yellow]Checking {name}@{version} ({ecosystem})...[/yellow]\n")

    pkg = Package(name=name, version=version, ecosystem=ecosystem)
    results = await query_osv_batch([pkg])
    vulns = results.get(f"{name}@{version}", [])

    if not vulns:
        return f"**{name}@{version}** — No known vulnerabilities found. Looks safe!"

    lines = [f"**{name}@{version}** has **{len(vulns)} known vulnerability(ies)**:\n"]
    for v in vulns[:10]:
        vid = v.get("id", "unknown")
        summary = v.get("summary", "No description")[:100]
        lines.append(f"- **{vid}**: {summary}")

    if len(vulns) > 10:
        lines.append(f"\n... and {len(vulns) - 10} more.")

    return "\n".join(lines)


async def _run_compliance(ctx: ChatContext, message: str) -> str:
    """Show compliance posture for available data."""
    if not ctx.last_blast_radii:
        return "No scan data available yet. Run a `scan` first to see compliance posture."

    # Detect which framework they're asking about
    msg = message.lower()
    framework_map = {
        "hipaa": ("hipaa_tags", "HIPAA Security Rule"),
        "cmmc": ("cmmc_tags", "CMMC 2.0 Level 2"),
        "soc2": ("soc2_tags", "SOC 2 TSC"),
        "soc 2": ("soc2_tags", "SOC 2 TSC"),
        "iso": ("iso_27001_tags", "ISO 27001:2022"),
        "nist csf": ("nist_csf_tags", "NIST CSF 2.0"),
        "nist ai": ("nist_ai_rmf_tags", "NIST AI RMF"),
        "nist": ("nist_csf_tags", "NIST CSF 2.0"),
        "cis": ("cis_tags", "CIS Controls v8"),
        "owasp": ("owasp_tags", "OWASP LLM Top 10"),
        "eu ai": ("eu_ai_act_tags", "EU AI Act"),
    }

    tag_field = None
    framework_name = None
    for key, (field_name, name) in framework_map.items():
        if key in msg:
            tag_field = field_name
            framework_name = name
            break

    if tag_field:
        # Show specific framework
        all_tags: set[str] = set()
        for br in ctx.last_blast_radii:
            tags = getattr(br, tag_field, [])
            all_tags.update(tags)

        if not all_tags:
            return f"**{framework_name}**: No controls triggered by current findings. All clear!"

        findings_by_tag: dict[str, int] = {}
        for br in ctx.last_blast_radii:
            for tag in getattr(br, tag_field, []):
                findings_by_tag[tag] = findings_by_tag.get(tag, 0) + 1

        lines = [f"**{framework_name} Compliance Posture**\n"]
        lines.append(f"**{len(all_tags)} controls triggered** across {len(ctx.last_blast_radii)} findings:\n")
        for tag in sorted(findings_by_tag.keys()):
            lines.append(f"- `{tag}` — {findings_by_tag[tag]} finding(s)")

        return "\n".join(lines)

    # Show overview of all frameworks
    frameworks = [
        ("owasp_tags", "OWASP LLM Top 10"),
        ("owasp_mcp_tags", "OWASP MCP Top 10"),
        ("atlas_tags", "MITRE ATLAS"),
        ("nist_ai_rmf_tags", "NIST AI RMF"),
        ("nist_csf_tags", "NIST CSF 2.0"),
        ("iso_27001_tags", "ISO 27001:2022"),
        ("soc2_tags", "SOC 2 TSC"),
        ("cis_tags", "CIS Controls v8"),
        ("cmmc_tags", "CMMC 2.0"),
        ("hipaa_tags", "HIPAA"),
        ("eu_ai_act_tags", "EU AI Act"),
    ]

    lines = ["**Compliance Posture Overview**\n"]
    lines.append("| Framework | Controls Triggered | Findings |")
    lines.append("|-----------|-------------------|----------|")

    for tag_field, name in frameworks:
        all_tags_set: set[str] = set()
        count = 0
        for br in ctx.last_blast_radii:
            tags = getattr(br, tag_field, [])
            all_tags_set.update(tags)
            if tags:
                count += 1
        lines.append(f"| {name} | {len(all_tags_set)} | {count} |")

    lines.append(f"\nAsk about a specific framework for details, e.g. `show HIPAA compliance`")
    return "\n".join(lines)


async def _run_inventory(ctx: ChatContext, console: Console) -> str:
    """List discovered agents."""
    from agent_bom.discovery import discover_all

    console.print("\n[yellow]Discovering agents...[/yellow]\n")
    agents = discover_all()
    ctx.last_agents = agents

    if not agents:
        return "No AI agents found on this system."

    lines = [f"**Found {len(agents)} agent(s):**\n"]
    for agent in agents:
        servers = len(agent.mcp_servers)
        pkgs = sum(len(s.packages) for s in agent.mcp_servers)
        tools = sum(len(s.tools) for s in agent.mcp_servers)
        lines.append(f"- **{agent.name}** ({agent.agent_type.value}) — {servers} server(s), {pkgs} package(s), {tools} tool(s)")

        for server in agent.mcp_servers[:5]:
            lines.append(f"  - `{server.name}` ({len(server.packages)} pkgs, {len(server.tools)} tools)")
        if len(agent.mcp_servers) > 5:
            lines.append(f"  - ... +{len(agent.mcp_servers) - 5} more")

    return "\n".join(lines)


async def _run_remediate(ctx: ChatContext) -> str:
    """Generate remediation plan from last scan."""
    if not ctx.last_blast_radii:
        return "No scan data available. Run a `scan` first."

    from agent_bom.remediate import generate_remediation_plan

    plan = generate_remediation_plan(ctx.last_blast_radii)

    lines = ["**Remediation Plan**\n"]

    if plan.package_fixes:
        lines.append(f"### Package Fixes ({len(plan.package_fixes)})\n")
        for fix in plan.package_fixes[:15]:
            lines.append(f"- **{fix.package}** ({fix.ecosystem}): `{fix.current_version}` → `{fix.fixed_version or 'no fix available'}`")
            if fix.command:
                lines.append(f"  ```\n  {fix.command}\n  ```")

    if plan.credential_fixes:
        lines.append(f"\n### Credential Fixes ({len(plan.credential_fixes)})\n")
        for fix in plan.credential_fixes[:5]:
            lines.append(f"- **{fix.credential_name}**: {fix.risk_description}")
            for step in fix.fix_steps[:3]:
                lines.append(f"  - {step}")

    if plan.unfixable:
        lines.append(f"\n### No Fix Available ({len(plan.unfixable)})\n")
        for item in plan.unfixable[:5]:
            lines.append(f"- `{item.get('package', 'unknown')}@{item.get('version', '?')}` — {item.get('vuln_id', '?')}")

    return "\n".join(lines)


async def _run_blast_radius(ctx: ChatContext) -> str:
    """Show blast radius details."""
    if not ctx.last_blast_radii:
        return "No scan data available. Run a `scan` first."

    top = sorted(ctx.last_blast_radii, key=lambda br: br.risk_score, reverse=True)[:10]
    lines = [f"**Top {len(top)} Blast Radius Findings** (by risk score)\n"]

    for br in top:
        agents = ", ".join(a.name for a in br.affected_agents[:3])
        creds = len(br.exposed_credentials)
        tools = len(br.exposed_tools)
        lines.append(f"### {br.vulnerability.id} — Risk {br.risk_score:.1f}/10")
        lines.append(f"- **Package:** `{br.package.name}@{br.package.version}` ({br.package.ecosystem})")
        lines.append(f"- **Severity:** {br.vulnerability.severity.value}")
        lines.append(f"- **Agents:** {agents}")
        if creds:
            lines.append(f"- **Exposed credentials:** {creds}")
        if tools:
            lines.append(f"- **Accessible tools:** {tools}")
        if br.vulnerability.fixed_version:
            lines.append(f"- **Fix:** upgrade to {br.vulnerability.fixed_version}")
        lines.append("")

    return "\n".join(lines)


def _get_help_text() -> str:
    """Return help text."""
    return """**agent-bom Chat** — here's what I can help with:

- **`scan`** — Discover agents and scan for vulnerabilities
- **`check <package>`** — Check a package for CVEs (e.g. `check lodash@4.17.20`)
- **`inventory`** — List discovered AI agents and MCP servers
- **`compliance`** — Show compliance posture (HIPAA, CMMC, SOC2, NIST, etc.)
- **`blast radius`** — Show vulnerability impact analysis
- **`remediate`** / **`fix`** — Get remediation steps
- **`status`** — Security posture overview
- **`help`** — Show this message
- **`exit`** / **`quit`** — Exit chat

You can also ask questions naturally, like:
- *"Is my setup HIPAA compliant?"*
- *"What's the blast radius of my vulnerabilities?"*
- *"How do I fix the critical issues?"*
"""


async def _run_status(ctx: ChatContext) -> str:
    """Show overall security status."""
    if not ctx.last_blast_radii and not ctx.last_agents:
        return "No data available yet. Run a `scan` to get your security posture."

    lines = ["**Security Posture Overview**\n"]

    if ctx.last_agents:
        lines.append(f"- **Agents:** {len(ctx.last_agents)}")
        total_servers = sum(len(a.mcp_servers) for a in ctx.last_agents)
        total_pkgs = sum(sum(len(s.packages) for s in a.mcp_servers) for a in ctx.last_agents)
        lines.append(f"- **MCP Servers:** {total_servers}")
        lines.append(f"- **Packages:** {total_pkgs}")

    if ctx.last_blast_radii:
        vulns = len(ctx.last_blast_radii)
        critical = sum(1 for br in ctx.last_blast_radii if br.vulnerability.severity.value == "critical")
        high = sum(1 for br in ctx.last_blast_radii if br.vulnerability.severity.value == "high")
        avg_risk = sum(br.risk_score for br in ctx.last_blast_radii) / vulns if vulns else 0
        fixable = sum(1 for br in ctx.last_blast_radii if br.vulnerability.fixed_version)

        lines.append(f"- **Vulnerabilities:** {vulns} ({critical} critical, {high} high)")
        lines.append(f"- **Average risk score:** {avg_risk:.1f}/10")
        lines.append(f"- **Fixable:** {fixable}/{vulns}")

        if critical + high == 0:
            lines.append("\n> Your security posture looks good — no critical or high severity issues.")
        else:
            lines.append(f"\n> **Action needed:** {critical + high} critical/high finding(s) require attention. Use `remediate` for fix steps.")
    else:
        lines.append("- **Vulnerabilities:** 0")
        lines.append("\n> No vulnerabilities found. Your setup looks clean!")

    return "\n".join(lines)


# ─── LLM-powered response (for general questions) ───────────────────────────


async def _ask_llm(message: str, ctx: ChatContext) -> Optional[str]:
    """Use LLM to answer general questions about the scan data."""
    from agent_bom.ai_enrich import _call_llm_via_litellm, _call_ollama_direct, _resolve_model

    model = _resolve_model()

    # Build context from available data
    context_parts = ["You are agent-bom, an AI Bill of Materials security tool for AI agents and MCP servers."]
    context_parts.append("Answer the user's question concisely based on available data.")
    context_parts.append("If you don't have enough data, suggest they run a scan first.")

    if ctx.last_agents:
        agent_names = [a.name for a in ctx.last_agents]
        context_parts.append(f"Discovered agents: {', '.join(agent_names)}")

    if ctx.last_blast_radii:
        vuln_count = len(ctx.last_blast_radii)
        top_vulns = [f"{br.vulnerability.id} ({br.vulnerability.severity.value}) in {br.package.name}" for br in sorted(ctx.last_blast_radii, key=lambda x: x.risk_score, reverse=True)[:5]]
        context_parts.append(f"Found {vuln_count} vulnerabilities. Top: {'; '.join(top_vulns)}")

    prompt = "\n".join(context_parts) + f"\n\nUser: {message}\nAssistant:"

    if model.startswith("ollama/"):
        bare_model = model.replace("ollama/", "", 1)
        return await _call_ollama_direct(prompt, bare_model, max_tokens=300)
    else:
        return await _call_llm_via_litellm(prompt, model, max_tokens=300)


# ─── Main chat handler ───────────────────────────────────────────────────────


async def handle_message(message: str, ctx: ChatContext) -> str:
    """Process a user message and return a response."""
    ctx.add_message("user", message)
    intent = detect_intent(message)

    try:
        if intent == "scan":
            response = await _run_scan(ctx, ctx.console)
        elif intent == "check_package":
            response = await _run_check_package(ctx, message, ctx.console)
        elif intent == "compliance":
            response = await _run_compliance(ctx, message)
        elif intent == "remediate":
            response = await _run_remediate(ctx)
        elif intent == "blast_radius":
            response = await _run_blast_radius(ctx)
        elif intent == "inventory":
            response = await _run_inventory(ctx, ctx.console)
        elif intent == "status":
            response = await _run_status(ctx)
        elif intent == "help":
            response = _get_help_text()
        else:
            # Try LLM for general questions
            llm_response = await _ask_llm(message, ctx)
            if llm_response:
                response = llm_response
            else:
                response = (
                    "I'm not sure how to help with that. "
                    "Try `help` to see what I can do, or ask about scanning, compliance, or vulnerabilities."
                )
    except Exception as exc:
        logger.exception("Error handling message")
        response = f"Something went wrong: {type(exc).__name__}: {exc}\n\nTry again or use `help` to see available commands."

    ctx.add_message("assistant", response)
    return response
