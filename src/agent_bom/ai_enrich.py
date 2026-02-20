"""AI-powered enrichment — LLM-generated risk narratives, executive summaries, and threat chains.

Supports two LLM backends:

1. **Ollama (free, local)** — auto-detected at ``http://localhost:11434``.
   No extra install needed (uses httpx, already a core dependency).
   Start with: ``ollama serve`` then ``ollama pull llama3.2``

2. **litellm (100+ providers)** — OpenAI, Anthropic, Mistral, Groq, etc.
   Install with: ``pip install agent-bom[ai-enrich]``

All LLM calls are:
- **Optional**: graceful fallback when no provider is available.
- **Cached**: in-memory dedup by ``sha256(model:prompt)`` within a scan run.
- **Batched**: grouped by package to minimize API calls.
"""

from __future__ import annotations

import asyncio
import hashlib
import logging
import os
from typing import TYPE_CHECKING, Optional

import httpx
from rich.console import Console

if TYPE_CHECKING:
    from agent_bom.models import AIBOMReport, BlastRadius

console = Console(stderr=True)
logger = logging.getLogger(__name__)

# Simple in-memory cache: hash(prompt) -> response
_cache: dict[str, str] = {}

DEFAULT_MODEL = "openai/gpt-4o-mini"
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "llama3.2"


# ─── Provider detection ──────────────────────────────────────────────────────


def _check_litellm() -> bool:
    """Check if litellm is installed."""
    try:
        import litellm  # noqa: F401
        return True
    except ImportError:
        return False


def _detect_ollama() -> bool:
    """Check if Ollama is running locally."""
    try:
        resp = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2.0)
        return resp.status_code == 200
    except (httpx.ConnectError, httpx.TimeoutException, Exception):
        return False


def _get_ollama_models() -> list[str]:
    """Get list of locally available Ollama models."""
    try:
        resp = httpx.get(f"{OLLAMA_BASE_URL}/api/tags", timeout=2.0)
        if resp.status_code == 200:
            data = resp.json()
            return [m["name"] for m in data.get("models", [])]
    except Exception:
        pass
    return []


def _resolve_model(model: str = DEFAULT_MODEL) -> str:
    """Auto-detect the best available model.

    Priority:
    1. If Ollama is running → ``ollama/llama3.2``
    2. If OPENAI_API_KEY is set → ``openai/gpt-4o-mini``
    3. Fallback to default (will fail gracefully at call time)
    """
    if _detect_ollama():
        return f"ollama/{OLLAMA_DEFAULT_MODEL}"
    if os.environ.get("OPENAI_API_KEY"):
        return DEFAULT_MODEL
    return model


def _has_any_provider(model: str) -> bool:
    """Check if any LLM provider is available for the given model."""
    if model.startswith("ollama/"):
        return _detect_ollama()
    return _check_litellm()


# ─── LLM calls ───────────────────────────────────────────────────────────────


def _cache_key(prompt: str, model: str) -> str:
    return hashlib.sha256(f"{model}:{prompt}".encode()).hexdigest()


async def _call_ollama_direct(prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
    """Call Ollama directly via HTTP API (no litellm dependency needed).

    The *model* parameter is the bare model name (e.g. ``llama3.2``).
    """
    key = _cache_key(prompt, f"ollama/{model}")
    if key in _cache:
        return _cache[key]

    try:
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "options": {
                        "num_predict": max_tokens,
                        "temperature": 0.3,
                    },
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                text = data.get("message", {}).get("content", "").strip()
                if text:
                    _cache[key] = text
                    return text
            logger.warning("Ollama returned status %d", resp.status_code)
            return None
    except (httpx.ConnectError, httpx.TimeoutException) as exc:
        logger.warning("Ollama connection failed: %s", exc)
        return None
    except Exception as exc:
        logger.warning("Ollama call failed: %s", exc)
        return None


async def _call_llm_via_litellm(prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
    """Call LLM via litellm with caching and error handling."""
    key = _cache_key(prompt, model)
    if key in _cache:
        return _cache[key]

    try:
        from litellm import acompletion

        response = await acompletion(
            model=model,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.3,
        )
        text = response.choices[0].message.content.strip()
        _cache[key] = text
        return text
    except ImportError:
        logger.warning("litellm not installed. Install with: pip install agent-bom[ai-enrich]")
        return None
    except Exception as exc:
        logger.warning("LLM call failed: %s", exc)
        return None


async def _call_llm(prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
    """Call LLM via the best available provider.

    Routing:
    - ``ollama/*`` models → direct Ollama HTTP API (no extra dependency)
    - Other models → litellm
    """
    if model.startswith("ollama/"):
        bare_model = model[len("ollama/"):]
        result = await _call_ollama_direct(prompt, bare_model, max_tokens)
        if result is not None:
            return result
        # Fall back to litellm if installed (it also supports ollama/)
        if _check_litellm():
            return await _call_llm_via_litellm(prompt, model, max_tokens)
        return None
    return await _call_llm_via_litellm(prompt, model, max_tokens)


# ─── Prompt builders ─────────────────────────────────────────────────────────


def _build_blast_radius_prompt(br: BlastRadius) -> str:
    """Build a prompt for analyzing a single blast radius finding."""
    agents = ", ".join(a.name for a in br.affected_agents[:5])
    creds = ", ".join(br.exposed_credentials[:5])
    tools = ", ".join(t.name for t in br.exposed_tools[:5])
    owasp = ", ".join(br.owasp_tags[:3])

    return (
        "You are an AI security analyst. Analyze this vulnerability finding "
        "in the context of an AI agent's MCP (Model Context Protocol) tool chain.\n\n"
        f"Vulnerability: {br.vulnerability.id}\n"
        f"Severity: {br.vulnerability.severity.value} (CVSS: {br.vulnerability.cvss_score or 'N/A'})\n"
        f"Summary: {br.vulnerability.summary}\n"
        f"Package: {br.package.name}@{br.package.version} ({br.package.ecosystem})\n"
        f"Fixed version: {br.vulnerability.fixed_version or 'No fix available'}\n"
        f"Affected AI agents: {agents}\n"
        f"Exposed credentials: {creds or 'None'}\n"
        f"Reachable tools: {tools or 'None'}\n"
        f"OWASP LLM Top 10 tags: {owasp or 'None'}\n"
        f"Risk score: {br.risk_score:.1f}/10\n\n"
        "Provide a concise 2-3 sentence analysis covering:\n"
        "1. Why this vulnerability matters specifically in an AI agent context\n"
        "2. How an attacker could exploit this through the agent's tool chain\n"
        "3. The specific business impact given the exposed credentials and tools\n\n"
        "Be specific about the attack path. Do not use generic language."
    )


def _build_executive_summary_prompt(report: AIBOMReport) -> str:
    """Build a prompt for generating an executive summary."""
    critical_ids = [
        br.vulnerability.id for br in report.blast_radii[:5]
        if br.vulnerability.severity.value == "critical"
    ]
    cred_count = len({c for br in report.blast_radii for c in br.exposed_credentials})
    tool_count = len({t.name for br in report.blast_radii for t in br.exposed_tools})

    return (
        "You are a CISO's AI security advisor. Write a one-paragraph executive "
        "summary of this AI agent security scan.\n\n"
        f"Scan results:\n"
        f"- {report.total_agents} AI agent(s) scanned\n"
        f"- {report.total_servers} MCP server(s) discovered\n"
        f"- {report.total_packages} package dependencies analyzed\n"
        f"- {report.total_vulnerabilities} vulnerabilities found\n"
        f"- {len(report.critical_vulns)} critical findings\n"
        f"- {cred_count} unique credentials at risk\n"
        f"- {tool_count} unique tools in blast radius\n"
        f"- Top critical CVEs: {', '.join(critical_ids) or 'None'}\n\n"
        "Write for a non-technical executive audience. Focus on business risk, "
        "not technical details. Include a clear risk rating (Critical/High/Medium/Low) "
        "and 1-2 recommended actions. Keep to one paragraph, 4-6 sentences."
    )


def _build_threat_chain_prompt(report: AIBOMReport) -> str:
    """Build a prompt for threat chain analysis."""
    chains = []
    for br in report.blast_radii[:5]:
        agents = ", ".join(a.name for a in br.affected_agents[:2])
        tools = ", ".join(t.name for t in br.exposed_tools[:3])
        creds = ", ".join(br.exposed_credentials[:3])
        chains.append(
            f"- {br.vulnerability.id} in {br.package.name}@{br.package.version} "
            f"| agents: {agents} | tools: {tools} | creds: {creds}"
        )

    return (
        "You are a red team AI security specialist. Analyze how an attacker could "
        "chain these vulnerabilities through an AI agent's MCP tool access to achieve "
        "maximum impact.\n\n"
        f"Vulnerabilities in blast radius:\n"
        f"{chr(10).join(chains)}\n\n"
        "Describe 1-2 realistic attack chains (3-5 steps each) showing:\n"
        "1. Initial exploitation vector\n"
        "2. Lateral movement through MCP tools\n"
        "3. Credential exfiltration or data access\n"
        "4. Final impact\n\n"
        "Be specific about which tools and credentials are used at each step. "
        "Format as numbered steps."
    )


def _build_remediation_prompt(items: list[dict]) -> str:
    """Build a prompt for generating remediation guidance."""
    package_lines = []
    for item in items[:10]:
        fix_str = f" -> {item['fix']}" if item.get("fix") else " (no fix)"
        package_lines.append(
            f"- {item['package']}@{item['current']} ({item['ecosystem']}){fix_str} "
            f"| {len(item['vulns'])} vuln(s) | agents: {', '.join(item['agents'][:3])}"
        )

    return (
        "You are an AI security engineer. Generate practical, prioritized "
        "remediation guidance for these vulnerable packages in AI agent MCP "
        "server configurations.\n\n"
        f"Findings:\n{chr(10).join(package_lines)}\n\n"
        "For each package, provide:\n"
        "1. Specific upgrade command (npm/pip/etc)\n"
        "2. Any breaking changes to watch for\n"
        "3. Temporary mitigation if no fix exists\n\n"
        "Keep each item to 2-3 lines. Be concrete and actionable."
    )


# ─── Enrichment functions ────────────────────────────────────────────────────


async def enrich_blast_radii(
    blast_radii: list[BlastRadius],
    model: str = DEFAULT_MODEL,
) -> int:
    """Add AI-generated risk narratives to blast radius findings.

    Groups findings by package to minimize API calls.
    Returns count of enriched findings.
    """
    if not blast_radii:
        return 0
    if not _check_litellm() and not _detect_ollama():
        return 0

    enriched = 0
    seen_packages: dict[str, Optional[str]] = {}  # pkg_key -> ai_summary

    for br in blast_radii:
        pkg_key = f"{br.package.ecosystem}:{br.package.name}@{br.package.version}"

        if pkg_key in seen_packages:
            cached = seen_packages[pkg_key]
            if cached:
                br.ai_summary = cached
                enriched += 1
            continue

        prompt = _build_blast_radius_prompt(br)
        result = await _call_llm(prompt, model)
        seen_packages[pkg_key] = result
        if result:
            br.ai_summary = result
            enriched += 1

    return enriched


async def generate_executive_summary(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
) -> Optional[str]:
    """Generate an LLM-powered executive summary of the scan."""
    if not report.blast_radii:
        return None
    if not _check_litellm() and not _detect_ollama():
        return None

    prompt = _build_executive_summary_prompt(report)
    return await _call_llm(prompt, model, max_tokens=300)


async def generate_threat_chains(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
) -> list[str]:
    """Generate LLM-powered threat chain analysis."""
    if not report.blast_radii:
        return []
    if not _check_litellm() and not _detect_ollama():
        return []

    prompt = _build_threat_chain_prompt(report)
    result = await _call_llm(prompt, model, max_tokens=800)
    return [result] if result else []


# ─── Orchestrator ─────────────────────────────────────────────────────────────


async def run_ai_enrichment(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
) -> None:
    """Run all AI enrichment steps on a report. Modifies report in-place."""
    # Auto-detect best model if using the default (which requires a paid key)
    if model == DEFAULT_MODEL:
        model = _resolve_model(model)

    # Determine provider for display
    if model.startswith("ollama/"):
        if not _detect_ollama():
            console.print("  [yellow]Ollama not running at localhost:11434. Skipping AI enrichment.[/yellow]")
            console.print("  [dim]Start with: ollama serve && ollama pull llama3.2[/dim]")
            return
        provider = "Ollama (local, free)"
    elif _check_litellm():
        provider = "litellm"
    else:
        console.print("  [yellow]No LLM provider available. Skipping AI enrichment.[/yellow]")
        console.print("  [dim]Option 1: Install Ollama (free, local) — ollama.com[/dim]")
        console.print("  [dim]Option 2: pip install agent-bom[ai-enrich] + set API key[/dim]")
        return

    console.print(f"\n[bold blue]AI Enrichment[/bold blue]  [dim]model: {model} via {provider}[/dim]\n")

    # Step 1: Enrich blast radii with contextual narratives
    console.print("  [cyan]>[/cyan] Generating risk narratives...")
    enriched = await enrich_blast_radii(report.blast_radii, model)
    console.print(f"  [green]{enriched} finding(s) enriched[/green]")

    # Step 2: Generate executive summary
    console.print("  [cyan]>[/cyan] Generating executive summary...")
    summary = await generate_executive_summary(report, model)
    if summary:
        report.executive_summary = summary
        console.print("  [green]Executive summary generated[/green]")

    # Step 3: Generate threat chain analysis
    console.print("  [cyan]>[/cyan] Analyzing threat chains...")
    chains = await generate_threat_chains(report, model)
    if chains:
        report.ai_threat_chains = chains
        console.print(f"  [green]{len(chains)} threat chain(s) analyzed[/green]")


def run_ai_enrichment_sync(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
) -> None:
    """Synchronous wrapper for run_ai_enrichment."""
    asyncio.run(run_ai_enrichment(report, model))
