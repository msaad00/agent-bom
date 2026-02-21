"""AI-powered enrichment — LLM-generated risk narratives, executive summaries, and threat chains.

Supports three LLM backends (in priority order):

1. **Ollama (free, local)** — auto-detected at ``http://localhost:11434``.
   No extra install needed (uses httpx, already a core dependency).
   Start with: ``ollama serve`` then ``ollama pull llama3.2``

2. **HuggingFace Inference API (free tier)** — open-source models in the cloud.
   Install with: ``pip install 'agent-bom[huggingface]'``
   Set ``HF_TOKEN`` env var for gated models.

3. **litellm (100+ providers)** — OpenAI, Anthropic, Mistral, Groq, etc.
   Install with: ``pip install 'agent-bom[ai-enrich]'``

All LLM calls are:
- **Optional**: graceful fallback when no provider is available.
- **Cached**: in-memory dedup by ``sha256(model:prompt)`` within a scan run.
- **Batched**: grouped by package to minimize API calls.
- **Structured**: Pydantic schemas + Ollama's ``format`` parameter for reliable JSON.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import logging
import os
import re
from typing import TYPE_CHECKING, Optional

import httpx
from rich.console import Console

if TYPE_CHECKING:
    from agent_bom.ai_schemas import MCPConfigSecurityAnalysis
    from agent_bom.models import AIBOMReport, BlastRadius
    from agent_bom.parsers.skill_audit import SkillAuditResult
    from agent_bom.parsers.skills import SkillScanResult

console = Console(stderr=True)
logger = logging.getLogger(__name__)

# Simple in-memory cache: hash(prompt) -> response
_cache: dict[str, str] = {}

DEFAULT_MODEL = "openai/gpt-4o-mini"
OLLAMA_BASE_URL = "http://localhost:11434"
OLLAMA_DEFAULT_MODEL = "llama3.2"
HF_DEFAULT_MODEL = "meta-llama/Llama-3.1-8B-Instruct"

# Ranked preference for local Ollama models (best for security analysis first)
OLLAMA_MODEL_PREFERENCE = [
    "llama3.1:8b",
    "llama3.2",
    "llama3.2:3b",
    "qwen2.5:7b",
    "mistral:7b",
    "mistral",
    "gemma2:9b",
    "phi3:medium",
]


# ─── Provider detection ──────────────────────────────────────────────────────


def _check_litellm() -> bool:
    """Check if litellm is installed."""
    try:
        import litellm  # noqa: F401
        return True
    except ImportError:
        return False


def _check_huggingface() -> bool:
    """Check if huggingface-hub is installed with InferenceClient."""
    try:
        from huggingface_hub import InferenceClient  # noqa: F401
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
    1. If Ollama is running → pick best installed model from preference list
    2. If HF_TOKEN set + huggingface-hub installed → HuggingFace Inference API
    3. If OPENAI_API_KEY is set → ``openai/gpt-4o-mini``
    4. Fallback to default (will fail gracefully at call time)
    """
    if _detect_ollama():
        installed = _get_ollama_models()
        if installed:
            # Check preference list first
            for preferred in OLLAMA_MODEL_PREFERENCE:
                if preferred in installed:
                    return f"ollama/{preferred}"
                # Also match without tag (e.g. "llama3.2" matches "llama3.2:latest")
                base = preferred.split(":")[0]
                for inst in installed:
                    if inst.startswith(base):
                        return f"ollama/{inst}"
            # None from preference list — use first available
            return f"ollama/{installed[0]}"
        # Ollama running but no models pulled — fall through
    if _check_huggingface() and os.environ.get("HF_TOKEN"):
        return f"huggingface/{HF_DEFAULT_MODEL}"
    if os.environ.get("OPENAI_API_KEY"):
        return DEFAULT_MODEL
    return model


def _has_any_provider(model: str) -> bool:
    """Check if any LLM provider is available for the given model."""
    if model.startswith("ollama/"):
        return _detect_ollama() or _check_huggingface() or _check_litellm()
    if model.startswith("huggingface/"):
        return _check_huggingface()
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
        logger.warning("litellm not installed. Install with: pip install 'agent-bom[ai-enrich]'")
        return None
    except Exception as exc:
        logger.warning("LLM call failed: %s", exc)
        return None


async def _call_huggingface(
    prompt: str, model: str = HF_DEFAULT_MODEL, max_tokens: int = 500,
) -> Optional[str]:
    """Call HuggingFace Inference API (free tier available).

    Uses ``huggingface_hub.InferenceClient.chat_completion()``.
    Requires ``HF_TOKEN`` env var for gated models.
    """
    key = _cache_key(prompt, f"huggingface/{model}")
    if key in _cache:
        return _cache[key]

    try:
        from huggingface_hub import InferenceClient

        client = InferenceClient(
            model=model,
            token=os.environ.get("HF_TOKEN"),
        )
        # Run sync client in executor to avoid blocking event loop
        response = await asyncio.to_thread(
            client.chat_completion,
            messages=[{"role": "user", "content": prompt}],
            max_tokens=max_tokens,
            temperature=0.3,
        )
        text = response.choices[0].message.content.strip()
        if text:
            _cache[key] = text
            return text
        return None
    except ImportError:
        logger.warning("huggingface-hub not installed. Install with: pip install 'agent-bom[huggingface]'")
        return None
    except Exception as exc:
        logger.warning("HuggingFace call failed: %s", exc)
        return None


async def _call_llm(prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
    """Call LLM via the best available provider.

    Routing:
    - ``ollama/*`` models → Ollama direct → HuggingFace → litellm
    - ``huggingface/*`` models → HuggingFace directly
    - Other models → litellm
    """
    if model.startswith("ollama/"):
        bare_model = model[len("ollama/"):]
        result = await _call_ollama_direct(prompt, bare_model, max_tokens)
        if result is not None:
            return result
        # Fallback to HuggingFace
        if _check_huggingface():
            result = await _call_huggingface(prompt, max_tokens=max_tokens)
            if result is not None:
                return result
        # Fallback to litellm
        if _check_litellm():
            return await _call_llm_via_litellm(prompt, model, max_tokens)
        return None

    if model.startswith("huggingface/"):
        hf_model = model[len("huggingface/"):]
        return await _call_huggingface(prompt, model=hf_model, max_tokens=max_tokens)

    return await _call_llm_via_litellm(prompt, model, max_tokens)


# ─── Structured output ──────────────────────────────────────────────────────


def _parse_json_response(response: str) -> dict | None:
    """Parse a JSON response with 3 fallback strategies.

    1. Clean JSON
    2. Markdown-fenced JSON (```json ... ```)
    3. Brace-extraction from text

    Returns None for non-parseable responses.
    """
    if not response or not response.strip():
        return None

    text = response.strip()

    # Attempt 1: Parse as clean JSON directly
    try:
        data = json.loads(text)
        if isinstance(data, dict):
            return data
    except json.JSONDecodeError:
        pass

    # Attempt 2: Extract from markdown fencing
    fence_match = re.search(r"```(?:json)?\s*\n?(.*?)\n?\s*```", text, re.DOTALL)
    if fence_match:
        try:
            data = json.loads(fence_match.group(1))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    # Attempt 3: Find JSON object embedded in other text
    brace_match = re.search(r"\{.*\}", text, re.DOTALL)
    if brace_match:
        try:
            data = json.loads(brace_match.group(0))
            if isinstance(data, dict):
                return data
        except json.JSONDecodeError:
            pass

    return None


async def _call_ollama_structured(
    prompt: str, model: str, schema_cls: type, max_tokens: int = 500,
) -> Optional[object]:
    """Call Ollama with structured output via the ``format`` parameter.

    Passes the Pydantic schema's JSON schema to force valid JSON output.
    Falls back to None on error.
    """
    key = _cache_key(prompt, f"ollama/{model}:structured")
    if key in _cache:
        try:
            return schema_cls.model_validate_json(_cache[key])
        except Exception:
            pass

    try:
        json_schema = schema_cls.model_json_schema()
        async with httpx.AsyncClient(timeout=120.0) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": prompt}],
                    "stream": False,
                    "format": json_schema,
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
                    return schema_cls.model_validate_json(text)
        return None
    except Exception as exc:
        logger.debug("Structured Ollama call failed: %s, falling back to unstructured", exc)
        return None


async def _call_llm_structured(
    prompt: str, model: str, schema_cls: type, max_tokens: int = 500,
) -> Optional[object]:
    """Call LLM with structured output, falling back to unstructured + parse.

    Routing:
    1. ollama/* → ``_call_ollama_structured`` (native ``format`` param)
    2. Fallback: unstructured call + ``schema.model_validate_json()``
    """
    if model.startswith("ollama/"):
        bare_model = model[len("ollama/"):]
        result = await _call_ollama_structured(prompt, bare_model, schema_cls, max_tokens)
        if result is not None:
            return result

    # Fallback: unstructured call + parse
    raw = await _call_llm(prompt, model, max_tokens)
    if raw:
        # Try direct JSON parse
        try:
            return schema_cls.model_validate_json(raw)
        except Exception:
            pass
        # Try extracting from markdown/braces
        parsed = _parse_json_response(raw)
        if parsed:
            try:
                return schema_cls.model_validate(parsed)
            except Exception:
                pass
    return None


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
    skill_result: "SkillScanResult | None" = None,
    skill_audit: "SkillAuditResult | None" = None,
) -> None:
    """Run all AI enrichment steps on a report. Modifies report in-place."""
    # Auto-detect best model if using the default (which requires a paid key)
    if model == DEFAULT_MODEL:
        model = _resolve_model(model)

    # Determine provider for display
    if model.startswith("ollama/"):
        if not _detect_ollama():
            # Check HuggingFace fallback
            if _check_huggingface() and os.environ.get("HF_TOKEN"):
                model = f"huggingface/{HF_DEFAULT_MODEL}"
                provider = "HuggingFace Inference API (free)"
            elif _check_litellm():
                provider = "litellm (Ollama unavailable)"
            else:
                console.print("  [yellow]Ollama not running at localhost:11434. Skipping AI enrichment.[/yellow]")
                console.print("  [dim]Start with: ollama serve && ollama pull llama3.2[/dim]")
                console.print("  [dim]Or: pip install 'agent-bom[huggingface]' + set HF_TOKEN[/dim]")
                return
        else:
            provider = "Ollama (local, free)"
    elif model.startswith("huggingface/"):
        if not _check_huggingface():
            console.print("  [yellow]huggingface-hub not installed. pip install 'agent-bom[huggingface]'[/yellow]")
            return
        provider = "HuggingFace Inference API (free)"
    elif _check_litellm():
        provider = "litellm"
    else:
        console.print("  [yellow]No LLM provider available. Skipping AI enrichment.[/yellow]")
        console.print("  [dim]Option 1: Install Ollama (free, local) — ollama.com[/dim]")
        console.print("  [dim]Option 2: pip install 'agent-bom[huggingface]' + set HF_TOKEN[/dim]")
        console.print("  [dim]Option 3: pip install 'agent-bom[ai-enrich]' + set API key[/dim]")
        return

    console.print(f"\n[bold blue]AI Enrichment[/bold blue]  [dim]model: {model} via {provider}[/dim]\n")

    # Step 1: Enrich blast radii with contextual narratives
    if report.blast_radii:
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

    # Step 4: MCP config security analysis
    total_servers = sum(len(a.mcp_servers) for a in report.agents)
    if total_servers > 0:
        console.print("  [cyan]>[/cyan] Analyzing MCP config security...")
        config_analysis = await analyze_mcp_config_security(report, model)
        if config_analysis:
            report.mcp_config_analysis = config_analysis.model_dump()
            console.print(f"  [green]Config analysis complete (risk: {config_analysis.overall_risk})[/green]")

    # Step 5: Skill file AI analysis
    if skill_result and skill_audit and skill_result.raw_content:
        console.print("  [cyan]>[/cyan] Analyzing skill file security...")
        skill_enriched = await enrich_skill_audit(skill_result, skill_audit, model)
        if skill_enriched:
            console.print(f"  [green]Skill files analyzed (risk: {skill_audit.ai_overall_risk_level or 'unknown'})[/green]")
        else:
            console.print("  [dim]  Skill analysis could not be completed[/dim]")


def run_ai_enrichment_sync(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    skill_result: "SkillScanResult | None" = None,
    skill_audit: "SkillAuditResult | None" = None,
) -> None:
    """Synchronous wrapper for run_ai_enrichment."""
    asyncio.run(run_ai_enrichment(report, model, skill_result, skill_audit))


# ─── Skill file AI analysis ──────────────────────────────────────────────────


_VALID_SEVERITIES = {"critical", "high", "medium", "low"}


def _build_skill_analysis_prompt(raw_content: dict[str, str], static_findings: list[dict]) -> str:
    """Build a prompt that sends raw skill file text + static findings to the LLM.

    The prompt asks the model to classify intent, review existing findings,
    detect new threats, and assess overall risk.
    """
    # Truncate each file to 6000 chars to stay within context limits
    file_sections = []
    for filepath, content in raw_content.items():
        truncated = content[:6000]
        if len(content) > 6000:
            truncated += "\n... [truncated]"
        file_sections.append(f"### File: {filepath}\n```\n{truncated}\n```")

    files_text = "\n\n".join(file_sections)

    findings_text = json.dumps(static_findings, indent=2) if static_findings else "[]"

    return (
        "You are an AI security auditor specializing in analyzing skill files "
        "(also called rules files, instruction files, or CLAUDE.md / .cursorrules / "
        "copilot-instructions.md files). These are instructions that developers write "
        "for AI coding assistants — they control how the AI behaves in a project.\n\n"
        "IMPORTANT CONTEXT: A line saying 'never bind to 0.0.0.0' is a SAFETY "
        "instruction, not a risk. A line saying 'always use 0.0.0.0 for the server' "
        "is a RISKY directive. You must distinguish between warnings/safety guidance "
        "and dangerous directives.\n\n"
        "## Raw skill file content\n\n"
        f"{files_text}\n\n"
        "## Static analysis findings\n\n"
        f"{findings_text}\n\n"
        "## Your tasks\n\n"
        "(a) **Intent classification**: For each notable instruction in the files, "
        "classify it as a 'warning' (safety guidance) or 'directive' (tells the AI to do something).\n\n"
        "(b) **Review static findings**: For each static finding above, provide a verdict: "
        "'confirmed' (real risk), 'false_positive' (not actually risky), or "
        "'severity_adjusted' (real but severity should change). Explain your reasoning.\n\n"
        "(c) **Detect new threats**: Look for threats the static analysis may have missed, "
        "including: social_engineering, prompt_injection, credential_harvesting, "
        "supply_chain, permission_escalation, data_exfiltration, obfuscation.\n\n"
        "(d) **Overall risk assessment**: Rate the overall risk as 'critical', 'high', "
        "'medium', 'low', or 'safe' and provide a 2-3 sentence summary.\n\n"
        "Respond with ONLY a JSON object (no markdown fencing, no extra text) with these keys:\n"
        "- overall_risk_level: string ('critical'|'high'|'medium'|'low'|'safe')\n"
        "- summary: string (2-3 sentence overall assessment)\n"
        "- finding_reviews: list of objects, each with:\n"
        "    - title: string (matching the static finding title)\n"
        "    - verdict: 'confirmed' | 'false_positive' | 'severity_adjusted'\n"
        "    - adjusted_severity: string | null (only if severity_adjusted)\n"
        "    - reasoning: string\n"
        "- new_findings: list of objects, each with:\n"
        "    - severity: 'critical' | 'high' | 'medium' | 'low'\n"
        "    - category: string (one of the threat categories above)\n"
        "    - title: string\n"
        "    - detail: string\n"
        "    - recommendation: string"
    )


def _parse_skill_analysis_response(response: str) -> dict | None:
    """Parse the LLM's skill analysis JSON response.

    Uses the generic ``_parse_json_response`` and validates that the result
    contains the expected ``overall_risk_level`` key.
    """
    data = _parse_json_response(response)
    if data and "overall_risk_level" in data:
        return data
    logger.warning("Could not parse skill analysis LLM response as JSON")
    return None


def _apply_skill_analysis(audit: "SkillAuditResult", ai_data: dict) -> None:
    """Apply parsed AI analysis results to a SkillAuditResult in-place.

    Updates existing findings with AI verdicts, adds new AI-detected findings,
    and recalculates the pass/fail status.
    """
    from agent_bom.parsers.skill_audit import SkillFinding

    # Set top-level AI fields
    audit.ai_overall_risk_level = ai_data.get("overall_risk_level")
    audit.ai_skill_summary = ai_data.get("summary")

    # Build a lookup of existing findings by title for matching
    findings_by_title: dict[str, SkillFinding] = {}
    for finding in audit.findings:
        findings_by_title[finding.title] = finding

    # Apply finding reviews
    for review in ai_data.get("finding_reviews", []):
        title = review.get("title") or review.get("original_title", "")
        matched = findings_by_title.get(title)
        if not matched:
            continue

        verdict = review.get("verdict", "confirmed")
        reasoning = review.get("reasoning", "")
        matched.ai_analysis = reasoning

        if verdict == "false_positive":
            matched.ai_adjusted_severity = "false_positive"
        elif verdict == "severity_adjusted":
            adjusted = review.get("adjusted_severity")
            if adjusted and adjusted.lower() in _VALID_SEVERITIES:
                matched.ai_adjusted_severity = adjusted.lower()

    # Add new AI-detected findings
    for new in ai_data.get("new_findings", []):
        severity = new.get("severity", "medium").lower()
        if severity not in _VALID_SEVERITIES:
            severity = "medium"

        source_file = next(iter(audit.findings), None)
        source = source_file.source_file if source_file else "unknown"

        audit.findings.append(SkillFinding(
            severity=severity,
            category=new.get("category", "ai_detected"),
            title=new.get("title", "AI-detected finding"),
            detail=new.get("detail", ""),
            source_file=source,
            recommendation=new.get("recommendation", ""),
            context="ai_analysis",
        ))

    # Recalculate passed status: false_positive findings don't count
    audit.passed = not any(
        f.severity in ("critical", "high")
        and f.ai_adjusted_severity != "false_positive"
        for f in audit.findings
    )


async def enrich_skill_audit(
    skill_result: "SkillScanResult",
    skill_audit: "SkillAuditResult",
    model: str = DEFAULT_MODEL,
) -> bool:
    """Orchestrate AI-powered skill file security analysis.

    Sends raw skill file content and static findings to an LLM for
    context-aware analysis, then applies the results to the audit.

    Returns True if enrichment was applied, False otherwise.
    """
    # Guard: need raw content to analyze
    if not skill_result.raw_content:
        logger.debug("No raw content available for skill AI enrichment")
        return False

    # Guard: need an LLM provider
    resolved_model = model
    if model == DEFAULT_MODEL:
        resolved_model = _resolve_model(model)

    if not _has_any_provider(resolved_model):
        logger.debug("No LLM provider available for skill enrichment")
        return False

    # Serialize static findings as list of dicts
    static_findings = [
        {
            "severity": f.severity,
            "category": f.category,
            "title": f.title,
            "detail": f.detail,
            "source_file": f.source_file,
            "context": f.context,
        }
        for f in skill_audit.findings
    ]

    # Build prompt and call LLM
    prompt = _build_skill_analysis_prompt(skill_result.raw_content, static_findings)
    response = await _call_llm(prompt, resolved_model, max_tokens=1500)

    if not response:
        logger.warning("LLM returned empty response for skill analysis")
        return False

    # Parse and apply
    ai_data = _parse_skill_analysis_response(response)
    if ai_data is None:
        logger.warning("Could not parse LLM skill analysis response")
        return False

    _apply_skill_analysis(skill_audit, ai_data)
    return True


# ─── MCP config security analysis ──────────────────────────────────────────


def _build_mcp_config_analysis_prompt(report: "AIBOMReport") -> str:
    """Build a prompt for LLM-powered MCP configuration security analysis.

    Examines the full server configuration (not individual CVEs) for
    architectural security risks.
    """
    server_configs = []
    for agent in report.agents[:20]:
        for server in agent.mcp_servers[:10]:
            creds = server.credential_names
            tools = [t.name for t in server.tools[:10]]
            server_configs.append(
                f"- Server: {server.name}\n"
                f"  Command: {server.command} {' '.join(server.args[:5])}\n"
                f"  Transport: {server.transport.value}\n"
                f"  Tools: {', '.join(tools) or 'unknown'}\n"
                f"  Credentials: {', '.join(creds) or 'none'}\n"
                f"  Agent: {agent.name} ({agent.agent_type.value})"
            )

    return (
        "You are an AI infrastructure security analyst specializing in MCP "
        "(Model Context Protocol) configurations. Analyze these MCP server "
        "configurations for security risks.\n\n"
        f"MCP Server Configurations:\n"
        f"{chr(10).join(server_configs)}\n\n"
        "Analyze for:\n"
        "1. **Missing authentication**: Servers with no credential env vars "
        "that expose write/execute tools\n"
        "2. **Overly permissive access**: Servers with filesystem write, "
        "shell exec, or database write tools\n"
        "3. **Credential exposure**: Multiple high-privilege credentials on "
        "a single server (blast radius risk)\n"
        "4. **Suspicious patterns**: AWM-generated environments (fastapi-mcp "
        "with no auth), unverified servers with critical tools\n"
        "5. **Transport risks**: SSE/HTTP servers without TLS\n\n"
        "Respond with ONLY a JSON object with these keys:\n"
        "- overall_risk: string ('Critical'|'High'|'Medium'|'Low')\n"
        "- summary: string (2-3 sentence assessment)\n"
        "- findings: list of objects, each with:\n"
        "    - severity: 'critical'|'high'|'medium'|'low'\n"
        "    - category: string (e.g. auth_missing, overpermissive, "
        "credential_exposure, awm_pattern, transport_risk)\n"
        "    - title: string\n"
        "    - detail: string\n"
        "    - recommendation: string"
    )


async def analyze_mcp_config_security(
    report: "AIBOMReport",
    model: str = DEFAULT_MODEL,
) -> Optional["MCPConfigSecurityAnalysis"]:
    """Run LLM-powered MCP configuration security analysis.

    Examines the full configuration surface — not individual CVEs — for
    architectural security risks like missing auth, overpermission, AWM patterns.
    """
    from agent_bom.ai_schemas import MCPConfigSecurityAnalysis

    total_servers = sum(len(a.mcp_servers) for a in report.agents)
    if total_servers == 0:
        return None
    if not _has_any_provider(model):
        return None

    prompt = _build_mcp_config_analysis_prompt(report)

    # Try structured output first
    result = await _call_llm_structured(prompt, model, MCPConfigSecurityAnalysis, max_tokens=1000)
    if result:
        return result

    # Fallback to unstructured
    raw = await _call_llm(prompt, model, max_tokens=1000)
    if raw:
        parsed = _parse_json_response(raw)
        if parsed:
            try:
                return MCPConfigSecurityAnalysis.model_validate(parsed)
            except Exception:
                pass
    return None
