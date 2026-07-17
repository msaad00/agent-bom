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
import random
import re
import threading
from contextvars import ContextVar
from dataclasses import dataclass, field
from enum import Enum
from typing import TYPE_CHECKING, Awaitable, Callable, Optional, TypeVar

import httpx
from rich.console import Console

from agent_bom import config
from agent_bom.config import AI_CACHE_MAX_ENTRIES as _MAX_AI_CACHE
from agent_bom.config import OLLAMA_BASE_URL
from agent_bom.security import sanitize_command_args

if TYPE_CHECKING:
    from pydantic import BaseModel

    from agent_bom.ai_schemas import MCPConfigSecurityAnalysis
    from agent_bom.finding import Finding
    from agent_bom.models import AIBOMReport, BlastRadius
    from agent_bom.parsers.skill_audit import SkillAuditResult
    from agent_bom.parsers.skills import SkillScanResult

console = Console(stderr=True)
logger = logging.getLogger(__name__)

# Simple in-memory cache: hash(prompt) -> response (bounded)
_cache: dict[str, str] = {}
_cache_lock = threading.RLock()


def _response_text(value: object) -> str:
    """Return stripped provider text only when the provider returned a string."""
    return value.strip() if isinstance(value, str) else ""


def _ai_cache_get(key: str) -> str | None:
    """Read a cached AI response with synchronization."""
    with _cache_lock:
        return _cache.get(key)


def _ai_cache_put(key: str, value: str) -> None:
    """Insert into bounded AI response cache."""
    with _cache_lock:
        _cache[key] = value
        if len(_cache) > _MAX_AI_CACHE:
            for k in list(_cache.keys())[: len(_cache) - _MAX_AI_CACHE]:
                del _cache[k]


DEFAULT_MODEL = "openai/gpt-4o-mini"
OLLAMA_DEFAULT_MODEL = "llama3.2"
HF_DEFAULT_MODEL = "meta-llama/Llama-3.1-8B-Instruct"

# Ranked preference for local Ollama models (best for security analysis first)
OLLAMA_MODEL_PREFERENCE = [
    "llama3.1:8b",
    "llama3.2",
    "llama3.2:3b",
    "qwen2.5:7b",
    "glm4:9b",
    "glm4",
    "mistral:7b",
    "mistral",
    "gemma2:9b",
    "phi3:medium",
]


@dataclass(frozen=True, slots=True)
class AIProviderDescriptor:
    """Public, non-secret provider contract for AI enrichment."""

    name: str
    display_name: str
    local: bool
    requires_network: bool
    required_env: tuple[str, ...] = ()
    optional_extra: str = ""
    supports_structured_output: bool = False

    def to_dict(self) -> dict[str, object]:
        return {
            "name": self.name,
            "display_name": self.display_name,
            "local": self.local,
            "requires_network": self.requires_network,
            "required_env": list(self.required_env),
            "optional_extra": self.optional_extra,
            "supports_structured_output": self.supports_structured_output,
        }


@dataclass(frozen=True, slots=True)
class AIProviderStatus:
    """Availability status without leaking configured token values."""

    descriptor: AIProviderDescriptor
    installed: bool
    configured: bool
    available: bool
    reason: str

    def to_dict(self) -> dict[str, object]:
        payload = self.descriptor.to_dict()
        payload.update(
            {
                "installed": self.installed,
                "configured": self.configured,
                "available": self.available,
                "reason": self.reason,
            }
        )
        return payload


@dataclass(frozen=True, slots=True)
class AIProviderResolution:
    """Resolved provider/model decision for one enrichment run."""

    requested_model: str
    model: str
    provider: AIProviderDescriptor | None
    available: bool
    status: str
    reason: str = ""
    fallback_from: str | None = None

    def to_metadata(self) -> dict[str, object]:
        return {
            "schema_version": "1",
            "requested_model": self.requested_model,
            "model": self.model,
            "provider": self.provider.name if self.provider else None,
            "provider_display_name": self.provider.display_name if self.provider else None,
            "local": self.provider.local if self.provider else False,
            "requires_network": self.provider.requires_network if self.provider else False,
            "status": self.status,
            "reason": self.reason,
            "fallback_from": self.fallback_from,
        }


AI_PROVIDER_DESCRIPTORS: dict[str, AIProviderDescriptor] = {
    "ollama": AIProviderDescriptor(
        name="ollama",
        display_name="Ollama",
        local=True,
        requires_network=False,
        optional_extra="core",
        supports_structured_output=True,
    ),
    "huggingface": AIProviderDescriptor(
        name="huggingface",
        display_name="HuggingFace Inference API",
        local=False,
        requires_network=True,
        required_env=("HF_TOKEN",),
        optional_extra="huggingface",
    ),
    "litellm": AIProviderDescriptor(
        name="litellm",
        display_name="litellm",
        local=False,
        requires_network=True,
        optional_extra="ai-enrich",
    ),
}


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
    except (httpx.HTTPError, ValueError, KeyError):
        pass
    return []


def _provider_name_for_model(model: str) -> str:
    if model.startswith("ollama/"):
        return "ollama"
    if model.startswith("huggingface/"):
        return "huggingface"
    return "litellm"


def _provider_status(provider_name: str) -> AIProviderStatus:
    descriptor = AI_PROVIDER_DESCRIPTORS[provider_name]
    if provider_name == "ollama":
        available = _detect_ollama()
        return AIProviderStatus(
            descriptor=descriptor,
            installed=True,
            configured=available,
            available=available,
            reason="available" if available else "ollama is not reachable at the configured local endpoint",
        )
    if provider_name == "huggingface":
        installed = _check_huggingface()
        configured = bool(os.environ.get("HF_TOKEN"))
        return AIProviderStatus(
            descriptor=descriptor,
            installed=installed,
            configured=configured,
            available=installed and configured,
            reason="available" if installed and configured else "huggingface-hub and HF_TOKEN are required for HuggingFace enrichment",
        )
    installed = _check_litellm()
    return AIProviderStatus(
        descriptor=descriptor,
        installed=installed,
        configured=installed,
        available=installed,
        reason="available" if installed else "litellm is not installed",
    )


def describe_ai_providers() -> list[dict[str, object]]:
    """Return non-secret provider capability and availability metadata."""
    return [_provider_status(name).to_dict() for name in ("ollama", "huggingface", "litellm")]


def _resolve_ai_provider(model: str = DEFAULT_MODEL) -> AIProviderResolution:
    """Resolve the provider/model used by AI enrichment with explicit fallback metadata."""
    requested_model = model
    resolved_model = _resolve_model(model) if model == DEFAULT_MODEL else model
    preferred_name = _provider_name_for_model(resolved_model)
    preferred_status = _provider_status(preferred_name)
    if preferred_status.available:
        return AIProviderResolution(
            requested_model=requested_model,
            model=resolved_model,
            provider=preferred_status.descriptor,
            available=True,
            status="active",
        )

    if preferred_name == "ollama":
        hf_status = _provider_status("huggingface")
        if hf_status.available:
            return AIProviderResolution(
                requested_model=requested_model,
                model=f"huggingface/{HF_DEFAULT_MODEL}",
                provider=hf_status.descriptor,
                available=True,
                status="active",
                fallback_from=resolved_model,
            )
        litellm_status = _provider_status("litellm")
        if litellm_status.available:
            return AIProviderResolution(
                requested_model=requested_model,
                model=resolved_model,
                provider=litellm_status.descriptor,
                available=True,
                status="active",
                fallback_from=resolved_model,
            )

    return AIProviderResolution(
        requested_model=requested_model,
        model=resolved_model,
        provider=preferred_status.descriptor,
        available=False,
        status="unavailable",
        reason=preferred_status.reason,
    )


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
    return _resolve_ai_provider(model).available


# ─── Secret redaction (no-exfiltration-by-default) ───────────────────────────
#
# Issue #3206 hard requirement #4: redact secrets before any prompt leaves the
# control plane. These patterns cover the credential shapes most likely to be
# swept into a prompt from scanned configs, env blocks, or source snippets.
# Redaction runs at every provider network boundary, so it protects local
# Ollama calls as well as remote providers.

# Prefix / block patterns, in priority order (more specific first — e.g.
# ``sk-ant-`` must run before the generic ``sk-``).
_SECRET_PATTERNS: tuple[tuple[re.Pattern[str], str], ...] = (
    # Private key blocks (PEM)
    (re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.DOTALL), "<redacted-private-key>"),
    # Provider API keys / tokens with recognizable prefixes
    (re.compile(r"\bsk-ant-[A-Za-z0-9_-]{16,}\b"), "<redacted-anthropic-key>"),
    (re.compile(r"\bsk-[A-Za-z0-9_-]{16,}\b"), "<redacted-openai-key>"),
    (re.compile(r"\b(?:ghp|gho|ghu|ghs|ghr|github_pat)_[A-Za-z0-9_]{16,}\b"), "<redacted-github-token>"),
    (re.compile(r"\bxox[baprs]-[A-Za-z0-9-]{10,}\b"), "<redacted-slack-token>"),
    (re.compile(r"\bAKIA[0-9A-Z]{16}\b"), "<redacted-aws-access-key>"),
    (re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b"), "<redacted-google-key>"),
    (re.compile(r"\bhf_[A-Za-z0-9]{20,}\b"), "<redacted-hf-token>"),
    # Bearer tokens in headers / auth strings
    (re.compile(r"(?i)\bbearer\s+[A-Za-z0-9._\-]{16,}"), "Bearer <redacted-token>"),
)

# KEY=VALUE / "key": "value" assignments for secret-named variables. Handled
# separately with a value heuristic so we don't clobber credential *names*
# (e.g. ``Exposed credentials: OPENAI_API_KEY``) that appear as values.
_ASSIGNMENT_PATTERN = re.compile(
    r"(?i)\b([A-Za-z0-9_]*(?:secret|token|password|passwd|api[_-]?key|access[_-]?key|private[_-]?key|credential)[A-Za-z0-9_]*)\b"
    r"(\s*[:=]\s*)(['\"]?)([^\s'\";,}]{6,})(\3)"
)

# A bare UPPER_SNAKE_CASE identifier is a variable *name*, not a secret value.
_IDENTIFIER_RE = re.compile(r"^[A-Z][A-Z0-9_]*$")


def _looks_like_secret_value(value: str) -> bool:
    """Heuristic: does a captured assignment value look like an actual secret?

    Rejects bare identifiers (``OPENAI_API_KEY``, ``DATABASE_URL``) that are
    names rather than values; accepts strings with real entropy.
    """
    if _IDENTIFIER_RE.match(value):
        return False
    # Real secrets mix character classes or are long — require a lowercase
    # letter or digit alongside length so ALL_CAPS words are left alone.
    return len(value) >= 6 and bool(re.search(r"[a-z0-9]", value))


def _redact_assignment(match: re.Match[str]) -> str:
    name, sep, quote, value, _ = match.groups()
    if not _looks_like_secret_value(value):
        return match.group(0)
    return f"{name}{sep}{quote}<redacted>{quote}"


def redact_secrets(text: str) -> str:
    """Scrub secret-looking material from *text* before it reaches a model.

    Idempotent and conservative: it targets recognizable credential shapes
    (API keys, tokens, private keys, ``SECRET=...`` assignments) and leaves the
    surrounding text — including credential *names* like ``OPENAI_API_KEY`` —
    intact so the model still has useful context.
    """
    if not text:
        return text
    for pattern, replacement in _SECRET_PATTERNS:
        text = pattern.sub(replacement, text)
    text = _ASSIGNMENT_PATTERN.sub(_redact_assignment, text)
    return text


def _prepare_prompt(prompt: str) -> str:
    """Apply redaction to an outbound prompt when enabled by config."""
    if getattr(config, "AI_REDACT_PROMPTS", True):
        return redact_secrets(prompt)
    return prompt


# ─── Determinism + reliability helpers ───────────────────────────────────────


def _effective_temperature() -> float:
    """Temperature for a call: 0.0 in deterministic mode, else configured."""
    deterministic = _AI_DETERMINISTIC_OVERRIDE.get()
    if deterministic is None:
        deterministic = bool(getattr(config, "AI_DETERMINISTIC", False))
    if deterministic:
        return 0.0
    return float(getattr(config, "AI_TEMPERATURE", 0.3))


_AI_DETERMINISTIC_OVERRIDE: ContextVar[bool | None] = ContextVar("ai_deterministic_override", default=None)


def _request_timeout() -> float:
    return float(getattr(config, "AI_REQUEST_TIMEOUT", 120.0))


_T = TypeVar("_T")

# Exceptions worth retrying — transient network / server-side conditions.
_RETRYABLE_EXC = (httpx.TimeoutException, httpx.ConnectError, httpx.ReadError, httpx.RemoteProtocolError)


async def retry_async(
    func: Callable[[], Awaitable[Optional[_T]]],
    *,
    max_retries: int | None = None,
    base_delay: float | None = None,
    max_delay: float | None = None,
    retry_on: tuple[type[BaseException], ...] = _RETRYABLE_EXC,
    label: str = "llm-call",
) -> Optional[_T]:
    """Call *func* with bounded exponential backoff + jitter.

    Returns the first non-None result. On a retryable exception it backs off and
    retries; once retries are exhausted (or a non-retryable exception fires) it
    returns None so the enrichment layer degrades gracefully rather than raising.
    """
    attempts = (max_retries if max_retries is not None else getattr(config, "AI_MAX_RETRIES", 2)) + 1
    base = base_delay if base_delay is not None else getattr(config, "AI_RETRY_BASE_DELAY", 0.5)
    ceiling = max_delay if max_delay is not None else getattr(config, "AI_RETRY_MAX_DELAY", 8.0)

    for attempt in range(attempts):
        try:
            result = await func()
        except retry_on as exc:
            if attempt >= attempts - 1:
                logger.warning("%s failed after %d attempt(s): %s", label, attempt + 1, exc)
                return None
            delay = min(base * (2**attempt), ceiling) + random.uniform(0, base)
            logger.debug("%s retry %d/%d after %.2fs (%s)", label, attempt + 1, attempts - 1, delay, exc)
            await asyncio.sleep(delay)
            continue
        except Exception as exc:  # non-retryable — degrade, don't raise
            logger.warning("%s failed (non-retryable): %s", label, exc)
            return None
        if result is not None:
            return result
        return None
    return None


# ─── Per-task model selection ────────────────────────────────────────────────
#
# Different enrichment tasks warrant different models: a cheap local model is
# fine for tagging and summaries; detection and remediation benefit from a
# stronger model. Operators pin these per-deployment via config; unset tiers
# fall back to the single auto-resolved model (legacy behavior).


class EnrichmentTask(str, Enum):
    """Kinds of enrichment work, used to pick a per-task model + provenance."""

    NARRATIVE = "narrative"  # blast-radius risk narratives
    SUMMARY = "summary"  # executive summaries
    TAGGING = "tagging"  # compliance / control classification (cheap)
    DETECTION = "detection"  # LLM-assisted novel-issue detection (strong)
    TRIAGE = "triage"  # FP reduction / dedup (strong)
    CONFIG_ANALYSIS = "config_analysis"  # MCP config security review


@dataclass
class AICallBudget:
    """Run-wide LLM call budget shared by all enrichment tasks."""

    max_calls: int = 50
    calls_used: int = 0
    calls_by_task: dict[str, int] = field(default_factory=dict)

    def try_consume(self, task: EnrichmentTask) -> bool:
        if self.max_calls > 0 and self.calls_used >= self.max_calls:
            return False
        self.calls_used += 1
        self.calls_by_task[task.value] = self.calls_by_task.get(task.value, 0) + 1
        return True

    def to_dict(self) -> dict[str, object]:
        remaining = None if self.max_calls <= 0 else max(self.max_calls - self.calls_used, 0)
        return {
            "max_calls": self.max_calls,
            "calls_used": self.calls_used,
            "calls_remaining": remaining,
            "exhausted": self.max_calls > 0 and self.calls_used >= self.max_calls,
            "calls_by_task": dict(sorted(self.calls_by_task.items())),
        }


# Which tier each task prefers when tiered models are configured.
_TASK_TIER: dict[EnrichmentTask, str] = {
    EnrichmentTask.NARRATIVE: "cheap",
    EnrichmentTask.SUMMARY: "cheap",
    EnrichmentTask.TAGGING: "cheap",
    EnrichmentTask.DETECTION: "strong",
    EnrichmentTask.TRIAGE: "strong",
    EnrichmentTask.CONFIG_ANALYSIS: "strong",
}


def resolve_task_model(task: EnrichmentTask, default_model: str = DEFAULT_MODEL) -> str:
    """Resolve the model to use for *task*.

    Precedence: an explicitly-configured per-tier model (cheap/strong) wins;
    otherwise fall back to *default_model* (which itself auto-detects Ollama /
    HF / litellm via :func:`_resolve_ai_provider`).
    """
    tier = _TASK_TIER.get(task, "strong")
    configured = getattr(config, "AI_MODEL_STRONG" if tier == "strong" else "AI_MODEL_CHEAP", "")
    if configured:
        return configured
    return default_model


# ─── Provider abstraction + registry ─────────────────────────────────────────
#
# A thin, uniform interface over the three backends so callers (and tests) can
# treat providers polymorphically. The concrete adapters wrap the existing
# ``_call_*`` functions, keeping one code path for the actual network calls.


class EnrichmentProvider:
    """Uniform provider contract for the enrichment harness.

    Subclasses expose availability + a single ``generate`` coroutine. Redaction,
    caching, retries and timeouts are handled inside the wrapped ``_call_*``
    functions, so adapters stay thin.
    """

    descriptor: AIProviderDescriptor

    def is_available(self) -> bool:  # pragma: no cover - trivial
        raise NotImplementedError

    async def generate(self, prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:  # pragma: no cover
        raise NotImplementedError

    @property
    def name(self) -> str:
        return self.descriptor.name


class OllamaProvider(EnrichmentProvider):
    descriptor = AI_PROVIDER_DESCRIPTORS["ollama"]

    def is_available(self) -> bool:
        return _detect_ollama()

    async def generate(self, prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
        bare = model[len("ollama/") :] if model.startswith("ollama/") else model
        return await _call_ollama_direct(prompt, bare, max_tokens)


class HuggingFaceProvider(EnrichmentProvider):
    descriptor = AI_PROVIDER_DESCRIPTORS["huggingface"]

    def is_available(self) -> bool:
        return _check_huggingface() and bool(os.environ.get("HF_TOKEN"))

    async def generate(self, prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
        hf_model = model[len("huggingface/") :] if model.startswith("huggingface/") else model
        return await _call_huggingface(prompt, model=hf_model or HF_DEFAULT_MODEL, max_tokens=max_tokens)


class LiteLLMProvider(EnrichmentProvider):
    descriptor = AI_PROVIDER_DESCRIPTORS["litellm"]

    def is_available(self) -> bool:
        return _check_litellm()

    async def generate(self, prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
        return await _call_llm_via_litellm(prompt, model, max_tokens)


PROVIDER_REGISTRY: dict[str, EnrichmentProvider] = {
    "ollama": OllamaProvider(),
    "huggingface": HuggingFaceProvider(),
    "litellm": LiteLLMProvider(),
}


def get_provider(name: str) -> EnrichmentProvider:
    """Return the registered provider adapter by name (KeyError if unknown)."""
    return PROVIDER_REGISTRY[name]


def provider_for_model(model: str) -> EnrichmentProvider:
    """Return the provider adapter that owns *model* by its prefix."""
    return PROVIDER_REGISTRY[_provider_name_for_model(model)]


# ─── LLM calls ───────────────────────────────────────────────────────────────


def _cache_key(prompt: str, model: str) -> str:
    return hashlib.sha256(f"{model}:{prompt}".encode()).hexdigest()


async def _call_ollama_direct(prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
    """Call Ollama directly via HTTP API (no litellm dependency needed).

    The *model* parameter is the bare model name (e.g. ``llama3.2``).
    """
    key = _cache_key(prompt, f"ollama/{model}")
    cached = _ai_cache_get(key)
    if cached is not None:
        return cached

    outbound = _prepare_prompt(prompt)
    try:
        async with httpx.AsyncClient(timeout=_request_timeout()) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": outbound}],
                    "stream": False,
                    "options": {
                        "num_predict": max_tokens,
                        "temperature": _effective_temperature(),
                    },
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                message = data.get("message", {})
                content = message.get("content") if isinstance(message, dict) else None
                text = _response_text(content)
                if text:
                    _ai_cache_put(key, text)
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
    cached = _ai_cache_get(key)
    if cached is not None:
        return cached

    outbound = _prepare_prompt(prompt)

    async def _once() -> Optional[str]:
        try:
            from litellm import acompletion
        except ImportError:
            logger.warning("litellm not installed. Install with: pip install 'agent-bom[ai-enrich]'")
            return None
        response = await acompletion(
            model=model,
            messages=[{"role": "user", "content": outbound}],
            max_tokens=max_tokens,
            temperature=_effective_temperature(),
            timeout=_request_timeout(),
        )
        text = _response_text(response.choices[0].message.content)
        return text or None

    text = await retry_async(_once, retry_on=(Exception,), label=f"litellm:{model}")
    if text:
        _ai_cache_put(key, text)
    return text


async def _call_huggingface(
    prompt: str,
    model: str = HF_DEFAULT_MODEL,
    max_tokens: int = 500,
) -> Optional[str]:
    """Call HuggingFace Inference API (free tier available).

    Uses ``huggingface_hub.InferenceClient.chat_completion()``.
    Requires ``HF_TOKEN`` env var for gated models.
    """
    key = _cache_key(prompt, f"huggingface/{model}")
    cached = _ai_cache_get(key)
    if cached is not None:
        return cached

    outbound = _prepare_prompt(prompt)

    async def _once() -> Optional[str]:
        try:
            from huggingface_hub import InferenceClient
        except ImportError:
            logger.warning("huggingface-hub not installed. Install with: pip install 'agent-bom[huggingface]'")
            return None
        client = InferenceClient(model=model, token=os.environ.get("HF_TOKEN"))
        # Run sync client in executor to avoid blocking event loop
        response = await asyncio.to_thread(
            client.chat_completion,
            messages=[{"role": "user", "content": outbound}],
            max_tokens=max_tokens,
            temperature=_effective_temperature(),
        )
        return _response_text(response.choices[0].message.content) or None

    text = await retry_async(_once, retry_on=(Exception,), label=f"huggingface:{model}")
    if text:
        _ai_cache_put(key, text)
    return text


async def _call_llm(prompt: str, model: str, max_tokens: int = 500) -> Optional[str]:
    """Call LLM via the best available provider.

    Routing:
    - ``ollama/*`` models → Ollama direct → HuggingFace → litellm
    - ``huggingface/*`` models → HuggingFace directly
    - Other models → litellm
    """
    if model.startswith("ollama/"):
        bare_model = model[len("ollama/") :]
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
        hf_model = model[len("huggingface/") :]
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
    prompt: str,
    model: str,
    schema_cls: type[BaseModel],
    max_tokens: int = 500,
) -> Optional[BaseModel]:
    """Call Ollama with structured output via the ``format`` parameter.

    Passes the Pydantic schema's JSON schema to force valid JSON output.
    Falls back to None on error.
    """
    key = _cache_key(prompt, f"ollama/{model}:structured")
    cached = _ai_cache_get(key)
    if cached is not None:
        try:
            return schema_cls.model_validate_json(cached)
        except (json.JSONDecodeError, ValueError, AttributeError):
            pass

    try:
        json_schema = schema_cls.model_json_schema()
        outbound = _prepare_prompt(prompt)
        async with httpx.AsyncClient(timeout=_request_timeout()) as client:
            resp = await client.post(
                f"{OLLAMA_BASE_URL}/api/chat",
                json={
                    "model": model,
                    "messages": [{"role": "user", "content": outbound}],
                    "stream": False,
                    "format": json_schema,
                    "options": {
                        "num_predict": max_tokens,
                        "temperature": _effective_temperature(),
                    },
                },
            )
            if resp.status_code == 200:
                data = resp.json()
                text = data.get("message", {}).get("content", "").strip()
                if text:
                    _ai_cache_put(key, text)
                    return schema_cls.model_validate_json(text)
        return None
    except Exception as exc:
        logger.debug("Structured Ollama call failed: %s, falling back to unstructured", exc)
        return None


async def _call_llm_structured(
    prompt: str,
    model: str,
    schema_cls: type[BaseModel],
    max_tokens: int = 500,
) -> Optional[BaseModel]:
    """Call LLM with structured output, falling back to unstructured + parse.

    Routing:
    1. ollama/* → ``_call_ollama_structured`` (native ``format`` param)
    2. Fallback: unstructured call + ``schema.model_validate_json()``
    """
    if model.startswith("ollama/"):
        bare_model = model[len("ollama/") :]
        result = await _call_ollama_structured(prompt, bare_model, schema_cls, max_tokens)
        if result is not None:
            return result

    # Fallback: unstructured call + parse
    raw = await _call_llm(prompt, model, max_tokens)
    if raw:
        # Try direct JSON parse
        try:
            return schema_cls.model_validate_json(raw)
        except (json.JSONDecodeError, ValueError):
            pass
        # Try extracting from markdown/braces
        parsed = _parse_json_response(raw)
        if parsed:
            try:
                return schema_cls.model_validate(parsed)
            except (ValueError, TypeError):
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
    critical_ids = [br.vulnerability.id for br in report.blast_radii[:5] if br.vulnerability.severity.value == "critical"]
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
            f"- {br.vulnerability.id} in {br.package.name}@{br.package.version} | agents: {agents} | tools: {tools} | creds: {creds}"
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


# ─── Enrichment functions ────────────────────────────────────────────────────


_DEFAULT_AI_MAX_CALLS = 50  # Hard cap: prevent runaway spend on large monorepos


async def enrich_blast_radii(
    blast_radii: list[BlastRadius],
    model: str = DEFAULT_MODEL,
    max_calls: int = _DEFAULT_AI_MAX_CALLS,
    budget: AICallBudget | None = None,
) -> int:
    """Add AI-generated risk narratives to blast radius findings.

    Groups findings by package to minimize API calls (one call per unique
    package, regardless of how many CVEs affect it).

    ``max_calls`` caps total LLM requests per scan run to prevent runaway
    API spend on large monorepos.  Defaults to 50; pass ``max_calls=0`` to
    disable the cap.  Returns count of enriched findings.
    """
    if not blast_radii:
        return 0
    if not _has_any_provider(model):
        return 0

    enriched = 0
    calls_made = 0
    seen_packages: dict[str, Optional[str]] = {}  # pkg_key -> ai_summary

    for br in blast_radii:
        pkg_key = f"{br.package.ecosystem}:{br.package.name}@{br.package.version}"

        if pkg_key in seen_packages:
            cached = seen_packages[pkg_key]
            if cached:
                br.ai_summary = cached
                enriched += 1
            continue

        if max_calls and calls_made >= max_calls:
            logger.warning(
                "AI enrichment cap reached (%d unique-package calls). Pass max_calls= to enrich_blast_radii() to increase the limit.",
                max_calls,
            )
            break

        if budget is not None and not budget.try_consume(EnrichmentTask.NARRATIVE):
            logger.warning("AI call budget exhausted before narrative enrichment completed")
            break

        prompt = _build_blast_radius_prompt(br)
        result = await _call_llm(prompt, model)
        seen_packages[pkg_key] = result
        calls_made += 1
        if result:
            br.ai_summary = result
            enriched += 1

    return enriched


async def generate_executive_summary(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    budget: AICallBudget | None = None,
) -> Optional[str]:
    """Generate an LLM-powered executive summary of the scan."""
    if not report.blast_radii:
        return None
    if not _has_any_provider(model):
        return None
    if budget is not None and not budget.try_consume(EnrichmentTask.SUMMARY):
        return None

    prompt = _build_executive_summary_prompt(report)
    return await _call_llm(prompt, model, max_tokens=300)


async def generate_threat_chains(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    budget: AICallBudget | None = None,
) -> list[str]:
    """Generate LLM-powered threat chain analysis."""
    if not report.blast_radii:
        return []
    if not _has_any_provider(model):
        return []
    if budget is not None and not budget.try_consume(EnrichmentTask.SUMMARY):
        return []

    prompt = _build_threat_chain_prompt(report)
    result = await _call_llm(prompt, model, max_tokens=800)
    return [result] if result else []


_AI_CONFIDENCE = {"high", "medium", "low"}


def _bounded_ai_text(value: object, limit: int, default: str = "") -> str:
    """Normalize untrusted model text into a bounded single string."""
    if not isinstance(value, str):
        return default
    return value.strip()[:limit] or default


def _build_finding_assessment_prompt(findings: list["Finding"]) -> str:
    """Build a bounded prompt from safe finding fields, excluding raw evidence."""
    rows = []
    for finding in findings:
        rows.append(
            {
                "finding_id": finding.id,
                "type": str(getattr(finding.finding_type, "value", finding.finding_type)),
                "source": str(getattr(finding.source, "value", finding.source)),
                "severity": finding.severity,
                "title": _bounded_ai_text(finding.title, 240),
                "description": _bounded_ai_text(finding.description, 800),
                "asset": {
                    "name": _bounded_ai_text(finding.asset.name, 240),
                    "type": _bounded_ai_text(finding.asset.asset_type, 80),
                },
                "risk_score": finding.risk_score,
                "reachability": finding.reachability,
                "is_kev": finding.is_kev,
                "controls": [f"{tag.framework}:{tag.control}" for tag in finding.controls[:20]],
            }
        )
    return (
        "Classify and triage these deterministic security findings. Your output is advisory only: "
        "do not change severity, suppress findings, or invent finding IDs. Return JSON only as "
        '{"assessments":[{"finding_id":"...","classification":"...",'
        '"confidence":"high|medium|low","false_positive_likelihood":"high|medium|low",'
        '"rationale":"...","suggested_controls":["..."]}]}.\nFindings:\n' + json.dumps(rows, separators=(",", ":"))
    )


def _parse_finding_assessments(
    response: str,
    *,
    known_ids: set[str],
    provider: str,
    model: str,
) -> list[dict]:
    data = _parse_json_response(response)
    raw_assessments = data.get("assessments", []) if isinstance(data, dict) else []
    if not isinstance(raw_assessments, list):
        return []
    accepted: list[dict] = []
    seen_ids: set[str] = set()
    for raw in raw_assessments:
        if not isinstance(raw, dict):
            continue
        finding_id = _bounded_ai_text(raw.get("finding_id"), 128)
        if finding_id not in known_ids or finding_id in seen_ids:
            continue
        seen_ids.add(finding_id)
        confidence = _bounded_ai_text(raw.get("confidence"), 16, "low").lower()
        false_positive = _bounded_ai_text(raw.get("false_positive_likelihood"), 16, "low").lower()
        controls: list[str] = []
        for control in raw.get("suggested_controls", []) if isinstance(raw.get("suggested_controls"), list) else []:
            normalized = _bounded_ai_text(control, 240)
            if normalized and normalized not in controls:
                controls.append(normalized)
            if len(controls) >= 10:
                break
        accepted.append(
            {
                "finding_id": finding_id,
                "task": EnrichmentTask.TRIAGE.value,
                "classification": _bounded_ai_text(raw.get("classification"), 64, "needs_review"),
                "confidence": confidence if confidence in _AI_CONFIDENCE else "low",
                "false_positive_likelihood": false_positive if false_positive in _AI_CONFIDENCE else "low",
                "rationale": _bounded_ai_text(raw.get("rationale"), 1000),
                "suggested_controls": controls,
                "advisory": True,
                "provider": provider,
                "model": model,
            }
        )
    return accepted


async def assess_report_findings(
    report: "AIBOMReport",
    model: str = DEFAULT_MODEL,
    *,
    provider: str = "unknown",
    budget: AICallBudget | None = None,
) -> list[dict]:
    """Return immutable, provenance-scored AI triage for deterministic findings."""
    if not _has_any_provider(model):
        return []
    max_findings = max(0, int(getattr(config, "AI_MAX_FINDINGS_PER_RUN", 100)))
    if max_findings == 0:
        return []
    findings = report.to_findings()[:max_findings]
    if not findings:
        return []
    batch_size = max(1, min(int(getattr(config, "AI_FINDING_BATCH_SIZE", 20)), 50))
    assessments: list[dict] = []
    for offset in range(0, len(findings), batch_size):
        batch = findings[offset : offset + batch_size]
        if budget is not None and not budget.try_consume(EnrichmentTask.TRIAGE):
            logger.warning("AI call budget exhausted before finding triage completed")
            break
        response = await _call_llm(_build_finding_assessment_prompt(batch), model, max_tokens=1800)
        if not response:
            continue
        assessments.extend(
            _parse_finding_assessments(
                response,
                known_ids={finding.id for finding in batch},
                provider=provider,
                model=model,
            )
        )
    return assessments


# ─── Orchestrator ─────────────────────────────────────────────────────────────


async def _run_ai_enrichment_impl(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    skill_result: "SkillScanResult | None" = None,
    skill_audit: "SkillAuditResult | None" = None,
    *,
    gate_ai_findings: bool = False,
) -> None:
    """Run all AI enrichment steps on a report. Modifies report in-place."""
    budget = AICallBudget(max_calls=max(0, int(getattr(config, "AI_MAX_CALLS_PER_RUN", 50))))
    resolution = _resolve_ai_provider(model)
    report.ai_enrichment_metadata = {**resolution.to_metadata(), "call_budget": budget.to_dict()}
    if not resolution.available:
        console.print("  [yellow]No LLM provider available. Skipping AI enrichment.[/yellow]")
        console.print("  [dim]Option 1: Install Ollama (free, local) — ollama.com[/dim]")
        console.print("  [dim]Option 2: pip install 'agent-bom[huggingface]' + set HF_TOKEN[/dim]")
        console.print("  [dim]Option 3: pip install 'agent-bom[ai-enrich]' + set API key[/dim]")
        return

    model = resolution.model
    provider = resolution.provider.display_name if resolution.provider else "unknown"

    # Per-task model selection: cheap tier for narratives/summaries, strong tier
    # for config analysis. Tiers fall back to the resolved model when unset.
    narrative_model = resolve_task_model(EnrichmentTask.NARRATIVE, model)
    summary_model = resolve_task_model(EnrichmentTask.SUMMARY, model)
    config_model = resolve_task_model(EnrichmentTask.CONFIG_ANALYSIS, model)
    triage_model = resolve_task_model(EnrichmentTask.TRIAGE, model)

    # Provenance: record the full harness posture, not just the primary model.
    report.ai_enrichment_metadata = {
        **resolution.to_metadata(),
        "harness_version": "2",
        "task_models": {
            "narrative": narrative_model,
            "summary": summary_model,
            "config_analysis": config_model,
            "triage": triage_model,
        },
        "redaction": bool(getattr(config, "AI_REDACT_PROMPTS", True)),
        "deterministic": _effective_temperature() == 0.0,
        "temperature": _effective_temperature(),
        "advisory_default": True,
        "ai_gate_enabled": gate_ai_findings,
        "call_budget": budget.to_dict(),
    }

    console.print(f"\n[bold blue]AI Enrichment[/bold blue]  [dim]model: {model} via {provider}[/dim]\n")

    # Advisory triage is the primary structured surface, so it receives budget
    # before optional narrative generation on large estates.
    triage_resolution = _resolve_ai_provider(triage_model)
    assessments = await assess_report_findings(
        report,
        triage_resolution.model if triage_resolution.available else triage_model,
        provider=triage_resolution.provider.name if triage_resolution.provider else "unknown",
        budget=budget,
    )
    if assessments:
        report.ai_finding_assessments = assessments
        console.print(f"  [green]{len(assessments)} advisory finding assessment(s) generated[/green]")

    # Step 1: Enrich blast radii with contextual narratives
    if report.blast_radii:
        console.print("  [cyan]>[/cyan] Generating risk narratives...")
        enriched = await enrich_blast_radii(report.blast_radii, narrative_model, budget=budget)
        console.print(f"  [green]{enriched} finding(s) enriched[/green]")

        # Step 2: Generate executive summary
        console.print("  [cyan]>[/cyan] Generating executive summary...")
        summary = await generate_executive_summary(report, summary_model, budget)
        if summary:
            report.executive_summary = summary
            console.print("  [green]Executive summary generated[/green]")

        # Step 3: Generate threat chain analysis
        console.print("  [cyan]>[/cyan] Analyzing threat chains...")
        chains = await generate_threat_chains(report, summary_model, budget)
        if chains:
            report.ai_threat_chains = chains
            console.print(f"  [green]{len(chains)} threat chain(s) analyzed[/green]")

    # Step 4: MCP config security analysis
    total_servers = sum(len(a.mcp_servers) for a in report.agents)
    if total_servers > 0:
        console.print("  [cyan]>[/cyan] Analyzing MCP config security...")
        config_analysis = await analyze_mcp_config_security(report, config_model, budget)
        if config_analysis:
            report.mcp_config_analysis = config_analysis.model_dump()
            console.print(f"  [green]Config analysis complete (risk: {config_analysis.overall_risk})[/green]")

    # Step 5: Skill file AI analysis
    if skill_result and skill_audit and skill_result.raw_content:
        console.print("  [cyan]>[/cyan] Analyzing skill file security...")
        skill_enriched = await enrich_skill_audit(
            skill_result,
            skill_audit,
            model,
            gate_ai_findings=gate_ai_findings,
            budget=budget,
        )
        if skill_enriched:
            console.print(f"  [green]Skill files analyzed (risk: {skill_audit.ai_overall_risk_level or 'unknown'})[/green]")
        else:
            console.print("  [dim]  Skill analysis could not be completed[/dim]")

    report.ai_enrichment_metadata["call_budget"] = budget.to_dict()


async def run_ai_enrichment(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    skill_result: "SkillScanResult | None" = None,
    skill_audit: "SkillAuditResult | None" = None,
    *,
    deterministic: bool | None = None,
    gate_ai_findings: bool = False,
) -> None:
    """Run enrichment with a task-local deterministic-mode override."""
    if gate_ai_findings and deterministic is not True and not getattr(config, "AI_DETERMINISTIC", False):
        raise ValueError("AI finding gating requires deterministic mode")
    token = _AI_DETERMINISTIC_OVERRIDE.set(deterministic)
    try:
        await _run_ai_enrichment_impl(
            report,
            model,
            skill_result,
            skill_audit,
            gate_ai_findings=gate_ai_findings,
        )
    finally:
        _AI_DETERMINISTIC_OVERRIDE.reset(token)


def run_ai_enrichment_sync(
    report: AIBOMReport,
    model: str = DEFAULT_MODEL,
    skill_result: "SkillScanResult | None" = None,
    skill_audit: "SkillAuditResult | None" = None,
    *,
    deterministic: bool | None = None,
    gate_ai_findings: bool = False,
) -> None:
    """Synchronous wrapper for run_ai_enrichment."""
    asyncio.run(
        run_ai_enrichment(
            report,
            model,
            skill_result,
            skill_audit,
            deterministic=deterministic,
            gate_ai_findings=gate_ai_findings,
        )
    )


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


def _apply_skill_analysis(
    audit: "SkillAuditResult",
    ai_data: dict,
    *,
    ai_source: str | None = None,
    ai_model: str | None = None,
    gate_ai_findings: bool = False,
) -> None:
    """Apply parsed AI analysis results to a SkillAuditResult in-place.

    Updates existing findings with AI verdicts and adds new AI-detected
    findings. Deterministic pass/fail is preserved unless the caller explicitly
    opts into AI gating after selecting deterministic model execution.
    """
    from agent_bom.parsers.skill_audit import SkillFinding

    # Capture the deterministic result exactly once, before AI annotations.
    if audit.deterministic_passed is None:
        audit.deterministic_passed = audit.passed
    audit.ai_gate_enabled = gate_ai_findings

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
        matched.ai_source = ai_source
        matched.ai_model = ai_model
        confidence = review.get("confidence")
        if isinstance(confidence, str) and confidence.lower() in {"high", "medium", "low"}:
            matched.ai_confidence = confidence.lower()

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

        audit.findings.append(
            SkillFinding(
                severity=severity,
                category=new.get("category", "ai_detected"),
                title=new.get("title", "AI-detected finding"),
                detail=new.get("detail", ""),
                source_file=source,
                recommendation=new.get("recommendation", ""),
                context="ai_analysis",
                ai_source=ai_source,
                ai_model=ai_model,
                ai_confidence=str(new.get("confidence", "medium")).lower()
                if str(new.get("confidence", "medium")).lower() in {"high", "medium", "low"}
                else "medium",
            )
        )

    if gate_ai_findings:
        # Explicit opt-in only: false-positive reviews and AI-detected findings
        # may affect the result. The deterministic baseline remains available.
        audit.passed = not any(f.severity in ("critical", "high") and f.ai_adjusted_severity != "false_positive" for f in audit.findings)
    else:
        audit.passed = audit.deterministic_passed


async def enrich_skill_audit(
    skill_result: "SkillScanResult",
    skill_audit: "SkillAuditResult",
    model: str = DEFAULT_MODEL,
    *,
    gate_ai_findings: bool = False,
    budget: AICallBudget | None = None,
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
    resolution = _resolve_ai_provider(model)
    if not resolution.available:
        logger.debug("No LLM provider available for skill enrichment")
        return False
    resolved_model = resolution.model
    if budget is not None and not budget.try_consume(EnrichmentTask.DETECTION):
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

    _apply_skill_analysis(
        skill_audit,
        ai_data,
        ai_source=resolution.provider.name if resolution.provider else None,
        ai_model=resolved_model,
        gate_ai_findings=gate_ai_findings,
    )
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
            server_args = sanitize_command_args(server.args[:5])
            server_configs.append(
                f"- Server: {server.name}\n"
                f"  Command: {server.command} {' '.join(server_args)}\n"
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
    budget: AICallBudget | None = None,
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

    # Budgeted orchestration uses exactly one provider call. The legacy direct
    # function path retains native structured output plus its fallback.
    if budget is not None:
        if not budget.try_consume(EnrichmentTask.CONFIG_ANALYSIS):
            return None
        raw = await _call_llm(prompt, model, max_tokens=1000)
        parsed = _parse_json_response(raw) if raw else None
        if parsed:
            try:
                return MCPConfigSecurityAnalysis.model_validate(parsed)
            except (ValueError, TypeError, KeyError) as exc:
                logger.debug("Failed to validate MCPConfigSecurityAnalysis: %s", exc)
        return None

    # Try structured output first
    result = await _call_llm_structured(prompt, model, MCPConfigSecurityAnalysis, max_tokens=1000)
    if result:
        return result  # type: ignore[return-value]

    # Fallback to unstructured
    raw = await _call_llm(prompt, model, max_tokens=1000)
    if raw:
        parsed = _parse_json_response(raw)
        if parsed:
            try:
                return MCPConfigSecurityAnalysis.model_validate(parsed)
            except (ValueError, TypeError, KeyError) as exc:
                logger.debug("Failed to validate MCPConfigSecurityAnalysis: %s", exc)
    return None
