"""Tests for the matured multi-provider LLM enrichment harness (issue #3206).

Covers the provider abstraction/registry, per-task model selection, secret
redaction, deterministic mode, and retry/backoff — all with mocked providers,
no real network or API calls.
"""

from __future__ import annotations

import asyncio
from unittest.mock import AsyncMock, patch

import httpx
import pytest

from agent_bom import ai_enrich, config
from agent_bom.ai_enrich import (
    AI_PROVIDER_DESCRIPTORS,
    DEFAULT_MODEL,
    PROVIDER_REGISTRY,
    EnrichmentProvider,
    EnrichmentTask,
    HuggingFaceProvider,
    LiteLLMProvider,
    OllamaProvider,
    get_provider,
    provider_for_model,
    redact_secrets,
    resolve_task_model,
    retry_async,
)

# ─── Redaction ───────────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    "raw, needle",
    [
        ("token sk-abcdef1234567890ABCD used", "<redacted-openai-key>"),
        ("key sk-ant-api03-abcdefgh12345678ijkl here", "<redacted-anthropic-key>"),
        ("pat ghp_ABCDEFGHIJKLMNOPQRSTUVWXYZ012345 x", "<redacted-github-token>"),
        ("aws AKIAIOSFODNN7EXAMPLE creds", "<redacted-aws-access-key>"),
        ("aws ASIAIOSFODNN7EXAMPLE creds", "<redacted-aws-access-key>"),
        ("hf hf_abcdefghijklmnopqrstuvwxyz done", "<redacted-hf-token>"),
        ("Authorization: Bearer eyJhbGciOiJIUzI1NiIsInR5cCI6", "Bearer <redacted-token>"),
        (
            "session eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiJ1c2VyMTIzNDU2Nzg5MCJ9.signature0123456789abcdef",
            "<redacted-jwt>",
        ),
        ("dsn postgresql://scanner:hunter2@db.internal:5432/prod", "<redacted-connection-url>"),
    ],
)
def test_redact_secrets_scrubs_known_shapes(raw, needle):
    out = redact_secrets(raw)
    assert needle in out
    # The original secret body must not survive.
    assert "sk-abcdef1234567890ABCD" not in out or needle == "<redacted-openai-key>"


def test_redact_secrets_scrubs_assignments():
    out = redact_secrets('API_KEY="supersecretvalue123"')
    assert "supersecretvalue123" not in out
    assert "<redacted>" in out
    # The variable name (context) is preserved.
    assert "API_KEY" in out


def test_redact_secrets_scrubs_private_key_block():
    pem = "-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKCAQEA\n-----END RSA PRIVATE KEY-----"
    out = redact_secrets(pem)
    assert "MIIEpAIBAAKCAQEA" not in out
    assert "<redacted-private-key>" in out


def test_redact_secrets_preserves_credential_names():
    # Credential *names* (not values) must survive so the model keeps context.
    out = redact_secrets("Exposed credentials: OPENAI_API_KEY, DATABASE_URL")
    assert "OPENAI_API_KEY" in out


def test_redact_secrets_idempotent_and_safe_on_empty():
    assert redact_secrets("") == ""
    once = redact_secrets("sk-abcdefghijklmnop1234 and text")
    assert redact_secrets(once) == once


def test_prepare_prompt_honors_config(monkeypatch):
    monkeypatch.setattr(config, "AI_REDACT_PROMPTS", True)
    assert "<redacted-openai-key>" in ai_enrich._prepare_prompt("x sk-abcdefghij1234567890 y")
    monkeypatch.setattr(config, "AI_REDACT_PROMPTS", False)
    assert ai_enrich._prepare_prompt("x sk-abcdefghij1234567890 y") == "x sk-abcdefghij1234567890 y"


@pytest.mark.asyncio
async def test_redaction_applied_at_ollama_boundary(monkeypatch):
    """The prompt that actually hits the network must be redacted."""
    monkeypatch.setattr(config, "AI_REDACT_PROMPTS", True)
    ai_enrich._cache.clear()
    captured = {}

    class _Resp:
        status_code = 200

        def json(self):
            return {"message": {"content": "ok"}}

    class _Client:
        async def __aenter__(self):
            return self

        async def __aexit__(self, *a):
            return False

        async def post(self, url, json):
            captured["content"] = json["messages"][0]["content"]
            return _Resp()

    with patch("agent_bom.ai_enrich.httpx.AsyncClient", return_value=_Client()):
        await ai_enrich._call_ollama_direct("leak sk-abcdefghijkl1234567890 now", "llama3.2")

    assert "sk-abcdefghijkl1234567890" not in captured["content"]
    assert "<redacted-openai-key>" in captured["content"]


# ─── Provider abstraction + registry ─────────────────────────────────────────


def test_registry_has_all_providers():
    assert set(PROVIDER_REGISTRY) == {"ollama", "huggingface", "litellm"}
    for name, prov in PROVIDER_REGISTRY.items():
        assert isinstance(prov, EnrichmentProvider)
        assert prov.name == name
        assert prov.descriptor is AI_PROVIDER_DESCRIPTORS[name]


def test_get_provider_and_unknown():
    assert isinstance(get_provider("ollama"), OllamaProvider)
    with pytest.raises(KeyError):
        get_provider("does-not-exist")


@pytest.mark.parametrize(
    "model, cls",
    [
        ("ollama/llama3.2", OllamaProvider),
        ("huggingface/meta-llama/x", HuggingFaceProvider),
        ("openai/gpt-4o-mini", LiteLLMProvider),
        ("anthropic/claude-sonnet-5", LiteLLMProvider),
    ],
)
def test_provider_for_model(model, cls):
    assert isinstance(provider_for_model(model), cls)


def test_provider_availability_reflects_detection():
    with patch("agent_bom.ai_enrich._detect_ollama", return_value=True):
        assert OllamaProvider().is_available() is True
    with patch("agent_bom.ai_enrich._detect_ollama", return_value=False):
        assert OllamaProvider().is_available() is False
    with patch("agent_bom.ai_enrich._check_litellm", return_value=True):
        assert LiteLLMProvider().is_available() is True


@pytest.mark.parametrize(
    ("endpoint", "expected_local"),
    [
        ("http://localhost:11434", True),
        ("http://127.0.0.2:11434", True),
        ("http://[::1]:11434", True),
        ("https://ollama.example.com", False),
        ("http://10.0.0.8:11434", False),
        ("http://host.docker.internal:11434", False),
    ],
)
def test_ollama_provider_metadata_reflects_endpoint_boundary(monkeypatch, endpoint, expected_local):
    """The provider's local/remote claim must follow its configured endpoint."""
    monkeypatch.setattr(ai_enrich, "OLLAMA_BASE_URL", endpoint)
    monkeypatch.setattr(ai_enrich, "_detect_ollama", lambda: True)

    status = ai_enrich._provider_status("ollama")

    assert status.available is True
    assert status.descriptor.local is expected_local
    assert status.descriptor.requires_network is (not expected_local)


@pytest.mark.asyncio
async def test_ollama_provider_generate_delegates():
    with patch("agent_bom.ai_enrich._call_ollama_direct", new_callable=AsyncMock, return_value="hi") as m:
        out = await OllamaProvider().generate("prompt", "ollama/llama3.2", max_tokens=42)
    assert out == "hi"
    # Strips the ollama/ prefix before delegating to the bare-model call.
    m.assert_awaited_once_with("prompt", "llama3.2", 42)


@pytest.mark.asyncio
async def test_litellm_provider_generate_delegates():
    with patch("agent_bom.ai_enrich._call_llm_via_litellm", new_callable=AsyncMock, return_value="lit") as m:
        out = await LiteLLMProvider().generate("p", "openai/gpt-4o-mini")
    assert out == "lit"
    m.assert_awaited_once()


# ─── Per-task model selection ────────────────────────────────────────────────


def test_resolve_task_model_defaults_to_resolved(monkeypatch):
    monkeypatch.setattr(config, "AI_MODEL_CHEAP", "")
    monkeypatch.setattr(config, "AI_MODEL_STRONG", "")
    assert resolve_task_model(EnrichmentTask.TAGGING, "ollama/llama3.2") == "ollama/llama3.2"
    assert resolve_task_model(EnrichmentTask.DETECTION, DEFAULT_MODEL) == DEFAULT_MODEL


def test_resolve_task_model_uses_tiers(monkeypatch):
    monkeypatch.setattr(config, "AI_MODEL_CHEAP", "ollama/llama3.2")
    monkeypatch.setattr(config, "AI_MODEL_STRONG", "anthropic/claude-sonnet-5")
    # Cheap tier tasks
    assert resolve_task_model(EnrichmentTask.TAGGING) == "ollama/llama3.2"
    assert resolve_task_model(EnrichmentTask.NARRATIVE) == "ollama/llama3.2"
    assert resolve_task_model(EnrichmentTask.SUMMARY) == "ollama/llama3.2"
    # Strong tier tasks
    assert resolve_task_model(EnrichmentTask.DETECTION) == "anthropic/claude-sonnet-5"
    assert resolve_task_model(EnrichmentTask.TRIAGE) == "anthropic/claude-sonnet-5"
    assert resolve_task_model(EnrichmentTask.CONFIG_ANALYSIS) == "anthropic/claude-sonnet-5"


# ─── Determinism ─────────────────────────────────────────────────────────────


def test_effective_temperature_deterministic(monkeypatch):
    monkeypatch.setattr(config, "AI_DETERMINISTIC", True)
    assert ai_enrich._effective_temperature() == 0.0
    monkeypatch.setattr(config, "AI_DETERMINISTIC", False)
    monkeypatch.setattr(config, "AI_TEMPERATURE", 0.7)
    assert ai_enrich._effective_temperature() == 0.7


@pytest.mark.asyncio
async def test_public_enrichment_inherits_environment_determinism(monkeypatch):
    """An omitted request override must not disable deployment policy."""
    observed: list[float] = []

    async def fake_impl(*args, **kwargs):
        observed.append(ai_enrich._effective_temperature())

    monkeypatch.setattr(config, "AI_DETERMINISTIC", True)
    monkeypatch.setattr(config, "AI_TEMPERATURE", 0.7)
    monkeypatch.setattr(ai_enrich, "_run_ai_enrichment_impl", fake_impl)

    await ai_enrich.run_ai_enrichment(object(), deterministic=None)

    assert observed == [0.0]


@pytest.mark.asyncio
async def test_concurrent_enrichment_runs_do_not_share_response_cache(monkeypatch):
    """A cached provider response must never be relabeled as another run's evidence."""
    observed: list[str] = []
    both_started = asyncio.Event()

    async def fake_impl(*args, **kwargs):
        observed.append(
            ai_enrich._cache_key(
                "identical tenant-neutral prompt",
                "openai/fake",
                task=EnrichmentTask.TRIAGE,
            )
        )
        if len(observed) == 2:
            both_started.set()
        await both_started.wait()

    monkeypatch.setattr(ai_enrich, "_run_ai_enrichment_impl", fake_impl)

    await asyncio.gather(
        ai_enrich.run_ai_enrichment(object()),
        ai_enrich.run_ai_enrichment(object()),
    )

    assert len(set(observed)) == 2


@pytest.mark.asyncio
async def test_concurrent_deterministic_modes_have_isolated_cache_entries(monkeypatch):
    """A nondeterministic response must never satisfy a deterministic request."""
    ai_enrich._cache.clear()
    temperatures: list[float] = []
    both_started = asyncio.Event()

    async def fake_acompletion(**kwargs):
        temperatures.append(kwargs["temperature"])
        if len(temperatures) == 2:
            both_started.set()
        await both_started.wait()

        class _Message:
            content = f"temperature={kwargs['temperature']}"

        class _Choice:
            message = _Message()

        class _Response:
            choices = [_Choice()]

        return _Response()

    fake_litellm = type("m", (), {"acompletion": staticmethod(fake_acompletion)})
    monkeypatch.setattr(config, "AI_TEMPERATURE", 0.7)

    async def call(deterministic: bool) -> str | None:
        token = ai_enrich._AI_DETERMINISTIC_OVERRIDE.set(deterministic)
        try:
            return await ai_enrich._call_llm_via_litellm(
                "same prompt",
                "openai/fake",
                task=EnrichmentTask.TRIAGE,
            )
        finally:
            ai_enrich._AI_DETERMINISTIC_OVERRIDE.reset(token)

    with patch.dict("sys.modules", {"litellm": fake_litellm}):
        nondeterministic, deterministic = await asyncio.gather(call(False), call(True))

    assert nondeterministic == "temperature=0.7"
    assert deterministic == "temperature=0.0"
    assert sorted(temperatures) == [0.0, 0.7]


def test_cache_key_includes_execution_posture(monkeypatch):
    monkeypatch.setattr(config, "AI_MODEL_REVISION", "revision-a")
    monkeypatch.setattr(config, "AI_REDACT_PROMPTS", True)
    monkeypatch.setattr(config, "AI_TEMPERATURE", 0.7)
    baseline = ai_enrich._cache_key(
        "prompt",
        "openai/fake",
        task=EnrichmentTask.TRIAGE,
        provider="litellm",
    )
    token = ai_enrich._AI_DETERMINISTIC_OVERRIDE.set(True)
    try:
        deterministic = ai_enrich._cache_key(
            "prompt",
            "openai/fake",
            task=EnrichmentTask.TRIAGE,
            provider="litellm",
        )
    finally:
        ai_enrich._AI_DETERMINISTIC_OVERRIDE.reset(token)

    variants = {
        deterministic,
        ai_enrich._cache_key("prompt", "openai/other", task=EnrichmentTask.TRIAGE, provider="litellm"),
        ai_enrich._cache_key("prompt", "openai/fake", task=EnrichmentTask.SUMMARY, provider="litellm"),
        ai_enrich._cache_key("prompt", "openai/fake", task=EnrichmentTask.TRIAGE, provider="other"),
    }
    monkeypatch.setattr(config, "AI_MODEL_REVISION", "revision-b")
    variants.add(ai_enrich._cache_key("prompt", "openai/fake", task=EnrichmentTask.TRIAGE, provider="litellm"))
    monkeypatch.setattr(config, "AI_MODEL_REVISION", "revision-a")
    monkeypatch.setattr(config, "AI_REDACT_PROMPTS", False)
    variants.add(ai_enrich._cache_key("prompt", "openai/fake", task=EnrichmentTask.TRIAGE, provider="litellm"))
    monkeypatch.setattr(config, "AI_REDACT_PROMPTS", True)
    monkeypatch.setattr(ai_enrich, "AI_PROMPT_VERSION", "ai-enrichment.test-version")
    variants.add(ai_enrich._cache_key("prompt", "openai/fake", task=EnrichmentTask.TRIAGE, provider="litellm"))

    assert baseline not in variants
    assert len(variants) == 7


# ─── Retry / backoff ─────────────────────────────────────────────────────────


@pytest.mark.asyncio
async def test_retry_async_succeeds_first_try():
    calls = 0

    async def f():
        nonlocal calls
        calls += 1
        return "ok"

    out = await retry_async(f, max_retries=3, base_delay=0)
    assert out == "ok"
    assert calls == 1


@pytest.mark.asyncio
async def test_retry_async_retries_then_succeeds(monkeypatch):
    monkeypatch.setattr(ai_enrich.asyncio, "sleep", AsyncMock())
    calls = 0

    async def f():
        nonlocal calls
        calls += 1
        if calls < 3:
            raise httpx.TimeoutException("transient")
        return "recovered"

    out = await retry_async(f, max_retries=3, base_delay=0)
    assert out == "recovered"
    assert calls == 3


@pytest.mark.asyncio
async def test_retry_async_exhausts_and_degrades(monkeypatch):
    monkeypatch.setattr(ai_enrich.asyncio, "sleep", AsyncMock())
    calls = 0

    async def f():
        nonlocal calls
        calls += 1
        raise httpx.ConnectError("down")

    out = await retry_async(f, max_retries=2, base_delay=0)
    assert out is None
    assert calls == 3  # initial + 2 retries


@pytest.mark.asyncio
async def test_retry_async_non_retryable_returns_none():
    calls = 0

    async def f():
        nonlocal calls
        calls += 1
        raise ValueError("permanent")

    # ValueError is not in the default retry set → single attempt, degrade.
    out = await retry_async(f, max_retries=3, base_delay=0)
    assert out is None
    assert calls == 1


@pytest.mark.asyncio
async def test_litellm_call_retries_transient(monkeypatch):
    """The litellm boundary retries a transient failure then caches success."""
    monkeypatch.setattr(config, "AI_MAX_RETRIES", 2)
    monkeypatch.setattr(ai_enrich.asyncio, "sleep", AsyncMock())
    ai_enrich._cache.clear()

    attempts = 0

    async def fake_acompletion(**kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.TimeoutException("boom")

        class _Msg:
            content = "final answer"

        class _Choice:
            message = _Msg()

        class _Resp:
            choices = [_Choice()]

        return _Resp()

    fake_litellm = type("m", (), {"acompletion": staticmethod(fake_acompletion)})
    with patch.dict("sys.modules", {"litellm": fake_litellm}):
        out = await ai_enrich._call_llm_via_litellm("prompt", "openai/gpt-4o-mini")

    assert out == "final answer"
    assert attempts == 2


@pytest.mark.asyncio
async def test_provider_attempt_budget_caps_retries(monkeypatch):
    """The advertised cap counts every provider request, including retries."""
    attempts = 0

    async def fake_acompletion(**kwargs):
        nonlocal attempts
        attempts += 1
        raise httpx.ConnectError("down")

    fake_litellm = type("m", (), {"acompletion": staticmethod(fake_acompletion)})
    monkeypatch.setattr(ai_enrich.asyncio, "sleep", AsyncMock())
    ai_enrich._cache.clear()
    budget = ai_enrich.AICallBudget(max_calls=1)

    with patch.dict("sys.modules", {"litellm": fake_litellm}):
        out = await ai_enrich._call_llm_via_litellm(
            "prompt",
            "openai/fake",
            task=EnrichmentTask.TRIAGE,
            budget=budget,
        )

    assert out is None
    assert attempts == 1
    assert budget.to_dict() == {
        "max_provider_attempts": 1,
        "provider_attempts": 1,
        "provider_attempts_remaining": 0,
        "cache_hits": 0,
        "retries": 0,
        "exhausted": True,
        "attempts_by_task": {"triage": 1},
    }


@pytest.mark.asyncio
async def test_provider_attempt_budget_counts_retry_and_cache_hit(monkeypatch):
    """Successful retries count as requests; a later cache hit does not consume the cap."""
    attempts = 0

    async def fake_acompletion(**kwargs):
        nonlocal attempts
        attempts += 1
        if attempts == 1:
            raise httpx.TimeoutException("transient")

        class _Message:
            content = "cached result"

        class _Choice:
            message = _Message()

        class _Response:
            choices = [_Choice()]

        return _Response()

    fake_litellm = type("m", (), {"acompletion": staticmethod(fake_acompletion)})
    monkeypatch.setattr(ai_enrich.asyncio, "sleep", AsyncMock())
    ai_enrich._cache.clear()
    budget = ai_enrich.AICallBudget(max_calls=2)

    with patch.dict("sys.modules", {"litellm": fake_litellm}):
        first = await ai_enrich._call_llm_via_litellm(
            "prompt",
            "openai/fake",
            task=EnrichmentTask.TRIAGE,
            budget=budget,
        )
        second = await ai_enrich._call_llm_via_litellm(
            "prompt",
            "openai/fake",
            task=EnrichmentTask.TRIAGE,
            budget=budget,
        )

    assert first == second == "cached result"
    assert attempts == 2
    assert budget.to_dict() == {
        "max_provider_attempts": 2,
        "provider_attempts": 2,
        "provider_attempts_remaining": 0,
        "cache_hits": 1,
        "retries": 1,
        "exhausted": True,
        "attempts_by_task": {"triage": 2},
    }


def test_provider_attempt_budget_rejects_negative_limit():
    with pytest.raises(ValueError, match="must be non-negative"):
        ai_enrich.AICallBudget(max_calls=-1)
