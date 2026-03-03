"""Tests for shared constants — single source of truth validation."""

from __future__ import annotations

from agent_bom.constants import (
    AI_PACKAGES,
    SENSITIVE_PATTERNS,
    TRAINING_DATA_PACKAGES,
    high_risk_severities,
    is_credential_key,
)

# ---------------------------------------------------------------------------
# AI_PACKAGES
# ---------------------------------------------------------------------------


class TestAIPackages:
    def test_contains_llm_orchestration(self):
        for pkg in ["langchain", "langchain-core", "llama-index", "crewai", "autogen"]:
            assert pkg in AI_PACKAGES

    def test_contains_llm_clients(self):
        for pkg in ["openai", "anthropic", "google-generativeai"]:
            assert pkg in AI_PACKAGES

    def test_contains_model_inference(self):
        for pkg in ["torch", "transformers", "diffusers", "tokenizers"]:
            assert pkg in AI_PACKAGES

    def test_contains_rag_backends(self):
        for pkg in ["chromadb", "pinecone-client", "pymilvus", "qdrant-client", "pgvector", "lancedb"]:
            assert pkg in AI_PACKAGES

    def test_contains_embeddings(self):
        assert "sentence-transformers" in AI_PACKAGES

    def test_is_frozenset(self):
        assert isinstance(AI_PACKAGES, frozenset)


# ---------------------------------------------------------------------------
# TRAINING_DATA_PACKAGES
# ---------------------------------------------------------------------------


class TestTrainingDataPackages:
    def test_contains_core_training_packages(self):
        for pkg in ["datasets", "huggingface-hub", "accelerate", "trl", "peft"]:
            assert pkg in TRAINING_DATA_PACKAGES

    def test_overlaps_with_ai_packages(self):
        overlap = AI_PACKAGES & TRAINING_DATA_PACKAGES
        assert "transformers" in overlap
        assert "torch" in overlap

    def test_is_frozenset(self):
        assert isinstance(TRAINING_DATA_PACKAGES, frozenset)


# ---------------------------------------------------------------------------
# high_risk_severities
# ---------------------------------------------------------------------------


class TestHighRiskSeverities:
    def test_returns_frozenset(self):
        result = high_risk_severities()
        assert isinstance(result, frozenset)

    def test_contains_critical_and_high(self):
        from agent_bom.models import Severity

        result = high_risk_severities()
        assert Severity.CRITICAL in result
        assert Severity.HIGH in result

    def test_excludes_medium_low_none(self):
        from agent_bom.models import Severity

        result = high_risk_severities()
        assert Severity.MEDIUM not in result
        assert Severity.LOW not in result
        assert Severity.NONE not in result


# ---------------------------------------------------------------------------
# SENSITIVE_PATTERNS / is_credential_key
# ---------------------------------------------------------------------------


class TestSensitivePatterns:
    def test_contains_common_patterns(self):
        for pat in ["key", "token", "secret", "password", "credential"]:
            assert pat in SENSITIVE_PATTERNS

    def test_contains_database_patterns(self):
        for pat in ["database_url", "db_url", "conn_str"]:
            assert pat in SENSITIVE_PATTERNS

    def test_is_credential_key_matches(self):
        assert is_credential_key("ANTHROPIC_API_KEY")
        assert is_credential_key("DB_PASSWORD")
        assert is_credential_key("GITHUB_TOKEN")
        assert is_credential_key("database_url")
        assert is_credential_key("OPENAI_SECRET")

    def test_is_credential_key_rejects(self):
        assert not is_credential_key("LOG_LEVEL")
        assert not is_credential_key("DEBUG")
        assert not is_credential_key("PORT")
        assert not is_credential_key("HOSTNAME")


# ---------------------------------------------------------------------------
# Cross-module consistency — all compliance modules use the same constants
# ---------------------------------------------------------------------------


class TestCrossModuleConsistency:
    def test_owasp_uses_shared_ai_packages(self):
        from agent_bom.owasp import _AI_PACKAGES

        assert _AI_PACKAGES is AI_PACKAGES

    def test_atlas_uses_shared_ai_packages(self):
        from agent_bom.atlas import _AI_PACKAGES

        assert _AI_PACKAGES is AI_PACKAGES

    def test_nist_uses_shared_ai_packages(self):
        from agent_bom.nist_ai_rmf import _AI_PACKAGES

        assert _AI_PACKAGES is AI_PACKAGES

    def test_eu_ai_act_uses_shared_ai_packages(self):
        from agent_bom.eu_ai_act import _AI_PACKAGES

        assert _AI_PACKAGES is AI_PACKAGES

    def test_owasp_agentic_uses_shared_ai_packages(self):
        from agent_bom.owasp_agentic import _AI_PACKAGES

        assert _AI_PACKAGES is AI_PACKAGES
