"""Data models for AI component source scanning.

AIComponent represents a single AI usage found in source code — an SDK import,
a model string reference, an API key, or a deprecated model call.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from agent_bom.finding import stable_id


class AIComponentType(str, Enum):
    """Classification of detected AI component."""

    LLM_PROVIDER = "llm_provider"  # openai, anthropic, google-generativeai
    AGENT_FRAMEWORK = "agent_framework"  # langchain, crewai, autogen
    ML_FRAMEWORK = "ml_framework"  # torch, tensorflow, jax
    VECTOR_STORE = "vector_store"  # chromadb, pinecone, weaviate
    MODEL_REFERENCE = "model_reference"  # "gpt-4o", "claude-3-5-sonnet"
    API_KEY = "api_key"  # hardcoded API key in source
    DEPRECATED_MODEL = "deprecated_model"  # gpt-3.5-turbo, text-davinci-003
    MLOPS = "mlops"  # mlflow, wandb, neptune
    INFERENCE_SERVER = "inference_server"  # vllm, triton, tgi
    INVISIBLE_UNICODE = "invisible_unicode"  # GlassWorm-style zero-width / RTL override chars in source


class AIComponentSeverity(str, Enum):
    """Risk severity for an AI component finding."""

    CRITICAL = "critical"  # hardcoded API key
    HIGH = "high"  # deprecated model with known issues
    MEDIUM = "medium"  # shadow AI (SDK in code but not manifest)
    LOW = "low"  # informational: detected AI SDK usage
    INFO = "info"  # model reference, no risk


@dataclass
class AIComponent:
    """A single AI component detected in source code."""

    component_type: AIComponentType
    name: str  # SDK/model/key name (e.g. "openai", "gpt-4o", "sk-proj-...")
    language: str  # python, javascript, typescript, java, go, rust, ruby
    file_path: str  # relative path where detected
    line_number: int  # 1-based line number
    matched_text: str  # the actual text that matched
    severity: AIComponentSeverity = AIComponentSeverity.LOW
    package_name: Optional[str] = None  # PyPI/npm package name for CVE linking
    ecosystem: Optional[str] = None  # pypi, npm, cargo, go, maven, nuget, rubygems
    description: Optional[str] = None  # human-readable explanation
    is_shadow: bool = False  # True if SDK is in code but not in manifest
    deprecated_replacement: Optional[str] = None  # replacement model if deprecated
    tags: list[str] = field(default_factory=list)  # compliance/context tags

    @property
    def stable_id(self) -> str:
        """Deterministic UUID for dedup across scans."""
        return stable_id(
            "ai_component",
            self.component_type.value,
            self.name,
            self.file_path,
            str(self.line_number),
        )

    def to_dict(self) -> dict:
        """Serialize a detected component for JSON/API consumers."""
        return {
            "stable_id": self.stable_id,
            "component_type": self.component_type.value,
            "name": self.name,
            "language": self.language,
            "file_path": self.file_path,
            "line_number": self.line_number,
            "matched_text": self.matched_text,
            "severity": self.severity.value,
            "package_name": self.package_name,
            "ecosystem": self.ecosystem,
            "description": self.description,
            "is_shadow": self.is_shadow,
            "deprecated_replacement": self.deprecated_replacement,
            "tags": list(self.tags),
        }


@dataclass
class AIComponentReport:
    """Aggregated results from AI component source scanning."""

    components: list[AIComponent] = field(default_factory=list)
    shadow_ai: list[AIComponent] = field(default_factory=list)  # in code, not in manifest
    deprecated_models: list[AIComponent] = field(default_factory=list)
    api_keys: list[AIComponent] = field(default_factory=list)  # hardcoded keys
    scan_paths: list[str] = field(default_factory=list)
    files_scanned: int = 0
    warnings: list[str] = field(default_factory=list)

    @property
    def total(self) -> int:
        return len(self.components)

    @property
    def by_type(self) -> dict[AIComponentType, list[AIComponent]]:
        result: dict[AIComponentType, list[AIComponent]] = {}
        for c in self.components:
            result.setdefault(c.component_type, []).append(c)
        return result

    @property
    def by_language(self) -> dict[str, list[AIComponent]]:
        result: dict[str, list[AIComponent]] = {}
        for c in self.components:
            result.setdefault(c.language, []).append(c)
        return result

    @property
    def unique_sdks(self) -> set[str]:
        return {
            c.name
            for c in self.components
            if c.component_type not in (AIComponentType.MODEL_REFERENCE, AIComponentType.API_KEY, AIComponentType.DEPRECATED_MODEL)
        }

    @property
    def unique_models(self) -> set[str]:
        return {c.name for c in self.components if c.component_type in (AIComponentType.MODEL_REFERENCE, AIComponentType.DEPRECATED_MODEL)}

    def to_dict(self) -> dict:
        """Serialize the full source-scan report."""
        return {
            "components": [c.to_dict() for c in self.components],
            "shadow_ai": [c.to_dict() for c in self.shadow_ai],
            "deprecated_models": [c.to_dict() for c in self.deprecated_models],
            "api_keys": [c.to_dict() for c in self.api_keys],
            "scan_paths": list(self.scan_paths),
            "files_scanned": self.files_scanned,
            "warnings": list(self.warnings),
            "stats": {
                "total_components": self.total,
                "shadow_ai": len(self.shadow_ai),
                "deprecated_models": len(self.deprecated_models),
                "api_keys": len(self.api_keys),
                "unique_sdks": sorted(self.unique_sdks),
                "unique_models": sorted(self.unique_models),
                "by_language": {lang: len(items) for lang, items in self.by_language.items()},
                "by_type": {component_type.value: len(items) for component_type, items in self.by_type.items()},
            },
        }
