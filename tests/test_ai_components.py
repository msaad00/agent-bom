"""Tests for AI component source scanning — SDK imports, model refs, API keys, shadow AI."""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.ai_components import (
    AIComponent,
    AIComponentSeverity,
    AIComponentType,
    scan_source,
)
from agent_bom.ai_components.patterns import (
    ALL_SDK_PATTERNS,
    API_KEY_PATTERNS,
    DEPRECATED_MODEL_PATTERNS,
    EXTENSION_TO_LANGUAGE,
    MODEL_PATTERNS,
    SDK_PATTERNS_BY_LANGUAGE,
)

# ── Test fixtures ────────────────────────────────────────────────────────────


@pytest.fixture
def tmp_project(tmp_path: Path) -> Path:
    """Create a temporary project with AI SDK usage across languages."""
    # Python file with openai + langchain imports
    py_file = tmp_path / "app.py"
    py_file.write_text(
        "import openai\n"
        "from langchain import chains\n"
        "from chromadb import Client\n"
        "\n"
        'client = openai.OpenAI(api_key="sk-proj-1234567890abcdef1234")\n'
        'response = client.chat.completions.create(model="gpt-4o")\n'
    )

    # Python file with deprecated model
    py_dep = tmp_path / "legacy.py"
    py_dep.write_text(
        "import openai\n"
        'response = openai.Completion.create(model="text-davinci-003")\n'
        'embed = openai.Embedding.create(model="text-embedding-ada-002")\n'
    )

    # JS file with anthropic SDK
    js_file = tmp_path / "index.js"
    js_file.write_text(
        'import Anthropic from "@anthropic-ai/sdk";\n'
        "const client = new Anthropic();\n"
        'const msg = await client.messages.create({model: "claude-3.5-sonnet"});\n'
    )

    # TypeScript file with openai
    ts_file = tmp_path / "agent.ts"
    ts_file.write_text(
        'import OpenAI from "openai";\n'
        "const openai = new OpenAI();\n"
        'const chat = await openai.chat.completions.create({model: "gpt-4o-mini"});\n'
    )

    # Go file
    go_file = tmp_path / "main.go"
    go_file.write_text(
        'package main\n\nimport "github.com/sashabaranov/go-openai"\n\nfunc main() {\n    client := openai.NewClient("sk-1234")\n}\n'
    )

    # Rust file
    rs_file = tmp_path / "main.rs"
    rs_file.write_text("use async_openai;\n\nfn main() {\n    let client = async_openai::Client::new();\n}\n")

    # Java file
    java_file = tmp_path / "App.java"
    java_file.write_text(
        "import dev.langchain4j.model.chat.ChatModel;\n\npublic class App {\n    public static void main(String[] args) {\n    }\n}\n"
    )

    # Ruby file
    rb_file = tmp_path / "bot.rb"
    rb_file.write_text('require "ruby-openai"\n\nclient = OpenAI::Client.new\n')

    return tmp_path


@pytest.fixture
def tmp_project_with_manifest(tmp_project: Path) -> Path:
    """Project with requirements.txt for shadow AI detection."""
    req = tmp_project / "requirements.txt"
    req.write_text("openai==1.30.0\nflask==3.0.0\n")
    return tmp_project


# ── Pattern coverage tests ───────────────────────────────────────────────────


class TestPatternCoverage:
    """Verify pattern registry completeness."""

    def test_all_languages_have_patterns(self):
        assert set(SDK_PATTERNS_BY_LANGUAGE.keys()) == {"python", "javascript", "java", "go", "rust", "ruby"}

    def test_python_has_comprehensive_patterns(self):
        names = {p.name for p in SDK_PATTERNS_BY_LANGUAGE["python"]}
        assert "openai" in names
        assert "anthropic" in names
        assert "langchain" in names
        assert "pytorch" in names
        assert "tensorflow" in names
        assert "chromadb" in names
        assert "mlflow" in names
        assert "vllm" in names

    def test_js_has_patterns(self):
        names = {p.name for p in SDK_PATTERNS_BY_LANGUAGE["javascript"]}
        assert "openai" in names
        assert "anthropic" in names
        assert "langchain" in names

    def test_all_sdk_patterns_combined(self):
        assert len(ALL_SDK_PATTERNS) >= 50  # 40+ Python + JS + Java + Go + Rust + Ruby

    def test_model_patterns_exist(self):
        assert len(MODEL_PATTERNS) >= 15

    def test_deprecated_model_patterns_exist(self):
        assert len(DEPRECATED_MODEL_PATTERNS) >= 8

    def test_api_key_patterns_exist(self):
        assert len(API_KEY_PATTERNS) >= 6

    def test_extension_to_language_mapping(self):
        assert EXTENSION_TO_LANGUAGE[".py"] == "python"
        assert EXTENSION_TO_LANGUAGE[".js"] == "javascript"
        assert EXTENSION_TO_LANGUAGE[".ts"] == "javascript"
        assert EXTENSION_TO_LANGUAGE[".tsx"] == "javascript"
        assert EXTENSION_TO_LANGUAGE[".go"] == "go"
        assert EXTENSION_TO_LANGUAGE[".rs"] == "rust"
        assert EXTENSION_TO_LANGUAGE[".java"] == "java"
        assert EXTENSION_TO_LANGUAGE[".rb"] == "ruby"

    def test_each_pattern_has_required_fields(self):
        for p in ALL_SDK_PATTERNS:
            assert p.name, f"Pattern missing name: {p}"
            assert p.package_name, f"Pattern missing package_name: {p}"
            assert p.ecosystem, f"Pattern missing ecosystem: {p}"
            assert p.language, f"Pattern missing language: {p}"
            assert p.component_type, f"Pattern missing component_type: {p}"


# ── Scanner tests ────────────────────────────────────────────────────────────


class TestScanner:
    """Test the scan_source function."""

    def test_scan_empty_dir(self, tmp_path: Path):
        report = scan_source(str(tmp_path))
        assert report.total == 0
        assert report.files_scanned == 0

    def test_scan_nonexistent_dir(self):
        report = scan_source("/nonexistent/path/abc")
        assert report.total == 0
        assert len(report.warnings) == 1

    def test_scan_python_imports(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        sdk_components = [
            c
            for c in report.components
            if c.component_type not in (AIComponentType.MODEL_REFERENCE, AIComponentType.API_KEY, AIComponentType.DEPRECATED_MODEL)
        ]
        names = {c.name for c in sdk_components if c.language == "python"}
        assert "openai" in names
        assert "langchain" in names
        assert "chromadb" in names

    def test_scan_js_imports(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        js_components = [c for c in report.components if c.language == "javascript"]
        names = {c.name for c in js_components if c.component_type != AIComponentType.MODEL_REFERENCE}
        assert "anthropic" in names
        assert "openai" in names

    def test_scan_go_imports(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        go_comps = [c for c in report.components if c.language == "go"]
        names = {c.name for c in go_comps}
        assert "go-openai" in names

    def test_scan_rust_imports(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        rust_comps = [c for c in report.components if c.language == "rust"]
        names = {c.name for c in rust_comps}
        assert "async-openai" in names

    def test_scan_java_imports(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        java_comps = [c for c in report.components if c.language == "java"]
        names = {c.name for c in java_comps}
        assert "langchain4j" in names

    def test_scan_ruby_imports(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        ruby_comps = [c for c in report.components if c.language == "ruby"]
        names = {c.name for c in ruby_comps}
        assert "ruby-openai" in names

    def test_files_scanned_count(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        # We created 8 source files (app.py, legacy.py, index.js, agent.ts, main.go, main.rs, App.java, bot.rb)
        assert report.files_scanned == 8

    def test_scan_paths_recorded(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        assert str(tmp_project) in report.scan_paths

    def test_multiple_paths(self, tmp_path: Path):
        dir_a = tmp_path / "a"
        dir_a.mkdir()
        (dir_a / "test.py").write_text("import openai\n")

        dir_b = tmp_path / "b"
        dir_b.mkdir()
        (dir_b / "test.py").write_text("import anthropic\n")

        report = scan_source(str(dir_a), str(dir_b))
        names = {c.name for c in report.components}
        assert "openai" in names
        assert "anthropic" in names
        assert report.files_scanned == 2

    def test_single_file_scan(self, tmp_path: Path):
        f = tmp_path / "single.py"
        f.write_text("import torch\n")
        report = scan_source(str(f))
        assert report.total >= 1
        names = {c.name for c in report.components}
        assert "pytorch" in names


# ── Model reference tests ────────────────────────────────────────────────────


class TestModelReferences:
    """Test detection of model string references."""

    def test_detect_gpt4o(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        model_refs = [c for c in report.components if c.component_type == AIComponentType.MODEL_REFERENCE]
        model_names = {c.name for c in model_refs}
        assert "gpt-4o" in model_names

    def test_detect_claude_sonnet(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        model_refs = [c for c in report.components if c.component_type == AIComponentType.MODEL_REFERENCE]
        model_names = {c.name for c in model_refs}
        assert "claude-3-5-sonnet" in model_names or "claude-3.5-sonnet" in model_names

    def test_detect_gpt4o_mini(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        model_refs = [c for c in report.components if c.component_type == AIComponentType.MODEL_REFERENCE]
        model_names = {c.name for c in model_refs}
        assert "gpt-4o-mini" in model_names

    def test_model_ref_has_provider(self, tmp_path: Path):
        f = tmp_path / "test.py"
        f.write_text('model = "gemini-2.0-flash"\n')
        report = scan_source(str(tmp_path))
        model_refs = [c for c in report.components if c.component_type == AIComponentType.MODEL_REFERENCE]
        assert any(c.description and "google" in c.description for c in model_refs)


# ── Deprecated model tests ───────────────────────────────────────────────────


class TestDeprecatedModels:
    """Test detection of deprecated AI models."""

    def test_detect_text_davinci(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        assert len(report.deprecated_models) >= 1
        names = {c.name for c in report.deprecated_models}
        assert "text-davinci-003" in names

    def test_deprecated_has_replacement(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        davinci = [c for c in report.deprecated_models if "davinci" in c.name]
        assert davinci
        assert davinci[0].deprecated_replacement is not None

    def test_deprecated_severity(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        davinci = [c for c in report.deprecated_models if "davinci" in c.name]
        assert davinci
        assert davinci[0].severity == AIComponentSeverity.HIGH

    def test_detect_gpt35_turbo(self, tmp_path: Path):
        f = tmp_path / "old.py"
        f.write_text('model = "gpt-3.5-turbo"\n')
        report = scan_source(str(tmp_path))
        assert len(report.deprecated_models) >= 1
        names = {c.name for c in report.deprecated_models}
        assert "gpt-3.5-turbo" in names

    def test_detect_claude_2(self, tmp_path: Path):
        f = tmp_path / "old.py"
        f.write_text('model = "claude-2.1"\n')
        report = scan_source(str(tmp_path))
        assert len(report.deprecated_models) >= 1

    def test_detect_palm_2(self, tmp_path: Path):
        f = tmp_path / "old.py"
        f.write_text('model = "palm-2"\n')
        report = scan_source(str(tmp_path))
        assert len(report.deprecated_models) >= 1


# ── API key detection tests ──────────────────────────────────────────────────


class TestAPIKeys:
    """Test detection of hardcoded API keys."""

    def test_detect_openai_key(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        assert len(report.api_keys) >= 1
        # Key should be masked
        for key in report.api_keys:
            assert "..." in key.name  # masked

    def test_key_severity_is_critical(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        for key in report.api_keys:
            assert key.severity == AIComponentSeverity.CRITICAL

    def test_detect_anthropic_key(self, tmp_path: Path):
        f = tmp_path / "config.py"
        f.write_text('API_KEY = "sk-ant-api03-abcdefghij1234567890"\n')
        report = scan_source(str(tmp_path))
        assert len(report.api_keys) >= 1

    def test_detect_hf_token(self, tmp_path: Path):
        f = tmp_path / "config.py"
        f.write_text('HF_TOKEN = "hf_abcdefghijklmnopqrstuvwx"\n')
        report = scan_source(str(tmp_path))
        assert len(report.api_keys) >= 1

    def test_key_never_stored_in_full(self, tmp_path: Path):
        full_key = "sk-proj-1234567890abcdefghij1234567890abcdef"
        f = tmp_path / "test.py"
        f.write_text(f'key = "{full_key}"\n')
        report = scan_source(str(tmp_path))
        for key in report.api_keys:
            assert full_key not in key.name
            assert full_key not in key.matched_text


# ── Shadow AI detection tests ────────────────────────────────────────────────


class TestShadowAI:
    """Test detection of SDKs imported but not in manifest."""

    def test_shadow_ai_detected(self, tmp_project_with_manifest: Path):
        # openai IS in requirements.txt, langchain is NOT
        report = scan_source(
            str(tmp_project_with_manifest),
            manifest_packages={"openai"},
        )
        shadow = [c for c in report.shadow_ai if c.language == "python"]
        shadow_names = {c.name for c in shadow}
        assert "langchain" in shadow_names
        assert "chromadb" in shadow_names

    def test_non_shadow_not_flagged(self, tmp_project_with_manifest: Path):
        report = scan_source(
            str(tmp_project_with_manifest),
            manifest_packages={"openai"},
        )
        openai_comps = [
            c
            for c in report.components
            if c.name == "openai" and c.language == "python" and c.component_type == AIComponentType.LLM_PROVIDER
        ]
        for c in openai_comps:
            assert not c.is_shadow

    def test_shadow_severity_medium(self, tmp_project_with_manifest: Path):
        report = scan_source(
            str(tmp_project_with_manifest),
            manifest_packages={"openai"},
        )
        for c in report.shadow_ai:
            assert c.severity == AIComponentSeverity.MEDIUM

    def test_no_shadow_without_manifest(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        assert len(report.shadow_ai) == 0


# ── AIComponent model tests ──────────────────────────────────────────────────


class TestAIComponentModel:
    """Test AIComponent dataclass properties."""

    def test_stable_id_deterministic(self):
        c1 = AIComponent(
            component_type=AIComponentType.LLM_PROVIDER,
            name="openai",
            language="python",
            file_path="app.py",
            line_number=1,
            matched_text="import openai",
        )
        c2 = AIComponent(
            component_type=AIComponentType.LLM_PROVIDER,
            name="openai",
            language="python",
            file_path="app.py",
            line_number=1,
            matched_text="import openai",
        )
        assert c1.stable_id == c2.stable_id

    def test_stable_id_differs_on_line(self):
        c1 = AIComponent(
            component_type=AIComponentType.LLM_PROVIDER,
            name="openai",
            language="python",
            file_path="app.py",
            line_number=1,
            matched_text="import openai",
        )
        c2 = AIComponent(
            component_type=AIComponentType.LLM_PROVIDER,
            name="openai",
            language="python",
            file_path="app.py",
            line_number=5,
            matched_text="import openai",
        )
        assert c1.stable_id != c2.stable_id


# ── AIComponentReport tests ──────────────────────────────────────────────────


class TestAIComponentReport:
    """Test report aggregation properties."""

    def test_by_type(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        by_type = report.by_type
        assert AIComponentType.LLM_PROVIDER in by_type

    def test_by_language(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        by_lang = report.by_language
        assert "python" in by_lang
        assert "javascript" in by_lang

    def test_unique_sdks(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        sdks = report.unique_sdks
        assert "openai" in sdks
        assert "langchain" in sdks

    def test_unique_models(self, tmp_project: Path):
        report = scan_source(str(tmp_project))
        models = report.unique_models
        assert "gpt-4o" in models


# ── Edge cases ───────────────────────────────────────────────────────────────


class TestEdgeCases:
    """Test edge cases and boundary conditions."""

    def test_skip_node_modules(self, tmp_path: Path):
        nm = tmp_path / "node_modules" / "openai"
        nm.mkdir(parents=True)
        (nm / "index.js").write_text('import OpenAI from "openai";\n')
        # Also create a real file
        (tmp_path / "app.py").write_text("import openai\n")
        report = scan_source(str(tmp_path))
        # Should only find the app.py file, not node_modules
        js_comps = [c for c in report.components if c.language == "javascript"]
        assert len(js_comps) == 0

    def test_skip_venv(self, tmp_path: Path):
        venv = tmp_path / ".venv" / "lib"
        venv.mkdir(parents=True)
        (venv / "openai.py").write_text("import openai\n")
        (tmp_path / "app.py").write_text("import anthropic\n")
        report = scan_source(str(tmp_path))
        names = {c.name for c in report.components if c.component_type != AIComponentType.MODEL_REFERENCE}
        assert "anthropic" in names
        # openai from venv should be skipped
        assert report.files_scanned == 1

    def test_skip_large_files(self, tmp_path: Path):
        big = tmp_path / "big.py"
        big.write_text("import openai\n" + "x = 1\n" * 200000)  # >512KB
        report = scan_source(str(tmp_path))
        assert report.files_scanned == 0

    def test_binary_file_ignored(self, tmp_path: Path):
        f = tmp_path / "model.py"
        f.write_bytes(b"\x00\x01\x02import openai\n")
        report = scan_source(str(tmp_path))
        # Should still scan (read_text with errors="replace")
        assert report.files_scanned == 1

    def test_unsupported_extension_ignored(self, tmp_path: Path):
        f = tmp_path / "data.csv"
        f.write_text("openai,anthropic\n")
        report = scan_source(str(tmp_path))
        assert report.files_scanned == 0

    def test_dedup_same_import_same_line(self, tmp_path: Path):
        # Same import on the same line should only appear once
        f = tmp_path / "app.py"
        f.write_text("import openai\n")
        report = scan_source(str(tmp_path))
        openai_comps = [c for c in report.components if c.name == "openai" and c.component_type == AIComponentType.LLM_PROVIDER]
        assert len(openai_comps) == 1

    def test_empty_file(self, tmp_path: Path):
        f = tmp_path / "empty.py"
        f.write_text("")
        report = scan_source(str(tmp_path))
        assert report.files_scanned == 0  # 0 bytes skipped

    def test_component_has_line_number(self, tmp_path: Path):
        f = tmp_path / "app.py"
        f.write_text("# comment\nimport openai\n")
        report = scan_source(str(tmp_path))
        comps = [c for c in report.components if c.name == "openai" and c.component_type == AIComponentType.LLM_PROVIDER]
        assert comps
        assert comps[0].line_number == 2

    def test_component_has_file_path(self, tmp_path: Path):
        f = tmp_path / "app.py"
        f.write_text("import openai\n")
        report = scan_source(str(tmp_path))
        comps = [c for c in report.components if c.name == "openai" and c.component_type == AIComponentType.LLM_PROVIDER]
        assert comps
        assert comps[0].file_path == "app.py"
