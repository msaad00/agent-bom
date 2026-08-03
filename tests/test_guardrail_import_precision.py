"""The guardrail-import table must match whole modules, not substrings.

``_GUARDRAIL_IMPORTS`` was matched with ``guard_module in module``. ``guardrails``
is a substring of ``nemoguardrails``, so NVIDIA's canonical
``from nemoguardrails import LLMRails, RailsConfig`` matched two table entries:
the AISPM inventory gained a phantom second guardrail, attributed to the wrong
vendor ("Guardrails AI", described as "Imported from nemoguardrails").
"""

from __future__ import annotations

from pathlib import Path

import pytest

from agent_bom.ast_analyzer import analyze_project


def _guardrails(tmp_path: Path, source: str) -> list[tuple[str, str]]:
    """Import-derived guardrails only.

    The call-name regex detector is a separate judgement and tags its hits
    ``framework="generic"``; this exercises the import table alone.
    """
    (tmp_path / "rails.py").write_text(source)
    result = analyze_project(tmp_path)
    return sorted((g.name, g.guardrail_type) for g in result.guardrails if g.framework != "generic")


def test_nemoguardrails_import_is_only_nemo_guardrails(tmp_path: Path) -> None:
    """NVIDIA NeMo Guardrails' documented import must resolve to one vendor."""
    source = "from nemoguardrails import LLMRails, RailsConfig\n\nrails = LLMRails(RailsConfig.from_path('./config'))\n"

    assert _guardrails(tmp_path, source) == [("NeMo Guardrails", "content_filter")]


def test_guardrails_ai_import_is_still_detected(tmp_path: Path) -> None:
    """Guardrails AI's documented import (``from guardrails import Guard``)."""
    source = "from guardrails import Guard\n\nguard = Guard()\n"

    assert _guardrails(tmp_path, source) == [("Guardrails AI", "content_filter")]


@pytest.mark.parametrize(
    ("source", "expected"),
    [
        ("from guardrails.hub import ToxicLanguage\n", ("Guardrails AI", "content_filter")),
        ("from langchain.callbacks.base import BaseCallbackHandler\n", ("LangChain Callbacks", "output_validator")),
        ("from presidio_analyzer import AnalyzerEngine\n", ("Presidio", "pii_filter")),
        ("import llm_guard\n", ("LLM Guard", "input_validator")),
    ],
)
def test_submodule_imports_still_resolve_to_their_vendor(tmp_path: Path, source: str, expected: tuple[str, str]) -> None:
    """Tightening to whole modules must keep dotted submodules matching."""
    assert _guardrails(tmp_path, source) == [expected]


@pytest.mark.parametrize(
    "source",
    [
        "from app.guardrails_config import RAILS\n",
        "from myproject.guardrails import policy\n",
        "import rebuff_stubs\n",
    ],
)
def test_project_local_modules_are_not_vendor_guardrails(tmp_path: Path, source: str) -> None:
    """A project's own module whose name merely contains a vendor name is not that vendor."""
    assert _guardrails(tmp_path, source) == []
