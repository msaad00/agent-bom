"""The regex prefilter may only skip patterns that provably cannot match."""

from __future__ import annotations

import re
from pathlib import Path

import pytest

from agent_bom.ai_components import patterns as ai_patterns
from agent_bom.regex_prefilter import ContentView, Requirement, may_match, requirement_for

_REPO = Path(__file__).resolve().parents[1]


def _ai_component_regexes() -> list[re.Pattern[str]]:
    regexes = [pattern.regex for group in ai_patterns.SDK_PATTERNS_BY_LANGUAGE.values() for pattern in group]
    for group in (
        ai_patterns.MODEL_PATTERNS,
        ai_patterns.DEPRECATED_MODEL_PATTERNS,
        ai_patterns.API_KEY_PATTERNS,
        ai_patterns.INVISIBLE_UNICODE_PATTERNS,
    ):
        regexes.extend(pattern.regex for pattern in group)
    return regexes


_EDGE_PATTERNS = [
    re.compile(r"\bgpt-4o\b"),
    re.compile(r"(?i)openai\.chat"),
    re.compile(r"(?i:ANTHROPIC)_key"),
    re.compile(r"kelvin", re.IGNORECASE),
    re.compile(r"[А-я]", re.IGNORECASE),
    re.compile(r"(?:import|from)\s+torch"),
    re.compile(r"a|bc"),
    re.compile(r"(?:x)?yz"),
    re.compile(r"[^\x00-\x7f]{2,}"),
    re.compile(r"(?<=ab)cd(?=ef)"),
    re.compile(r"(?:foo){2,}bar"),
]

_EDGE_TEXTS = [
    "",
    "plain ascii text without anything",
    "model = 'gpt-4o'",
    "OPENAI.CHAT.completions",
    "KELVIN",  # KELVIN SIGN folds to "k" under IGNORECASE
    "Kelvin",
    "а",
    "from   torch import nn",
    "a",
    "bc",
    "yz",
    "éé",
    "abcdef",
    "foofoobar",
    "anthropic_key ANTHROPIC_key",
]


def _corpus() -> list[str]:
    texts = list(_EDGE_TEXTS)
    for rel in (
        "src/agent_bom/ai_components/patterns.py",
        "src/agent_bom/ai_components/scanner.py",
        "tests/test_ai_components.py",
        "README.md",
    ):
        path = _REPO / rel
        if path.is_file():
            texts.append(path.read_text(encoding="utf-8", errors="replace"))
    return texts


@pytest.mark.parametrize("regex", _ai_component_regexes() + _EDGE_PATTERNS, ids=lambda regex: regex.pattern[:40])
def test_prefilter_never_skips_a_pattern_that_matches(regex: re.Pattern[str]) -> None:
    for text in _corpus():
        if regex.search(text) is not None:
            assert may_match(regex, ContentView(text)), (regex.pattern, text[:80])


def test_requirements_are_derived_from_mandatory_text() -> None:
    assert requirement_for(re.compile(r"\bgpt-4o(?:-mini)?\b")) == Requirement(literals=("gpt-4o",))
    assert requirement_for(re.compile(r"(?:import|from)\s+torch")) == Requirement(literals=("torch",))
    assert requirement_for(re.compile(r"(?:import|from)\s+t")) == Requirement(literals=("import", "from"))
    assert requirement_for(re.compile(r"(?i)OpenAI")) == Requirement(literals=("openai",), ignorecase=True)
    assert requirement_for(re.compile(r"[​‍]{2,}")) == Requirement(non_ascii=True)
    assert requirement_for(re.compile(r"(?:x)?y")) is None
    assert requirement_for(re.compile(r"[А-я]", re.IGNORECASE)) is None


def test_most_ai_component_patterns_are_prefiltered() -> None:
    regexes = _ai_component_regexes()
    filtered = [regex for regex in regexes if requirement_for(regex) is not None]
    assert len(filtered) >= 0.9 * len(regexes)


def test_non_ascii_and_case_folding_are_conservative() -> None:
    kelvin = re.compile(r"kelvin", re.IGNORECASE)
    assert kelvin.search("KELVIN")
    assert may_match(kelvin, ContentView("KELVIN"))
    assert not may_match(re.compile(r"[​‍]{2,}"), ContentView("ascii only"))
    assert not may_match(re.compile(r"\bgpt-4o\b"), ContentView("no model here"))
