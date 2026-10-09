"""Front-door documentation contracts: the README first screen, the architecture
overview, the decision log and repository-relative links."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
README = ROOT / "README.md"
ARCHITECTURE = ROOT / "docs" / "ARCHITECTURE.md"
DECISIONS = ROOT / "docs" / "decisions"

_FENCE = re.compile(r"^\s*(```|~~~)")
_MD_LINK = re.compile(r"\]\(\s*<?([^)\s>]+)>?(?:\s+\"[^\"]*\")?\s*\)")
_HTML_REF = re.compile(r"(?:href|src|srcset)=\"([^\"]+)\"")
_SCHEME = re.compile(r"^[a-z][a-z0-9+.-]*:", re.I)
_TEST_PATH = re.compile(r"(?<![\w/.-])(?:\.\./)*(tests/[A-Za-z0-9_/]+\.py)")


def _markdown_files() -> list[Path]:
    return [README, *sorted((ROOT / "docs").rglob("*.md"))]


def _prose_lines(path: Path) -> list[tuple[int, str]]:
    lines: list[tuple[int, str]] = []
    in_fence = False
    for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
        if _FENCE.match(line):
            in_fence = not in_fence
            continue
        if not in_fence:
            lines.append((number, line))
    return lines


def _broken_relative_links(path: Path) -> list[str]:
    broken = []
    for number, line in _prose_lines(path):
        for match in [*_MD_LINK.finditer(line), *_HTML_REF.finditer(line)]:
            url = match.group(1).split()[0]
            if _SCHEME.match(url) or url.startswith(("#", "//")):
                continue
            target = url.split("#", 1)[0].split("?", 1)[0]
            if target and not (path.parent / target).exists():
                broken.append(f"{path.relative_to(ROOT)}:{number}: {url}")
    return broken


def test_readme_and_docs_relative_links_resolve() -> None:
    broken = [entry for path in _markdown_files() for entry in _broken_relative_links(path)]
    assert broken == []


def test_docs_name_only_test_files_that_exist() -> None:
    stale = []
    for path in [*_markdown_files(), *sorted((ROOT / "site-docs").rglob("*.md"))]:
        for number, line in enumerate(path.read_text(encoding="utf-8").splitlines(), 1):
            for match in _TEST_PATH.finditer(line):
                if not (ROOT / match.group(1)).exists():
                    stale.append(f"{path.relative_to(ROOT)}:{number}: {match.group(1)}")
    assert stale == []


def _first_screen(text: str) -> str:
    """README text before the first second-level heading after the intro."""
    headings = [m.start() for m in re.finditer(r"^## ", text, re.M)]
    return text[: headings[1]] if len(headings) > 1 else text


def test_readme_first_screen_states_audience_and_visible_quick_start() -> None:
    text = README.read_text(encoding="utf-8")
    first = _first_screen(text)
    assert "## Quick start" in first, "Quick start must be the first README section"
    quick_start = first[first.index("## Quick start") :]
    visible = quick_start.split("<details>", 1)[0]
    for command in ("pip install agent-bom", "agent-bom scan .", "agent-bom scan --demo --offline"):
        assert command in visible, f"uncollapsed quick start is missing {command!r}"
    intro = first[: first.index("## Quick start")]
    assert re.search(r"\bfor (security|AppSec)", intro, re.I), "intro must say who the tool is for"
    assert "Source version:" not in first, "release plumbing does not belong on the first screen"


def test_architecture_opens_with_system_overview_and_layer_rules() -> None:
    text = ARCHITECTURE.read_text(encoding="utf-8")
    sections = re.findall(r"^## (.+)$", text, re.M)
    assert sections[:2] == ["System overview", "Layers and dependency rules"]
    overview = text[: text.index("## Layers and dependency rules")]
    assert "```mermaid" in overview
    for layer in ("CLI", "MCP server", "REST API", "Gateway", "core"):
        assert layer in overview
    assert "## Module notes" in text
    assert text.index("## Module notes") > text.index("## Layers and dependency rules")
    rules = text[text.index("## Layers and dependency rules") : text.index("## Module notes")]
    assert "scripts/check_architecture.py" in rules


def test_single_decision_log_with_unique_numbering() -> None:
    assert not (ROOT / "docs" / "adr").exists(), "decision records live only in docs/decisions"
    records = sorted(p.name for p in DECISIONS.glob("[0-9][0-9][0-9]-*.md"))
    numbers = [name[:3] for name in records]
    assert len(numbers) == len(set(numbers))
    assert numbers == [f"{i:03d}" for i in range(1, len(numbers) + 1)]
    index = (DECISIONS / "README.md").read_text(encoding="utf-8")
    for name in records:
        assert f"({name})" in index, f"{name} missing from docs/decisions/README.md"
    for name in records:
        heading = (DECISIONS / name).read_text(encoding="utf-8").splitlines()[0]
        assert heading.startswith(f"# ADR-{name[:3]}:"), f"{name} heading must carry its number"
    superseded = (DECISIONS / "013-no-rbac-custom-auth.md").read_text(encoding="utf-8")
    assert "**Status:** Superseded" in superseded
    assert "rbac.py" in superseded


def _unindexed_docs(index: str) -> list[str]:
    linked = set(re.findall(r"\]\(([^)#]+)", index))
    return sorted(p.name for p in (ROOT / "docs").glob("*.md") if p.name != "README.md" and p.name not in linked)


def test_docs_index_groups_every_top_level_doc() -> None:
    index = (ROOT / "docs" / "README.md").read_text(encoding="utf-8")
    groups = re.findall(r"^## (.+)$", index, re.M)
    assert groups == [
        "Using agent-bom",
        "Deploying",
        "Security and compliance",
        "Architecture and decisions",
        "Operations and enterprise",
    ]
    assert _unindexed_docs(index) == []
