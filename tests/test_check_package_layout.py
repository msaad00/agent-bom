"""The frozen top-level module guard: passes on the tree, fails on growth, and
tells the contributor where the new code belongs."""

from __future__ import annotations

from pathlib import Path

from scripts.check_package_layout import CODE_MAP, PACKAGE_HINTS, check, suggest_package

ROOT = Path(__file__).resolve().parents[1]


def _package(tmp_path: Path, names: set[str]) -> Path:
    pkg = tmp_path / "agent_bom"
    pkg.mkdir()
    for name in names:
        (pkg / name).write_text("", encoding="utf-8")
    return pkg


def test_current_tree_matches_allowlist() -> None:
    code, lines = check()
    assert code == 0, "\n".join(lines)


def test_new_top_level_module_fails_with_package_hint_and_code_map(tmp_path: Path) -> None:
    pkg = _package(tmp_path, {"__init__.py", "mcp_widget.py", "zz_new.py"})
    code, lines = check(pkg, frozenset({"__init__.py"}))
    message = "\n".join(lines)
    assert code == 1
    assert "+ mcp_widget.py  -> try src/agent_bom/mcp_tools/" in message
    assert "+ zz_new.py" in message
    assert CODE_MAP in message


def test_removed_allowlisted_module_requires_allowlist_update(tmp_path: Path) -> None:
    pkg = _package(tmp_path, {"__init__.py"})
    code, lines = check(pkg, frozenset({"__init__.py", "legacy.py"}))
    assert code == 1
    assert "  - legacy.py" in lines


def test_package_hints_point_at_existing_subpackages() -> None:
    for prefixes, package in PACKAGE_HINTS:
        assert (ROOT / "src" / "agent_bom" / package / "__init__.py").is_file(), package
        assert suggest_package(f"{prefixes[0]}x.py") == f"src/agent_bom/{package}"
    assert CODE_MAP in suggest_package("unrelated.py")


def test_code_map_documents_the_guard() -> None:
    text = (ROOT / CODE_MAP).read_text(encoding="utf-8")
    assert "scripts/check_package_layout.py" in text
