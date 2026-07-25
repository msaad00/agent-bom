"""Reachability must survive the import-name vs distribution-name split.

The AST records the *import* name a module is reached through (``yaml``,
``PIL``, ``sklearn``) while an SCA finding and its advisory name the
*distribution* (``PyYAML``, ``pillow``, ``scikit-learn``). Comparing the two
directly reports a genuinely reachable CVE as unreachable, which then applies
the unreachable risk penalty and de-prioritizes a real finding.
"""

from __future__ import annotations

import pytest

from agent_bom.ast_models import DependencySymbolReach
from agent_bom.reachability_cve import SymbolReachIndex

# (distribution as an advisory names it, import name as code reaches it)
_SPLIT_NAMES = [
    ("PyYAML", "yaml"),
    ("pillow", "PIL"),
    ("scikit-learn", "sklearn"),
    ("beautifulsoup4", "bs4"),
    ("pyjwt", "jwt"),
    ("opencv-python", "cv2"),
    ("python-dateutil", "dateutil"),
    ("Django", "django"),  # same name — must keep working
]


def _index_for(import_name: str, symbol: str = "safe_load") -> SymbolReachIndex:
    return SymbolReachIndex.from_reaches(
        [
            DependencySymbolReach(
                entrypoint="tool_entry",
                package=import_name,
                module=import_name,
                symbol=symbol,
                file_path="app.py",
                line_number=1,
                call_path=["tool_entry", symbol],
                ecosystem="pypi",
            )
        ]
    )


@pytest.mark.parametrize(("distribution", "import_name"), _SPLIT_NAMES)
def test_distribution_name_matches_reached_import_name(distribution: str, import_name: str) -> None:
    index = _index_for(import_name)

    assert index.is_package_reached(distribution, ecosystem="pypi") is True


@pytest.mark.parametrize(("distribution", "import_name"), _SPLIT_NAMES)
def test_symbols_resolve_through_the_distribution_name(distribution: str, import_name: str) -> None:
    index = _index_for(import_name, symbol="safe_load")

    assert "safe_load" in index.symbols_for_package(distribution, ecosystem="pypi")


def test_unrelated_package_is_still_unreached() -> None:
    """The mapping must not turn every lookup into a match."""
    index = _index_for("yaml")

    assert index.is_package_reached("requests", ecosystem="pypi") is False
    assert index.symbols_for_package("requests", ecosystem="pypi") == set()


def test_import_name_lookup_still_works_directly() -> None:
    """Callers that already hold the import name keep working."""
    index = _index_for("yaml")

    assert index.is_package_reached("yaml", ecosystem="pypi") is True


def test_mapping_is_scoped_to_pypi() -> None:
    """A Go module named ``pillow`` must not inherit the PyPI alias."""
    index = SymbolReachIndex.from_reaches(
        [
            DependencySymbolReach(
                entrypoint="main",
                package="PIL",
                module="PIL",
                symbol="open",
                file_path="main.go",
                line_number=1,
                ecosystem="go",
            )
        ]
    )

    assert index.is_package_reached("pillow", ecosystem="go") is False
