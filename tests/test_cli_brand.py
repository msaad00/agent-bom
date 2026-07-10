"""CLI / terminal brand lockup — product name agent-bom, mark is BOM-with-agent-O."""

from __future__ import annotations

from agent_bom.output.brand_tokens import (
    PRODUCT_NAME,
    TAGLINE_SHORT,
    cli_banner_plain,
    cli_mark_lines,
    print_cli_startup_banner,
)


def test_cli_mark_contains_bom_letters() -> None:
    mark = "\n".join(cli_mark_lines(force_ascii=True))
    assert "B" in mark and "M" in mark
    assert "o" in mark.lower()  # agent O


def test_cli_banner_uses_locked_product_name_and_tagline() -> None:
    banner = cli_banner_plain(version="0.0.0-test", force_ascii=True)
    assert PRODUCT_NAME in banner
    assert TAGLINE_SHORT in banner
    assert "v0.0.0-test" in banner


def test_startup_banner_renders_mark_and_quick_start() -> None:
    lines: list[str] = []

    class _Capture:
        def print(self, *args: object, **_kwargs: object) -> None:
            lines.append(" ".join(str(a) for a in args))

    print_cli_startup_banner(_Capture(), version="9.9.9")
    blob = "\n".join(lines)
    assert PRODUCT_NAME in blob
    assert TAGLINE_SHORT in blob
    assert "9.9.9" in blob
    assert f"{PRODUCT_NAME} scan" in blob
    assert "Quick start" in blob
