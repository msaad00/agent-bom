"""Bounded source reads that preserve honest AST scan coverage."""

from __future__ import annotations

from pathlib import Path

from agent_bom.coverage import record_scan_input_warning


def read_source_for_analysis(
    file_path: Path,
    rel_path: str,
    *,
    scanner: str,
    max_size: int,
) -> str | None:
    """Read one source file or record why AST analysis is partial."""
    try:
        source = file_path.read_text(encoding="utf-8", errors="replace")
    except OSError:
        record_scan_input_warning(
            scanner=scanner,
            path=rel_path,
            reason="source_read_error",
            detail="Source file could not be read; AST analysis is incomplete.",
        )
        return None

    if len(source) > max_size:
        record_scan_input_warning(
            scanner=scanner,
            path=rel_path,
            reason="source_size_limit",
            detail=f"Source file exceeds the {max_size:,}-character AST analysis limit.",
        )
        return None
    return source
