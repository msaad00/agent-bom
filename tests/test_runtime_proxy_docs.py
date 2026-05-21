"""Runtime proxy public-doc contract checks."""

from __future__ import annotations

import re
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
PROXY = ROOT / "src" / "agent_bom" / "proxy.py"
RUNTIME_PROXY_DOC = ROOT / "site-docs" / "features" / "runtime-proxy.md"


def _inline_proxy_detector_names() -> list[str]:
    body = PROXY.read_text(encoding="utf-8")
    match = re.search(r"# Runtime detectors\s+from agent_bom\.runtime\.detectors import \((.*?)\)", body, re.DOTALL)
    assert match is not None
    return sorted(name.strip().rstrip(",") for name in match.group(1).splitlines() if name.strip() and not name.strip().startswith("#"))


def test_runtime_proxy_docs_list_inline_detector_set() -> None:
    doc = RUNTIME_PROXY_DOC.read_text(encoding="utf-8")
    detectors = _inline_proxy_detector_names()

    assert f"## {len(detectors)} inline proxy detectors" in doc
    for detector in detectors:
        assert f"**{detector}**" in doc
    assert "## Five detectors" not in doc
