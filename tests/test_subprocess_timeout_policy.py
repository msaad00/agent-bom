from __future__ import annotations

import ast
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
SRC = ROOT / "src" / "agent_bom"
TIMEOUT_ENFORCED = {"run", "check_call", "check_output"}


def test_blocking_subprocess_helpers_declare_timeout() -> None:
    """Keep blocking subprocess helpers bounded or explicitly marked long-running."""
    missing: list[str] = []

    for path in sorted(SRC.rglob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call) or not isinstance(node.func, ast.Attribute):
                continue
            if node.func.attr not in TIMEOUT_ENFORCED:
                continue
            if not isinstance(node.func.value, ast.Name) or node.func.value.id != "subprocess":
                continue
            if not any(keyword.arg == "timeout" for keyword in node.keywords):
                rel = path.relative_to(ROOT)
                missing.append(f"{rel}:{node.lineno} subprocess.{node.func.attr}")

    assert not missing, "subprocess calls missing timeout=:\n" + "\n".join(missing)
