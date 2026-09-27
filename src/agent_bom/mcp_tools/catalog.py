"""Static tool registration inventory across server and package registration modules."""

import ast
from pathlib import Path


def _is_mcp_tool_decorator(node: ast.expr) -> bool:
    target = node.func if isinstance(node, ast.Call) else node
    return isinstance(target, ast.Attribute) and target.attr == "tool" and isinstance(target.value, ast.Name) and target.value.id == "mcp"


def registered_mcp_tool_decorator_names() -> frozenset[str]:
    """Return MCP tool function names across server registration modules."""
    package_root = Path(__file__).resolve().parents[1]
    names: set[str] = set()
    for path in sorted([*package_root.glob("mcp_server*.py"), *package_root.joinpath("mcp_tools").rglob("*.py")]):
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
        for node in ast.walk(tree):
            if not isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
                continue
            if any(_is_mcp_tool_decorator(decorator) for decorator in node.decorator_list):
                names.add(node.name)
    return frozenset(names)
