#!/usr/bin/env python3
"""Generate a verified snapshot of volatile product metrics from the repo."""

from __future__ import annotations

import argparse
import ast
import json
import re
from datetime import date
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def _count_workflows() -> int:
    return len(list((ROOT / ".github" / "workflows").glob("*.y*ml")))


def _count_test_files() -> int:
    return len(list((ROOT / "tests").rglob("test_*.py")))


def _count_api_route_modules() -> int:
    return len(list((ROOT / "src" / "agent_bom" / "api" / "routes").glob("*.py")))


def _count_ui_app_pages() -> int:
    app_root = ROOT / "ui" / "app"
    return len(list(app_root.rglob("page.tsx"))) + len(list(app_root.rglob("page.jsx")))


def _count_python_modules() -> int:
    return len(list((ROOT / "src" / "agent_bom").rglob("*.py")))


def _count_mcp_tools() -> int:
    return _count_server_card_entries("_SERVER_CARD_TOOLS")


def _count_mcp_resources() -> int:
    return _count_server_card_entries("_SERVER_CARD_RESOURCES")


def _count_mcp_prompts() -> int:
    return _count_server_card_entries("_SERVER_CARD_PROMPTS")


def _count_server_card_entries(variable_name: str) -> int:
    content = (ROOT / "src" / "agent_bom" / "mcp_server_metadata.py").read_text()
    module = ast.parse(content)
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == variable_name for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        return len(value) if isinstance(value, list) else 0
    return 0


def _count_package_ecosystems() -> int:
    content = (ROOT / "src" / "agent_bom" / "ecosystems.py").read_text()
    match = re.search(r"SUPPORTED_PACKAGE_ECOSYSTEMS[^=]*=\s*\((.*?)\)", content, re.DOTALL)
    if not match:
        return 0
    return len(re.findall(r'"[a-z0-9_-]+"', match.group(1)))


def _count_compliance_frameworks() -> int:
    content = (ROOT / "src" / "agent_bom" / "compliance_coverage.py").read_text()
    module = ast.parse(content)
    for node in module.body:
        if isinstance(node, ast.Assign):
            if not any(isinstance(target, ast.Name) and target.id == "TAG_MAPPED_FRAMEWORKS" for target in node.targets):
                continue
            return len(node.value.elts) if isinstance(node.value, ast.Tuple) else 0
        if isinstance(node, ast.AnnAssign) and isinstance(node.target, ast.Name) and node.target.id == "TAG_MAPPED_FRAMEWORKS":
            return len(node.value.elts) if isinstance(node.value, ast.Tuple) else 0
    return 0


def _count_compliance_surfaces() -> int:
    return _count_compliance_frameworks() + 1


def _count_proxy_inline_detectors() -> int:
    content = (ROOT / "src" / "agent_bom" / "proxy.py").read_text()
    detector_block = re.search(
        r"# Runtime detectors\s+from agent_bom\.runtime\.detectors import \((.*?)\)\s+\s*drift_detector =",
        content,
        re.DOTALL,
    )
    if not detector_block:
        return 0
    return len([line for line in detector_block.group(1).splitlines() if line.strip()])


def _count_runtime_protection_detectors() -> int:
    content = (ROOT / "src" / "agent_bom" / "runtime" / "protection.py").read_text()
    import_block = re.search(r"from agent_bom\.runtime\.detectors import \((.*?)\)\n", content, re.DOTALL)
    if not import_block:
        return 0
    return len([line for line in import_block.group(1).splitlines() if line.strip()])


def _current_version() -> str:
    content = (ROOT / "pyproject.toml").read_text()
    match = re.search(r'^version\s*=\s*"([^"]+)"', content, re.MULTILINE)
    return match.group(1) if match else "unknown"


def build_snapshot() -> dict[str, object]:
    return {
        "generated_on": str(date.today()),
        "version": _current_version(),
        "metrics": [
            {
                "name": "MCP tools",
                "value": _count_mcp_tools(),
                "source": "src/agent_bom/mcp_server_metadata.py",
                "notes": "Counted from the advertised server-card tools.",
            },
            {
                "name": "MCP resources",
                "value": _count_mcp_resources(),
                "source": "src/agent_bom/mcp_server_metadata.py",
                "notes": "Counted from the advertised server-card resources.",
            },
            {
                "name": "MCP prompts",
                "value": _count_mcp_prompts(),
                "source": "src/agent_bom/mcp_server_metadata.py",
                "notes": "Counted from the advertised server-card workflow prompts.",
            },
            {
                "name": "GitHub workflow files",
                "value": _count_workflows(),
                "source": ".github/workflows",
                "notes": "Counts .yml and .yaml workflow definitions.",
            },
            {
                "name": "Test files",
                "value": _count_test_files(),
                "source": "tests/",
                "notes": "Counts files matching test_*.py.",
            },
            {
                "name": "API route modules",
                "value": _count_api_route_modules(),
                "source": "src/agent_bom/api/routes",
                "notes": "Counts Python files in the routes package, including __init__.py.",
            },
            {
                "name": "UI app pages",
                "value": _count_ui_app_pages(),
                "source": "ui/app",
                "notes": "Counts page.tsx and page.jsx files recursively.",
            },
            {
                "name": "Python modules",
                "value": _count_python_modules(),
                "source": "src/agent_bom",
                "notes": "Counts all Python files recursively.",
            },
            {
                "name": "Supported package ecosystems",
                "value": _count_package_ecosystems(),
                "source": "src/agent_bom/ecosystems.py",
                "notes": "Counted from SUPPORTED_PACKAGE_ECOSYSTEMS.",
            },
            {
                "name": "Compliance surfaces",
                "value": _count_compliance_surfaces(),
                "source": "src/agent_bom/compliance_coverage.py",
                "notes": "14 tag-mapped frameworks plus the OWASP AISVS benchmark surface.",
            },
            {
                "name": "Proxy inline detectors",
                "value": _count_proxy_inline_detectors(),
                "source": "src/agent_bom/proxy.py",
                "notes": "Inline detector chain used by the MCP proxy path.",
            },
            {
                "name": "Runtime protection engine detectors",
                "value": _count_runtime_protection_detectors(),
                "source": "src/agent_bom/runtime/protection.py",
                "notes": "Broader protection engine used outside the lighter proxy-only path.",
            },
        ],
    }


def render_markdown(snapshot: dict[str, object]) -> str:
    lines = [
        "# Product Metrics",
        "",
        "<!-- Generated by scripts/product_metrics_snapshot.py -->",
        "",
        "This appendix is the canonical home for volatile product counts.",
        "Keep counts out of public positioning copy and update this file from the repo instead of hand-editing numbers.",
        "",
        f"- Generated on: `{snapshot['generated_on']}`",
        f"- Version: `{snapshot['version']}`",
        "",
        "| Metric | Value | Source | Notes |",
        "| --- | ---: | --- | --- |",
    ]
    for entry in snapshot["metrics"]:
        lines.append(f"| {entry['name']} | {entry['value']} | `{entry['source']}` | {entry['notes']} |")
    lines.extend(
        [
            "",
            "## Runtime wording",
            "",
            "- `agent-bom proxy` uses `7` inline detectors in the MCP JSON-RPC path.",
            "- The broader runtime protection engine uses `8` detectors.",
            "",
            "## Regenerate",
            "",
            "```bash",
            "python scripts/product_metrics_snapshot.py --write",
            "```",
        ]
    )
    return "\n".join(lines) + "\n"


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Write docs/PRODUCT_METRICS.md and docs/PRODUCT_METRICS.json")
    parser.add_argument("--markdown-out", default="docs/PRODUCT_METRICS.md", help="Markdown output path when writing")
    parser.add_argument("--json-out", default="docs/PRODUCT_METRICS.json", help="JSON output path when writing")
    args = parser.parse_args()

    snapshot = build_snapshot()
    markdown = render_markdown(snapshot)

    if args.write:
        markdown_path = ROOT / args.markdown_out
        json_path = ROOT / args.json_out
        markdown_path.write_text(markdown)
        json_path.write_text(json.dumps(snapshot, indent=2, sort_keys=False) + "\n")
    else:
        print(markdown, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
