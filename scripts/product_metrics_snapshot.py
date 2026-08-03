#!/usr/bin/env python3
"""Generate a verified snapshot of volatile product metrics from the repo."""

from __future__ import annotations

import argparse
import ast
import json
import re
import subprocess
from datetime import date
from pathlib import Path
from typing import Any, cast

ROOT = Path(__file__).resolve().parent.parent


def _tracked_files(*pathspecs: str) -> list[Path]:
    """Return tracked files for metrics so local ignored artifacts do not skew counts.

    Falls back to a filesystem walk when git cannot answer. The Alpine/musl CI
    job runs where ``git -C <root> ls-files`` exits 128 — git declines a
    repository whose ownership it considers dubious — and a hard failure there
    took down the whole metrics snapshot for a reason unrelated to any metric.

    The fallback is equivalent on the checkout that matters: a fresh CI clone
    has no untracked or ignored files, so the walk yields the same set. It is
    only a divergence risk in a dirty working tree, which is exactly where the
    git path still works.
    """
    try:
        result = subprocess.run(
            ["git", "-C", str(ROOT), "ls-files", "--", *pathspecs],
            check=True,
            capture_output=True,
            text=True,
        )
    except (subprocess.CalledProcessError, OSError):
        return _globbed_files(*pathspecs)
    return [ROOT / line for line in result.stdout.splitlines() if line]


def _globbed_files(*pathspecs: str) -> list[Path]:
    """Resolve git pathspecs against the filesystem, de-duplicated and sorted."""
    found: set[Path] = set()
    for spec in pathspecs:
        for path in ROOT.glob(spec):
            if path.is_file():
                found.add(path)
    return sorted(found)


def _count_workflows() -> int:
    return len(_tracked_files(".github/workflows/*.yml", ".github/workflows/*.yaml"))


def _count_test_files() -> int:
    return len(_tracked_files("tests/test_*.py", "tests/**/test_*.py"))


def _count_api_route_modules() -> int:
    return len(_tracked_files("src/agent_bom/api/routes/*.py"))


def _count_ui_app_pages() -> int:
    return len(_tracked_files("ui/app/page.tsx", "ui/app/page.jsx", "ui/app/**/page.tsx", "ui/app/**/page.jsx"))


def _count_python_modules() -> int:
    return len(_tracked_files("src/agent_bom/*.py", "src/agent_bom/**/*.py"))


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
    compliance_framework_count = _count_compliance_frameworks()
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
                "value": compliance_framework_count + 1,
                "source": "src/agent_bom/compliance_coverage.py",
                "notes": f"{compliance_framework_count} tag-mapped frameworks plus the OWASP AISVS benchmark surface.",
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
    for entry in cast(list[dict[str, object]], snapshot["metrics"]):
        lines.append(f"| {entry['name']} | {entry['value']} | `{entry['source']}` | {entry['notes']} |")
    proxy_detectors = next(
        (entry["value"] for entry in cast(list[dict[str, object]], snapshot["metrics"]) if entry["name"] == "Proxy inline detectors"),
        "7",
    )
    runtime_detectors = next(
        (
            entry["value"]
            for entry in cast(list[dict[str, object]], snapshot["metrics"])
            if entry["name"] == "Runtime protection engine detectors"
        ),
        "8",
    )
    lines.extend(
        [
            "",
            "## Runtime wording",
            "",
            f"- `agent-bom proxy` uses `{proxy_detectors}` inline detectors in the MCP JSON-RPC path.",
            f"- The broader runtime protection engine uses `{runtime_detectors}` detectors.",
            "",
            "## Regenerate",
            "",
            "```bash",
            "python scripts/product_metrics_snapshot.py --write",
            "```",
        ]
    )
    return "\n".join(lines) + "\n"


def _metric_value(snapshot: dict[str, Any], name: str) -> object:
    """Value of a named metric in *snapshot*, or None when it carries no such metric."""
    for metric in snapshot.get("metrics", []):
        if isinstance(metric, dict) and metric.get("name") == name:
            return metric.get("value")
    return None


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--write", action="store_true", help="Write docs/PRODUCT_METRICS.md and docs/PRODUCT_METRICS.json")
    parser.add_argument("--check", action="store_true", help="Exit non-zero if the committed snapshot is stale")
    parser.add_argument("--markdown-out", default="docs/PRODUCT_METRICS.md", help="Markdown output path when writing")
    parser.add_argument("--json-out", default="docs/PRODUCT_METRICS.json", help="JSON output path when writing")
    args = parser.parse_args(argv)

    snapshot = build_snapshot()
    markdown = render_markdown(snapshot)

    if args.check:
        # Compare on the same basis the drift gate uses: version and metrics.
        # ``generated_on`` deliberately does not participate — re-stamping on
        # every run is churn with no signal.
        json_path = ROOT / args.json_out
        try:
            committed = json.loads(json_path.read_text(encoding="utf-8"))
        except (OSError, json.JSONDecodeError) as exc:
            print(f"cannot read {args.json_out}: {exc}")
            return 1

        drifted = [
            f"  {metric['name']}: committed={_metric_value(committed, str(metric['name']))} actual={metric['value']}"
            for metric in cast(list[dict[str, object]], snapshot["metrics"])
            if _metric_value(committed, str(metric["name"])) != metric["value"]
        ]
        if drifted or committed.get("version") != snapshot["version"]:
            print("PRODUCT_METRICS snapshot is stale:")
            if committed.get("version") != snapshot["version"]:
                print(f"  version: committed={committed.get('version')} actual={snapshot['version']}")
            print("\n".join(drifted))
            print("Regenerate with: python scripts/product_metrics_snapshot.py --write")
            return 1

        print(f"OK: {args.json_out} matches the repository.")
        return 0

    if args.write:
        markdown_path = ROOT / args.markdown_out
        json_path = ROOT / args.json_out

        # Keep the existing stamp when nothing measurable moved. The drift gate
        # compares only ``version`` and ``metrics``, so re-stamping on every run
        # produced a diff carrying no signal — one that every branch had to
        # revert or carry, and that collided whenever two branches ran the
        # generator on different days.
        if json_path.exists():
            try:
                previous = json.loads(json_path.read_text(encoding="utf-8"))
            except (OSError, json.JSONDecodeError):
                previous = None
            if (
                isinstance(previous, dict)
                and previous.get("version") == snapshot["version"]
                and previous.get("metrics") == snapshot["metrics"]
                and isinstance(previous.get("generated_on"), str)
            ):
                snapshot["generated_on"] = previous["generated_on"]
                markdown = render_markdown(snapshot)

        markdown_path.write_text(markdown)
        json_path.write_text(json.dumps(snapshot, indent=2, sort_keys=False) + "\n")
    else:
        print(markdown, end="")

    return 0


if __name__ == "__main__":
    raise SystemExit(main())
