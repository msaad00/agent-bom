#!/usr/bin/env python3
"""Every advertised inventory count must equal what the build actually ships.

A number typed into prose is a claim with no owner. It is correct on the day it
is written and silently wrong from the next refresh onward, because nothing
recomputes it. That is how the bundled MCP registry grew to 1081 entries while
six public surfaces — including two *runtime* strings the MCP server sends to
every connecting client — kept advertising 1013, and how a skill doc kept
claiming "940 verified" against an actual 60.

So this gate never stores an expected number. It DERIVES each one from the
artifact that ships:

    registry entries   len(src/agent_bom/mcp_registry.json["servers"])
    registry verified  those entries with verified=true
    MCP tools          _SERVER_CARD_TOOLS      (mcp_server_metadata.py)
    MCP resources      _SERVER_CARD_RESOURCES
    MCP prompts        _SERVER_CARD_PROMPTS

then sweeps every published surface — docs, site docs, integrations, READMEs,
SVG diagrams, and the shipped Python package — for sentences that state one of
those counts, and fails if any disagrees. Adding an entry to the registry is
then a two-line change: the data, and whatever prose the gate points at.

Note that SVGs are swept here deliberately. ``check_release_consistency.py``
skips every image suffix, which is exactly why a stale count sat unnoticed
inside ``docs/images/scan-pipeline-light.svg``.
"""

from __future__ import annotations

import argparse
import ast
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
REGISTRY = ROOT / "src" / "agent_bom" / "mcp_registry.json"
SERVER_METADATA = ROOT / "src" / "agent_bom" / "mcp_server_metadata.py"

# Published surfaces. Anything a user, client, or marketplace can read.
SEARCH_ROOTS: tuple[Path, ...] = (
    ROOT / "README.md",
    ROOT / "PYPI_README.md",
    ROOT / "DOCKER_HUB_README.md",
    ROOT / "docs",
    ROOT / "site-docs",
    ROOT / "integrations",
    ROOT / "src" / "agent_bom",
    ROOT / "ui" / "app",
    ROOT / "ui" / "components",
    # Shipping surfaces an advertised count can also reach: deploy manifests and
    # compose profiles are read by operators, and ui/lib holds the strings the
    # dashboard renders. Folded in from a second sweep that was covering these
    # two roots separately — one sweep, one judgement.
    ROOT / "deploy",
    ROOT / "ui" / "lib",
)
SEARCH_SUFFIXES = {".md", ".py", ".ts", ".tsx", ".json", ".svg", ".yaml", ".yml", ".txt"}
# Generated API artifacts restate prose from elsewhere; fixing the source fixes
# these, and sweeping them too would report one drift twice.
EXCLUDED_PARTS = {"node_modules", ".next", "__pycache__", "openapi", "archive", "egg-info"}
# The registry bundle is the source of truth, not a claim about itself — and each
# of its entries records that server's own tool count.
EXCLUDED_FILES = {REGISTRY}
# Lines of leeway when looking for the vocabulary that makes a number a claim
# about the registry. An SVG puts its "MCP Registry" label one line above the
# value it labels.
CONTEXT_WINDOW = 2

_NUMBER = r"([0-9][0-9,]*)"


@dataclass(frozen=True)
class CountRule:
    """One derived quantity plus the phrasings that advertise it.

    ``context`` keeps the sweep honest. "4 MCP servers" in a blog post about one
    person's laptop is a scan result, not a claim about the bundled registry, and
    a gate that cannot tell them apart gets muted. A rule with a ``context``
    pattern only fires when that vocabulary appears within
    ``CONTEXT_WINDOW`` lines — enough to catch an SVG whose "MCP Registry" label
    sits one line above its "1013 servers" value.
    """

    name: str
    patterns: tuple[re.Pattern[str], ...]
    context: re.Pattern[str] | None = None
    context_window: int = 0


# Each pattern must be anchored on vocabulary specific to the thing counted, so
# an unrelated "1000-entry ring buffer" or a benchmark's "604 servers" is not
# swept up. Every capture group is compared against the derived value.
RULES: tuple[CountRule, ...] = (
    CountRule(
        "registry entries",
        (
            re.compile(rf"{_NUMBER}[-\s]entry\s+(?:\S+\s+){{0,3}}?(?:server|registry)", re.I),
            re.compile(rf"{_NUMBER}\s+MCP\s+servers?\b", re.I),
            re.compile(rf"{_NUMBER}\s+MCP\s+server\s+(?:security\s+)?metadata\s+records", re.I),
            re.compile(rf"registry\s*\(\s*{_NUMBER}\s+servers", re.I),
            re.compile(rf"{_NUMBER}\s+servers?\s*,\s*[0-9][0-9,]*\s+verified", re.I),
        ),
        context=re.compile(r"registry|security\s+metadata", re.I),
    ),
    # Diagram labels sit on their own element, so the vocabulary that identifies
    # them lives on a neighbouring line rather than beside the number.
    CountRule(
        "registry entries",
        (re.compile(rf">\s*{_NUMBER}\s+servers\s*<", re.I),),
        context=re.compile(r"registry", re.I),
        context_window=2,
    ),
    CountRule(
        "registry verified entries",
        (re.compile(rf"[0-9][0-9,]*\s+servers?\s*,\s*{_NUMBER}\s+verified", re.I),),
        context=re.compile(r"registry|security\s+metadata", re.I),
    ),
    CountRule(
        "MCP tools",
        (
            # Inline HTML is presentation, not a shield from count drift.
            re.compile(rf"(?:<[^>]+>\s*)*{_NUMBER}(?:\s*</[^>]+>)*\s+MCP\s+tools\b", re.I),
            re.compile(rf"Tool\s+Categories\s*\(\s*{_NUMBER}\s+tools\s*\)", re.I),
        ),
    ),
    CountRule(
        "MCP resources",
        (re.compile(rf"{_NUMBER}\s+resources\s+and\s+[0-9][0-9,]*\s+workflow\s+prompts", re.I),),
    ),
    CountRule(
        "MCP prompts",
        (re.compile(rf"[0-9][0-9,]*\s+resources\s+and\s+{_NUMBER}\s+workflow\s+prompts", re.I),),
    ),
)


def _server_card_list(variable_name: str) -> list[object]:
    module = ast.parse(SERVER_METADATA.read_text(encoding="utf-8"))
    for node in module.body:
        if not isinstance(node, ast.Assign):
            continue
        if not any(isinstance(target, ast.Name) and target.id == variable_name for target in node.targets):
            continue
        value = ast.literal_eval(node.value)
        if isinstance(value, list):
            return value
    raise SystemExit(f"{SERVER_METADATA.relative_to(ROOT)} is missing {variable_name}")


def derive_counts() -> dict[str, int]:
    """Compute every advertised quantity from the artifact that actually ships."""
    registry = json.loads(REGISTRY.read_text(encoding="utf-8"))
    servers = registry.get("servers") or {}
    header = registry.get("_total_servers")
    if header is not None and int(header) != len(servers):
        raise SystemExit(f"{REGISTRY.relative_to(ROOT)}: _total_servers={header} but the bundle holds {len(servers)} servers")
    return {
        "registry entries": len(servers),
        "registry verified entries": sum(1 for entry in servers.values() if entry.get("verified") is True),
        "MCP tools": len(_server_card_list("_SERVER_CARD_TOOLS")),
        "MCP resources": len(_server_card_list("_SERVER_CARD_RESOURCES")),
        "MCP prompts": len(_server_card_list("_SERVER_CARD_PROMPTS")),
    }


def _files() -> list[Path]:
    seen: list[Path] = []
    for root in SEARCH_ROOTS:
        if root.is_file():
            seen.append(root)
            continue
        if not root.is_dir():
            continue
        for path in sorted(root.rglob("*")):
            if not path.is_file() or path.suffix.lower() not in SEARCH_SUFFIXES:
                continue
            if EXCLUDED_PARTS.intersection(path.parts) or path in EXCLUDED_FILES:
                continue
            seen.append(path)
    return seen


def _line_of(text: str, offset: int) -> int:
    return text.count("\n", 0, offset) + 1


def _has_context(rule: CountRule, lines: list[str], line_number: int) -> bool:
    if rule.context is None:
        return True
    start = max(0, line_number - 1 - rule.context_window)
    window = "\n".join(lines[start : line_number + rule.context_window])
    return rule.context.search(window) is not None


def find_stale_claims(counts: dict[str, int]) -> list[str]:
    problems: list[str] = []
    for path in _files():
        try:
            text = path.read_text(encoding="utf-8")
        except (UnicodeDecodeError, OSError):
            continue
        lines = text.splitlines()
        for rule in RULES:
            expected = counts[rule.name]
            for pattern in rule.patterns:
                for match in pattern.finditer(text):
                    claimed = int(match.group(1).replace(",", ""))
                    if claimed == expected:
                        continue
                    if not _has_context(rule, lines, _line_of(text, match.start())):
                        continue
                    problems.append(
                        f"{path.relative_to(ROOT)}:{_line_of(text, match.start())}: "
                        f"advertises {claimed} {rule.name}, but the build ships {expected} "
                        f"— {match.group(0).strip()!r}"
                    )
    return sorted(set(problems))


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--print-counts", action="store_true", help="Print the derived counts and exit.")
    args = parser.parse_args(argv)

    counts = derive_counts()
    if args.print_counts:
        print(json.dumps(counts, indent=2))
        return 0

    problems = find_stale_claims(counts)
    if problems:
        print(f"ERROR: {len(problems)} published count(s) disagree with what the build ships:\n", file=sys.stderr)
        for problem in problems:
            print(f"  - {problem}", file=sys.stderr)
        print("\nUpdate the prose (or the data) so every advertised number matches the shipped artifact.", file=sys.stderr)
        return 1

    summary = ", ".join(f"{value} {name}" for name, value in counts.items())
    print(f"Published counts match the shipped build — {summary}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
