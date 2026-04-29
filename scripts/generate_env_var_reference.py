#!/usr/bin/env python3
"""Generate the canonical AGENT_BOM_* env-var reference from src/agent_bom/config.py.

Two outputs:

1. docs/operations/ENV_VARS.md — operator-facing reference table grouped by
   the section comments in config.py.

2. A drift check (`--check`) that asserts:
   - docs/operations/ENV_VARS.md is up to date with config.py, and
   - every AGENT_BOM_* literal referenced anywhere under src/agent_bom/ is
     either declared in config.py (the canonical source) or explicitly
     allowlisted in scripts/env_var_allowlist.txt (intentionally dynamic
     vars that don't belong in config.py — runtime feature flags, secrets,
     deploy-only toggles).

Pre-merge gate: the .github/workflows/ci.yml "Lint and Type Check" job runs
this script with --check so newly added env vars must either be promoted to
config.py or explicitly allowlisted, with a comment explaining why.

Usage:
    python scripts/generate_env_var_reference.py            # regenerate
    python scripts/generate_env_var_reference.py --check    # CI guard
"""

from __future__ import annotations

import argparse
import ast
import re
import sys
from dataclasses import dataclass
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
CONFIG_FILE = ROOT / "src" / "agent_bom" / "config.py"
SRC_DIR = ROOT / "src" / "agent_bom"
DOC_FILE = ROOT / "docs" / "operations" / "ENV_VARS.md"
ALLOWLIST_FILE = ROOT / "scripts" / "env_var_allowlist.txt"

# Helpers in config.py that wrap os.environ.get() with a typed default.
_CONFIG_HELPERS = {"_bool", "_float", "_int", "_str"}

ENV_VAR_LITERAL = re.compile(r'"(AGENT_BOM_[A-Z][A-Z0-9_]*)"')

DOC_HEADER = """# AGENT_BOM_* environment variable reference

> Generated from `src/agent_bom/config.py` by
> `scripts/generate_env_var_reference.py`. Do not edit by hand — re-run the
> generator and commit the diff. CI fails if this file is out of date or if
> a new `AGENT_BOM_*` reference appears in `src/agent_bom/` without being
> declared in `config.py` or added to `scripts/env_var_allowlist.txt`.

This is the canonical operator reference for the tuning knobs in
`src/agent_bom/config.py`. Helm values, deployment runbooks, and procurement
evidence should link here rather than redocument env vars locally.

For dynamic operational env vars that intentionally live outside `config.py`
(secrets, runtime feature flags, deploy-only toggles, OIDC/SAML/SCIM
credentials, etc.), see `scripts/env_var_allowlist.txt`. Those are tracked
so they cannot regress silently, but they are not part of this reference.

"""


@dataclass(frozen=True)
class EnvVar:
    env_key: str
    python_name: str
    type_label: str
    default_repr: str
    section: str
    description: str
    line: int

    def sort_key(self) -> tuple[str, str]:
        return (self.section, self.env_key)


def _parse_config(path: Path) -> list[EnvVar]:
    source = path.read_text(encoding="utf-8")
    lines = source.splitlines()
    tree = ast.parse(source)

    # Build a list of (start_line, header_text) section markers from comments
    # of the form ``# ── Some Section ────``.
    section_re = re.compile(r"^\s*#\s*[─━-]+\s*(.+?)\s*[─━-]+\s*$")
    sections: list[tuple[int, str]] = []
    for idx, raw in enumerate(lines, start=1):
        m = section_re.match(raw)
        if m:
            sections.append((idx, m.group(1).strip()))

    def section_for(line_no: int) -> str:
        active = "Uncategorized"
        for marker_line, name in sections:
            if marker_line <= line_no:
                active = name
            else:
                break
        return active

    # Trailing-comment description on the same line as the assignment, or the
    # nearest preceding `# …` comment block (skipping section markers).
    def description_for(line_no: int) -> str:
        if 1 <= line_no <= len(lines):
            inline = lines[line_no - 1]
            if "  # " in inline:
                return inline.split("  # ", 1)[1].strip()
        # Walk backwards collecting consecutive comment lines.
        collected: list[str] = []
        i = line_no - 2
        while i >= 0:
            stripped = lines[i].strip()
            if not stripped:
                if collected:
                    break
                i -= 1
                continue
            if section_re.match(lines[i]):
                break
            if stripped.startswith("#"):
                collected.append(stripped.lstrip("#").strip())
                i -= 1
                continue
            break
        if not collected:
            return ""
        # Comments were collected bottom-up.
        return " ".join(reversed(collected))[:240]

    out: list[EnvVar] = []
    for node in ast.walk(tree):
        if not isinstance(node, ast.Assign):
            continue
        if len(node.targets) != 1 or not isinstance(node.targets[0], ast.Name):
            continue
        py_name = node.targets[0].id
        value = node.value

        env_key: str | None = None
        type_label = ""
        default_repr = ""

        if isinstance(value, ast.Call) and isinstance(value.func, ast.Name) and value.func.id in _CONFIG_HELPERS:
            if not value.args or not isinstance(value.args[0], ast.Constant) or not isinstance(value.args[0].value, str):
                continue
            env_key = value.args[0].value
            type_label = {"_bool": "bool", "_float": "float", "_int": "int", "_str": "str"}[value.func.id]
            default_repr = ast.unparse(value.args[1]).strip() if len(value.args) >= 2 and value.args[1] is not None else ""
        elif isinstance(value, ast.Call) and _is_environ_get(value) and value.args and isinstance(value.args[0], ast.Constant):
            arg = value.args[0].value
            if isinstance(arg, str) and arg.startswith("AGENT_BOM_"):
                env_key = arg
                type_label = "str"
                default_repr = ast.unparse(value.args[1]).strip() if len(value.args) >= 2 and value.args[1] is not None else '""'

        if env_key is None or not env_key.startswith("AGENT_BOM_"):
            continue

        out.append(
            EnvVar(
                env_key=env_key,
                python_name=py_name,
                type_label=type_label,
                default_repr=default_repr,
                section=section_for(node.lineno),
                description=description_for(node.lineno),
                line=node.lineno,
            )
        )

    return sorted(out, key=lambda v: v.sort_key())


def _is_environ_get(call: ast.Call) -> bool:
    func = call.func
    if isinstance(func, ast.Attribute) and func.attr == "get":
        target = func.value
        if isinstance(target, ast.Attribute) and target.attr == "environ":
            return True
    return False


def _scan_src_references(src_dir: Path, declared: set[str]) -> set[str]:
    """Return AGENT_BOM_* env-var literals referenced in src/ outside config.py."""
    found: set[str] = set()
    for path in sorted(src_dir.rglob("*.py")):
        if path == CONFIG_FILE:
            continue
        try:
            text = path.read_text(encoding="utf-8")
        except OSError:
            continue
        for match in ENV_VAR_LITERAL.findall(text):
            if match not in declared:
                found.add(match)
    return found


def _load_allowlist(path: Path) -> set[str]:
    if not path.exists():
        return set()
    out: set[str] = set()
    for raw in path.read_text(encoding="utf-8").splitlines():
        line = raw.split("#", 1)[0].strip()
        if line:
            out.add(line)
    return out


def _render_doc(env_vars: list[EnvVar]) -> str:
    by_section: dict[str, list[EnvVar]] = {}
    for var in env_vars:
        by_section.setdefault(var.section, []).append(var)

    parts = [DOC_HEADER]
    section_blocks: list[str] = []
    for section_name in sorted(by_section):
        block: list[str] = [f"## {section_name}\n", "| Env var | Type | Default | Description |\n", "|---|---|---|---|\n"]
        for var in by_section[section_name]:
            default = var.default_repr or "—"
            description = var.description.replace("|", "\\|") or "—"
            block.append(f"| `{var.env_key}` | `{var.type_label}` | `{default}` | {description} |\n")
        section_blocks.append("".join(block))
    parts.append("\n".join(section_blocks))
    # End the file with a single trailing newline (pre-commit's end-of-file
    # fixer strips extra blank lines, so we must match that on the dot).
    return "".join(parts).rstrip("\n") + "\n"


def _diff_summary(expected: str, actual: str) -> str:
    if expected == actual:
        return ""
    expected_lines = expected.splitlines()
    actual_lines = actual.splitlines()
    head = []
    for idx, (e, a) in enumerate(zip(expected_lines, actual_lines), start=1):
        if e != a:
            head.append(f"  line {idx}\n    on disk: {a!r}\n    expected: {e!r}")
            if len(head) >= 5:
                break
    if len(expected_lines) != len(actual_lines):
        head.append(f"  length differs: on-disk={len(actual_lines)} expected={len(expected_lines)}")
    return "\n".join(head)


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--check",
        action="store_true",
        help="Verify the doc is up to date and no new ad-hoc env vars exist; exit 1 on drift.",
    )
    args = parser.parse_args()

    env_vars = _parse_config(CONFIG_FILE)
    declared = {var.env_key for var in env_vars}

    ad_hoc = _scan_src_references(SRC_DIR, declared)
    allowlist = _load_allowlist(ALLOWLIST_FILE)
    untracked = sorted(ad_hoc - allowlist)
    stale_allowlist = sorted(allowlist - ad_hoc)

    rendered = _render_doc(env_vars)

    if args.check:
        problems: list[str] = []
        on_disk = DOC_FILE.read_text(encoding="utf-8") if DOC_FILE.exists() else ""
        if on_disk != rendered:
            problems.append(
                f"{DOC_FILE.relative_to(ROOT)} is out of date — re-run "
                "`python scripts/generate_env_var_reference.py` and commit the diff.\n" + _diff_summary(rendered, on_disk)
            )
        if untracked:
            joined = "\n  - ".join(untracked)
            problems.append(
                "These AGENT_BOM_* env vars are referenced under src/agent_bom/ but are\n"
                "neither declared in src/agent_bom/config.py nor allowlisted in\n"
                "scripts/env_var_allowlist.txt. Promote them to config.py (preferred)\n"
                f"or add them to the allowlist with a one-line reason:\n  - {joined}"
            )
        if stale_allowlist:
            joined = "\n  - ".join(stale_allowlist)
            problems.append(
                f"These entries in scripts/env_var_allowlist.txt are no longer referenced under src/agent_bom/ — remove them:\n  - {joined}"
            )
        if problems:
            print("\n\n".join(problems), file=sys.stderr)
            return 1
        print(f"OK: {len(env_vars)} declared, {len(allowlist)} allowlisted.")
        return 0

    DOC_FILE.parent.mkdir(parents=True, exist_ok=True)
    DOC_FILE.write_text(rendered, encoding="utf-8")
    print(f"Wrote {DOC_FILE.relative_to(ROOT)} ({len(env_vars)} env vars).")
    if untracked:
        print(
            f"WARNING: {len(untracked)} ad-hoc AGENT_BOM_* refs not in config.py or allowlist. Run with --check for the full list.",
            file=sys.stderr,
        )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
