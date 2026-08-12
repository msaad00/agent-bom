#!/usr/bin/env python3
"""Fail closed on CI shell pipelines that cannot report a failure.

GitHub Actions runs an unqualified ``run:`` step as ``bash -e {0}`` — ``-e`` but
NOT ``-o pipefail``. A pipeline therefore exits with the status of its LAST
command, so ``some-scanner | tee log`` exits 0 no matter how badly
``some-scanner`` failed. Declaring ``shell: bash`` instead runs
``bash --noprofile --norc -eo pipefail {0}``, which does propagate the failure.
Both invocations are documented under "workflow syntax → jobs.<job_id>.steps[*].shell".

This gate exists because the class bit us twice in one day: ``npm install --silent``
returned 0 while ERESOLVE-failing, and a capture script piped to ``tail`` hid a
non-zero exit. Worse, the repo's own OSV CVE gate piped ``osv-scanner`` into
``tee`` and then branched on ``|| { ... }`` — a branch that could never be taken,
so the "block on fixable CVEs" logic was dead code that always reported success.

A gate that cannot fail is not a gate. Every ``run:`` step containing a shell
pipeline must run under a pipefail shell, either by declaring ``shell: bash``
(or a job/workflow ``defaults.run.shell``) or by calling ``set -o pipefail``
before the first pipeline in the script body.
"""

from __future__ import annotations

import argparse
import re
import sys
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator

import yaml

ROOT = Path(__file__).resolve().parent.parent
WORKFLOWS = ROOT / ".github" / "workflows"
ACTIONS = ROOT / ".github" / "actions"
ROOT_ACTION = ROOT / "action.yml"

# Shells whose GitHub-Actions invocation already includes ``-o pipefail``, plus
# the non-POSIX shells where bash pipeline semantics simply do not apply.
_PIPEFAIL_SHELLS = {"bash", "pwsh", "powershell", "python"}
# ``sh -e {0}`` and the implicit ``bash -e {0}`` are the unsafe ones.
_UNSAFE_EXPLICIT_SHELLS = {"sh"}

_SET_PIPEFAIL = re.compile(r"^\s*set\s+[-+]\S*o?\s*.*\bpipefail\b|^\s*set\s+-\S*o\s+pipefail\b", re.M)
_HEREDOC_START = re.compile(r"<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")
_CASE_IN = re.compile(r"\bcase\b.*\bin\b\s*$")
_ESAC = re.compile(r"^\s*esac\b")
# A `case` alternation arm such as `  *.md|*.txt)` — a pattern list, not a pipeline.
_CASE_ARM = re.compile(r"^\s*\(?[^;&()]*\)(?:\s*(?:#.*)?)$")


@dataclass(frozen=True)
class Finding:
    path: Path
    step: str
    line: int
    pipeline: str

    def render(self) -> str:
        rel = self.path.relative_to(ROOT)
        return f"{rel}:{self.line}: step {self.step!r} pipes without pipefail:\n      {self.pipeline.strip()}"


def _strip_quotes_and_comments(line: str) -> str:
    """Blank out quoted spans and trailing comments so only shell operators remain.

    Pipes inside strings are data, not operators: a ``--jq '.a|.b'`` filter, a
    markdown table echoed into the step summary, and a Python regex in a heredoc
    all contain ``|`` and none of them is a pipeline.
    """
    out: list[str] = []
    quote: str | None = None
    index = 0
    while index < len(line):
        char = line[index]
        if quote is None and char == "\\":
            index += 2
            continue
        if quote is None and char in "'\"":
            quote = char
            out.append(" ")
        elif quote is not None and char == quote:
            quote = None
            out.append(" ")
        elif quote is None and char == "#" and (not out or out[-1].isspace()):
            break
        else:
            out.append(" " if quote is not None else char)
        index += 1
    return "".join(out)


def _script_lines(script: str) -> Iterator[tuple[int, str, str]]:
    """Yield ``(1-based line number, raw line, operator-only line)``.

    Heredoc bodies are skipped entirely — an embedded Python/SQL program is not
    shell, and its pipes are not shell pipelines.
    """
    heredoc: str | None = None
    for number, raw in enumerate(script.splitlines(), start=1):
        if heredoc is not None:
            if raw.strip() == heredoc:
                heredoc = None
            continue
        stripped = _strip_quotes_and_comments(raw)
        match = _HEREDOC_START.search(raw)
        if match:
            heredoc = match.group(2)
            # The line that opens the heredoc is still shell and may itself pipe.
            yield number, raw, stripped
            continue
        yield number, raw, stripped


def _pipelines(script: str) -> list[tuple[int, str]]:
    """Return ``(line number, raw line)`` for every real shell pipeline."""
    found: list[tuple[int, str]] = []
    case_depth = 0
    for number, raw, stripped in _script_lines(script):
        if _CASE_IN.search(stripped):
            case_depth += 1
            continue
        if _ESAC.match(stripped):
            case_depth = max(0, case_depth - 1)
            continue
        # Inside a `case`, a bare `a|b)` arm is a pattern list, not a pipeline.
        if case_depth and _CASE_ARM.match(stripped):
            continue
        # Collapse `||` so only single-pipe operators remain.
        operators = stripped.replace("||", "  ")
        if "|" in operators.replace("|&", "  "):
            found.append((number, raw))
    return found


def _mapping(node: yaml.Node | None) -> dict[str, yaml.Node]:
    if not isinstance(node, yaml.MappingNode):
        return {}
    return {str(key.value): value for key, value in node.value if isinstance(key, yaml.ScalarNode)}


def _sequence(node: yaml.Node | None) -> list[yaml.Node]:
    return list(node.value) if isinstance(node, yaml.SequenceNode) else []


def _scalar(node: yaml.Node | None) -> str | None:
    return str(node.value) if isinstance(node, yaml.ScalarNode) else None


def _default_shell(scope: dict[str, yaml.Node]) -> str | None:
    return _scalar(_mapping(_mapping(scope.get("defaults")).get("run")).get("shell"))


def _effective_shell(step: dict[str, yaml.Node], job_default: str | None, workflow_default: str | None) -> str | None:
    explicit = _scalar(step.get("shell"))
    for candidate in (explicit, job_default, workflow_default):
        if candidate and candidate.strip():
            return candidate.strip()
    return None


def _shell_is_pipefail(shell: str | None) -> bool:
    if shell is None:
        return False  # implicit `bash -e {0}` — no pipefail
    head = shell.split()[0]
    if head in _UNSAFE_EXPLICIT_SHELLS:
        return False
    if head in _PIPEFAIL_SHELLS:
        return True
    return "pipefail" in shell


def _steps(root: yaml.Node) -> Iterator[tuple[dict[str, yaml.Node], str | None, str | None]]:
    """Yield ``(step, job default shell, workflow default shell)``.

    Walks the composed node tree rather than ``safe_load`` output so every
    ``run:`` body keeps the source line it came from — a finding the reader
    cannot jump to is a finding they will not fix.
    """
    document = _mapping(root)
    workflow_default = _default_shell(document)
    jobs = _mapping(document.get("jobs"))
    if jobs:
        for job_node in jobs.values():
            job = _mapping(job_node)
            job_default = _default_shell(job) or workflow_default
            for step_node in _sequence(job.get("steps")):
                yield _mapping(step_node), job_default, workflow_default
        return
    runs = _mapping(document.get("runs"))
    for step_node in _sequence(runs.get("steps")):
        yield _mapping(step_node), None, None


def check_document(path: Path, text: str) -> list[Finding]:
    root = yaml.compose(text)
    if root is None:
        return []
    findings: list[Finding] = []
    for step, job_default, workflow_default in _steps(root):
        run_node = step.get("run")
        if not isinstance(run_node, yaml.ScalarNode):
            continue
        script = str(run_node.value)
        if _shell_is_pipefail(_effective_shell(step, job_default, workflow_default)):
            continue
        pipelines = _pipelines(script)
        if not pipelines:
            continue
        guard = _SET_PIPEFAIL.search(script)
        first_pipeline_line = pipelines[0][0]
        if guard and script[: guard.start()].count("\n") + 1 < first_pipeline_line:
            continue
        name = _scalar(step.get("name")) or _scalar(step.get("uses")) or "<unnamed>"
        # Report the step once; the first offending pipeline is enough to fix it.
        number, raw = pipelines[0]
        # ``start_mark.line`` is 0-based. For a block scalar (`run: |`) it points
        # at the indicator line, so the body starts one line later; for a plain
        # single-line `run:` the value is already on that line.
        header = 1 if run_node.style in {"|", ">"} else 0
        findings.append(Finding(path=path, step=name, line=run_node.start_mark.line + header + number, pipeline=raw))
    return findings


def _targets() -> list[Path]:
    paths: list[Path] = []
    if WORKFLOWS.is_dir():
        paths.extend(sorted(WORKFLOWS.glob("*.yml")))
        paths.extend(sorted(WORKFLOWS.glob("*.yaml")))
    if ACTIONS.is_dir():
        paths.extend(sorted(ACTIONS.rglob("action.yml")))
        paths.extend(sorted(ACTIONS.rglob("action.yaml")))
    if ROOT_ACTION.is_file():
        paths.append(ROOT_ACTION)
    return paths


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("paths", nargs="*", type=Path, help="Workflow files to check (default: every workflow + action).")
    args = parser.parse_args(argv)

    targets = [p.resolve() for p in args.paths] if args.paths else _targets()
    findings: list[Finding] = []
    for path in targets:
        findings.extend(check_document(path, path.read_text(encoding="utf-8")))

    if findings:
        print(f"ERROR: {len(findings)} CI step(s) pipe without pipefail — a failing command would be masked:\n", file=sys.stderr)
        for finding in findings:
            print(f"  - {finding.render()}", file=sys.stderr)
        print(
            "\nFix by adding `shell: bash` to the step (GitHub then runs "
            "`bash --noprofile --norc -eo pipefail {0}`), or `set -o pipefail` "
            "before the first pipeline.",
            file=sys.stderr,
        )
        return 1

    print(f"CI pipefail gate passed — {len(targets)} workflow/action file(s), no masked pipelines")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
