"""Contract for the CI pipefail gate (`scripts/check_ci_pipefail.py`).

The gate has to be simultaneously strict (a masked failure is a dead gate) and
quiet (a noisy gate gets disabled). These tests pin both halves: every shape
that genuinely masks an exit code must be caught, and every `|` that is data
rather than a pipeline must be ignored.
"""

from __future__ import annotations

import importlib.util
import sys
import textwrap
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parent.parent
SCRIPT = ROOT / "scripts" / "check_ci_pipefail.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_ci_pipefail", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    # `@dataclass` resolves annotations through `sys.modules[cls.__module__]`,
    # so the module must be registered before it executes.
    sys.modules[spec.name] = module
    spec.loader.exec_module(module)
    return module


gate = _load()


def _findings(workflow: str, path: Path | None = None):
    return gate.check_document(path or (ROOT / ".github" / "workflows" / "synthetic.yml"), workflow)


def _workflow(step_body: str) -> str:
    return "name: t\njobs:\n  j:\n    runs-on: ubuntu-latest\n    steps:\n" + step_body


class TestMaskedPipelinesAreCaught:
    def test_scanner_piped_to_tee_is_a_finding(self):
        """The exact shape that made the OSV CVE gate dead code."""
        wf = _workflow("      - name: scan\n        run: |\n          osv-scanner scan --lockfile=uv.lock | tee /tmp/out.txt || exit 1\n")
        findings = _findings(wf)
        assert len(findings) == 1
        assert findings[0].step == "scan"

    def test_capture_piped_to_tail_is_a_finding(self):
        wf = _workflow("      - name: capture\n        run: |\n          ./capture.sh | tail -100\n")
        assert len(_findings(wf)) == 1

    def test_set_pipefail_after_the_pipeline_does_not_count(self):
        """Guarding below the pipeline leaves the pipeline itself unguarded."""
        wf = _workflow("      - name: late\n        run: |\n          ./thing | tee out\n          set -o pipefail\n")
        assert len(_findings(wf)) == 1

    def test_reported_line_is_the_absolute_file_line(self):
        wf = _workflow("      - name: scan\n        run: |\n          echo start\n          ./thing | tee out\n")
        # Body line 2 of a block scalar that opens on file line 7.
        assert _findings(wf)[0].line == 9


class TestGuardsAreHonoured:
    def test_shell_bash_is_accepted(self):
        """GitHub runs `shell: bash` as `bash --noprofile --norc -eo pipefail {0}`."""
        wf = _workflow("      - name: ok\n        shell: bash\n        run: |\n          ./thing | tee out\n")
        assert _findings(wf) == []

    def test_set_pipefail_before_the_pipeline_is_accepted(self):
        wf = _workflow("      - name: ok\n        run: |\n          set -euo pipefail\n          ./thing | tee out\n")
        assert _findings(wf) == []

    def test_job_level_default_shell_is_accepted(self):
        wf = textwrap.dedent("""\
            name: t
            jobs:
              j:
                runs-on: ubuntu-latest
                defaults:
                  run:
                    shell: bash
                steps:
                  - name: ok
                    run: |
                      ./thing | tee out
            """)
        assert _findings(wf) == []

    def test_workflow_level_default_shell_is_accepted(self):
        wf = textwrap.dedent("""\
            name: t
            defaults:
              run:
                shell: bash
            jobs:
              j:
                runs-on: ubuntu-latest
                steps:
                  - name: ok
                    run: |
                      ./thing | tee out
            """)
        assert _findings(wf) == []

    @pytest.mark.parametrize("shell", ["pwsh", "powershell", "python"])
    def test_non_posix_shells_are_exempt(self, shell: str):
        wf = _workflow(f"      - name: ok\n        shell: {shell}\n        run: |\n          a | b\n")
        assert _findings(wf) == []

    def test_explicit_sh_is_not_exempt(self):
        """`shell: sh` runs as `sh -e {0}` — still no pipefail."""
        wf = _workflow("      - name: nope\n        shell: sh\n        run: |\n          ./thing | tee out\n")
        assert len(_findings(wf)) == 1


class TestPipesThatAreNotPipelines:
    def test_double_pipe_or_is_not_a_pipeline(self):
        wf = _workflow("      - name: ok\n        run: |\n          ./thing || echo failed\n")
        assert _findings(wf) == []

    def test_pipe_inside_single_quotes_is_data(self):
        """A jq filter is a string argument, not a shell pipeline."""
        wf = _workflow("      - name: ok\n        run: |\n          gh api x --jq '.a|.b'\n")
        assert _findings(wf) == []

    def test_markdown_table_echo_is_data(self):
        wf = _workflow('      - name: ok\n        run: |\n          echo "| col | col |" >> "$GITHUB_STEP_SUMMARY"\n')
        assert _findings(wf) == []

    def test_pipe_inside_a_heredoc_body_is_not_shell(self):
        """An embedded Python program's regex alternation is not a pipeline."""
        body = textwrap.indent(
            textwrap.dedent("""\
                python - <<'PY'
                import re
                re.match(r'a|b', x)
                PY
                """),
            " " * 10,
        )
        assert _findings(_workflow("      - name: ok\n        run: |\n" + body)) == []

    def test_pipeline_on_the_heredoc_opening_line_is_still_caught(self):
        wf = _workflow("      - name: nope\n        run: |\n          python - <<'PY' | tee out\n          print(1)\n          PY\n")
        assert len(_findings(wf)) == 1

    def test_case_alternation_arm_is_not_a_pipeline(self):
        body = textwrap.indent(
            textwrap.dedent("""\
                case $x in
                  a|b)
                    echo hi
                    ;;
                esac
                """),
            " " * 10,
        )
        assert _findings(_workflow("      - name: ok\n        run: |\n" + body)) == []

    def test_comment_containing_a_pipe_is_ignored(self):
        wf = _workflow("      - name: ok\n        run: |\n          # pipe a | b here\n          echo hi\n")
        assert _findings(wf) == []


class TestCompositeActions:
    def test_composite_action_steps_are_scanned(self):
        action = "runs:\n  using: composite\n  steps:\n    - name: nope\n      run: |\n        ./thing | tee out\n"
        findings = gate.check_document(ROOT / ".github" / "actions" / "x" / "action.yml", action)
        assert len(findings) == 1


class TestTheRepositoryItself:
    def test_every_shipped_workflow_passes_the_gate(self):
        """The whole point: no CI step in this repo may mask a failing command."""
        findings = [f for path in gate._targets() for f in gate.check_document(path, path.read_text(encoding="utf-8"))]
        assert findings == [], "masked CI pipelines:\n" + "\n".join(f.render() for f in findings)
