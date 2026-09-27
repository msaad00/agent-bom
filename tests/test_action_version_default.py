"""The GitHub Action installs the agent-bom release its own ref ships.

Pinning ``msaad00/agent-bom@vX`` must install ``agent-bom==X``, not whatever is
newest on PyPI. The install step is executed here against a stub ``pip`` so the
test asserts the real shell logic, not a string in action.yml.
"""

from __future__ import annotations

import os
import stat
import subprocess
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def _install_step() -> dict:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    return next(step for step in action["runs"]["steps"] if step.get("name") == "Install agent-bom")


def _run_install(
    tmp_path: Path, *, version_input: str, action_version: str | None, fail_pinned: bool = False, ai_enrich: str = "false"
) -> tuple[list[str], str]:
    action_dir = tmp_path / "action"
    action_dir.mkdir()
    if action_version is not None:
        (action_dir / "pyproject.toml").write_text(f'[project]\nname = "agent-bom"\nversion = "{action_version}"\n', encoding="utf-8")
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    log = tmp_path / "pip.log"
    pip = bin_dir / "pip"
    fail_clause = f'case "$*" in *"agent-bom=={action_version}"*) exit 1;; esac\n' if fail_pinned else ""
    pip.write_text(f'#!/usr/bin/env bash\necho "$*" >> "{log}"\n{fail_clause}exit 0\n', encoding="utf-8")
    pip.chmod(pip.stat().st_mode | stat.S_IEXEC)

    # Same shell flags GitHub uses for `shell: bash` steps.
    step = _install_step()
    env = {"PATH": f"{bin_dir}:{os.environ['PATH']}", "HOME": str(tmp_path)}
    for name in step["env"]:
        env[name] = ""
    env.update(
        {
            "AGENT_BOM_VERSION": version_input,
            "AI_ENRICH": ai_enrich,
            "INSTALL_FROM_SOURCE": "false",
            "ACTION_PATH": str(action_dir),
        }
    )
    shell = ["bash", "--noprofile", "--norc", "-eo", "pipefail", "-c", step["run"]]
    result = subprocess.run(shell, env=env, capture_output=True, text=True, check=True)
    return log.read_text(encoding="utf-8").splitlines(), result.stdout + result.stderr


def test_install_step_receives_the_action_path() -> None:
    assert _install_step()["env"]["ACTION_PATH"] == "${{ github.action_path }}"


def test_empty_input_installs_the_version_the_action_ref_ships(tmp_path: Path) -> None:
    calls, _ = _run_install(tmp_path, version_input="", action_version="9.8.7")
    assert calls == ["install agent-bom==9.8.7 packaging"]


def test_explicit_version_input_wins(tmp_path: Path) -> None:
    calls, _ = _run_install(tmp_path, version_input="1.2.3", action_version="9.8.7")
    assert calls == ["install agent-bom==1.2.3 packaging"]


def test_latest_input_installs_newest_release(tmp_path: Path) -> None:
    calls, _ = _run_install(tmp_path, version_input="latest", action_version="9.8.7")
    assert calls == ["install agent-bom packaging"]


def test_unreleased_ref_version_falls_back_to_latest_with_a_warning(tmp_path: Path) -> None:
    calls, output = _run_install(tmp_path, version_input="", action_version="9.8.7", fail_pinned=True)
    assert calls == ["install agent-bom==9.8.7 packaging", "install agent-bom packaging"]
    assert "::warning" in output and "9.8.7" in output


def test_input_description_documents_the_ref_default() -> None:
    action = yaml.safe_load((ROOT / "action.yml").read_text(encoding="utf-8"))
    description = action["inputs"]["agent-bom-version"]["description"]
    assert "Empty = latest" not in description
    assert "action ref" in description and "latest" in description


def test_ai_enrich_extra_is_valid_pip_syntax_with_a_pinned_version(tmp_path: Path) -> None:
    calls, _ = _run_install(tmp_path, version_input="", action_version="9.8.7", ai_enrich="true")
    assert calls == ["install agent-bom[ai-enrich]==9.8.7 packaging"]


def test_missing_action_pyproject_falls_back_under_pipefail(tmp_path: Path) -> None:
    calls, output = _run_install(tmp_path, version_input="", action_version=None)
    assert calls == ["install agent-bom packaging"]
    assert "::warning" in output
