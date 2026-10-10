"""Keep CI and publication on the same compatible docs renderer."""

from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]


def test_docs_builds_share_the_compatible_highlighter_pin():
    commands = []
    for name in ("ci.yml", "docs.yml"):
        workflow = yaml.safe_load((ROOT / ".github/workflows" / name).read_text())
        commands.extend(
            step["run"]
            for job in workflow["jobs"].values()
            for step in job.get("steps", [])
            if step.get("run", "").startswith("uv tool run") and "mkdocs build --strict" in step["run"]
        )
    assert len(commands) == 2
    assert commands[0] == commands[1]
    # mkdocstrings 1.0.3 uses the pre-12 Highlight constructor.
    assert "--with pymdown-extensions==11.0.2" in commands[0]
