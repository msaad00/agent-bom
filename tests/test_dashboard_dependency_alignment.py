from __future__ import annotations

import tomllib
from pathlib import Path


def test_dashboard_requirements_match_optional_extra_exactly() -> None:
    pyproject = tomllib.loads(Path("pyproject.toml").read_text(encoding="utf-8"))
    optional = set(pyproject["project"]["optional-dependencies"]["dashboard"])
    requirements = {
        line.strip()
        for line in Path("dashboard/requirements.txt").read_text(encoding="utf-8").splitlines()
        if line.strip() and not line.lstrip().startswith("#")
    }

    assert optional == requirements
