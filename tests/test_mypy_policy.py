from __future__ import annotations

import tomllib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]


def test_api_and_core_models_are_in_strict_mypy_phase() -> None:
    """Issue #1969: API/model typing should advance module-by-module."""
    data = tomllib.loads((ROOT / "pyproject.toml").read_text(encoding="utf-8"))
    overrides = data["tool"]["mypy"]["overrides"]
    strict_modules = set(overrides[0]["module"])

    assert {
        "agent_bom.api.auth",
        "agent_bom.api.models",
        "agent_bom.api.scim",
        "agent_bom.api.tenant_quota",
        "agent_bom.models",
    }.issubset(strict_modules)
    assert overrides[0]["disallow_untyped_defs"] is True
    assert overrides[0]["disallow_incomplete_defs"] is True
