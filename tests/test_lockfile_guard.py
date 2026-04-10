from __future__ import annotations

import importlib.util
import json
from pathlib import Path

_MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "check_npm_lockfile.py"
_SPEC = importlib.util.spec_from_file_location("check_npm_lockfile", _MODULE_PATH)
assert _SPEC and _SPEC.loader
_MODULE = importlib.util.module_from_spec(_SPEC)
_SPEC.loader.exec_module(_MODULE)
validate_lockfile = _MODULE.validate_lockfile


def _write_lockfile(tmp_path: Path, packages: dict[str, object]) -> Path:
    path = tmp_path / "package-lock.json"
    path.write_text(json.dumps({"name": "ui", "lockfileVersion": 3, "packages": packages}))
    return path


def test_validate_lockfile_accepts_standard_package_keys(tmp_path: Path) -> None:
    path = _write_lockfile(
        tmp_path,
        {
            "": {"name": "ui"},
            "node_modules/eslint": {"version": "9.39.4"},
            "node_modules/@babel/core": {"version": "7.29.0"},
        },
    )
    assert validate_lockfile(path) == []


def test_validate_lockfile_rejects_nonportable_package_keys(tmp_path: Path) -> None:
    path = _write_lockfile(
        tmp_path,
        {
            "": {"name": "ui"},
            "../../../private/tmp/worktree/ui/node_modules/eslint": {"version": "9.39.4"},
        },
    )
    errors = validate_lockfile(path)
    assert len(errors) == 1
    assert "non-portable package key" in errors[0]
