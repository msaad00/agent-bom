from __future__ import annotations

import importlib.util
import json
import sys
from pathlib import Path

MODULE_PATH = Path(__file__).resolve().parents[1] / "scripts" / "pip_audit_delta_gate.py"
SPEC = importlib.util.spec_from_file_location("pip_audit_delta_gate", MODULE_PATH)
assert SPEC is not None
assert SPEC.loader is not None
gate = importlib.util.module_from_spec(SPEC)
sys.modules[SPEC.name] = gate
SPEC.loader.exec_module(gate)


def _audit(*dependencies: dict[str, object]) -> dict[str, object]:
    return {"dependencies": list(dependencies)}


def _dependency(
    name: str = "starlette",
    version: str = "1.0.0",
    vuln_id: str = "PYSEC-2026-161",
    *,
    fix_versions: list[str] | None = None,
    severity: str | None = None,
) -> dict[str, object]:
    vuln: dict[str, object] = {"id": vuln_id}
    if fix_versions is not None:
        vuln["fix_versions"] = fix_versions
    if severity is not None:
        vuln["severity"] = severity
    return {"name": name, "version": version, "vulns": [vuln]}


def _write_json(path: Path, data: dict[str, object]) -> None:
    path.write_text(json.dumps(data), encoding="utf-8")


def test_delta_gate_allows_findings_already_present_on_base(tmp_path: Path) -> None:
    current = tmp_path / "current.json"
    base = tmp_path / "base.json"
    finding = _dependency(fix_versions=["1.0.1"])
    _write_json(current, _audit(finding))
    _write_json(base, _audit(finding))

    assert gate.main(["--mode", "delta", "--current", str(current), "--base", str(base)]) == 0


def test_delta_gate_blocks_new_fixable_findings(tmp_path: Path) -> None:
    current = tmp_path / "current.json"
    base = tmp_path / "base.json"
    _write_json(current, _audit(_dependency(fix_versions=["1.0.1"])))
    _write_json(base, _audit())

    assert gate.main(["--mode", "delta", "--current", str(current), "--base", str(base)]) == 1


def test_strict_gate_blocks_existing_actionable_findings(tmp_path: Path) -> None:
    current = tmp_path / "current.json"
    _write_json(current, _audit(_dependency(fix_versions=["1.0.1"])))

    assert gate.main(["--mode", "strict", "--current", str(current)]) == 1


def test_high_severity_without_fix_is_actionable() -> None:
    findings = gate.actionable_findings(_audit(_dependency(severity="HIGH")))

    assert len(findings) == 1
    assert findings[0].severe is True
