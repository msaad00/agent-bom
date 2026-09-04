"""Contract tests for the exact-lockfile npm advisory release gate."""

from __future__ import annotations

import json
import subprocess
from pathlib import Path
from types import SimpleNamespace

import pytest

from scripts import check_npm_advisories
from scripts.check_npm_advisories import lockfile_payload, validate_audit_report


def _write_lockfile(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {"": {"name": "app", "version": "1.0.0"}, "node_modules/pkg": {"version": "2.0.0"}},
            }
        ),
        encoding="utf-8",
    )


def _audit_report(*, severity: str | None = None, audited: int = 1) -> dict:
    counts = {name: 0 for name in (*sorted(check_npm_advisories.VALID_SEVERITIES), "total")}
    vulnerabilities = {}
    if severity is not None:
        counts[severity] = 1
        counts["total"] = 1
        vulnerabilities["pkg"] = {"name": "pkg", "severity": severity, "via": []}
    return {
        "auditReportVersion": 2,
        "vulnerabilities": vulnerabilities,
        "metadata": {
            "vulnerabilities": counts,
            "dependencies": {"prod": audited, "dev": 0, "optional": 0, "peer": 0, "peerOptional": 0, "total": audited},
        },
    }


def test_lockfile_payload_preserves_exact_nested_and_scoped_versions(tmp_path: Path) -> None:
    lockfile = tmp_path / "package-lock.json"
    lockfile.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "version": "1.0.0"},
                    "node_modules/plain": {"version": "2.0.0"},
                    "node_modules/@scope/pkg": {"version": "3.0.0"},
                    "node_modules/parent/node_modules/plain": {"version": "1.5.0"},
                },
            }
        ),
        encoding="utf-8",
    )

    assert lockfile_payload(lockfile) == {
        "@scope/pkg": ["3.0.0"],
        "plain": ["1.5.0", "2.0.0"],
    }


def test_gate_accepts_valid_complete_audit(tmp_path: Path, monkeypatch) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    monkeypatch.setattr(check_npm_advisories, "run_npm_audit", lambda _path: (_audit_report(), 0))

    assert check_npm_advisories.run(lockfile) == 0


def test_gate_blocks_validated_high_or_critical_audit(tmp_path: Path, monkeypatch) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    monkeypatch.setattr(check_npm_advisories, "run_npm_audit", lambda _path: (_audit_report(severity="critical"), 1))

    assert check_npm_advisories.run(lockfile) == 1


@pytest.mark.parametrize(
    "report",
    [
        {},
        {"auditReportVersion": 1},
        _audit_report(audited=0),
        {
            **_audit_report(),
            "vulnerabilities": {"not-requested": {"name": "not-requested", "severity": "high"}},
        },
        {
            **_audit_report(),
            "vulnerabilities": {"pkg": {"name": "pkg", "severity": "unknown"}},
        },
    ],
)
def test_gate_fails_closed_on_invalid_or_incomplete_report(tmp_path: Path, monkeypatch, report) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    monkeypatch.setattr(check_npm_advisories, "run_npm_audit", lambda _path: (report, 0))

    assert check_npm_advisories.run(lockfile) == 2


@pytest.mark.parametrize("report,returncode", [(_audit_report(), 1), (_audit_report(severity="high"), 0)])
def test_gate_fails_closed_when_exit_status_disagrees_with_report(tmp_path: Path, monkeypatch, report, returncode) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    monkeypatch.setattr(check_npm_advisories, "run_npm_audit", lambda _path: (report, returncode))

    assert check_npm_advisories.run(lockfile) == 2


def test_validate_audit_report_rejects_count_mismatch() -> None:
    report = _audit_report()
    report["metadata"]["vulnerabilities"]["high"] = 1
    report["metadata"]["vulnerabilities"]["total"] = 1

    with pytest.raises(ValueError, match="counts do not match"):
        validate_audit_report(report, {"pkg": ["2.0.0"]})


def test_run_npm_audit_uses_supported_bounded_client(tmp_path: Path, monkeypatch) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    seen: dict = {}

    def fake_run(command, **kwargs):
        seen.update(command=command, **kwargs)
        kwargs["stdout"].write(json.dumps(_audit_report()).encode())
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(check_npm_advisories.subprocess, "run", fake_run)

    report, returncode = check_npm_advisories.run_npm_audit(lockfile)

    assert returncode == 0
    assert report == _audit_report()
    assert seen["command"] == [
        "npm",
        "audit",
        "--package-lock-only",
        "--ignore-scripts",
        "--audit-level=high",
        "--json",
    ]
    assert seen["cwd"] == tmp_path
    assert seen["stdin"] is subprocess.DEVNULL
    assert seen["check"] is False
    assert seen["timeout"] == check_npm_advisories.NPM_AUDIT_TIMEOUT_SECONDS


def test_run_npm_audit_rejects_oversized_or_failed_output(tmp_path: Path, monkeypatch) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    monkeypatch.setattr(check_npm_advisories, "MAX_AUDIT_REPORT_BYTES", 32)

    def oversized(_command, **kwargs):
        kwargs["stdout"].write(b"{" + b" " * 32)
        return SimpleNamespace(returncode=0)

    monkeypatch.setattr(check_npm_advisories.subprocess, "run", oversized)
    with pytest.raises(ValueError, match="size limit"):
        check_npm_advisories.run_npm_audit(lockfile)

    def failed(_command, **_kwargs):
        return SimpleNamespace(returncode=2)

    monkeypatch.setattr(check_npm_advisories.subprocess, "run", failed)
    with pytest.raises(OSError, match="transport failed"):
        check_npm_advisories.run_npm_audit(lockfile)


def test_gate_fails_closed_on_npm_timeout(tmp_path: Path, monkeypatch) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)

    def timeout(_path):
        raise subprocess.TimeoutExpired(["npm", "audit"], 360)

    monkeypatch.setattr(check_npm_advisories, "run_npm_audit", timeout)

    assert check_npm_advisories.run(lockfile) == 2
