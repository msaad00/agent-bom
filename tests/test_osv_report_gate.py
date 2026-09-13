"""OSV failures and unreadable output must never become a green CVE gate."""

import importlib.util
from pathlib import Path

import pytest

SCRIPT = Path(__file__).resolve().parents[1] / "scripts/check_osv_report.py"
spec = importlib.util.spec_from_file_location("osv_report_gate", SCRIPT)
assert spec and spec.loader
gate = importlib.util.module_from_spec(spec)
spec.loader.exec_module(gate)


def report(*, fixed=False):
    events = [{"introduced": "0"}]
    if fixed:
        events.append({"fixed": "2.0"})
    return {
        "results": [
            {
                "packages": [
                    {
                        "vulnerabilities": [
                            {
                                "id": "TEST-1",
                                "affected": [
                                    {
                                        "package": {"name": "example", "ecosystem": "PyPI"},
                                        "ranges": [{"type": "ECOSYSTEM", "events": events}],
                                    }
                                ],
                            }
                        ]
                    }
                ]
            }
        ]
    }


@pytest.mark.parametrize("status", [2, 126, 127, 128, 129, 255])
def test_scanner_failure_is_never_an_unfixable_exemption(status):
    assert not gate.evaluate(report(), status)


def test_preserves_clean_and_unfixable_policy():
    assert gate.evaluate({"results": []}, 0)
    assert gate.evaluate(report(), 1)
    assert not gate.evaluate(report(fixed=True), 1)


@pytest.mark.parametrize("value", [None, {}, [], {"results": None}, {"results": [None]}, {"results": [{"packages": [None]}]}])
def test_malformed_report_fails_closed(value):
    assert not gate.evaluate(value, 1)


def test_status_and_report_must_agree():
    assert not gate.evaluate({"results": []}, 1)
    assert not gate.evaluate(report(), 0)


def test_missing_advisory_data_is_not_an_unfixable_advisory():
    data = report()
    del data["results"][0]["packages"][0]["vulnerabilities"][0]["affected"]
    assert not gate.evaluate(data, 1)


@pytest.mark.parametrize(
    "status,payload,passes",
    [
        (127, "network error", False),
        (128, "no packages found", False),
        (1, "unrecognized table output", False),
        (1, report(fixed=True), False),
        (1, report(), True),
        (0, {"results": []}, True),
    ],
)
def test_actual_workflow_wrapper(tmp_path, monkeypatch, status, payload, passes):
    import json
    import os
    import subprocess

    import yaml

    root = SCRIPT.parents[1]
    workflow = yaml.safe_load((root / ".github/workflows/ci.yml").read_text())
    step = next(s for s in workflow["jobs"]["security"]["steps"] if s.get("name") == "OSV Scanner (all lockfiles)")
    body = step["run"]
    function = body[body.index("osv_gate() {") : body.index("\nosv_gate uv.lock")]
    scanner = tmp_path / "osv-scanner"
    scanner.write_text('#!/bin/sh\nprintf \'%s\' "$OSV_TEST_OUTPUT"\nexit "$OSV_TEST_STATUS"\n')
    scanner.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    monkeypatch.setenv("OSV_TEST_OUTPUT", json.dumps(payload) if isinstance(payload, dict) else payload)
    monkeypatch.setenv("OSV_TEST_STATUS", str(status))
    result = subprocess.run(
        ["bash", "-euo", "pipefail", "-c", function + '\nosv_gate uv.lock "$1"', "test", str(tmp_path / "report.json")],
        cwd=root,
        capture_output=True,
    )
    assert (result.returncode == 0) is passes
