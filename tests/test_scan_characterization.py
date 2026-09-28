"""Characterization goldens for the ``scan`` command.

These pin the observable contract of ``agent-bom scan`` — the normalized
machine output and the process exit code — across the demo inventory, a small
project fixture, the severity gate, SARIF and CycloneDX. Volatile values
(timestamps, UUIDs, durations, temp paths, the package version) are replaced
with stable placeholders before comparison so a golden only changes when the
scan's behaviour does.

Regenerate after an intentional behaviour change with::

    AGENT_BOM_UPDATE_SCAN_GOLDENS=1 pytest tests/test_scan_characterization.py
"""

from __future__ import annotations

import hashlib
import json
import os
import re
from pathlib import Path
from typing import Any

import pytest
from click.testing import CliRunner

from agent_bom import __version__
from agent_bom.cli import main

GOLDEN_DIR = Path(__file__).parent / "fixtures" / "scan_characterization"
UPDATE = os.environ.get("AGENT_BOM_UPDATE_SCAN_GOLDENS") == "1"

_UUID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}", re.IGNORECASE)
_TIMESTAMP = re.compile(r"\d{4}-\d{2}-\d{2}[T ]\d{2}:\d{2}:\d{2}(?:\.\d+)?(?:Z|[+-]\d{2}:?\d{2})?")
_LONG_HEX = re.compile(r"\b[0-9a-f]{16,}\b")
_VOLATILE_KEY = re.compile(r"(duration|elapsed|_ms$|_seconds$|^seconds$|timing|latency)", re.IGNORECASE)


def _normalize_str(value: str, tmp: str) -> str:
    if tmp:
        value = value.replace(tmp, "<TMP>")
    value = value.replace(__version__, "<VERSION>")
    value = _UUID.sub("<UUID>", value)
    value = _TIMESTAMP.sub("<TS>", value)
    return _LONG_HEX.sub("<HEX>", value)


def normalize(value: Any, tmp: str = "") -> Any:
    """Replace run-specific values with stable placeholders, recursively."""
    if isinstance(value, dict):
        return {
            _normalize_str(str(key), tmp): ("<VOLATILE>" if _VOLATILE_KEY.search(str(key)) else normalize(item, tmp))
            for key, item in value.items()
        }
    if isinstance(value, list):
        # Entity order keys off identifiers hashed from the absolute scan path,
        # which differs per temp dir, so list order is compared canonically.
        return sorted((normalize(item, tmp) for item in value), key=lambda item: json.dumps(item, sort_keys=True))
    if isinstance(value, str):
        return _normalize_str(value, tmp)
    return value


def _project_fixture(root: Path) -> Path:
    project = root / "proj"
    project.mkdir()
    (project / "requirements.txt").write_text("requests==2.19.0\njinja2==2.10\n", encoding="utf-8")
    (project / "package.json").write_text(
        json.dumps({"name": "fixture-app", "version": "1.0.0", "dependencies": {"lodash": "4.17.4", "minimist": "1.2.0"}}),
        encoding="utf-8",
    )
    (project / ".mcp.json").write_text(
        json.dumps(
            {
                "mcpServers": {
                    "filesystem": {
                        "command": "npx",
                        "args": ["-y", "@modelcontextprotocol/server-filesystem@0.6.2", "/data"],
                        "env": {"API_TOKEN": "${API_TOKEN}"},
                    }
                }
            }
        ),
        encoding="utf-8",
    )
    return project


_EXTENSIONS = {"json": ".json", "sarif": ".sarif", "cyclonedx": ".cdx.json"}
_BASE = ["scan", "--offline", "--no-auto-update-db", "--quiet"]

CASES: dict[str, dict[str, Any]] = {
    "demo_json": {"args": ["--demo", "--format", "json"], "fmt": "json"},
    "demo_json_exit_zero": {"args": ["--demo", "--format", "json", "--exit-zero"], "fmt": "json", "digest": True},
    "demo_fail_on_high": {"args": ["--demo", "--format", "json", "--fail-on-severity", "high"], "fmt": "json", "digest": True},
    "demo_sarif": {"args": ["--demo", "--format", "sarif"], "fmt": "sarif"},
    "demo_cyclonedx": {"args": ["--demo", "--format", "cyclonedx"], "fmt": "cyclonedx"},
    "project_json": {"args": ["--project", "{project}", "--format", "json"], "fmt": "json"},
    "project_fail_on_low": {
        "args": ["--project", "{project}", "--format", "json", "--fail-on-severity", "low"],
        "fmt": "json",
        "digest": True,
    },
    "project_sarif": {"args": ["--project", "{project}", "--format", "sarif"], "fmt": "sarif"},
    "project_cyclonedx": {"args": ["--project", "{project}", "--format", "cyclonedx"], "fmt": "cyclonedx"},
}


def run_case(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> dict[str, Any]:
    monkeypatch.setattr("agent_bom.db.local_analytics.record_scan_report_best_effort", lambda *_a, **_k: None)
    project = _project_fixture(tmp_path)
    out = tmp_path / f"{name}{_EXTENSIONS[CASES[name]['fmt']]}"
    args = [a.replace("{project}", str(project)) for a in CASES[name]["args"]]
    result = CliRunner().invoke(main, [*_BASE, *args, "--output", str(out)], catch_exceptions=False)
    document = json.loads(out.read_text(encoding="utf-8")) if out.exists() else None
    normalized = normalize(document, str(tmp_path.resolve()))
    if CASES[name].get("digest") and normalized is not None:
        # Gate variants share the base case's document; pin its digest and the
        # verdict rather than duplicating the full golden.
        canonical = json.dumps(normalized, sort_keys=True).encode("utf-8")
        normalized = {"sha256": hashlib.sha256(canonical).hexdigest(), "summary": normalized.get("summary")}
    return {"exit_code": result.exit_code, "document": normalized, "_output": result.output}


@pytest.mark.parametrize("name", sorted(CASES))
def test_scan_characterization(name: str, tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    actual = run_case(name, tmp_path, monkeypatch)
    cli_output = actual.pop("_output")
    golden = GOLDEN_DIR / f"{name}.json"
    rendered = json.dumps(actual, indent=1, sort_keys=True) + "\n"
    if UPDATE:
        golden.parent.mkdir(parents=True, exist_ok=True)
        golden.write_text(rendered, encoding="utf-8")
    assert golden.exists(), f"missing golden {golden}; run with AGENT_BOM_UPDATE_SCAN_GOLDENS=1"
    assert actual["document"] is not None, f"scan wrote no machine output: {cli_output}"
    assert rendered == golden.read_text(encoding="utf-8")


def test_normalizer_strips_only_volatile_values() -> None:
    raw = {
        "scan_id": "7f3e4b2a-9c1d-5f8e-a0b4-12c3d4e5f6a7",
        "generated_at": "2026-09-27T10:11:12.123456Z",
        "path": "/tmp/xyz/proj/requirements.txt",
        "duration_ms": 12.5,
        "severity": "critical",
        "count": 3,
    }
    assert normalize(raw, "/tmp/xyz") == {
        "scan_id": "<UUID>",
        "generated_at": "<TS>",
        "path": "<TMP>/proj/requirements.txt",
        "duration_ms": "<VOLATILE>",
        "severity": "critical",
        "count": 3,
    }
