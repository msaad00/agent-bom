"""Contract tests for the npm bulk-advisory release gate."""

from __future__ import annotations

import gzip
import json
from pathlib import Path

import pytest

from scripts import check_npm_advisories
from scripts.check_npm_advisories import blocking_advisories, decode_report, lockfile_payload


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


def test_decode_report_accepts_unlabelled_gzip_and_blocks_high_severity() -> None:
    report = {
        "safe-package": [{"id": 1, "severity": "moderate", "title": "moderate"}],
        "unsafe-package": [{"id": 2, "severity": "high", "title": "high risk", "url": "https://example.test/2"}],
    }

    decoded = decode_report(gzip.compress(json.dumps(report).encode("utf-8")))

    assert decoded == report
    assert blocking_advisories(decoded) == [
        {
            "package": "unsafe-package",
            "id": 2,
            "severity": "high",
            "title": "high risk",
            "url": "https://example.test/2",
        }
    ]


def test_gate_blocks_high_advisories(tmp_path: Path, monkeypatch) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    monkeypatch.setattr(
        check_npm_advisories,
        "fetch_report",
        lambda _payload: {"pkg": [{"id": 2, "severity": "critical", "title": "unsafe"}]},
    )

    assert check_npm_advisories.run(lockfile) == 1


def test_gate_retries_and_fails_closed_on_transport_errors(tmp_path: Path, monkeypatch) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    attempts = 0

    def fail(_payload) -> dict:
        nonlocal attempts
        attempts += 1
        raise OSError("registry unavailable")

    monkeypatch.setattr(check_npm_advisories, "fetch_report", fail)
    monkeypatch.setattr(check_npm_advisories.time, "sleep", lambda _seconds: None)

    assert check_npm_advisories.run(lockfile) == 2
    assert attempts == 3


@pytest.mark.parametrize("advisory", [{}, {"severity": "unknown"}, {"severity": None}])
def test_gate_fails_closed_on_missing_or_unknown_severity(tmp_path: Path, monkeypatch, advisory) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    monkeypatch.setattr(check_npm_advisories, "fetch_report", lambda _payload: {"pkg": [advisory]})
    monkeypatch.setattr(check_npm_advisories.time, "sleep", lambda _seconds: None)

    assert check_npm_advisories.run(lockfile) == 2


def test_decode_report_bounds_uncompressed_and_gzip_expansion(monkeypatch) -> None:
    monkeypatch.setattr(check_npm_advisories, "MAX_COMPRESSED_RESPONSE_BYTES", 32)
    monkeypatch.setattr(check_npm_advisories, "MAX_DECOMPRESSED_RESPONSE_BYTES", 64)

    with pytest.raises(ValueError, match="compressed response exceeds"):
        decode_report(b"{" + b" " * 32)
    with pytest.raises(ValueError, match="decompressed response exceeds"):
        decode_report(gzip.compress(b"{" + b" " * 64))


def test_fetch_report_uses_a_bounded_transport_read(monkeypatch) -> None:
    seen_limits: list[int] = []

    class _Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, limit: int) -> bytes:
            seen_limits.append(limit)
            return b"{}"

    monkeypatch.setattr(check_npm_advisories.urllib.request, "urlopen", lambda _request, timeout: _Response())

    assert check_npm_advisories.fetch_report({"pkg": ["1.0.0"]}) == {}
    assert seen_limits == [check_npm_advisories.MAX_COMPRESSED_RESPONSE_BYTES + 1]
