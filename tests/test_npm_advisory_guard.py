"""Contract tests for the npm bulk-advisory release gate."""

from __future__ import annotations

import gzip
import json
import urllib.request
from pathlib import Path

import pytest

from scripts import check_npm_advisories
from scripts.check_npm_advisories import (
    blocking_advisories,
    decode_report,
    lockfile_payload,
)


def _write_lockfile(path: Path) -> None:
    path.write_text(
        json.dumps(
            {
                "lockfileVersion": 3,
                "packages": {
                    "": {"name": "app", "version": "1.0.0"},
                    "node_modules/pkg": {"version": "2.0.0"},
                },
            }
        ),
        encoding="utf-8",
    )


def test_lockfile_payload_preserves_exact_nested_and_scoped_versions(
    tmp_path: Path,
) -> None:
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
        "unsafe-package": [
            {
                "id": 2,
                "severity": "high",
                "title": "high risk",
                "url": "https://example.test/2",
            }
        ],
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


def test_gate_fails_closed_on_exhausted_transport_errors(
    tmp_path: Path,
    monkeypatch,
) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)

    def fail(_payload) -> dict:
        raise OSError("registry unavailable")

    monkeypatch.setattr(check_npm_advisories, "fetch_report", fail)

    assert check_npm_advisories.run(lockfile) == 2


@pytest.mark.parametrize(
    "advisory",
    [{}, {"severity": "unknown"}, {"severity": None}],
)
def test_gate_fails_closed_on_missing_or_unknown_severity(
    tmp_path: Path,
    monkeypatch,
    advisory,
) -> None:
    lockfile = tmp_path / "package-lock.json"
    _write_lockfile(lockfile)
    monkeypatch.setattr(
        check_npm_advisories,
        "fetch_report",
        lambda _payload: {"pkg": [advisory]},
    )

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
    seen_timeouts: list[int] = []
    seen_requests: list[urllib.request.Request] = []

    class Response:
        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, limit: int) -> bytes:
            seen_limits.append(limit)
            return b"{}"

    def open_response(request, timeout: int):
        seen_requests.append(request)
        seen_timeouts.append(timeout)
        return Response()

    monkeypatch.setattr(
        check_npm_advisories.urllib.request,
        "urlopen",
        open_response,
    )

    assert check_npm_advisories.fetch_report({"pkg": ["1.0.0"]}) == {}
    assert seen_limits == [check_npm_advisories.MAX_COMPRESSED_RESPONSE_BYTES + 1]
    assert seen_timeouts == [30]
    assert seen_requests[0].data == b'{"pkg":["1.0.0"]}'
    assert seen_requests[0].get_header("Content-encoding") is None
    assert seen_requests[0].get_header("Content-type") == "application/json"


def test_fetch_report_batches_large_lockfiles_and_rejects_unrequested_packages(
    monkeypatch,
) -> None:
    batch_sizes: list[int] = []

    class Response:
        def __init__(self, body: bytes):
            self.body = body

        def __enter__(self):
            return self

        def __exit__(self, *_args):
            return None

        def read(self, _limit: int) -> bytes:
            return self.body

    def open_response(request, timeout: int):
        assert timeout == check_npm_advisories.REQUEST_TIMEOUT_SECONDS
        request_payload = json.loads(request.data)
        batch_sizes.append(len(request_payload))
        first_name = next(iter(request_payload))
        return Response(json.dumps({first_name: []}).encode())

    monkeypatch.setattr(
        check_npm_advisories.urllib.request,
        "urlopen",
        open_response,
    )
    monkeypatch.setattr(check_npm_advisories, "MAX_PARALLEL_REQUESTS", 1)
    payload = {f"pkg-{index:03d}": ["1.0.0"] for index in range(205)}

    report = check_npm_advisories.fetch_report(payload)

    assert batch_sizes == [50, 50, 50, 50, 5]
    assert sorted(report) == [
        "pkg-000",
        "pkg-050",
        "pkg-100",
        "pkg-150",
        "pkg-200",
    ]

    def inject_unrequested(_request, timeout: int):
        assert timeout == check_npm_advisories.REQUEST_TIMEOUT_SECONDS
        return Response(b'{"not-requested":[]}')

    monkeypatch.setattr(
        check_npm_advisories.urllib.request,
        "urlopen",
        inject_unrequested,
    )
    with pytest.raises(ValueError, match="unrequested package"):
        check_npm_advisories.fetch_report({"pkg": ["1.0.0"]})


def test_fetch_report_retries_only_the_failed_batch(monkeypatch) -> None:
    attempts: dict[str, int] = {}

    def fetch_batch(batch):
        first_name = next(iter(batch))
        attempts[first_name] = attempts.get(first_name, 0) + 1
        if first_name == "pkg-050" and attempts[first_name] == 1:
            raise TimeoutError("transient npm timeout")
        return {}

    monkeypatch.setattr(check_npm_advisories, "_fetch_batch", fetch_batch)
    monkeypatch.setattr(check_npm_advisories, "MAX_PARALLEL_REQUESTS", 1)
    monkeypatch.setattr(check_npm_advisories.time, "sleep", lambda _seconds: None)
    payload = {f"pkg-{index:03d}": ["1.0.0"] for index in range(101)}

    assert check_npm_advisories.fetch_report(payload) == {}
    assert attempts == {"pkg-000": 1, "pkg-050": 2, "pkg-100": 1}
