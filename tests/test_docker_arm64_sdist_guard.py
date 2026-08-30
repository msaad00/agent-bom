"""Regression contract for Alpine arm64 source-only grammar dependencies."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VENDOR_ROOT = ROOT / "deploy/docker/vendor/tree-sitter-typescript-0.23.2"
HEADERS = {
    VENDOR_ROOT / "tree_sitter/parser.h": "a1f6ef161fbaf48a0e10fca90ef5290a062462b307b3898aa562993853b9f80a",
    VENDOR_ROOT / "common/scanner.h": "da66ef2bd14a3f7ea743e25ba068c6c9aae2c3509db200ff80c4a0e6116e564c",
}


def test_vendored_headers_match_signed_upstream_release() -> None:
    for header, expected_sha256 in HEADERS.items():
        assert header.is_file()
        assert hashlib.sha256(header.read_bytes()).hexdigest() == expected_sha256
    assert (VENDOR_ROOT / "LICENSE").is_file()


def test_release_image_installs_the_missing_headers_before_uv_sync() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    copies = (
        "COPY deploy/docker/vendor/tree-sitter-typescript-0.23.2/tree_sitter/parser.h",
        "COPY deploy/docker/vendor/tree-sitter-typescript-0.23.2/common/scanner.h",
    )
    for copy in copies:
        assert copy in dockerfile
        assert dockerfile.index(copy) < dockerfile.index("uv sync --locked")
    for expected_sha256 in HEADERS.values():
        assert expected_sha256 in dockerfile
    assert "mkdir -p /usr/local/include/tree-sitter-typescript/tsx/src" in dockerfile
    assert 'CFLAGS="-I/usr/local/include/tree-sitter-typescript/tsx/src"' in dockerfile


def test_docker_input_prs_run_the_release_shaped_multiarch_gate() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    docker_job = workflow.split("\n  docker:\n", 1)[1].split("\n  action-dogfood:\n", 1)[0]
    assert "needs: [changes, security, lint, test-core]" in docker_job
    assert "github.event_name == 'pull_request'" in docker_job
    assert "needs.changes.outputs.alpine_full == 'true'" in docker_job
    assert "--platform linux/amd64,linux/arm64" in docker_job

    required_job = workflow.split("\n  test:\n", 1)[1].split("\n  # 6. Dogfood", 1)[0]
    assert "name: Test (Python 3.13)" in required_job
    assert "needs: [changes, test-core, docker]" in required_job
    assert "DOCKER_RESULT: ${{ needs.docker.result }}" in required_job
    assert 'if [ "$DOCKER_REQUIRED" = "true" ] && [ "$DOCKER_RESULT" != "success" ]' in required_job
