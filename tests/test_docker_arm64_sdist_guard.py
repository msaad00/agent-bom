"""Regression contract for Alpine arm64 source-only grammar dependencies."""

from __future__ import annotations

import hashlib
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
HEADER = ROOT / "deploy/docker/vendor/tree-sitter-typescript-0.23.2/tree_sitter/parser.h"
HEADER_SHA256 = "a1f6ef161fbaf48a0e10fca90ef5290a062462b307b3898aa562993853b9f80a"


def test_vendored_parser_header_matches_signed_upstream_release() -> None:
    assert HEADER.is_file()
    assert hashlib.sha256(HEADER.read_bytes()).hexdigest() == HEADER_SHA256
    assert (HEADER.parent.parent / "LICENSE").is_file()


def test_release_image_installs_the_missing_header_before_uv_sync() -> None:
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    copy = "COPY deploy/docker/vendor/tree-sitter-typescript-0.23.2/tree_sitter/parser.h"
    assert copy in dockerfile
    assert dockerfile.index(copy) < dockerfile.index("uv sync --locked")
    assert HEADER_SHA256 in dockerfile


def test_docker_input_prs_run_the_release_shaped_multiarch_gate() -> None:
    workflow = (ROOT / ".github/workflows/ci.yml").read_text(encoding="utf-8")
    docker_job = workflow.split("\n  docker:\n", 1)[1].split("\n  action-dogfood:\n", 1)[0]
    assert "needs: [changes, security, lint, test]" in docker_job
    assert "github.event_name == 'pull_request'" in docker_job
    assert "needs.changes.outputs.alpine_full == 'true'" in docker_job
    assert "--platform linux/amd64,linux/arm64" in docker_job
