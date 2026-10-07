"""Fail-closed source verification for the pinned CPython runtime repair."""

from __future__ import annotations

import hashlib
import importlib.util
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "deploy/docker/vendor/cpython-3.14.8/apply_tarfile_fix.py"


@pytest.fixture
def overlay():
    spec = importlib.util.spec_from_file_location("tarfile_security_overlay", SCRIPT)
    assert spec and spec.loader
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_unknown_source_is_rejected_without_changes(overlay):
    source = b"unrecognized standard library source\n"
    with pytest.raises(ValueError, match="Unexpected CPython tarfile source"):
        overlay.patched_source(source)


def test_patch_is_idempotent_for_verified_output(overlay, monkeypatch):
    source = b"# already verified patched source\n"
    monkeypatch.setattr(overlay, "AFTER_SHA256", hashlib.sha256(source).hexdigest())
    assert overlay.patched_source(source) is source


def test_verified_input_cannot_produce_unverified_output(overlay, monkeypatch):
    source = overlay.BEFORE
    monkeypatch.setattr(overlay, "BEFORE_SHA256", hashlib.sha256(source).hexdigest())
    with pytest.raises(ValueError, match="does not match the pinned upstream fix"):
        overlay.patched_source(source)


def test_image_applies_repair_before_install_and_copies_it_to_runtime():
    dockerfile = (ROOT / "Dockerfile").read_text()
    repair = "RUN python /tmp/apply_tarfile_fix.py"
    assert repair in dockerfile
    assert dockerfile.index(repair) < dockerfile.index("uv sync --locked")
    assert "COPY --from=builder /usr/local/lib/python3.14/tarfile.py /usr/local/lib/python3.14/tarfile.py" in dockerfile


def test_released_image_refresh_includes_the_overlay_source():
    workflow = (ROOT / ".github/workflows/refresh-latest-container.yml").read_text()
    security_overlay = workflow.split("- name: Apply current runtime security overlay", 1)[1].split("- name:", 1)[0]
    assert "deploy/docker/vendor/cpython-3.14.8" in security_overlay
