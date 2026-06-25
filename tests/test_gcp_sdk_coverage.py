"""Guard: every google.cloud module the GCP code imports is in the gcp extra.

The Google SDKs are per-service distributions, so a missing one only surfaces as
a live ImportError that degrades a whole discovery class to empty. This test
scrapes every ``from google.cloud import <mod>`` in the cloud code and asserts
each resolves under the installed gcp extra — failing fast in CI instead.
"""

from __future__ import annotations

import importlib
import re
from pathlib import Path

import pytest

_CLOUD_DIR = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "cloud"


def _imported_google_cloud_modules() -> set[str]:
    mods: set[str] = set()
    for py in _CLOUD_DIR.glob("gcp*.py"):
        text = py.read_text()
        for m in re.findall(r"from google\.cloud import ([a-zA-Z0-9_]+)", text):
            mods.add(m)
        for m in re.findall(r"\bgoogle\.cloud\.([a-zA-Z0-9_]+)", text):
            mods.add(m)
    return mods


def test_every_google_cloud_module_imported_is_installed() -> None:
    pytest.importorskip("google.cloud.compute_v1")  # gate on a non-transitive, extra-only module
    used = _imported_google_cloud_modules()
    assert used, "no google.cloud imports found — scraper regex may be stale"
    missing = []
    for mod in sorted(used):
        # import_module is more reliable than find_spec here: google.cloud.*
        # are namespace subpackages whose __spec__ can be None, which makes
        # find_spec raise ValueError even though the module imports fine.
        try:
            importlib.import_module(f"google.cloud.{mod}")
        except Exception:  # noqa: BLE001 — only ImportError means truly absent
            missing.append(mod)
    assert not missing, (
        f"google.cloud modules imported by GCP code but missing from the gcp extra: {missing} — add the distribution to pyproject.toml"
    )
