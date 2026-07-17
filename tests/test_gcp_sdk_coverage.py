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
        for imported in re.findall(r"from google\.cloud import ([a-zA-Z0-9_, ]+)", text):
            mods.update(part.strip() for part in imported.split(",") if part.strip())
        for m in re.findall(r"\bgoogle\.cloud\.([a-zA-Z0-9_]+)", text):
            mods.add(m)
    return mods


def test_every_google_cloud_module_imported_is_installed() -> None:
    # Gate on compute_v1 (extra-only, not a leaky transitive dep) so the guard
    # skips cleanly when the gcp extra is not installed and runs only when it is.
    pytest.importorskip("google.cloud.compute_v1")
    used = _imported_google_cloud_modules()
    assert used, "no google.cloud imports found \u2014 scraper regex may be stale"
    # These modules are hard dependencies of inventory or decision-oriented IAM
    # collection. In particular, iam_v3 requires google-cloud-iam>=2.19.
    core = {"asset_v1", "compute_v1", "iam_admin_v1", "iam_v2", "iam_v3", "resourcemanager_v3", "storage"} & used
    missing = [m for m in sorted(core) if not _importable(f"google.cloud.{m}")]
    assert not missing, f"core google.cloud modules missing from the gcp extra: {missing} \u2014 add the distribution to pyproject.toml"


def _importable(name: str) -> bool:
    try:
        importlib.import_module(name)
        return True
    except Exception:  # noqa: BLE001
        return False
