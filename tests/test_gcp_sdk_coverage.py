"""Guard: every google.cloud module the GCP code imports is in the gcp extra.

The Google SDKs are per-service distributions, so a missing one only surfaces as
a live ImportError that degrades a whole discovery class to empty. This test
scrapes every ``from google.cloud import <mod>`` in the cloud code and asserts
each maps to a distribution declared by the gcp extra — failing fast without
depending on which optional extras happen to be installed in the test process.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_CLOUD_DIR = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "cloud"
_PYPROJECT = _CLOUD_DIR.parents[2] / "pyproject.toml"
_MODULE_DISTRIBUTIONS = {
    "asset_v1": "google-cloud-asset",
    "compute_v1": "google-cloud-compute",
    "iam_admin_v1": "google-cloud-iam",
    "iam_v2": "google-cloud-iam",
    "iam_v3": "google-cloud-iam",
    "resourcemanager_v3": "google-cloud-resource-manager",
    "storage": "google-cloud-storage",
}


def _imported_google_cloud_modules() -> set[str]:
    mods: set[str] = set()
    for py in _CLOUD_DIR.glob("gcp*.py"):
        text = py.read_text()
        for imported in re.findall(r"from google\.cloud import ([a-zA-Z0-9_, ]+)", text):
            mods.update(part.strip() for part in imported.split(",") if part.strip())
        for m in re.findall(r"\bgoogle\.cloud\.([a-zA-Z0-9_]+)", text):
            mods.add(m)
    return mods


def test_every_google_cloud_module_imported_is_declared_in_gcp_extra() -> None:
    used = _imported_google_cloud_modules()
    assert used, "no google.cloud imports found — scraper regex may be stale"
    metadata = tomllib.loads(_PYPROJECT.read_text())
    declarations = metadata["project"]["optional-dependencies"]["gcp"]
    declared_names = {re.split(r"[<>=!~; ]", item, maxsplit=1)[0].casefold() for item in declarations}
    missing = {
        module: distribution
        for module, distribution in _MODULE_DISTRIBUTIONS.items()
        if module in used and distribution.casefold() not in declared_names
    }
    assert not missing, f"google.cloud modules missing from the gcp extra: {missing}"
