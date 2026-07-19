"""Guard: every google.cloud module the cloud code imports is in the gcp extra.

The Google SDKs are per-service distributions, so a missing one only surfaces as
a live ImportError that degrades a whole discovery class to empty (the imports
are guarded, so CI never sees it). This test scrapes every ``google.cloud.<mod>``
reference across the cloud code and asserts each maps to a distribution declared
by the gcp extra — failing fast without depending on which optional extras
happen to be installed in the test process.

Two hard rules keep the guard from silently rotting:
  1. Every scraped module MUST have a distribution mapping here (an unmapped
     module fails the test — that is how apigateway_v1 / artifactregistry_v1 /
     orgpolicy_v2 slipped through when the map was partial).
  2. Every mapped distribution MUST be declared in the gcp extra.
"""

from __future__ import annotations

import re
import tomllib
from pathlib import Path

_CLOUD_DIR = Path(__file__).resolve().parents[1] / "src" / "agent_bom" / "cloud"
_PYPROJECT = _CLOUD_DIR.parents[2] / "pyproject.toml"

# Every google.cloud.* module the cloud code imports -> its PyPI distribution.
_MODULE_DISTRIBUTIONS = {
    "aiplatform": "google-cloud-aiplatform",
    "aiplatform_v1": "google-cloud-aiplatform",
    "apigateway_v1": "google-cloud-api-gateway",
    "artifactregistry_v1": "google-cloud-artifact-registry",
    "asset_v1": "google-cloud-asset",
    "bigquery": "google-cloud-bigquery",
    "compute_v1": "google-cloud-compute",
    "container_v1": "google-cloud-container",
    "functions_v2": "google-cloud-functions",
    "iam_admin_v1": "google-cloud-iam",
    "iam_v2": "google-cloud-iam",
    "iam_v3": "google-cloud-iam",
    "logging": "google-cloud-logging",
    "logging_v2": "google-cloud-logging",
    "orgpolicy_v2": "google-cloud-org-policy",
    "pubsub_v1": "google-cloud-pubsub",
    "resourcemanager_v3": "google-cloud-resource-manager",
    "run_v2": "google-cloud-run",
    "storage": "google-cloud-storage",
}


def _imported_google_cloud_modules() -> set[str]:
    mods: set[str] = set()
    for py in _CLOUD_DIR.rglob("*.py"):
        text = py.read_text()
        # `from google.cloud import a, b as c, d`
        for imported in re.findall(r"from google\.cloud import ([a-zA-Z0-9_, ]+)", text):
            for part in imported.split(","):
                name = part.strip().split(" as ")[0].strip()
                if name:
                    mods.add(name)
        # `google.cloud.<mod>` attribute / dotted-import references
        for m in re.findall(r"\bgoogle\.cloud\.([a-zA-Z0-9_]+)", text):
            mods.add(m)
    return mods


def test_every_scraped_module_has_a_distribution_mapping() -> None:
    used = _imported_google_cloud_modules()
    assert used, "no google.cloud imports found — scraper regex may be stale"
    unmapped = used - _MODULE_DISTRIBUTIONS.keys()
    assert not unmapped, (
        f"google.cloud modules imported by the cloud code with no distribution "
        f"mapping in this test: {sorted(unmapped)} — add them here AND to the gcp extra"
    )


def test_every_google_cloud_module_imported_is_declared_in_gcp_extra() -> None:
    used = _imported_google_cloud_modules()
    metadata = tomllib.loads(_PYPROJECT.read_text())
    declarations = metadata["project"]["optional-dependencies"]["gcp"]
    declared_names = {re.split(r"[<>=!~; ]", item, maxsplit=1)[0].casefold() for item in declarations}
    missing = {
        module: distribution
        for module, distribution in _MODULE_DISTRIBUTIONS.items()
        if module in used and distribution.casefold() not in declared_names
    }
    assert not missing, f"google.cloud modules missing from the gcp extra: {missing}"
