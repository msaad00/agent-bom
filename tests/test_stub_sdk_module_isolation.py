"""Guard: hand-rolled provider-SDK stubs must not leak between tests.

Several suites fake optional cloud SDKs (`snowflake`, `boto3`, `databricks`,
`google`, ...) by writing synthetic modules straight into ``sys.modules``. Those
entries outlive the test that wrote them, so under ``pytest-xdist --dist
worksteal`` (plus ``pytest-randomly``) a stub from one file can be sitting in
``sys.modules`` when an unrelated file starts. A victim installer that uses
``setdefault`` then silently no-ops, patches an orphan module, and the code under
test resolves the *leaked* stub instead — an intermittent, seed-dependent
failure.

``reset_global_test_state`` in ``tests/conftest.py`` restores the stub namespace
around every test. These tests pin that contract down.
"""

from __future__ import annotations

import subprocess
import sys
import types
from pathlib import Path

from tests.conftest import _restore_stub_sdk_modules, _snapshot_stub_sdk_modules

_REPO_ROOT = Path(__file__).resolve().parent.parent


def test_snapshot_restore_drops_stubs_a_test_added():
    snapshot = _snapshot_stub_sdk_modules()

    stub = types.ModuleType("snowflake")
    stub.connector = types.ModuleType("snowflake.connector")
    sys.modules["snowflake"] = stub
    sys.modules["snowflake.connector"] = stub.connector

    _restore_stub_sdk_modules(snapshot)

    assert "snowflake" not in sys.modules
    assert "snowflake.connector" not in sys.modules


def test_snapshot_restore_reinstates_a_stub_a_test_replaced():
    original = types.ModuleType("databricks")
    sys.modules["databricks"] = original
    try:
        snapshot = _snapshot_stub_sdk_modules()
        sys.modules["databricks"] = types.ModuleType("databricks")

        _restore_stub_sdk_modules(snapshot)

        assert sys.modules["databricks"] is original
    finally:
        sys.modules.pop("databricks", None)


def test_snapshot_restore_leaves_real_packages_alone():
    """Only synthetic stubs are reverted; genuinely imported packages stay."""
    snapshot = _snapshot_stub_sdk_modules()
    import json as _real_module_probe  # noqa: F401

    _restore_stub_sdk_modules(snapshot)

    assert "json" in sys.modules
    assert sys.modules["json"].__spec__ is not None


def test_snowflake_cortex_discovery_survives_a_prior_stub_installer():
    """The exact CI ordering that failed: leaker file first, victim test second.

    ``tests/cloud/test_snowflake_inventory_evaluation_failed.py`` installs a stub
    ``snowflake`` package; ``test_snowflake_cortex_agents`` then has to still see
    its own mock. Run as a subprocess so the ordering is real rather than
    simulated.
    """
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "pytest",
            "tests/cloud/test_snowflake_inventory_evaluation_failed.py",
            "tests/cloud/test_cloud.py::test_snowflake_cortex_agents",
            "-p",
            "no:randomly",
            "-p",
            "no:cacheprovider",
            "-q",
            "--no-header",
        ],
        cwd=_REPO_ROOT,
        capture_output=True,
        text=True,
        timeout=600,
    )

    assert result.returncode == 0, f"stub leaked across files:\n{result.stdout}\n{result.stderr}"
