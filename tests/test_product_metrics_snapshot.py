"""Contract tests for the generated product-metrics snapshot."""

from __future__ import annotations

import importlib.util
import json
import subprocess
import sys
from pathlib import Path
from types import ModuleType
from typing import cast
from unittest import mock

from agent_bom.compliance_coverage import TAG_MAPPED_FRAMEWORKS

ROOT = Path(__file__).resolve().parents[1]
SCRIPT = ROOT / "scripts" / "product_metrics_snapshot.py"
METRICS_JSON = ROOT / "docs" / "PRODUCT_METRICS.json"
METRICS_MARKDOWN = ROOT / "docs" / "PRODUCT_METRICS.md"


def _load_metrics_script() -> ModuleType:
    spec = importlib.util.spec_from_file_location("product_metrics_snapshot", SCRIPT)
    assert spec is not None and spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_compliance_metric_uses_the_canonical_framework_count() -> None:
    module = _load_metrics_script()
    snapshot = module.build_snapshot()
    metrics = cast(list[dict[str, object]], snapshot["metrics"])
    compliance = next(metric for metric in metrics if metric["name"] == "Compliance surfaces")
    tag_mapped_count = len(TAG_MAPPED_FRAMEWORKS)

    assert tag_mapped_count == 15
    assert compliance["value"] == tag_mapped_count + 1 == 16
    assert compliance["notes"] == f"{tag_mapped_count} tag-mapped frameworks plus the OWASP AISVS benchmark surface."

    checked_in = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
    assert checked_in["version"] == snapshot["version"]
    assert checked_in["metrics"] == snapshot["metrics"]
    checked_in_compliance = next(metric for metric in checked_in["metrics"] if metric["name"] == "Compliance surfaces")
    assert checked_in_compliance == compliance
    assert (
        f"| Compliance surfaces | {compliance['value']} | `src/agent_bom/compliance_coverage.py` | {compliance['notes']} |"
        in METRICS_MARKDOWN.read_text(encoding="utf-8")
    )


def test_counts_survive_git_being_unusable():
    """CI's Alpine job runs where git refuses to operate on the checkout.

    `git -C <root> ls-files` exits 128 inside that container — git declines a
    repository whose ownership it considers dubious. `_tracked_files` used
    check=True, so the whole metrics snapshot raised CalledProcessError and the
    job failed for a reason unrelated to any metric.

    A pristine CI checkout has no untracked or ignored files, so a filesystem
    walk yields the same set. Fall back to it rather than failing the build.
    """
    snapshot = _load_metrics_script()

    real_run = subprocess.run

    def _git_refuses(cmd, *args, **kwargs):
        if cmd and cmd[0] == "git":
            raise subprocess.CalledProcessError(128, cmd, stderr="detected dubious ownership")
        return real_run(cmd, *args, **kwargs)

    with mock.patch.object(subprocess, "run", _git_refuses):
        workflows = snapshot._count_workflows()
        tests = snapshot._count_test_files()
        routes = snapshot._count_api_route_modules()

    assert workflows > 0, "workflow count must not silently collapse to zero"
    assert tests > 0
    assert routes > 0


def test_git_and_fallback_agree_on_a_clean_checkout():
    """The fallback must not quietly report a different number than git does."""
    snapshot = _load_metrics_script()

    via_git = snapshot._count_api_route_modules()

    real_run = subprocess.run

    def _git_refuses(cmd, *args, **kwargs):
        if cmd and cmd[0] == "git":
            raise subprocess.CalledProcessError(128, cmd, stderr="dubious ownership")
        return real_run(cmd, *args, **kwargs)

    with mock.patch.object(subprocess, "run", _git_refuses):
        via_glob = snapshot._count_api_route_modules()

    assert via_git == via_glob


def test_write_preserves_the_stamp_when_no_metric_changed() -> None:
    """Re-running --write must not churn the committed artifact.

    The snapshot stamps ``generated_on``, but the drift gate compares only
    ``version`` and ``metrics``. Re-stamping on every run produced a diff with
    no signal, which every branch then had to revert or carry, and which
    collided whenever two branches ran the generator on different days.

    Simulated by ageing the committed stamp rather than by waiting a day, so
    the assertion is real on the day it is written.
    """
    original_json = METRICS_JSON.read_text(encoding="utf-8")
    original_md = METRICS_MARKDOWN.read_text(encoding="utf-8")
    try:
        aged = json.loads(original_json)
        aged["generated_on"] = "2020-01-01"
        METRICS_JSON.write_text(json.dumps(aged, indent=2, sort_keys=False) + "\n", encoding="utf-8")

        subprocess.run(  # noqa: S603
            [sys.executable, str(SCRIPT), "--write"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )

        rewritten = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
        assert rewritten["generated_on"] == "2020-01-01", (
            "--write re-stamped generated_on even though no metric changed; "
            "that is churn every branch has to carry"
        )
        assert rewritten["metrics"] == aged["metrics"], "metrics must be untouched when nothing moved"
    finally:
        METRICS_JSON.write_text(original_json, encoding="utf-8")
        METRICS_MARKDOWN.write_text(original_md, encoding="utf-8")


def test_write_restamps_when_a_metric_actually_moved() -> None:
    """The stamp must still advance when a metric genuinely changes."""
    original_json = METRICS_JSON.read_text(encoding="utf-8")
    original_md = METRICS_MARKDOWN.read_text(encoding="utf-8")
    try:
        stale = json.loads(original_json)
        stale["generated_on"] = "2020-01-01"
        stale["metrics"][0]["value"] = -1
        METRICS_JSON.write_text(json.dumps(stale, indent=2, sort_keys=False) + "\n", encoding="utf-8")

        subprocess.run(  # noqa: S603
            [sys.executable, str(SCRIPT), "--write"],
            cwd=ROOT,
            check=True,
            capture_output=True,
        )

        rewritten = json.loads(METRICS_JSON.read_text(encoding="utf-8"))
        assert rewritten["generated_on"] != "2020-01-01", "a real metric change must refresh the stamp"
        assert rewritten["metrics"][0]["value"] != -1, "the stale metric must be corrected"
    finally:
        METRICS_JSON.write_text(original_json, encoding="utf-8")
        METRICS_MARKDOWN.write_text(original_md, encoding="utf-8")
